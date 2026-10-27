'use strict';

/**
 * step 6 — writing, anchoring and boot-verifying signed audit-chain checkpoints.
 *
 * createSignedCheckpoint()  signs the current chain position (lifetime modern count + head hash) with the dedicated
 *                           checkpoint key, chains it to the previous signed checkpoint, persists it
 *                             · to PostgreSQL (audit_signed_checkpoints, append-only) when PG is enabled, and
 *                             · to <audit.log>.checkpoints.jsonl (one JSON line per checkpoint, fsynced) — the
 *                               file deployment's record, and what the independent verifier reads next to audit.log,
 *                           and anchors it as an AUDIT_CHECKPOINT transparency leaf (M2) when transparency is on.
 * startCheckpointScheduler() every AUDIT_CHECKPOINT_TICK_MS: a new checkpoint once QODIQA_AUDIT_CHECKPOINT_EVERY
 * entries or QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS (default 15 min — was 24 h, only if
 *                           the chain grew) have passed since the last one. Never on the request path.
 * verifyLatestCheckpointAtBoot()  FAIL-CLOSED: the latest signed checkpoint (PG and/or sidecar) must verify
 *                           (signature by a published, non-revoked checkpoint key) and the audit chain must hold
 *                           exactly its headHash at its chainLength. No checkpoint yet = nothing to verify.
 */

const fs = require('fs');
const path = require('path');
const { signCheckpoint, verifyCheckpoint } = require('./checkpoint');

// tighter defaults — the window an insider can rewrite before the next signed (and, when configured,
// witnessed + exported) checkpoint pins it. Was 10,000 entries / 24 h.
const DEFAULT_EVERY = 1_000;
const DEFAULT_MAX_AGE_MS = 15 * 60_000;
// GA-CKPT-RATE: the boot check refuses more than 2 x QODIQA_AUDIT_CHECKPOINT_EVERY uncovered
// entries on the premise that the scheduler signs every `every` entries. A 60 s tick could not keep that premise above
// ~17 entries/s (one checkpoint per tick at most): 3,600+ entries per minute at 60 req/s, so any stop under load made the
// next boot fail closed. The tick is now 1 s (QODIQA_AUDIT_CHECKPOINT_TICK_MS, 250–60,000) and only compares two
// in-process numbers; signing still happens once `every` entries (or MAX_AGE) have accrued. The boot check is unchanged.
const AUDIT_CHECKPOINT_TICK_MS = (() => { const v = Number(process.env.QODIQA_AUDIT_CHECKPOINT_TICK_MS); return Number.isInteger(v) && v >= 250 && v <= 60_000 ? v : 1_000; })();
// Bound on the mirror wait inside one checkpoint run (the checkpoint is signed without a pgSeq when it is exceeded).
const MIRROR_WAIT_MS = 5_000;
// Bound on the final checkpoint at graceful shutdown.
const SHUTDOWN_CHECKPOINT_TIMEOUT_MS = 10_000;

// ER 2026-10-06: anchor publication outcome counter (qodiqa_audit_anchor_events_total{outcome}); never throws.
function _anchorMetric(outcome) { try { require('../../../observability/metrics').auditAnchorEventsTotal.inc({ outcome }); } catch { /* metrics are best-effort */ } }

function sidecarPath(logPath) { return `${logPath}.checkpoints.jsonl`; }

function readSidecar(logPath) {
  const p = sidecarPath(logPath);
  if (!fs.existsSync(p)) return [];
  const out = [];
  const lines = fs.readFileSync(p, 'utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i]) continue;
    try { out.push(JSON.parse(lines[i])); } catch {
      if (i === lines.length - 1 || (i === lines.length - 2 && lines[lines.length - 1] === '')) break; // torn last line (crash mid-append): ignored
      throw new Error(`AUDIT_CHECKPOINT_SIDECAR_CORRUPT: line ${i + 1} of ${p} is not JSON`);
    }
  }
  return out;
}

// PH16-D2: whole-record write + torn-tail repair (copy-then-truncate) — the sidecar is the
// gateway's own file; a torn tail from a crash/short write no longer swallows the next checkpoint or blocks the boot.
function appendSidecar(logPath, signed) {
  require('../jsonlAppend').appendJsonlRecord(sidecarPath(logPath), signed, { onTornTail: 'repair', errorPrefix: 'AUDIT_CHECKPOINT_SIDECAR', mode: 0o640,
    emit: (l, t, d) => { try { require('../../../../services/logger').emit(l, t, d); } catch { /* best-effort */ } } });
}

function _deps(o = {}) {
  return {
    auditLog: o.auditLog || require('../audit-log'),
    pgPool: o.pgPool || require('../../../infra/postgres/pool'),
    backend: o.backend || require('../../../infra/postgres/pg-audit-backend'),
    registrar: o.registrar === undefined ? (() => { try { return require('../../transparency/registrar'); } catch { return null; } })() : o.registrar,
    logStore: o.logStore === undefined ? (() => { try { return require('../../transparency/logStore'); } catch { return null; } })() : o.logStore,
    emit: o.emit || require('../../../../services/logger').emit,
    keyStore: o.keyStore || require('./checkpointKeyStore'),
    logPath: o.logPath || require('../audit-log').LOG_PATH,
    anchoring: o.anchoring || _defaultAnchoring(),
  };
}

// witness co-signing + customer-held anchor export (../anchoring/*), configured by environment.
function _defaultAnchoring() {
  const anchors = require('../anchoring/anchors');
  const { witnessesFromEnv } = require('../anchoring/witness');
  return {
    exportPath: () => anchors.exportPathFromEnv(),
    enabled: () => !!anchors.exportPathFromEnv() || (process.env.QODIQA_WITNESS_MODE || 'none') !== 'none' || !!process.env.QODIQA_WITNESSES_CONFIG,
    publish: (signed, opts = {}) => anchors.publishAnchor(signed, { witnesses: witnessesFromEnv(), exportPath: anchors.exportPathFromEnv(), requireCosignature: !!opts.requireCosignature }),
    // ANCHOR-1: the normal path — held checkpoints first, every record witnessed (anchors.publishAnchorBacklog)
    publishWithBacklog: (signed, backlog) => anchors.publishAnchorBacklog(signed, { witnesses: witnessesFromEnv(), exportPath: anchors.exportPathFromEnv(), backlog }),
    read: (p) => anchors.readAnchors(p),
    verify: (args) => anchors.verifyChainAgainstAnchors(args),
    trustedWitnessKeys: () => anchors.trustedWitnessKeysFromEnv(),
    witnesses: () => witnessesFromEnv(),
    independence: () => require('../anchoring/witness').anchoringIndependence(),
  };
}

// the operator-independence label reported with every anchoring boot result (never inferred as independent).
function _independence(a) {
  try { return a && typeof a.independence === 'function' ? a.independence() : require('../anchoring/witness').anchoringIndependence(); } catch { return 'unknown'; }
}

/**
 *production anchoring must be REAL, not merely configured. FAIL-CLOSED (throws
 * AUDIT_ANCHOR_BOOT_FAILED) unless: an export path is set; at least one witness is configured; the trusted witness key
 * set holds at least one ACTIVE key; and every LOCAL witness's own key is in that trusted set (an anchor co-signed by a
 * key the verifier does not trust can never verify). An exec witness's key is checked on its first cosignature.
 */
function verifyAnchoringPosture(o = {}) {
  const a = (o.anchoring || _defaultAnchoring());
  const fail = (detail) => { const e = new Error(`AUDIT_ANCHOR_BOOT_FAILED: ${detail}`); e.code = 'AUDIT_ANCHOR_BOOT_FAILED'; e.findings = [{ code: 'ANCHORING_POSTURE', detail }]; throw e; };
  if (!a.exportPath()) fail('no anchor export path is configured (QODIQA_ANCHOR_EXPORT_PATH)');
  let witnesses; try { witnesses = a.witnesses(); } catch (e) { fail(`the witness configuration is invalid: ${e.message}`); }
  if (!witnesses.length) fail('no witness is configured (QODIQA_WITNESS_MODE=local|exec)');
  let trusted; try { trusted = a.trustedWitnessKeys(); } catch (e) { fail(`the trusted witness key set cannot be read: ${e.message}`); }
  const active = (trusted && Array.isArray(trusted.keys) ? trusted.keys : []).filter((k) => k && k.keyId && k.publicKey && (k.status || 'active') === 'active');
  if (!active.length) fail('the trusted witness key set (QODIQA_WITNESS_PUBLIC_KEYS) holds no active key — minWitnesses >= 1 can never be met');
  for (const w of witnesses) {
    if (typeof w.publicKeyRecord !== 'function') continue; // exec witness: verified on its first cosignature
    let rec; try { rec = w.publicKeyRecord(); } catch (e) { fail(`local witness ${w.witnessId} key is unreadable: ${e.message}`); }
    if (!active.some((k) => k.keyId === rec.keyId && k.publicKey === rec.publicKey)) fail(`local witness ${w.witnessId} key ${rec.keyId} is not in the trusted witness key set — its cosignatures could never verify`);
  }
  // a posture that passes is not an independent one — say which it is.
  return { witnesses: witnesses.length, trustedKeys: active.length, anchoringIndependence: _independence(a) };
}

/** The newest signed checkpoint known to this process (PG first, else the sidecar). */
async function latestSignedCheckpoint(o = {}) {
  const d = _deps(o);
  let best = null;
  if (d.pgPool.isEnabled()) {
    try { best = await d.backend.getLatestSignedCheckpoint(); } catch (e) {
      // at boot (strict) a lookup error is a failure, never "no checkpoint yet".
      if (o.strict) { const err = new Error(`AUDIT_CHECKPOINT_BOOT_FAILED: the PostgreSQL checkpoint lookup failed (${e.message})`); err.code = 'AUDIT_CHECKPOINT_BOOT_FAILED'; throw err; }
      best = null;
    }
  }
  const side = readSidecar(d.logPath);
  const s = side.length ? side[side.length - 1] : null;
  if (s && (!best || s.payload.chainLength > best.payload.chainLength)) best = s;
  return best;
}

// checkpoint signing is SINGLE-FLIGHT per process. Each run awaits the mirror drain
// and several PostgreSQL reads, so a stalled mirror used to let overlapping scheduler ticks (and any other caller) wake
// together and each sign the same chain position — 5 checkpoints for one entry in the sidecar, after which the next boot
// refused ("two different checkpoints vouch for entry N"). Calls are now serialised: a call made while a run is in
// flight waits for it and then finds that position already covered (latestSignedCheckpoint), and the scheduler skips a
// tick outright while a run is in flight.
let _checkpointChain = Promise.resolve();
// GA-CKPT-RATE: the last position signed (or found at the first tick) by this process; null = not known yet.
let _lastSigned = null;
let _schedulerTimer = null;
let _checkpointInFlight = 0;
function createSignedCheckpoint(args) {
  _checkpointInFlight++;
  const run = _checkpointChain.then(() => _createSignedCheckpoint(args));
  _checkpointChain = run.catch(() => {}).finally(() => { _checkpointInFlight--; });
  return run;
}
function checkpointInFlight() { return _checkpointInFlight; }

// GA-CKPT-RATE: the audit_chain seq of the checkpoint's head row, VERIFIED by hash, or null. Under load the mirrored tail
// has moved past the head by the time it is read, so the tail is used only to locate a candidate: `settled - target`
// rows were mirrored after the head's own write (FIFO, one writer). Every candidate is confirmed with
// fetchRowBySeq(seq) === headHash before it is used; sequence gaps (a rolled-back batch consumes nextval) are covered by
// a small window; anything unconfirmed signs the checkpoint with pgSeq null, exactly as before when the tail differed.
async function _pgSeqOfHead(d, headHash, mirroredThrough) {
  const t = await d.backend.getChainTail();
  if (!t || !t.hash) return null;
  if (String(t.hash).trim() === headHash) return Number(t.seq);
  if (mirroredThrough === null || typeof d.backend.fetchRowBySeq !== 'function' || typeof d.auditLog.mirrorWriterCounters !== 'function') return null;
  const after = d.auditLog.mirrorWriterCounters().settled - mirroredThrough;
  const base = Number(t.seq) - Math.max(0, after);
  for (let k = -2; k <= 8; k++) {
    const seq = base - k;
    if (!(seq > 0) || seq > Number(t.seq)) continue;
    const h = await d.backend.fetchRowBySeq(seq);
    if (h && String(h).trim() === headHash) return seq;
  }
  return null;
}

// ANCHOR-1: live (sidecar) checkpoints signed BEFORE `signed` and above the anchor export's top — held during a witness
// outage — oldest first. Read errors leave the backlog empty (the new checkpoint is still published or held itself).
function _heldCheckpoints(d, signed) {
  try {
    const exportPath = d.anchoring.exportPath();
    if (!exportPath) return [];
    const top = d.anchoring.read(exportPath).reduce((m, a) => Math.max(m, a && a.checkpoint && a.checkpoint.payload ? a.checkpoint.payload.chainLength : 0), 0);
    return readSidecar(d.logPath)
      .filter((c) => c && c.payload && c.payload.chainLength > top && c.payload.chainLength < signed.payload.chainLength)
      .sort((x, y) => x.payload.chainLength - y.payload.chainLength);
  } catch { return []; }
}

async function _createSignedCheckpoint({ trigger = 'scheduled', ...o } = {}) {
  const d = _deps(o);
  // GA-CKPT-RATE: the position is fixed FIRST, then only the mirror writes enqueued up to it are awaited (bounded).
  // drainMirrorWriter() waited for an EMPTY queue, which sustained load never produces, and stalled every later tick.
  const snap = d.auditLog.memorySnapshot();
  const chainLength = snap.modernCount;
  if (!(chainLength > 0)) return null;
  // Captured synchronously with the snapshot (no await in between): the mirror writes enqueued so far include the head's.
  const target = typeof d.auditLog.mirrorWriterCounters === 'function' ? d.auditLog.mirrorWriterCounters().enqueued : null;
  const head = await d.auditLog.getModernEntryAt(chainLength - 1);
  if (!head || !head.hash) throw new Error(`AUDIT_CHECKPOINT_HEAD_UNAVAILABLE: entry ${chainLength} not readable`);
  let mirroredThrough = null;
  if (typeof d.auditLog.drainMirrorWriterThrough === 'function') {
    let timer;
    const done = await Promise.race([d.auditLog.drainMirrorWriterThrough().then(() => true),
      new Promise((r) => { timer = setTimeout(() => r(false), o.mirrorWaitMs || MIRROR_WAIT_MS); if (timer.unref) timer.unref(); })]);
    clearTimeout(timer);
    if (done) mirroredThrough = target;
  } else if (typeof d.auditLog.drainMirrorWriter === 'function') {
    await d.auditLog.drainMirrorWriter();
  }
  const previous = await latestSignedCheckpoint(o);
  if (previous && previous.payload.chainLength >= chainLength) {
    _lastSigned = { chainLength: previous.payload.chainLength, createdAtMs: Date.parse(previous.payload.createdAt) };
    return previous;
  }

  let pgSeq = null; let evidenceHead = null; let transparencyAnchor = null;
  if (d.pgPool.isEnabled()) {
    try { pgSeq = await _pgSeqOfHead(d, head.hash, mirroredThrough); } catch { /* optional */ }
    try {
      const r = await d.pgPool.query('SELECT tail_id, tail_hash FROM evidence_chain_head', [], 'audit_checkpoint_evidence_head');
      if (r.rows[0] && r.rows[0].tail_hash) evidenceHead = { id: Number(r.rows[0].tail_id), hash: String(r.rows[0].tail_hash).trim() };
    } catch { /* optional */ }
    try {
      const root = d.logStore && typeof d.logStore.getLatestRoot === 'function' ? await d.logStore.getLatestRoot() : null;
      if (root) transparencyAnchor = { rootId: root.root_id, rootHash: String(root.root_hash).trim(), seqTo: Number(root.seq_to) };
    } catch { /* optional */ }
  }

  const signed = signCheckpoint({ chainLength, headHash: head.hash, pgSeq, evidenceHead, transparencyAnchor,
    previousCheckpointHash: previous ? previous.payloadHash : null }, { keyStore: d.keyStore });

  appendSidecar(d.logPath, signed);
  _lastSigned = { chainLength, createdAtMs: Date.parse(signed.payload.createdAt) }; // GA-CKPT-RATE: the tick reads this, not the stores
  let persisted = false;
  if (d.pgPool.isEnabled()) persisted = await d.backend.insertSignedCheckpoint(signed, trigger.slice(0, 64));

  let anchoredTransparencyId = null;
  if (d.registrar && d.pgPool.isEnabled()) {
    try {
      const leaf = await d.registrar.register({ entryType: 'AUDIT_CHECKPOINT', artifactId: signed.payload.checkpointId, registeredBy: 'audit-checkpoint',
        payload: { checkpointId: signed.payload.checkpointId, checkpointPayloadHash: signed.payloadHash, chainLength, headHash: head.hash } });
      anchoredTransparencyId = leaf && (leaf.transparencyId || leaf.transparency_id) || null;
    } catch (e) {
      _anchorMetric('transparency_anchor_failed'); // counted, not only logged
      d.emit('WARN', 'AUDIT_CHECKPOINT_ANCHOR_FAILED', { checkpointId: signed.payload.checkpointId, error: e.message });
    }
  }
  // co-sign with the configured witnesses and append to the customer-held anchor export. Never on the request
  // path; a failure is reported loudly (a REFUSED cosignature means the witness saw a rollback/fork attempt).
  let anchored = null;
  if (d.anchoring.enabled()) {
    try {
      // ANCHOR-1: never export an unwitnessed checkpoint; checkpoints held during a witness
      // outage are offered again (oldest first) with the next one and exported in order once witnessed.
      let record; let errors; let backlogInfo = null;
      if (typeof d.anchoring.publishWithBacklog === 'function') {
        const backlog = _heldCheckpoints(d, signed);
        const r = await d.anchoring.publishWithBacklog(signed, backlog);
        ({ record, errors } = r);
        backlogInfo = { held: r.held, exported: r.exported, backlog: backlog.length };
        if (r.held > 0) {
          _anchorMetric('held');
          d.emit('WARN', 'AUDIT_ANCHOR_HELD', { checkpointId: signed.payload.checkpointId, chainLength, held: r.held, exportedNow: r.exported,
            message: 'No trusted witness cosigned these checkpoints yet; they are held (never exported unwitnessed) and offered again, oldest first, with the next checkpoint.' });
        } else if (backlog.length > 0) {
          d.emit('INFO', 'AUDIT_ANCHOR_BACKLOG_EXPORTED', { checkpointId: signed.payload.checkpointId, exported: r.exported });
        }
      } else {
        ({ record, errors } = await d.anchoring.publish(signed)); // ER 2026-10-06: async
      }
      anchored = { exported: !!record, cosignatures: record ? record.cosignatures.length : 0, ...(backlogInfo ? { backlog: backlogInfo } : {}) };
      if (record) _anchorMetric('anchored');
      // (M8): WITNESS_FORK_REFUSED (forward fork) is a refusal too, like rollback/equivocation.
      const refused = (code) => code === 'WITNESS_ROLLBACK_REFUSED' || code === 'WITNESS_EQUIVOCATION_REFUSED' || code === 'WITNESS_FORK_REFUSED';
      for (const e of errors) _anchorMetric(refused(e.code) ? 'witness_refused' : 'witness_failed');
      for (const e of errors) d.emit('ERROR', refused(e.code) ? 'AUDIT_ANCHOR_WITNESS_REFUSED' : 'AUDIT_ANCHOR_WITNESS_FAILED',
        { checkpointId: signed.payload.checkpointId, chainLength, witnessId: e.witnessId, code: e.code, error: e.message });
    } catch (e) {
      _anchorMetric('export_failed');
      d.emit('ERROR', 'AUDIT_ANCHOR_EXPORT_FAILED', { checkpointId: signed.payload.checkpointId, error: e.message });
    }
  }
  // external anchors (git signed commit / OpenTimestamps / RFC 3161), at most one checkpoint per QODIQA_ANCHOR_EXTERNAL_INTERVAL_MS (default 24 h).
  // Asynchronous and best-effort by construction: enqueue() never throws, and the publishing happens in the background (a failure is counted and alerted).
  try { await require('../anchoring/externalAnchors').enqueue(signed, { force: trigger === 'shutdown' }); } catch { /* enqueue never throws; belt and braces */ }
  d.emit('INFO', 'AUDIT_CHECKPOINT_SIGNED', { checkpointId: signed.payload.checkpointId, chainLength, headHash: head.hash,
    keyId: signed.payload.keyId, trigger, persistedToPg: persisted, anchoredTransparencyId, anchored });
  return signed;
}

/**
 * Correction pass 2026-10-05 (C13): is the checkpoint/anchor BOOTSTRAP accepted for this boot?
 * Outside production: QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true, as before. In production a bare `true` was an ordinary
 * configuration switch that skipped the deleted-anchor / deleted-checkpoint / broken-chain / staleness checks with a
 * WARN, and stayed effective for as long as it was left set. Now it is honoured only together with
 * QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=<chainLength>:<first 16 hex of the newest entry's hash> matching the LIVE chain:
 * the operator must inspect the exact chain state being re-baselined, the acknowledgement stops matching as soon as one
 * more entry is appended, and acceptance is reported at ERROR. A mismatch fails the boot (FAIL-CLOSED).
 * Called only on the paths where a check would otherwise fail.
 */
async function bootstrapAccepted(d, where) {
  if (process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP !== 'true') return false;
  if (process.env.NODE_ENV !== 'production') return true;
  const n = d.auditLog.memorySnapshot().modernCount;
  const head = n > 0 ? await d.auditLog.getModernEntryAt(n - 1) : null;
  const expected = `${n}:${head && head.hash ? String(head.hash).slice(0, 16) : '0000000000000000'}`;
  if (process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK !== expected) {
    const e = new Error(`AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED: ${where}. In production QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true is honoured only with QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK bound to the live chain head; the acknowledgement given does not match it. Investigate first; then, for one boot, set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK=${expected}`);
    e.code = 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED';
    throw e;
  }
  d.emit('ERROR', 'AUDIT_CHECKPOINT_BOOTSTRAP_ACCEPTED', { chainLength: n, ack: expected, where,
    message: 'Production boot accepted a checkpoint/anchor bootstrap bound to this exact chain head. Investigate why it was needed and remove both variables.' });
  return true;
}

/**
 * FAIL-CLOSED boot verification of the live chain and checkpoint set against the customer-held anchor export
 * (only when QODIQA_ANCHOR_EXPORT_PATH is configured and present). Catches what the checkpoint check alone cannot:
 * deleted checkpoints, a rollback below an anchored position, a rewritten prefix, and a re-signed replacement history.
 */
async function verifyAnchorsAtBoot(o = {}) {
  const d = _deps(o);
  const exportPath = d.anchoring.exportPath();
  const anchoringIndependence = _independence(d.anchoring); //
  if (!exportPath) return { checked: false, reason: 'ANCHORING_NOT_CONFIGURED' };
  if (anchoringIndependence === 'none-local-witness') {
    d.emit('WARN', 'AUDIT_ANCHORING_NOT_INDEPENDENT', { anchoringIndependence,
      message: 'QODIQA_WITNESS_MODE=local: the witness key and log are on the gateway host, so anyone controlling the gateway host can re-sign, re-witness and re-export a rewritten audit history. Anchors detect tampering only by parties without that access; they are NOT independent of the operator.' });
  }
  const anchors = d.anchoring.read(exportPath);
  if (!anchors.length) {
    // a missing or emptied export used to read as "nothing anchored yet" whatever the chain length — an
    // insider could defeat the check by deleting the file. Past two checkpoint intervals an anchor MUST exist.
    const n = d.auditLog.memorySnapshot().modernCount;
    const every = Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) : DEFAULT_EVERY;
    if (n > 2 * every && !(await bootstrapAccepted(d, `the anchor export is missing or empty for a chain of ${n} entries`))) {
      const e = new Error(`AUDIT_ANCHOR_BOOT_FAILED: the anchor export ${path.basename(exportPath)} is missing or empty, but the chain holds ${n} entries (more than 2 x ${every}): anchors were deleted, or anchoring was only now enabled — set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot to start anchoring`);
      e.code = 'AUDIT_ANCHOR_BOOT_FAILED'; e.findings = [{ code: 'ANCHORS_MISSING', detail: `chainLength ${n}` }]; throw e;
    }
    return { checked: false, reason: 'NO_ANCHORS_YET' };
  }
  const live = readSidecar(d.logPath);
  if (d.pgPool.isEnabled()) { try { const pgLatest = await d.backend.getLatestSignedCheckpoint(); if (pgLatest && !live.some((c) => c.payload.checkpointId === pgLatest.payload.checkpointId)) live.push(pgLatest); } catch { /* sidecar is authoritative for the list */ } }
  const start = typeof d.auditLog.getChainStart === 'function' ? d.auditLog.getChainStart() : null;
  // the verifier asks for the live hash at every anchor's position; resolve them all in ONE pass
  // (getModernHashesAt) instead of one scan from the start of the file per anchor (403 anchors x 430k entries stalled
  // the boot indefinitely). Same hashes; any position not resolved there falls back to the per-position lookup.
  // the positions are first resolved through the byte-offset index — ONE forward raw newline count
  // (no JSON parse of the history; same counted-position semantics) and one parse per anchored line. Accepted only when
  // it reproduces EVERY signed anchor hash in the live range; otherwise the parse pass above resolves them and decides,
  // so the verdict is always the one the previous lookup gives. The persisted index is compared, never trusted.
  const positions = anchors.map((a) => a && a.checkpoint && a.checkpoint.payload ? a.checkpoint.payload.chainLength - 1 : null);
  const prunedBefore = start && start.startCount > 0 ? start.startCount : 0;
  const lookupStarted = Date.now();
  let prefetched = null; let lookup = 'parse'; let derived = null;
  if (typeof d.auditLog.getModernHashesAtByOffset === 'function') {
    try {
      derived = await d.auditLog.getModernHashesAtByOffset(positions);
      const reproduces = anchors.every((a) => {
        const p = a && a.checkpoint && a.checkpoint.payload ? a.checkpoint.payload : null;
        if (!p || !Number.isInteger(p.chainLength) || p.chainLength <= prunedBefore) return true;   // not checked by position
        return derived.hashes.get(p.chainLength - 1) === p.headHash;
      });
      if (reproduces) { prefetched = derived.hashes; lookup = 'offset-index'; }
    } catch (err) {
      derived = null;
      d.emit('WARN', 'AUDIT_ANCHOR_INDEX_LOOKUP_FAILED', { error: err.message, action: 'the parse-based lookup decides this boot' });
    }
  }
  if (!prefetched) {
    prefetched = typeof d.auditLog.getModernHashesAt === 'function' ? await d.auditLog.getModernHashesAt(positions) : new Map();
  }
  const lookupMs = Date.now() - lookupStarted;
  const res = await d.anchoring.verify({
    anchors,
    chainLength: d.auditLog.memorySnapshot().modernCount,
    headHashAt: async (n) => {
      if (prefetched.has(n - 1)) return prefetched.get(n - 1);
      const e = await d.auditLog.getModernEntryAt(n - 1); return e ? e.hash : null;
    },
    checkpoints: live,
    resolveCheckpointKey: o.resolvePublicKey || ((keyId) => d.keyStore.getPublicKey(keyId)), // record: retirement check
    trustedWitnessKeys: d.anchoring.trustedWitnessKeys(),
    // production requires at least one witness cosignature on every anchor (0 only outside production
    // when no witness keys are configured).
    minWitnesses: Number(process.env.QODIQA_ANCHOR_MIN_WITNESSES) > 0 ? Number(process.env.QODIQA_ANCHOR_MIN_WITNESSES)
      : (d.anchoring.trustedWitnessKeys().keys.length >= 2 && process.env.QODIQA_WITNESSES_CONFIG ? 2   //
        : ((d.anchoring.trustedWitnessKeys().keys.length || process.env.NODE_ENV === 'production') ? 1 : 0)),
    prunedBefore,
  });
  const indexState = _anchorIndexConsistency(d, derived);   // G-3: reported whatever the verdict
  if (!res.ok) {
    const e = new Error(`AUDIT_ANCHOR_BOOT_FAILED: ${res.findings.map((x) => `${x.code} (${x.detail})`).join('; ')}`);
    e.code = 'AUDIT_ANCHOR_BOOT_FAILED'; e.findings = res.findings; throw e;
  }
  const exportTail = await _checkExportTail(d, anchors, live);
  // G-4: the index is (re)written only after a PASSING check whose positions the byte-offset lookup reproduced.
  if (lookup === 'offset-index' && indexState.rewrite) _writeAnchorIndex(d, derived);
  d.emit('INFO', 'AUDIT_ANCHORS_BOOT_VERIFIED', { anchors: res.checked, exportPath: path.basename(exportPath), anchoringIndependence, exportTail,
    lookup, lookupMs, anchorIndex: indexState.status });
  return { checked: true, anchors: res.checked, anchoringIndependence, exportTail };   // return contract unchanged
}

// G-3: persisted index vs the offsets re-derived from the log this boot. Never affects the verdict.
function _anchorIndexConsistency(d, derived) {
  if (!derived || (typeof d.auditLog.isFollower === 'function' && d.auditLog.isFollower())) return { status: 'NOT_CHECKED', rewrite: false };
  const anchorIndex = require('../anchoring/anchorIndex');
  let read;
  try { read = anchorIndex.readIndex(d.logPath); } catch (err) { read = { status: 'MALFORMED', error: err.message }; }
  if (read.status === 'MISSING') {
    d.emit('INFO', 'AUDIT_ANCHOR_INDEX_REBUILT', { reason: 'MISSING', action: 'rebuilt from the audit log after a passing anchor check' });
    return { status: 'MISSING', rewrite: true };
  }
  if (read.status !== 'OK') {
    d.emit('WARN', 'AUDIT_ANCHOR_INDEX_INCONSISTENT', { reason: read.status, error: read.error || null,
      action: 'The persisted anchor index is unreadable; it is never trusted for a verdict and is rebuilt from the audit log after a passing anchor check.' });
    return { status: read.status, rewrite: true };
  }
  const cmp = anchorIndex.compareIndex(read.index, { logHead: _logHead(d), offsets: derived.offsets, hashes: derived.hashes });
  if (!cmp.consistent) {
    d.emit('WARN', 'AUDIT_ANCHOR_INDEX_INCONSISTENT', { reason: cmp.reason, compared: cmp.compared, mismatches: cmp.mismatches, firstMismatch: cmp.firstMismatch,
      action: 'The audit log\'s line layout differs from the persisted anchor index (log replaced, rewritten or restored, or the index edited). The index is never trusted for a verdict; the anchor check above re-derived every position from the log itself. Rebuilt after a passing check; investigate if the log was not deliberately restored.' });
    return { status: 'INCONSISTENT', rewrite: true };
  }
  return { status: 'CONSISTENT', rewrite: derived.offsets.size !== read.index.entries.size || [...derived.offsets.keys()].some((p) => !read.index.entries.has(p)) };
}

function _logHead(d) {
  try { return typeof d.auditLog.getChainStats === 'function' ? d.auditLog.getChainStats().headHash || null : null; } catch { return null; }
}

function _writeAnchorIndex(d, derived) {
  if (typeof d.auditLog.isFollower === 'function' && d.auditLog.isFollower()) return;
  try {
    const n = require('../anchoring/anchorIndex').writeIndex(d.logPath, { logHead: _logHead(d), offsets: derived.offsets, hashes: derived.hashes });
    d.emit('INFO', 'AUDIT_ANCHOR_INDEX_WRITTEN', { entries: n });
  } catch (err) {
    d.emit('WARN', 'AUDIT_ANCHOR_INDEX_WRITE_FAILED', { error: err.message, action: 'boot continues; the next boot rebuilds the index' });
  }
}

/**
 * M10: verifyChainAgainstAnchors() checks only the anchors PRESENT in the export, so removing
 * the export's last k records (and rewriting the chain above the newest remaining anchor, re-signing checkpoints) passed
 * the boot. The export's top is now cross-checked against two records kept outside the export, FAIL-CLOSED
 * (AUDIT_ANCHOR_BOOT_FAILED, finding ANCHOR_EXPORT_TRUNCATED; QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP(+_ACK) is the explicit,
 * reported override, exactly as for the other anchor/checkpoint boot checks):
 *   (a) every configured witness that exposes its log head (local mode): a witnessed position above the export's top is
 *       a truncated export — unless that very checkpoint (same payloadHash) is still in the live checkpoint set, which is
 *       the benign crash window between the witness's cosignature and the export append (the live checkpoint keeps
 *       pinning the chain through verifyLatestCheckpointAtBoot);
 *   (b) the live checkpoint set: every checkpoint is exported in the same run that signs it, so at most ONE live
 *       checkpoint (the crash/shutdown window) may sit above the export's top, and it must chain to the export's top.
 *       More than one, or one that does not chain, means the export's tail was removed or exporting has been failing.
 * Residual (exec witness): the gateway cannot read a remote witness log, so a truncation that also replaces the newest
 * live checkpoints by ONE re-signed checkpoint chaining to the remaining top is not visible here; the witness refuses
 * the next checkpoint (M8: WITNESS_FORK_REFUSED -> AUDIT_ANCHOR_WITNESS_REFUSED) and the customer-copy check
 * reports it.
 */
async function _checkExportTail(d, anchors, live) {
  const top = anchors.reduce((m, a) => (a && a.checkpoint && a.checkpoint.payload && (!m || a.checkpoint.payload.chainLength > m.payload.chainLength) ? a.checkpoint : m), null);
  if (!top) return null;
  const topLen = top.payload.chainLength;
  const findings = [];
  let witnessesChecked = 0;
  let witnesses = [];
  try { witnesses = typeof d.anchoring.witnesses === 'function' ? d.anchoring.witnesses() : []; } catch { witnesses = []; }
  for (const w of witnesses) {
    if (!w || typeof w.head !== 'function') continue; // exec witness: no readable log (see the residual above)
    let h;
    try { h = w.head(); } catch (e) { findings.push({ code: 'WITNESS_LOG_UNREADABLE', detail: `witness ${w.witnessId}: ${e.message}` }); continue; }
    witnessesChecked++;
    if (!h) continue;
    if (h.chainLength > topLen) {
      const benign = live.some((c) => c && c.payload && c.payload.chainLength === h.chainLength && c.payloadHash === h.checkpointPayloadHash);
      if (!benign) findings.push({ code: 'ANCHOR_EXPORT_TRUNCATED', detail: `witness ${w.witnessId} co-signed entry ${h.chainLength} (checkpoint ${String(h.checkpointPayloadHash).slice(0, 16)}), but the anchor export ends at entry ${topLen} and no live checkpoint matches it` });
    } else if (h.chainLength === topLen && h.checkpointPayloadHash !== top.payloadHash) {
      findings.push({ code: 'ANCHOR_EXPORT_TRUNCATED', detail: `witness ${w.witnessId} co-signed a different checkpoint at entry ${topLen} than the export's last anchor` });
    }
  }
  const above = live.filter((c) => c && c.payload && c.payload.chainLength > topLen).sort((x, y) => x.payload.chainLength - y.payload.chainLength);
  if (above.length > 1) {
    findings.push({ code: 'ANCHOR_EXPORT_TRUNCATED', detail: `${above.length} live checkpoints (entries ${above.map((c) => c.payload.chainLength).join(', ')}) are above the anchor export's last anchor (entry ${topLen}): the export's tail was removed, or exporting has been failing` });
  } else if (above.length === 1 && above[0].payload.previousCheckpointHash !== top.payloadHash) {
    findings.push({ code: 'ANCHOR_EXPORT_TRUNCATED', detail: `the live checkpoint at entry ${above[0].payload.chainLength} is above the anchor export's last anchor (entry ${topLen}) and does not chain to it` });
  }
  if (findings.length) {
    if (!(await bootstrapAccepted(d, `the anchor export's tail does not match the witness log / live checkpoints (${findings.map((f) => f.code).join(', ')})`))) {
      const e = new Error(`AUDIT_ANCHOR_BOOT_FAILED: ${findings.map((x) => `${x.code} (${x.detail})`).join('; ')}`);
      e.code = 'AUDIT_ANCHOR_BOOT_FAILED'; e.findings = findings; throw e;
    }
    d.emit('WARN', 'AUDIT_ANCHOR_EXPORT_TAIL_BOOTSTRAP', { findings });
  }
  if (above.length === 1) {
    d.emit('WARN', 'AUDIT_ANCHOR_EXPORT_BEHIND', { exportTop: topLen, liveTop: above[0].payload.chainLength,
      message: 'The newest signed checkpoint is not in the anchor export (a crash or shutdown between signing and exporting, or a failed export). It chains to the last exported anchor; the next checkpoint is exported normally.' });
  }
  return { exportTop: topLen, witnessesChecked, unexportedLive: above.length };
}

/**
 * FAIL-CLOSED boot check. Throws AUDIT_CHECKPOINT_BOOT_FAILED (with a reason) when the latest signed checkpoint does
 * not verify or does not match the chain. Returns a summary otherwise.
 */
async function verifyLatestCheckpointAtBoot(o = {}) {
  const d = _deps(o);
  const fail = (reason) => { const e = new Error(`AUDIT_CHECKPOINT_BOOT_FAILED: ${reason}`); e.code = 'AUDIT_CHECKPOINT_BOOT_FAILED'; throw e; };
  const cp = await latestSignedCheckpoint({ ...o, strict: true });
  if (!cp) {
    // "no checkpoint" used to pass whatever the chain length — deleting the sidecar and PG rows turned a
    // detected re-chain into an undetected one. A chain longer than two checkpoint intervals with no signed checkpoint
    // means checkpoints were deleted (or the chain predates checkpointing: QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for
    // ONE boot lets the scheduler sign the first one, and is reported).
    const n = d.auditLog.memorySnapshot().modernCount;
    const every = Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) : DEFAULT_EVERY;
    if (n > 2 * every) {
      if (!(await bootstrapAccepted(d, `no signed checkpoint exists for a chain of ${n} entries`))) {
        fail(`no signed checkpoint exists, but the chain holds ${n} entries (more than 2 x ${every}): the checkpoints were deleted, or this chain predates checkpointing — set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot to sign the first checkpoint`);
      }
      d.emit('WARN', 'AUDIT_CHECKPOINT_BOOTSTRAP', { chainLength: n, message: 'No signed checkpoint for a long chain; QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true accepted it for this boot — the scheduler signs the first checkpoint now. Remove the variable afterwards.' });
    }
    return { checked: false, reason: 'NO_SIGNED_CHECKPOINT_YET' };
  }
  const vopts = o.resolvePublicKey ? { resolvePublicKey: o.resolvePublicKey } : {};
  const v = verifyCheckpoint(cp, vopts);
  if (!v.ok) fail(`latest checkpoint ${cp.payload && cp.payload.checkpointId} does not verify (${v.reason})`);
  const { chainLength, headHash } = cp.payload;
  const snap = d.auditLog.memorySnapshot();
  let _bootstrap;
  const bootstrap = async (where) => { if (_bootstrap === undefined) _bootstrap = await bootstrapAccepted(d, where); return _bootstrap; };

  // the WHOLE checkpoint chain, not just the latest one.
  //  (a) every checkpoint in the sidecar and in PostgreSQL verifies, and one checkpointId never carries two payloads;
  //  (b) consecutive checkpoints (ordered by chainLength) link: next.previousCheckpointHash === prev.payloadHash — a
  //      removed or replaced checkpoint in the middle breaks the link;
  //  (c) the newest PostgreSQL checkpoint is present (same payloadHash) in the sidecar — the sidecar's newest
  //      checkpoints cannot be deleted while PostgreSQL still remembers them.
  {
    const side = readSidecar(d.logPath);
    let pgList = null;
    if (d.pgPool.isEnabled() && typeof d.backend.listSignedCheckpoints === 'function') {
      try { pgList = await d.backend.listSignedCheckpoints(); } catch (e) { fail(`the PostgreSQL checkpoint list could not be read (${e.message})`); }
    }
    const byId = new Map();
    for (const c of [...side, ...(pgList || [])]) {
      if (!c || !c.payload || !c.payload.checkpointId) fail('a stored checkpoint is malformed');
      const prev = byId.get(c.payload.checkpointId);
      if (prev && prev.payloadHash !== c.payloadHash) fail(`checkpoint ${c.payload.checkpointId} has two different payloads (sidecar vs PostgreSQL) — it was replaced`);
      if (!prev) {
        const cv = verifyCheckpoint(c, vopts);
        if (!cv.ok) fail(`stored checkpoint ${c.payload.checkpointId} (entry ${c.payload.chainLength}) does not verify (${cv.reason})`);
        byId.set(c.payload.checkpointId, c);
      }
    }
    const ordered = [...byId.values()].sort((x, y) => x.payload.chainLength - y.payload.chainLength);
    for (let i = 1; i < ordered.length; i++) {
      const a = ordered[i - 1]; const b = ordered[i];
      if (b.payload.chainLength === a.payload.chainLength) fail(`two different checkpoints vouch for entry ${a.payload.chainLength}`);
      if (b.payload.previousCheckpointHash !== a.payloadHash && !(await bootstrap(`the checkpoint chain is broken after entry ${a.payload.chainLength}`))) {
        fail(`the checkpoint chain is broken between entry ${a.payload.chainLength} and entry ${b.payload.chainLength}: a checkpoint between them was removed or replaced — set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot only after investigating`);
      }
    }
    if (pgList && pgList.length) {
      const pgLatest = pgList.reduce((m, c) => (!m || c.payload.chainLength > m.payload.chainLength ? c : m), null);
      const inSide = side.some((c) => c.payload.checkpointId === pgLatest.payload.checkpointId && c.payloadHash === pgLatest.payloadHash);
      if (!inSide && !(await bootstrap(`the newest PostgreSQL checkpoint is missing from the sidecar`))) fail(`the newest PostgreSQL checkpoint ${pgLatest.payload.checkpointId} (entry ${pgLatest.payload.chainLength}) is missing from the checkpoint sidecar — newest checkpoints were deleted`);
    }
  }
  // freshness, measured on the ENTRIES — not on wall-clock time since the checkpoint (a
  // gateway that was simply down for a day must still boot). While the process runs, the scheduler signs at least every
  // QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS once the chain has grown, so uncovered entries whose own timestamps span more
  // than twice that interval mean newer checkpoints were deleted or checkpointing has been failing.
  if (snap.modernCount > chainLength) {
    const maxAge = Number(process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS) : DEFAULT_MAX_AGE_MS;
    const ts = (e) => (e ? (typeof e.timestamp === 'number' ? e.timestamp : Date.parse(e.timestamp)) : NaN);
    const first = ts(await d.auditLog.getModernEntryAt(chainLength));            // first entry NOT covered
    const last = ts(await d.auditLog.getModernEntryAt(snap.modernCount - 1));    // newest entry
    const span = last - first;
    if (Number.isFinite(span) && span > 2 * maxAge && !(await bootstrap(`${snap.modernCount - chainLength} uncovered entries span more than 2 x the checkpoint max age`))) {
      fail(`the ${snap.modernCount - chainLength} entries after the latest signed checkpoint span ${Math.round(span / 1000)} s (more than 2 x ${Math.round(maxAge / 1000)} s) without a checkpoint: newer checkpoints were deleted, or checkpointing has been failing — set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot to sign a fresh checkpoint`);
    }
  }
  if (snap.modernCount < chainLength) fail(`chain holds ${snap.modernCount} entries, the signed checkpoint vouches for ${chainLength}`);
  // M3/M4: after a prune the entries up to the base record are archived, not in audit.log. The latest checkpoint
  // is then at least the base's own (it is stored like every checkpoint); exactly at the base it must BE the base head.
  const start = typeof d.auditLog.getChainStart === 'function' ? d.auditLog.getChainStart() : null;
  if (start && start.startCount > 0 && chainLength <= start.startCount) {
    if (chainLength < start.startCount) fail(`the latest signed checkpoint (entry ${chainLength}) is older than the signed base record (entry ${start.startCount}) — checkpoints are missing`);
    if (headHash !== start.startHash) fail(`entry ${chainLength} is the signed base record's head ${start.startHash}, the signed checkpoint says ${headHash}`);
    d.emit('INFO', 'AUDIT_CHECKPOINT_BOOT_VERIFIED', { checkpointId: cp.payload.checkpointId, chainLength, keyId: cp.payload.keyId, atBase: true });
    return { checked: true, checkpointId: cp.payload.checkpointId, chainLength, atBase: true };
  }
  const entry = await d.auditLog.getModernEntryAt(chainLength - 1);
  if (!entry || entry.hash !== headHash) fail(`entry ${chainLength} is ${entry ? entry.hash : 'missing'}, the signed checkpoint says ${headHash}`);
  // the rule above caught deletion of ALL checkpoints only. Deleting just the newest ones left an
  // older, still-valid checkpoint, and everything after it could be rewritten unseen. The scheduler signs a checkpoint
  // every `every` entries, so more than 2 x `every` entries beyond the latest signed one means newer checkpoints were
  // deleted (or checkpointing has been failing) — refused unless QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot.
  {
    const every = Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) : DEFAULT_EVERY;
    const uncovered = snap.modernCount - chainLength;
    if (uncovered > 2 * every) {
      if (!(await bootstrap(`${uncovered} entries are not covered by any checkpoint`))) {
        fail(`the latest signed checkpoint vouches for ${chainLength} of ${snap.modernCount} entries — ${uncovered} entries (more than 2 x ${every}) are not covered by any checkpoint: newer checkpoints were deleted, or checkpointing has been failing — set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot to sign a fresh checkpoint`);
      }
      d.emit('WARN', 'AUDIT_CHECKPOINT_BOOTSTRAP', { chainLength: snap.modernCount, checkpointedLength: chainLength, message: 'More than two checkpoint intervals are uncovered; QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true accepted it for this boot — the scheduler signs a checkpoint now. Remove the variable afterwards.' });
    }
  }
  d.emit('INFO', 'AUDIT_CHECKPOINT_BOOT_VERIFIED', { checkpointId: cp.payload.checkpointId, chainLength, keyId: cp.payload.keyId });
  return { checked: true, checkpointId: cp.payload.checkpointId, chainLength };
}

/**
 *once per process, after the boot checks have passed, re-establish an anchor export that is
 * MISSING or EMPTY while a signed checkpoint exists, by publishing that latest checkpoint. Without it an accepted
 * bootstrap boot ("set QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true for one boot to start anchoring") anchored nothing until
 * `every` new entries or MAX_AGE of new traffic produced a new checkpoint (createSignedCheckpoint returns early when the
 * previous checkpoint already covers the chain), so a restart in that window failed the boot again — found when an
 * unwritable anchors volume was repaired. An export that already holds anchors is never touched here, so the
 * boot check's detection of a deleted or truncated export is unchanged.
 */
async function _reestablishEmptyExport(d, latest) {
  if (!latest || !d.anchoring.enabled()) return null;
  const exportPath = d.anchoring.exportPath();
  if (!exportPath || d.anchoring.read(exportPath).length) return null;
  try {
    const { record, errors } = await d.anchoring.publish(latest, { requireCosignature: true });
    if (record) _anchorMetric('anchored');
    for (const e of errors) d.emit('ERROR', 'AUDIT_ANCHOR_WITNESS_FAILED', { checkpointId: latest.payload.checkpointId, witnessId: e.witnessId, code: e.code, error: e.message });
    if (!record) {
      // No witness cosigned: nothing was written, so the export stays empty and the chain-bound bootstrap still applies.
      _anchorMetric('export_failed');
      d.emit('ERROR', 'AUDIT_ANCHOR_EXPORT_FAILED', { checkpointId: latest.payload.checkpointId, phase: 'reestablish',
        error: 'no witness cosigned the checkpoint; the export was left empty (an unwitnessed anchor would fail every production boot)' });
      return null;
    }
    d.emit('WARN', 'AUDIT_ANCHOR_EXPORT_REESTABLISHED', { checkpointId: latest.payload.checkpointId, chainLength: latest.payload.chainLength,
      exported: true, cosignatures: record.cosignatures.length, exportPath: path.basename(exportPath),
      message: 'The anchor export was missing or empty; the latest signed checkpoint was published to it. Investigate why it was empty.' });
    return record;
  } catch (e) {
    _anchorMetric('export_failed');
    d.emit('ERROR', 'AUDIT_ANCHOR_EXPORT_FAILED', { checkpointId: latest.payload.checkpointId, error: e.message, phase: 'reestablish' });
    return null;
  }
}

function startCheckpointScheduler(o = {}) {
  let exportChecked = false; // one re-establishment attempt per process (the first tick)
  const every = Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_EVERY) : DEFAULT_EVERY;
  const maxAge = Number(process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS) > 0 ? Number(process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS) : DEFAULT_MAX_AGE_MS;
  const runner = o.taskRunner || require('../../../runtime/backgroundTasks/BackgroundTaskRunner');
  const d = _deps(o);
  const tickMs = o.tickMs || AUDIT_CHECKPOINT_TICK_MS;
  let busySince = null; let busyWarned = false;
  const busyWarnMs = o.busyWarnMs || 60_000;
  const timer = setInterval(() => {
    if (_checkpointInFlight > 0) { // never stack ticks behind a slow run
      // GA-CKPT-RATE: with a 1 s tick a run in flight is normal; report only a run stuck for over a minute (once per run).
      if (busySince === null) busySince = Date.now();
      if (!busyWarned && Date.now() - busySince >= busyWarnMs) {
        busyWarned = true;
        try { d.emit('WARN', 'AUDIT_CHECKPOINT_TICK_SKIPPED', { reason: 'previous checkpoint run still in flight', inFlight: _checkpointInFlight, forMs: Date.now() - busySince }); } catch { /* */ }
      }
      return;
    }
    busySince = null; busyWarned = false;
    // GA-CKPT-RATE: the per-tick decision compares two in-process numbers. The stores are read only when the last signed
    // position is not known yet (first tick after boot); the task runner (and its log line) runs only to sign.
    // Never an unhandled rejection: a failed checkpoint tick is reported and retried on the next tick; it must not end
    // the process.
    Promise.resolve().then(async () => {
      if (_lastSigned === null) {
        const last = await latestSignedCheckpoint(o);
        if (_lastSigned === null) _lastSigned = last ? { chainLength: last.payload.chainLength, createdAtMs: Date.parse(last.payload.createdAt) } : { chainLength: 0, createdAtMs: -Infinity };
      }
      if (!exportChecked) { exportChecked = true; await _reestablishEmptyExport(d, await latestSignedCheckpoint(o)); }
      const n = d.auditLog.memorySnapshot().modernCount;
      const lastLen = _lastSigned.chainLength;
      const age = Date.now() - _lastSigned.createdAtMs;
      if (n - lastLen >= every || (n > lastLen && age >= maxAge)) {
        await runner.runTask('audit-checkpoint', () => createSignedCheckpoint({ ...o, trigger: 'scheduled' }));
      }
    }).catch((e) => { try { d.emit('ERROR', 'AUDIT_CHECKPOINT_TICK_FAILED', { error: e.message }); } catch { /* */ } });
  }, tickMs);
  if (timer.unref) timer.unref();
  _schedulerTimer = timer;
  return () => { clearInterval(timer); if (_schedulerTimer === timer) _schedulerTimer = null; };
}

/**
 * GA-CKPT-RATE (): the final signed checkpoint at graceful shutdown — called after in-flight requests have
 * drained and the audit queue has flushed, while PostgreSQL is still connected. Stops the scheduler, waits for a run in
 * flight, then signs the current position if anything is uncovered. Bounded (SHUTDOWN_CHECKPOINT_TIMEOUT_MS) and never
 * throws: a failure is reported and the next boot applies the unchanged boot check.
 */
async function signFinalCheckpoint(o = {}) {
  const d = _deps(o);
  if (_schedulerTimer) { clearInterval(_schedulerTimer); _schedulerTimer = null; }
  const timeoutMs = o.timeoutMs || SHUTDOWN_CHECKPOINT_TIMEOUT_MS;
  let timer;
  try {
    const run = (async () => {
      await _checkpointChain; // a scheduled run in flight finishes first (single-flight)
      const n = d.auditLog.memorySnapshot().modernCount;
      if (!(n > 0)) return { signed: false, reason: 'EMPTY_CHAIN' };
      const last = await latestSignedCheckpoint(o);
      if (last && last.payload.chainLength >= n) return { signed: false, reason: 'ALREADY_COVERED', chainLength: n };
      const s = await createSignedCheckpoint({ ...o, trigger: 'shutdown' });
      return { signed: true, chainLength: s && s.payload ? s.payload.chainLength : null };
    })();
    const out = await Promise.race([run, new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timed out after ' + timeoutMs + ' ms')), timeoutMs); if (timer.unref) timer.unref(); })]);
    d.emit('INFO', 'AUDIT_CHECKPOINT_SHUTDOWN', out);
    return out;
  } catch (e) {
    d.emit('ERROR', 'AUDIT_CHECKPOINT_SHUTDOWN_FAILED', { error: e.message });
    return { signed: false, reason: 'FAILED', error: e.message };
  } finally { clearTimeout(timer); }
}

/** Test seam: forget the cached last-signed position (a fresh process has none). */
function _resetSchedulerStateForTests() { _lastSigned = null; if (_schedulerTimer) { clearInterval(_schedulerTimer); _schedulerTimer = null; } }

module.exports = { createSignedCheckpoint, signFinalCheckpoint, _resetSchedulerStateForTests, AUDIT_CHECKPOINT_TICK_MS, checkpointInFlight, verifyLatestCheckpointAtBoot, verifyAnchorsAtBoot, verifyAnchoringPosture, startCheckpointScheduler, latestSignedCheckpoint,
  readSidecar, sidecarPath, DEFAULT_EVERY, DEFAULT_MAX_AGE_MS };
