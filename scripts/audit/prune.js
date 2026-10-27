#!/usr/bin/env node
'use strict';
/**
 * QODIQA audit retention — the ONLY path that removes audit history (step 6, design decisions M3/M4/M5 and
 * option 2 of 2026-09-30).
 *
 *   node scripts/audit/prune.js --confirm-server-stopped [--retention-days N] [--archive-root DIR] [--dry-run]
 *
 * OFF until the owner sets a period: without QODIQA_AUDIT_RETENTION_DAYS or --retention-days the command refuses.
 * Nothing schedules it and no running service holds delete rights (M4): an operator runs it, with the server
 * stopped, against a PostgreSQL identity given ONLY to this command (QODIQA_PG_PRUNE_URL — it must bypass RLS and
 * hold DELETE on audit_chain / evidence_chain_records and INSERT on audit_chain_prunes; checked before anything).
 * Without PostgreSQL (QODIQA_PG_ENABLED≠true and no QODIQA_PG_PRUNE_URL) only the file chain is pruned.
 *
 * What it removes — only after the range is ARCHIVED and the archive VERIFIED, and only up to a SIGNED checkpoint C
 * (the newest one created at least N days ago whose signature verifies and which matches the chain):
 *   · audit.log entries up to C (single-node file chain); <audit.log>.base.json then holds C (M3);
 *   · audit_chain rows before C's own row (seq < C.pgSeq) — C's row stays, it anchors the kept chain;
 *   · evidence_chain_records up to E ≤ C.evidenceHead.id, where E stops before the first evidence record bound to a
 *     kept audit row (so no kept audit entry loses its evidence).
 * Transparency leaves are NOT pruned: --transparency refuses until the GapScanner root check and proofLookup are
 * rebuilt on persisted Merkle blocks + kept leaves. Signed checkpoints,
 * the checkpoint sidecar and the checksum anchor's lifetime count are never removed.
 *
 * Crash-safe order (every intermediate state boots and verifies — audit-log.js _resolveStart):
 *   1 archive written + fsynced, then re-read and verified (by the independent verifier's own code);
 *   2 checksum anchor rewritten WITHOUT its v2 block (the next boot takes the full validating pass);
 *   3 base record written (tmp + fsync + rename): state 'full-file';
 *   4 audit.log replaced by the suffix (tmp + fsync + rename): state 'rebased';
 *   5 PostgreSQL rows deleted and the prune recorded in audit_chain_prunes, in ONE transaction (pg_dump then carries
 *     the base record).
 * Re-running resumes an interrupted prune. Every deletion is logged as an event (AUDIT_PRUNE_*) and listed in the
 * archive's prune-report.json.
 *
 * Refuses (exit 2): no --confirm-server-stopped; no retention period; --transparency; distributed ordering mode; a
 * WAL file present; legacy (pre-hash) lines in the chain; a PostgreSQL identity without the rights above.
 * Exit 0 = pruned, resumed, or nothing to prune · 1 = failed (nothing past the failing step was done) · 2 = refused.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..');
const DAY_MS = 86_400_000;
const PAGE = 5000;

// Crash injection for the proof (test/integration/auditPrune.integration.test.js): under NODE_ENV=test only, exit abruptly
// right after the named step, exactly as a kill between steps would leave the files. Never honoured outside tests.
function crashPoint(step) {
  if (process.env.NODE_ENV === 'test' && process.env.QODIQA_PRUNE_TEST_STOP_AFTER === step) {
    try { require(path.join(REPO, 'services/logger')).flush(); } catch { /* */ }
    process.exit(99);
  }
}

class Refusal extends Error { constructor(m) { super(m); this.refusal = true; } }

function parseArgs(argv) {
  const a = { 'confirm-server-stopped': false, 'dry-run': false, transparency: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) throw new Refusal(`unexpected argument ${k}`);
    const n = k.slice(2);
    if (['confirm-server-stopped', 'dry-run', 'transparency'].includes(n)) { a[n] = true; continue; }
    if (!['retention-days', 'archive-root'].includes(n)) throw new Refusal(`unknown option ${k}`);
    if (i + 1 >= argv.length) throw new Refusal(`${k} needs a value`);
    a[n] = argv[++i];
  }
  return a;
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
function fsyncFile(p) { const fd = fs.openSync(p, 'r+'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function fsyncDir(d) { try { const fd = fs.openSync(d, 'r'); try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } } catch { /* not supported on Windows */ } }
function writeDurable(p, data) {
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, data); fsyncFile(tmp); fs.renameSync(tmp, p); fsyncDir(path.dirname(p));
}

/** Byte offset just past the n-th non-empty line of a file. */
function prefixScan(file, n) {
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(1 << 20);
  let pos = 0; let lines = 0; let carry = Buffer.alloc(0); let off = null;
  try {
    while (off === null) {
      const r = fs.readSync(fd, buf, 0, buf.length, pos);
      if (r <= 0) break;
      let chunk = Buffer.concat([carry, buf.subarray(0, r)]);
      const chunkStart = pos - carry.length;
      let from = 0;
      for (;;) {
        const nl = chunk.indexOf(0x0a, from);
        if (nl < 0) break;
        const line = chunk.subarray(from, nl).toString('utf8').trim();
        if (line) {
          lines++;
          if (lines === n) { off = chunkStart + nl + 1; break; }
        }
        from = nl + 1;
      }
      carry = Buffer.from(chunk.subarray(from));
      pos += r;
    }
  } finally { fs.closeSync(fd); }
  if (off === null) throw new Error(`the log holds fewer than ${n} complete lines`);
  return { off };
}

function copyRange(src, dst, from, to) {
  const rfd = fs.openSync(src, 'r'); const wfd = fs.openSync(dst, 'w');
  const buf = Buffer.alloc(1 << 20);
  try {
    let pos = from;
    while (pos < to) {
      const r = fs.readSync(rfd, buf, 0, Math.min(buf.length, to - pos), pos);
      if (r <= 0) throw new Error('short read');
      fs.writeSync(wfd, buf, 0, r); pos += r;
    }
    fs.fsyncSync(wfd);
  } finally { fs.closeSync(rfd); fs.closeSync(wfd); }
}

function main() {
  const events = [];
  let emit = (level, event, extra) => { events.push({ at: new Date().toISOString(), level, event, ...extra }); };
  const args = parseArgs(process.argv.slice(2));

  // ── Preconditions (refusals, nothing touched) ─────────────────────────────────────────────────────────────────
  if (args.transparency) throw new Refusal('--transparency is not available yet: transparency leaves are pruned only after the GapScanner root check and proofLookup are rebuilt on persisted Merkle blocks + kept leaves');
  if (!args['confirm-server-stopped']) throw new Refusal('--confirm-server-stopped is required: the prune rewrites audit.log and must never run while a server holds it');
  const days = Number(args['retention-days'] ?? process.env.QODIQA_AUDIT_RETENTION_DAYS);
  if (!Number.isInteger(days) || days < 1) throw new Refusal('no retention period: set QODIQA_AUDIT_RETENTION_DAYS or pass --retention-days N (a positive integer) — retention is OFF until the owner sets one');
  if (process.env.QODIQA_AUDIT_ORDERING_MODE === 'distributed') throw new Refusal('distributed ordering mode: pruning PostgreSQL-authoritative chains is not supported');

  // Load the chain exactly as a boot would — read-only (follower), fully validated, fail-closed on any defect.
  process.env.QODIQA_AUDIT_FOLLOWER = 'true';
  const auditLogPath = require.resolve(path.join(REPO, 'src/core/audit/audit-log'));
  const LOG_PATH = process.env.QODIQA_AUDIT_LOG || path.join(REPO, 'audit.log');
  if (fs.existsSync(LOG_PATH + '.wal')) throw new Refusal(`a WAL file exists (${path.basename(LOG_PATH)}.wal): start and stop the server once so it replays, then re-run`);
  let auditLog;
  try { auditLog = require(auditLogPath); } catch (e) { throw new Error(`the audit chain does not verify — nothing pruned: ${e.message}`); }
  const logger = require(path.join(REPO, 'services/logger'));
  emit = (level, event, extra) => { events.push({ at: new Date().toISOString(), level, event, ...extra }); logger.emit(level, event, extra); };
  const { verifyCheckpoint } = require(path.join(REPO, 'src/core/audit/checkpoint/checkpoint'));
  const cpKeys = require(path.join(REPO, 'src/core/audit/checkpoint/checkpointKeyStore'));
  const { readSidecar } = require(path.join(REPO, 'src/core/audit/checkpoint/checkpointWriter'));
  const indep = require(path.join(REPO, 'scripts/audit-repro/verify/checkpoint'));
  const contract = require(path.join(REPO, 'scripts/audit-repro/verify/auditContract'));
  const evidenceChain = require(path.join(REPO, 'src/core/evidence/chain'));
  const checksumAnchor = require(path.join(REPO, 'src/core/audit/checksumAnchor'));

  const snap = auditLog.memorySnapshot();
  const start = auditLog.getChainStart();
  const BASE_PATH = auditLog.BASE_PATH;
  const logSize = fs.existsSync(LOG_PATH) ? fs.statSync(LOG_PATH).size : 0;
  if (snap.totalCount !== snap.modernCount) throw new Refusal(`the chain holds ${snap.totalCount - snap.modernCount} legacy (pre-hash) lines — a prefix with legacy lines is never pruned`);
  const currentBase = fs.existsSync(BASE_PATH) ? JSON.parse(fs.readFileSync(BASE_PATH, 'utf8')) : null;

  const archiveRoot = path.resolve(args['archive-root'] || process.env.QODIQA_AUDIT_ARCHIVE_ROOT || path.join(path.dirname(LOG_PATH), 'audit-archive'));
  const resolvePub = indep.keyResolver({ keys: cpKeys.publishedKeys().map((k) => ({ keyId: k.keyId, publicKey: k.publicKeySpkiDerB64, status: k.status })) });

  return (async () => {
    // ── PostgreSQL (optional) ───────────────────────────────────────────────────────────────────────────────────
    const pgWanted = !!process.env.QODIQA_PG_PRUNE_URL || process.env.QODIQA_PG_ENABLED === 'true';
    let pg = null;
    if (pgWanted) {
      if (!process.env.QODIQA_PG_PRUNE_URL) throw new Refusal('PostgreSQL is enabled but QODIQA_PG_PRUNE_URL is not set: the prune runs only with the dedicated prune identity (BYPASSRLS, DELETE on audit_chain/evidence_chain_records, INSERT on audit_chain_prunes) — no running service holds these rights');
      const { Client } = require('pg');
      pg = new Client({ connectionString: process.env.QODIQA_PG_PRUNE_URL });
      await pg.connect();
      const r = await pg.query(`SELECT current_user AS u, r.rolbypassrls OR r.rolsuper AS bypass,
          has_table_privilege(current_user, 'audit_chain', 'SELECT,DELETE') AS ac,
          has_table_privilege(current_user, 'evidence_chain_records', 'SELECT,DELETE') AS ev,
          has_table_privilege(current_user, 'audit_chain_prunes', 'SELECT,INSERT') AS pr,
          has_table_privilege(current_user, 'audit_signed_checkpoints', 'SELECT') AS cp
        FROM pg_roles r WHERE r.rolname = current_user`);
      const p = r.rows[0];
      const missing = ['bypass', 'ac', 'ev', 'pr', 'cp'].filter((k) => !p[k]);
      if (missing.length) { await pg.end(); throw new Refusal(`the prune identity "${p.u}" lacks: ${missing.join(', ')} (bypass = BYPASSRLS; ac/ev = SELECT+DELETE on audit_chain/evidence_chain_records; pr = SELECT+INSERT on audit_chain_prunes; cp = SELECT on audit_signed_checkpoints)`); }
    }
    const q = async (sql, params = []) => (await pg.query(sql, params)).rows;

    try {
      // ── Resume or select the checkpoint C ──────────────────────────────────────────────────────────────────────
      let C; let resume = null;
      if (start.state === 'full-file') { C = currentBase.checkpoint; resume = 'replace-log'; }
      else if (start.state === 'rebased' && pg) {
        const done = await q('SELECT 1 FROM audit_chain_prunes WHERE checkpoint_id = $1', [currentBase.checkpoint.payload.checkpointId]);
        if (!done.length) { C = currentBase.checkpoint; resume = 'pg'; }
      }
      const cutoff = Date.now() - days * DAY_MS;
      if (!C) {
        const cands = new Map();
        if (pg) for (const r of await q('SELECT payload, payload_hash, signature FROM audit_signed_checkpoints ORDER BY chain_length')) cands.set(r.payload.checkpointId, { payload: r.payload, payloadHash: String(r.payload_hash).trim(), signature: r.signature });
        for (const s of readSidecar(LOG_PATH)) if (!cands.has(s.payload.checkpointId)) cands.set(s.payload.checkpointId, s);
        const ok = [];
        for (const s of cands.values()) {
          const p = s.payload;
          if (!verifyCheckpoint(s).ok || Date.parse(p.createdAt) > cutoff) continue;
          if (!(p.chainLength > start.startCount) || p.chainLength > snap.modernCount) continue;
          if (pg && !(Number.isInteger(p.pgSeq) && p.pgSeq > 0)) continue;
          const e = await auditLog.getModernEntryAt(p.chainLength - 1);
          if (!e || e.hash !== p.headHash) continue;
          ok.push(s);
        }
        ok.sort((a, b) => b.payload.chainLength - a.payload.chainLength);
        C = ok[0];
        if (!C) {
          const out = { result: 'NOTHING_TO_PRUNE', retentionDays: days, cutoff: new Date(cutoff).toISOString(), chainStart: start.startCount, chainLength: snap.modernCount, signedCheckpoints: cands.size };
          emit('INFO', 'AUDIT_PRUNE_NOTHING_TO_DO', out);
          return out;
        }
      }
      const cp = C.payload;
      const archiveDir = path.join(archiveRoot, cp.checkpointId);
      const prior = start.state === 'rebased' && !resume ? currentBase : (currentBase && currentBase.priorBase) || null;
      const fromCount = prior ? prior.checkpoint.payload.chainLength : 0;
      const fromHash = prior ? prior.checkpoint.payload.headHash : 'GENESIS';

      // ── Plan: file range, PG rows, evidence bound ─────────────────────────────────────────────────────────────
      const plan = { checkpointId: cp.checkpointId, checkpointCreatedAt: cp.createdAt, retentionDays: days, fromCount, toCount: cp.chainLength,
        fileEntries: cp.chainLength - fromCount, archiveDir, resume, pg: null };
      let rowC = null; let evPrevId = 0; let evPrevHash; let E = null;
      if (pg) {
        rowC = (await q('SELECT seq, hash, prev_hash FROM audit_chain WHERE seq = $1', [cp.pgSeq]))[0];
        if (!rowC || String(rowC.hash).trim() !== cp.headHash) throw new Error(`audit_chain row seq=${cp.pgSeq} is not the checkpoint's head — run the mirror consistency check first`);
        const evBase = resume ? (currentBase.evidence || null) : (prior && prior.evidence) || null;
        if (resume) { E = evBase ? evBase.lastPrunedId : null; evPrevId = (prior && prior.evidence && prior.evidence.lastPrunedId) || 0; evPrevHash = prior && prior.evidence ? prior.evidence.lastPrunedHash : undefined; }
        else {
          evPrevId = evBase ? evBase.lastPrunedId : 0; evPrevHash = evBase ? evBase.lastPrunedHash : undefined;
          if (cp.evidenceHead && cp.evidenceHead.id > evPrevId) {
            const m = (await q(`SELECT min(e.id) AS m FROM evidence_chain_records e WHERE e.id > $1 AND e.id <= $2
                AND EXISTS (SELECT 1 FROM audit_chain a WHERE a.seq > $3 AND a.artifact_id = e.artifact_id)`, [evPrevId, cp.evidenceHead.id, cp.pgSeq]))[0].m;
            E = m === null ? cp.evidenceHead.id : Number(m) - 1;
            if (E <= evPrevId) E = null;
          }
        }
        const [{ n: acRows }] = await q('SELECT count(*)::bigint AS n FROM audit_chain WHERE seq < $1', [cp.pgSeq]);
        const [{ n: evRows }] = E ? await q('SELECT count(*)::bigint AS n FROM evidence_chain_records WHERE id > $1 AND id <= $2', [evPrevId, E]) : [{ n: 0 }];
        const [{ n: orphans }] = await q(`SELECT count(*)::bigint AS n FROM evidence_chain_records e WHERE e.id > $1
            AND EXISTS (SELECT 1 FROM audit_chain a WHERE a.seq <= $2 AND a.artifact_id = e.artifact_id)`, [E || evPrevId, cp.pgSeq]);
        plan.pg = { auditRows: Number(acRows), keptAnchorSeq: Number(cp.pgSeq), evidenceFromIdExclusive: evPrevId, evidenceToId: E, evidenceRows: Number(evRows),
          evidenceKeptBoundToPrunedAudit: Number(orphans) };
      }
      if (args['dry-run']) { const out = { result: 'DRY_RUN', plan }; emit('INFO', 'AUDIT_PRUNE_DRY_RUN', out); return out; }
      emit('INFO', 'AUDIT_PRUNE_STARTED', plan);

      // ── Step 1: archive (or re-verify an existing one) ─────────────────────────────────────────────────────────
      const manifestPath = path.join(archiveDir, 'manifest.json');
      if (fs.existsSync(archiveDir) && !fs.existsSync(manifestPath)) {
        const aside = `${archiveDir}.incomplete-${Date.now()}`;
        fs.renameSync(archiveDir, aside);                         // an interrupted archive: kept aside, never deleted
        emit('WARN', 'AUDIT_PRUNE_INCOMPLETE_ARCHIVE_SET_ASIDE', { from: archiveDir, to: aside });
      }
      if (!fs.existsSync(manifestPath)) {
        if (resume === 'replace-log' || resume === 'pg') throw new Error(`the archive for ${cp.checkpointId} is missing (${archiveDir}) — an interrupted prune cannot be resumed without it`);
        fs.mkdirSync(archiveDir, { recursive: true });
        const files = {};
        const put = (name, data) => { const p = path.join(archiveDir, name); fs.writeFileSync(p, data); fsyncFile(p); files[name] = { sha256: sha256(data), bytes: Buffer.byteLength(data) }; };
        // audit.log segment: the file's first (C.chainLength − fromCount) lines, byte for byte
        const { off } = prefixScan(LOG_PATH, cp.chainLength - fromCount);
        copyRange(LOG_PATH, path.join(archiveDir, 'audit.log.segment'), 0, off);
        const seg = fs.readFileSync(path.join(archiveDir, 'audit.log.segment'));
        files['audit.log.segment'] = { sha256: sha256(seg), bytes: seg.length };
        put('checkpoint.json', JSON.stringify(C));
        if (prior) put('prior-base.json', JSON.stringify(prior));
        const man = { v: 1, tool: 'scripts/audit/prune.js', createdAt: new Date().toISOString(), checkpointId: cp.checkpointId,
          from: { count: fromCount, hash: fromHash }, to: { count: cp.chainLength, hash: cp.headHash }, pg: null, evidence: null, files };
        if (pg) {
          const rows = []; let last = -1;
          for (;;) {
            const page = await q('SELECT * FROM audit_chain WHERE seq < $1 AND seq > $2 ORDER BY seq LIMIT $3', [cp.pgSeq, last, PAGE]);
            if (!page.length) break;
            rows.push(...page); last = page[page.length - 1].seq;
          }
          put('audit_chain.jsonl', rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : ''));
          man.pg = { table: 'audit_chain', seqBelow: Number(cp.pgSeq), rows: rows.length };
          if (E) {
            const ev = await q('SELECT * FROM evidence_chain_records WHERE id > $1 AND id <= $2 ORDER BY id', [evPrevId, E]);
            put('evidence_chain_records.jsonl', ev.map((r) => JSON.stringify(r)).join('\n') + '\n');
            man.evidence = { fromIdExclusive: evPrevId, fromHash: evPrevHash ?? null, toId: E, lastHash: ev.length ? String(ev[ev.length - 1].evidence_hash).trim() : null, rows: ev.length };
          }
        }
        const manText = JSON.stringify(man, null, 1);
        fs.writeFileSync(manifestPath, manText); fsyncFile(manifestPath); fsyncDir(archiveDir);
      }

      // Verify the archive — the file segment by the independent verifier's own code, then the PG rows.
      const manText = fs.readFileSync(manifestPath, 'utf8');
      const man = JSON.parse(manText);
      const manifestSha256 = sha256(Buffer.from(manText));
      const av = indep.verifyArchive(archiveDir, resolvePub, { hash: fromHash, count: fromCount });
      if (!av.valid) throw new Error(`archive verification failed: ${av.reason}`);
      const segEntries = contract.parseNdjson(fs.readFileSync(path.join(archiveDir, 'audit.log.segment'), 'utf8')).entries;
      const prefixStats = { allowCount: 0, blockCount: 0, replayCount: 0, headHash: prior && prior.prefixStats ? prior.prefixStats.headHash : (segEntries[0] ? segEntries[0].hash : null) };
      if (prior && prior.prefixStats) for (const k of ['allowCount', 'blockCount', 'replayCount']) prefixStats[k] = prior.prefixStats[k] || 0;
      for (const e of segEntries) {
        if (e.decision === 'ALLOW') prefixStats.allowCount++; else if (e.decision === 'BLOCK') prefixStats.blockCount++;
        if (e.executionContext && typeof e.executionContext.replayOf === 'string' && e.executionContext.replayOf) prefixStats.replayCount++;
      }
      let evidence = null;
      if (pg && man.pg) {
        const rows = fs.readFileSync(path.join(archiveDir, 'audit_chain.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
        const anchor = prior ? rows.find((r) => String(r.hash).trim() === fromHash) : null;
        if (prior && !anchor && rows.length) throw new Error('PG archive: the prior base\'s anchor row is not among the archived rows');
        const chainRows = rows.filter((r) => r !== anchor).map((r) => ({ ...r, hash: String(r.hash).trim() }));
        const { ordered, anomalies } = contract.orderPgRows(chainRows, { start: fromHash });
        const fatal = anomalies.filter((x) => x.severity !== 'WARN');
        const walk = contract.walkChain(ordered.map(contract.entryFromPgRow), { startPrevHash: fromHash });
        const expectN = cp.chainLength - fromCount - 1;
        const tail = ordered.length ? ordered[ordered.length - 1].hash : fromHash;
        if (fatal.length || !walk.valid || ordered.length !== expectN || tail !== String(rowC.prev_hash).trim()) {
          throw new Error(`PG archive does not verify (anomalies ${JSON.stringify(fatal)}, walk ${walk.reason}, rows ${ordered.length}/${expectN}, tail ${tail === String(rowC.prev_hash).trim()}) — run the mirror consistency check first`);
        }
        for (let i = 0; i < ordered.length; i++) if (ordered[i].hash !== segEntries[i].hash) throw new Error(`PG archive row ${i + 1} (${ordered[i].hash}) is not the file entry ${fromCount + i + 1} (${segEntries[i].hash})`);
        if (man.evidence) {
          const ev = fs.readFileSync(path.join(archiveDir, 'evidence_chain_records.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
            .map((r) => ({ ...r, evidence_hash: String(r.evidence_hash).trim(), audit_record_hash: r.audit_record_hash && String(r.audit_record_hash).trim() }));
          const c = evidenceChain.validateChainContinuity(ev, man.evidence.fromHash === null ? {} : { startHash: man.evidence.fromHash });
          if (!c.valid || c.checkedCount !== ev.length || Number(ev[ev.length - 1].id) !== man.evidence.toId) throw new Error(`evidence archive does not verify: ${c.failureDetail || 'incomplete'}`);
          evidence = { lastPrunedId: man.evidence.toId, lastPrunedHash: ev[ev.length - 1].evidence_hash, signedHead: cp.evidenceHead, checkpoint: C };
        } else if (prior && prior.evidence) {
          // no evidence pruned this time: the kept evidence chain still starts where the prior prune left it, vouched
          // for by the checkpoint that prune used (carried with it — evidenceBase.js verifies against that one)
          evidence = { ...prior.evidence, checkpoint: prior.evidence.checkpoint || prior.checkpoint };
        }
      }
      emit('INFO', 'AUDIT_PRUNE_ARCHIVED', { checkpointId: cp.checkpointId, archiveDir, manifestSha256, fileEntries: segEntries.length,
        auditRows: man.pg ? man.pg.rows : 0, evidenceRows: man.evidence ? man.evidence.rows : 0 });
      crashPoint('archive');

      const headEntry = segEntries[segEntries.length - 1];
      const baseRecord = { v: 1, checkpoint: C, prefixStats, headRecordedAt: headEntry.timestamp, file: { fromCount, toCount: cp.chainLength },
        evidence, archive: { location: archiveDir, manifestSha256 }, prunedAt: new Date().toISOString(),
        priorBase: prior ? { checkpoint: prior.checkpoint, prefixStats: prior.prefixStats || null, evidence: prior.evidence || null } : null };

      let fileBytesRemoved = 0;
      if (resume !== 'pg') {
        if (resume !== 'replace-log') {
          if (fs.statSync(LOG_PATH).size !== logSize) throw new Error('audit.log changed while the prune ran — is the server really stopped?');
          // ── Step 2: the checksum anchor without its v2 block (next boot: full validating pass) ──────────────────
          const csPath = checksumAnchor.resolveFileAnchorPath(LOG_PATH);
          const cs = checksumAnchor.loadChecksum(csPath);
          if (cs) { checksumAnchor.saveChecksum(csPath, cs.count, cs.tailHash); fsyncFile(csPath); }
          crashPoint('anchor');
          // ── Step 3: the signed base record ────────────────────────────────────────────────────────────────────
          writeDurable(BASE_PATH, JSON.stringify(baseRecord, null, 1));
          emit('INFO', 'AUDIT_PRUNE_BASE_WRITTEN', { checkpointId: cp.checkpointId, basePath: BASE_PATH });
          crashPoint('base');
        } else if (currentBase.checkpoint.payload.checkpointId !== cp.checkpointId) throw new Error('resume: base record / checkpoint mismatch');
        // ── Step 4: audit.log ← the suffix ────────────────────────────────────────────────────────────────────────
        const { off } = prefixScan(LOG_PATH, cp.chainLength - fromCount);
        const size = fs.statSync(LOG_PATH).size;
        const tmp = LOG_PATH + '.prune.tmp';
        copyRange(LOG_PATH, tmp, off, size);
        fs.renameSync(tmp, LOG_PATH); fsyncDir(path.dirname(LOG_PATH));
        fileBytesRemoved = off;
        emit('INFO', 'AUDIT_PRUNE_FILE_PREFIX_REMOVED', { checkpointId: cp.checkpointId, entriesRemoved: cp.chainLength - fromCount, fromCount, toCount: cp.chainLength, bytesRemoved: off });
        crashPoint('log');
      }

      // ── Step 5: PostgreSQL, one transaction ────────────────────────────────────────────────────────────────────
      let deleted = { audit: 0, evidence: 0 };
      if (pg) {
        const baseForRow = resume ? currentBase : baseRecord;   // a resumed prune records the base already on disk
        await pg.query('BEGIN');
        try {
          // DB-05 (migration 076): audit_chain refuses DELETE unless the transaction declares this maintenance intent.
          await pg.query("SET LOCAL qodiqa.audit_maintenance = 'prune'");
          const a = await pg.query('DELETE FROM audit_chain WHERE seq < $1', [cp.pgSeq]);
          const ev = man.evidence ? await pg.query('DELETE FROM evidence_chain_records WHERE id > $1 AND id <= $2', [man.evidence.fromIdExclusive, man.evidence.toId]) : { rowCount: 0 };
          if (a.rowCount !== man.pg.rows || ev.rowCount !== (man.evidence ? man.evidence.rows : 0)) {
            throw new Error(`deleted ${a.rowCount} audit / ${ev.rowCount} evidence rows but archived ${man.pg.rows} / ${man.evidence ? man.evidence.rows : 0} — rolled back`);
          }
          await pg.query(`INSERT INTO audit_chain_prunes (prune_id, checkpoint_id, from_count, to_count, audit_rows_deleted, evidence_rows_deleted,
              transparency_rows_deleted, archive_manifest_sha256, archive_location, base_record, pruned_by)
            VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8,$9,$10)`,
          [crypto.randomUUID(), cp.checkpointId, fromCount, cp.chainLength, a.rowCount, ev.rowCount, manifestSha256, archiveDir, JSON.stringify(baseForRow),
            (process.env.QODIQA_PRUNE_OPERATOR || require('os').userInfo().username || 'operator').slice(0, 64)]);
          await pg.query('COMMIT');
          deleted = { audit: a.rowCount, evidence: ev.rowCount };
        } catch (e) { await pg.query('ROLLBACK').catch(() => {}); throw e; }
        emit('INFO', 'AUDIT_PRUNE_PG_ROWS_DELETED', { checkpointId: cp.checkpointId, table: 'audit_chain', rows: deleted.audit, seqBelow: Number(cp.pgSeq) });
        emit('INFO', 'AUDIT_PRUNE_PG_ROWS_DELETED', { checkpointId: cp.checkpointId, table: 'evidence_chain_records', rows: deleted.evidence,
          idFromExclusive: man.evidence ? man.evidence.fromIdExclusive : null, idTo: man.evidence ? man.evidence.toId : null });
      }

      // ── Post-verify: a fresh process boots the pruned chain (read-only) ────────────────────────────────────────
      const probe = spawnSync(process.execPath, ['-e',
        "const a=require(process.argv[1]);const s=a.getChainStart();const m=a.memorySnapshot();require(process.argv[2]).flush();console.log('\\n'+JSON.stringify({state:s.state,startCount:s.startCount,modernCount:m.modernCount}))",
        auditLogPath, path.join(REPO, 'services/logger')], { env: { ...process.env, QODIQA_AUDIT_FOLLOWER: 'true' }, encoding: 'utf8', timeout: 600_000 });
      let post = null;
      try { post = JSON.parse(probe.stdout.trim().split('\n').pop()); } catch { /* reported below */ }
      if (!post || post.state !== 'rebased' || post.startCount !== cp.chainLength || post.modernCount !== snap.modernCount) {
        throw new Error(`post-prune boot check failed: ${post ? JSON.stringify(post) : (probe.stderr || '').slice(-400)}`);
      }
      const out = { result: resume ? 'RESUMED' : 'PRUNED', checkpointId: cp.checkpointId, fromCount, toCount: cp.chainLength, fileBytesRemoved,
        pgRowsDeleted: deleted, archiveDir, manifestSha256, postBoot: post };
      emit('INFO', 'AUDIT_PRUNE_COMPLETED', out);
      fs.writeFileSync(path.join(archiveDir, `prune-report-${Date.now()}.json`), JSON.stringify({ ...out, plan, events }, null, 1));
      return out;
    } finally {
      if (pg) await pg.end().catch(() => {});
    }
  })();
}

if (require.main === module) {
  let p;
  try { p = Promise.resolve(main()); } catch (e) { p = Promise.reject(e); }
  p.then((out) => { try { require(path.join(REPO, 'services/logger')).flush(); } catch { /* */ } console.log(JSON.stringify(out)); process.exitCode = 0; },
    (e) => {
      try { require(path.join(REPO, 'services/logger')).flush(); } catch { /* */ }
      console.log(JSON.stringify({ result: e.refusal ? 'REFUSED' : 'FAILED', reason: e.message }));
      process.exitCode = e.refusal ? 2 : 1;
    });
}

module.exports = { main, parseArgs, prefixScan };
