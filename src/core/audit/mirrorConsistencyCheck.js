'use strict';

/**
 * Startup Audit-Chain / PostgreSQL Mirror Consistency Check — / CHAIN-4
 *
 * ROOT CAUSE (see docs/protocol/AUDIT-SCHEMA-V8.md and
 * pg-audit-backend.js's header): every audit entry is dual-written to the
 * append-only NDJSON file (authoritative in single-node mode) and, when
 * QODIQA_PG_ENABLED=true, to PostgreSQL (a queryable mirror). Nothing
 * previously compared the two at startup, so a truncated/replaced/restored
 * audit.log would only be caught if an operator manually hit
 * GET /audit/chain/integrity or ran the DR probe — both of which only check
 * the file's *own* internal hash-chain, never against the PG mirror. A file
 * that was wholesale replaced by an old-but-internally-valid backup would
 * pass that check and go undetected forever. This module closes that gap by
 * running an independent, deterministic, fail-closed comparison once at boot,
 * before the process starts accepting requests.
 *
 * CHAIN-4 (this revision) hardens from a summary-only comparison
 * (record count, head hash, tail hash) to a full record-by-record,
 * content-addressed walk of both chains —
 * record count, per-record hash, per-record previousHash, chain head,
 * genesis record, full chain continuity, and duplicate-hash detection on
 * either side. The summary comparison was
 * cryptographically sufficient to *detect* divergence (see the "WHY
 * (count, head, tail) IS SUFFICIENT" note preserved below), but it could not
 * tell an operator *where* two chains diverged. CHAIN-4 was commissioned
 * specifically to close that diagnostic gap: every mismatch now reports the
 * first diverging sequence number, both sides' hash/previousHash at that
 * position, and the last record both stores still agree on.
 *
 * SCOPE — when this check applies:
 *   - Distributed mode (QODIQA_AUDIT_ORDERING_MODE=distributed) is a no-op
 *     here: PostgreSQL IS the ordering authority in that mode (the in-memory
 *     chain is hydrated FROM it — see audit-log.js's
 *     hydrateFromPgIfDistributed()), so there is no independent local file
 *     chain to cross-check it against. checkDistributedPreconditions() in
 *     multiInstanceGuard.js already gates PG reachability for that mode.
 *   - PG mirror disabled (QODIQA_PG_ENABLED not "true") is a no-op here too:
 * dual-write is an optional feature (pg-audit-backend.js). A
 *     deployment that has never enabled it has no second copy to diverge
 *     from, so there is nothing for this check to protect against.
 *   - The check is only meaningful, and only fatal, for single-node mode with
 *     the PG mirror enabled — exactly the configuration the root cause above
 *     describes.
 *
 * WHY EXACT MATCH, NOT A LAG TOLERANCE:
 *   pgLagMonitor.js already runs a *live*, best-effort background check that
 *   WARNs (never blocks) when PG falls behind the file by more than a
 *   threshold — because the dual-write is fire-and-forget on the hot path,
 *   transient lag during normal operation is expected there.
 *   This module is different: it runs once, at boot, before any request is
 *   served. Anything the dual-write was going to durably persist from the
 *   *previous* run has already settled by the time this process starts again
 *   (there is no in-flight write to "catch up" on) — so any discrepancy found
 *   here reflects either a real divergence (truncation, restore-from-backup,
 *   tampering) or a mirror that never caught up after a prior outage. The
 *   task's fail-closed / no-heuristics requirement treats both as equally
 *   worth stopping for: an operator must look, not the process guess which
 *   copy is "right". (If PG was just enabled for the first time against a
 *   pre-existing file chain, run scripts/migrate-files-to-pg.js to backfill
 *   before starting — that is the explicit administrative action, not an
 *   automatic one.)
 *
 * WHY (count, head, tail) IS SUFFICIENT TO *DETECT* DIVERGENCE — NOT WHY IT'S
 * SUFFICIENT TO *DIAGNOSE* IT:
 *   Both sides are independently proven internally consistent before they are
 *   ever compared: the file chain is re-walked here via
 *   verifyAuditChainDetailed() exactly like the PG side, so each side is a
 *   valid SHA-256 hash chain on its own terms. Given two chains that are each
 *   internally a valid hash chain, having the same length and the same tail
 *   hash is only possible if every entry in between is identical — a
 *   different chain of equal length ending in the same tail hash would
 *   require a SHA-256 collision. So the summary comparison alone is
 *   sufficient to *know* whether the two chains are identical. It is,
 *   however, useless for telling an operator *where* they diverge, which is
 *   why CHAIN-4 adds the full content-addressed walk below purely for
 *   diagnostics — not because the summary check was cryptographically
 *   unsound.
 *
 * FAIL-CLOSED / NO AUTO-REPAIR:
 *   Any mismatch, or any failure to even load the PG side, is fatal by
 *   default: a clear diagnostic is logged and the process exits non-zero
 *   before the app can accept a single request. This module never rewrites
 *   the file, never overwrites PostgreSQL, never picks a "newer" copy, and
 *   never retries past a single load attempt. Reconciliation is an explicit
 *   operator action outside this code path (see the `action` field of the
 *   FATAL record).
 *
 * RECOVERY MODE (CHAIN-4, explicit opt-in only — QODIQA_AUDIT_MIRROR_RECOVERY_MODE=true):
 *   Setting this flag does NOT reconcile, repair, or overwrite anything. It
 *   changes exactly one thing: a detected divergence is logged (at WARN,
 *   with the exact same full diagnostic payload a FATAL record would have
 *   carried) instead of aborting startup. This exists solely so an operator
 *   who is actively investigating a known, already-diagnosed divergence can
 *   bring the service up in a supervised, degraded state (e.g. to serve reads
 *   while a backfill runs) without silently losing the fact that history is
 *   still unverified. It must never be left enabled as a standing
 *   configuration — there is no automatic exit from recovery mode; an
 *   operator must fix the divergence and unset the flag. Every recovery-mode
 *   startup emits AUDIT_MIRROR_RECOVERY_MODE_ENGAGED so this is never quiet.
 *
 * OPERATOR DIAGNOSTICS:
 *   On any divergence the FATAL (or, in recovery mode, WARN) record includes:
 *   firstMismatchSequence, fileHash / pgHash at that sequence, expected vs.
 *   actual previousHash, fileChainLength / pgChainLength, lastCommonRecord,
 *   divergencePoint, and a machine-readable reason code (see
 *   MISMATCH_REASON below) — enough to locate the exact diverging record
 *   without re-deriving anything by hand.
 *
 * METRICS (src/observability/metrics.js):
 *   qodiqa_audit_crosscheck_success_total / _failure_total,
 *   qodiqa_audit_crosscheck_duration_seconds,
 *   qodiqa_audit_crosscheck_records_checked,
 *   qodiqa_audit_crosscheck_last_verified_timestamp_seconds.
 *   Only emitted for runs that actually execute the cross-check (not the
 *   distributed-mode / PG-disabled skip paths, which are structural no-ops).
 *
 * PERFORMANCE:
 *   Runs exactly once, during startup, before the HTTP server accepts
 *   connections. The added content-addressed walk is a single O(n) pass over
 *   already-in-memory arrays (no additional disk or network I/O beyond the
 *   one PG load already required) — tens of thousands of records compare in
 *   low tens of milliseconds. Nothing here executes on the request path, so
 *   there is zero added runtime overhead once startup succeeds.
 */

const { emit } = require('../../../services/logger');
const { writeDiagnostic: _writeDiagnostic } = require('../../runtime/rawStderrDiagnostic');

const MISMATCH_REASON = Object.freeze({
  MISSING_IN_FILE:      'MISSING_IN_FILE',       // PG has a record at this sequence, file does not
  MISSING_IN_PG:         'MISSING_IN_PG',         // File has a record at this sequence, PG does not
  HASH_MISMATCH:         'HASH_MISMATCH',
  PREV_HASH_MISMATCH:    'PREV_HASH_MISMATCH',
  METADATA_MISMATCH:     'METADATA_MISMATCH',     // hash/prevHash equal but canonical payload differs
  GENESIS_MISMATCH:      'GENESIS_MISMATCH',      // mismatch specifically at sequence 0
});

// FATAL records bypass the shared logger and write directly to stderr, same
// as multiInstanceGuard.js — deliberately: the shared logger's central-store
// sink is PostgreSQL-backed (services/logger.js registerCentralStore()), and
// a PG-reachability problem is exactly one of the failure modes this check
// exists to catch. A FATAL/WARN diagnostic must not depend on the thing that
// may be broken. See src/runtime/rawStderrDiagnostic.js for the
// single shared implementation of this fail-safe write path.

// audit-log.js's getChainStats() uses the sentinel 'GENESIS' for tailHash and
// null for headHash when the modern chain is empty; the PG-side chain walk
// (verifyAuditChainDetailed) uses null/null for "no entries" in both fields.
// Normalize both sides to the same empty-chain representation so the
// comparison below needs no special-cased branch per field.
function _normalizedHash(hash, count) {
  if (count === 0) return null;
  return hash ?? null;
}

// reconstructs `rows` into true logical (hash-chain) order, independent
// of whatever order they arrived in. PostgreSQL's own `seq` column reflects
// INSERT-execution order under concurrent fire-and-forget dual-writes, not
// necessarily true logical chain order — see crossValidateRecords()'s own
// comment above for the full mechanism. verifyAuditChainDetailed()
// (audit-log.js) walks its input POSITIONALLY (entry[i]'s prevHash must
// equal entry[i-1]'s hash) — correct when given the file's own true append
// order, but this same function is also used below to re-validate the PG
// side's OWN internal chain from `loadChainFromPg()`'s seq-ordered rows,
// which inherits the identical seq-vs-logical-order assumption
// crossValidateRecords used to make. A benign reorder read as
// AUDIT_MIRROR_PG_CHAIN_INVALID (a second, independent false-FATAL path
// beyond crossValidateRecords' own — live-reproduced under real load in
// Session 3, confirmed again here under the remediation's own
// regression tests) before this fix.
//
// Falls back to returning `rows` unchanged if a single linear chain can't be
// reconstructed (a genuine break, branch, or duplicate prevHash) —
// verifyAuditChainDetailed() below still catches that case correctly via
// its own existing detection, no worse than before this fix for a genuinely
// corrupted chain.
// M3: startHash = the signed base record's head after a prune; then rows before the base (still in PG while a
// prune is between its file and PG steps) are simply not reached, and the ordered suffix is returned.
function _reorderByHashChain(rows, startHash = 'GENESIS') {
  if (!Array.isArray(rows) || rows.length === 0) return rows;
  const partial = startHash !== 'GENESIS';

  const byPrevHash = new Map();
  for (const r of rows) {
    if (!r || typeof r.prevHash !== 'string' || byPrevHash.has(r.prevHash)) return rows;
    byPrevHash.set(r.prevHash, r);
  }

  const ordered = [];
  let cursor = startHash;
  for (let i = 0; i < rows.length; i++) {
    const next = byPrevHash.get(cursor);
    if (!next) return partial ? ordered : rows;
    ordered.push(next);
    cursor = next.hash;
  }
  return ordered;
}

// Returns the array of hash values that appear more than once in `entries`,
// or [] if every hash is unique. A duplicate hash on either side is, under
// correct SHA-256 domain-separated hashing, either a data-integrity bug (a
// stale row that survived an `ON CONFLICT DO NOTHING` race) or tampering —
// never a legitimate state.
function _findDuplicateHashes(entries) {
  if (!Array.isArray(entries)) return [];
  const seen = new Set();
  const duplicates = [];
  for (const e of entries) {
    const hash = e && typeof e.hash === 'string' ? e.hash : null;
    if (hash === null) continue;
    if (seen.has(hash)) duplicates.push(hash);
    else seen.add(hash);
  }
  return duplicates;
}

// Content-addressed (hash-keyed) cross-validation between the file chain and
// the PG chain. Only meaningful when both raw entry arrays are available (in
// production this is always true — audit-log.js exports getModernChain()).
// Returns null when raw entries could not be obtained on either side, in
// which case callers fall back to the count/head/tail summary comparison
// alone.
//
// this used to be a positional walk
// (fileEntries[i] vs. pgEntries[i] at the same array index), which silently
// assumed file-append order and PG's own seq-ASC insertion order stay
// 1:1-comparable. They do not under ordinary concurrent fire-and-forget
// dual-writes — two records can land in PostgreSQL in a different order than
// the file's own true logical order with zero data loss or corruption
// (live-reproduced under real sustained load Session 3; see
//). A positional walk reported that
// benign reordering as a false PG_MIRROR_HASH_MISMATCH — including through
// this module's own FATAL, process.exit(1)-on-mismatch startup gate, so a
// perfectly healthy server could refuse to boot after ordinary concurrent
// write load.
//
// The chain's own identity is its hash (SHA-256 over canonical content), not
// its position in either array, so the correct comparison is content-
// addressed: for every file entry, does a PG row with that same hash exist,
// and does it carry the same previousHash/canonical payload? This is
// insensitive to insertion-order differences by construction, while still
// catching every real divergence a positional walk could (missing records on
// either side, a record whose linkage was corrupted, tampering) — see the
// artifactId fallback below for why it is, if anything, a *more* precise
// diagnostic than the positional walk it replaces, not merely order-tolerant.
//
// artifactId (a stable, always-present, per-entry unique identifier —
// audit-log.js indexes the whole chain by it) is used as a secondary
// correlation key only when a file entry's hash has no match in PG: if the
// SAME artifactId exists in PG under a *different* hash, that is a real
// content divergence (the record's hash/content itself was tampered with or
// corrupted) and is reported as HASH_MISMATCH/GENESIS_MISMATCH, exactly as
// the old positional walk would have — preserving that diagnostic distinction
// rather than collapsing every hash-not-found case into a generic "missing".
// Only when neither the hash nor the artifactId can be found in PG is a
// record genuinely reported as MISSING_IN_PG. The symmetric case — a PG row
// whose hash was never matched by any file entry — is MISSING_IN_FILE,
// checked once after the forward walk (a hash-only pass is sufficient there,
// since anything that legitimately belongs to the file's own chain was
// already matched above).
// ── checkpoint fast path ─────────────────────────────────────────
//
// every single-node boot loaded the ENTIRE PG mirror and re-derived
// it (loadChainFromPg). Now, when a checkpoint exists (audit_chain_checkpoints,
// migration 059 — written by this check after a previous successful run), the
// boot verifies:
//   1. the file entry at position chain_length-1 has the checkpoint hash;
//   2. the PG row at the checkpoint seq has the checkpoint hash;
//   3. PG's total row count (server-side) equals the file's entry count, so a
//      row removed from the prefix is still caught;
//   4. both suffixes after the checkpoint walk validly FROM the checkpoint hash
//      and cross-validate record by record (hash, prevHash, canonical).
// Any doubt returns a reason and the caller runs the unchanged full check,
// which stays fatal on divergence. Checkpoints are unsigned until the
// scheduled live verifier (ChainVerifier) still re-walks the whole chain.
const _CHECKPOINT_DEPS = ['getLatestAuditCheckpoint', 'countChainRows', 'fetchRowBySeq', 'fetchChainBatch'];

async function _checkpointFastPath({ _auditLog, _pgAuditBackend, fileCount, start = null }) {
  if (_CHECKPOINT_DEPS.some((k) => typeof _pgAuditBackend[k] !== 'function')
      || typeof _auditLog.getModernEntryAt !== 'function' || typeof _auditLog.getModernChainSlice !== 'function') {
    return null; // a test double / older backend without the checkpoint surface
  }
  const cp = await _pgAuditBackend.getLatestAuditCheckpoint();
  if (!cp) return { ok: false, reason: 'NO_CHECKPOINT' };
  if (cp.chainLength > fileCount) return { ok: false, reason: 'CHECKPOINT_BEYOND_FILE' };
  // locate the checkpoint entry by raw newline count (no JSON parse of the prefix); accepted only when the entry
  // found there IS the checkpoint entry. Otherwise the parse-based locate below gives today's verdict, unchanged.
  let loc = null;
  try { loc = await _locateConfirmed(_auditLog, cp.chainLength - 1, cp.hash); } catch { loc = null; }
  if (!loc) {
    const fileAt = await _auditLog.getModernEntryAt(cp.chainLength - 1);
    if (!fileAt || fileAt.hash !== cp.hash) return { ok: false, reason: 'FILE_CHECKPOINT_HASH_MISMATCH' };
  }
  const pgAt = await _pgAuditBackend.fetchRowBySeq(cp.seq);
  if (!pgAt || String(pgAt).trim() !== cp.hash) return { ok: false, reason: 'PG_CHECKPOINT_HASH_MISMATCH' };
  const pgTotal = await _pgAuditBackend.countChainRows();
  // M3: a pruned mirror (fewer rows than the lifetime count, the file rebased) is checked by the full path, which
  // compares both sides from the signed base record.
  if (pgTotal !== fileCount && start && start.startCount > 0) return { ok: false, reason: 'REBASED_MIRROR_FULL_CHECK' };
  if (pgTotal !== fileCount) return { ok: false, reason: 'COUNT_MISMATCH' };
  // the suffix (everything since the last successful boot) is streamed, not materialised. The
  // previous code held BOTH whole suffixes in memory — after a long uptime or a 1-h soak (430k entries) that exhausted
  // the heap at boot. Same checks: each suffix walked from the checkpoint hash by a persistent walker (identical
  // per-entry checks and cross-entry state as verifyAuditChainDetailed — createChainWalker shares its step), the two
  // suffixes compared record by record, lengths matched against PG's server-side total. Positional comparison equals
  // the previous hash-indexed crossValidateRecords here: both sides are valid chains from the same hash, and a hash
  // commits to its prevHash, so equal hashes can only occur at equal positions.
  if (typeof _auditLog.createChainWalker !== 'function' || typeof _auditLog.getModernChainPage !== 'function') {
    return _checkpointSuffixMaterialised({ _auditLog, _pgAuditBackend, cp, pgTotal });
  }
  const PAGE = 5000;
  const pgWalker = _auditLog.createChainWalker(cp.hash);
  const fileWalker = _auditLog.createChainWalker(cp.hash);
  let pgFrom = cp.seq; let pgBuf = []; let pgDone = false;
  let fileCursor = loc ? loc.next : { m: cp.chainLength }; let fileBuf = []; let fileDone = loc ? !loc.next : false;
  let checked = 0; let tailSeq = cp.seq;
  for (;;) {
    if (pgBuf.length === 0 && !pgDone) {
      pgBuf = await _pgAuditBackend.fetchChainBatch(pgFrom, PAGE);
      if (pgBuf.length < PAGE) pgDone = true;
      if (pgBuf.length) pgFrom = pgBuf[pgBuf.length - 1].seq;
    }
    if (fileBuf.length === 0 && !fileDone) {
      const page = await _auditLog.getModernChainPage({ cursor: fileCursor, limit: PAGE });
      fileBuf = page.entries;
      fileCursor = page.nextCursor;
      if (!fileCursor) fileDone = true;
    }
    if (pgBuf.length === 0 && fileBuf.length === 0) break;
    if (pgBuf.length === 0 || fileBuf.length === 0) return { ok: false, reason: 'SUFFIX_LENGTH_MISMATCH' };
    const n = Math.min(pgBuf.length, fileBuf.length);
    for (let i = 0; i < n; i++) {
      const p = pgBuf[i]; const f = fileBuf[i];
      if (pgWalker.push(p)) return { ok: false, reason: 'PG_SUFFIX_INVALID' };
      if (fileWalker.push(f)) return { ok: false, reason: 'FILE_SUFFIX_INVALID' };
      if (f.hash !== p.hash || f.prevHash !== p.prevHash || f.canonical !== p.canonical) return { ok: false, reason: 'SUFFIX_DIVERGENCE' };
    }
    tailSeq = Number(pgBuf[n - 1].seq);
    checked += n;
    pgBuf = pgBuf.slice(n); fileBuf = fileBuf.slice(n);
    await _yield();
  }
  if (cp.chainLength + checked !== pgTotal) return { ok: false, reason: 'SUFFIX_LENGTH_MISMATCH' };
  if (!pgWalker.result().valid) return { ok: false, reason: 'PG_SUFFIX_INVALID' };
  if (!fileWalker.result().valid) return { ok: false, reason: 'FILE_SUFFIX_INVALID' };
  return { ok: true, checkpointLength: cp.chainLength, suffixChecked: checked, tailSeq, locate: loc ? 'newline' : 'parse' };
}

// the entry at modern position `pos` located by raw newline count and CONFIRMED by its hash; returns
// { entry, next } (next = the cursor of pos+1 with its byte offset, null when pos is the last entry), or null when the
// shortcut does not apply or does not reproduce the expected entry (the caller then uses the parse-based locate).
async function _locateConfirmed(_auditLog, pos, hash) {
  if (typeof _auditLog.locateModernCursor !== 'function' || typeof _auditLog.getModernChainPage !== 'function') return null;
  const c = await _auditLog.locateModernCursor(pos);
  if (!c || !Number.isInteger(c.o)) return null;
  const page = await _auditLog.getModernChainPage({ cursor: c, limit: 1, durable: true });
  const e = page && page.entries ? page.entries[0] : null;
  if (!e || e.hash !== hash || page.startPos !== pos) return null;
  return { entry: e, next: page.nextCursor || null };
}

// The earlier materialising suffix check, kept verbatim for audit-log test doubles without the streaming surface.
async function _checkpointSuffixMaterialised({ _auditLog, _pgAuditBackend, cp, pgTotal }) {
  const pgSuffix = [];
  for (let from = cp.seq; ;) {
    const batch = await _pgAuditBackend.fetchChainBatch(from, 5000);
    pgSuffix.push(...batch);
    if (batch.length < 5000) break;
    from = batch[batch.length - 1].seq;
  }
  const fileSuffix = await _auditLog.getModernChainSlice(cp.chainLength);
  if (pgSuffix.length !== fileSuffix.length || cp.chainLength + pgSuffix.length !== pgTotal) {
    return { ok: false, reason: 'SUFFIX_LENGTH_MISMATCH' };
  }
  if (!_auditLog.verifyAuditChainDetailed(pgSuffix, cp.hash).valid) return { ok: false, reason: 'PG_SUFFIX_INVALID' };
  if (!_auditLog.verifyAuditChainDetailed(fileSuffix, cp.hash).valid) return { ok: false, reason: 'FILE_SUFFIX_INVALID' };
  if (crossValidateRecords(fileSuffix, pgSuffix).firstMismatch) return { ok: false, reason: 'SUFFIX_DIVERGENCE' };
  return {
    ok: true,
    checkpointLength: cp.chainLength,
    suffixChecked: pgSuffix.length,
    tailSeq: pgSuffix.length ? Number(pgSuffix[pgSuffix.length - 1].seq) : cp.seq,
  };
}

// Record the verified tail as the next boot's starting point. Never affects the
// boot: a failure is a WARN (the next boot simply runs the full check).
async function _recordCheckpoint({ _pgAuditBackend, _emit, fileCount, fileTail, tailSeq }) {
  if (typeof _pgAuditBackend.insertAuditCheckpoint !== 'function' || !(fileCount > 0)) return;
  try {
    let seq = tailSeq;
    if (seq === undefined || seq === null) {
      const tail = typeof _pgAuditBackend.getChainTail === 'function' ? await _pgAuditBackend.getChainTail() : null;
      if (!tail || tail.hash !== fileTail) return;
      seq = tail.seq;
    }
    await _pgAuditBackend.insertAuditCheckpoint({ chainLength: fileCount, hash: fileTail, seq, createdBy: 'startup-mirror-check' });
  } catch (err) {
    _emit('WARN', 'AUDIT_MIRROR_CHECKPOINT_WRITE_FAILED', { error: err.message });
  }
}

// ──: runtime advancement of the mirror checkpoint ───────────────────────────────
//
// Design, invariants I-1..I-10 and threat model:
// DESIGN-AND-THREAT-MODEL.md. Before this, only the boot wrote a checkpoint, so every boot re-verified everything since
// the previous boot (431,958 entries / 82 s after a 1-h soak). The verifier worker now runs THE BOOT FAST PATH'S CHECKS
// over [latest checkpoint, newest signed checkpoint with a confirmed pgSeq] and records that position — and nothing
// else: no check is skipped, a doubtful latest checkpoint is never superseded (I-3), any disagreement writes nothing and
// is reported loudly (I-4), benign "not yet" states write nothing (I-5). It never repairs or rewrites either store.
const MAX_ADVANCE_ENTRIES = (() => { const v = parseInt(process.env.QODIQA_AUDIT_MIRROR_CHECKPOINT_ADVANCE_MAX, 10); return Number.isInteger(v) && v >= 1000 ? v : 250_000; })();
const ADVANCE_PAGE = 5000;
const ADVANCE_LOCK_KEY = 'qodiqa_audit_mirror_checkpoint_advance';
const _ADVANCE_DEPS = ['getLatestAuditCheckpoint', 'fetchRowBySeq', 'fetchChainBatch', 'insertAuditCheckpoint',
  'findSignedCheckpointForAdvance', 'countChainRowsThroughSeq'];
// Per-process state (the verifier worker): I-3's sticky stop, and the verified file cursor after the last checkpoint this
// process wrote (an O(1) start for the next run; re-confirmed before every use, discarded on any doubt).
const _advanceState = { stopped: null, hint: null };

async function advanceMirrorCheckpoint({
  _env            = process.env,
  _pgPool         = require('../../infra/postgres/pool'),
  _pgAuditBackend = require('../../infra/postgres/pg-audit-backend'),
  _auditLog       = require('./audit-log'),
  _emit           = emit,
  _checkpointVerify = null,
  _now            = () => Date.now(),
  maxEntries      = MAX_ADVANCE_ENTRIES,
  trigger         = 'SCHEDULED',
} = {}) {
  const skip = (reason, extra = {}) => ({ success: true, skipped: true, reason, trigger, ...extra });
  if (_env.QODIQA_AUDIT_MIRROR_CHECKPOINT_ADVANCE === 'false') return skip('DISABLED');                           // I-9
  if (_env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' || _auditLog.ORDERING_MODE === 'distributed') return skip('DISTRIBUTED_MODE'); // I-8
  if (!_pgPool.isEnabled()) return skip('PG_DISABLED');
  if (_ADVANCE_DEPS.some((k) => typeof _pgAuditBackend[k] !== 'function') || typeof _pgPool.withTransaction !== 'function'
      || typeof _auditLog.createChainWalker !== 'function' || typeof _auditLog.getModernChainPage !== 'function') return skip('UNSUPPORTED');
  if (_advanceState.stopped) {
    _emit('ERROR', 'AUDIT_MIRROR_CHECKPOINT_INCONSISTENT', { trigger, ..._advanceState.stopped, stillStopped: true,
      action: 'Advancement stays stopped for the life of this process. The next boot falls back to the full mirror check for this checkpoint.' });
    return skip('STOPPED_INCONSISTENT', { detail: _advanceState.stopped });
  }
  const startedAt = _now();
  const out = await _pgPool.withTransaction(async (tx) => {
    const r = await tx.query('SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired', [ADVANCE_LOCK_KEY]);   // I-7
    if (!r.rows[0].acquired) return skip('LOCK_NOT_ACQUIRED');
    return _advanceUnderLock({ _pgAuditBackend, _auditLog, _emit, _checkpointVerify, maxEntries, trigger, skip });
  }, { isolationLevel: 'READ COMMITTED' });
  if (out && !out.skipped) out.durationMs = _now() - startedAt;
  if (out && out.advanced) {
    _emit('INFO', 'AUDIT_MIRROR_CHECKPOINT_ADVANCED', { trigger, from: out.from, to: out.to, entries: out.entries, toSeq: out.toSeq,
      durationMs: out.durationMs, startLocate: out.startLocate, signatureChecked: out.signatureChecked });
  }
  return out;
}

async function _advanceUnderLock({ _pgAuditBackend, _auditLog, _emit, _checkpointVerify, maxEntries, trigger, skip }) {
  const inconsistent = (reason, detail = {}) => {                                                                   // I-3
    _advanceState.stopped = { reason, ...detail, at: new Date().toISOString() };
    _advanceState.hint = null;
    _emit('ERROR', 'AUDIT_MIRROR_CHECKPOINT_INCONSISTENT', { trigger, reason, ...detail,
      action: 'The latest mirror checkpoint does not re-validate against the audit file and the PostgreSQL mirror. Nothing ' +
              'was written and advancement is stopped for the life of this process, so the doubtful checkpoint stays the ' +
              'latest and the next boot falls back to the full fail-closed mirror check. Investigate before restarting.' });
    return { success: true, advanced: false, inconsistent: true, reason, trigger, ...detail };
  };
  const refused = (reason, detail = {}) => {                                                                        // I-4
    _advanceState.hint = null;
    _emit('ERROR', 'AUDIT_MIRROR_CHECKPOINT_ADVANCE_REFUSED', { trigger, reason, ...detail,
      action: 'The range after the latest mirror checkpoint did not verify; no checkpoint was written, so the range stays ' +
              'in the next boot\'s fail-closed mirror check. Investigate the audit file and the audit_chain table.' });
    return { success: true, advanced: false, refused: true, reason, trigger, ...detail };
  };

  const stats = _auditLog.getChainStats();
  const fileCount = stats.modernLength;
  const start = typeof _auditLog.getChainStart === 'function' ? _auditLog.getChainStart() : { startCount: 0 };
  if (start && start.startCount > 0) return skip('REBASED_CHAIN');   // after a prune the boot's full check re-establishes the base

  let cp = await _pgAuditBackend.getLatestAuditCheckpoint();
  let fileCursor; let startLocate;
  if (!cp) {
    cp = { chainLength: 0, hash: 'GENESIS', seq: 0 };   // missing: verify from GENESIS (un-pruned chain only)
    fileCursor = { m: 0, o: 0 };
    startLocate = 'genesis';
  } else {
    if (cp.chainLength > fileCount) return inconsistent('CHECKPOINT_BEYOND_FILE', { checkpointLength: cp.chainLength, fileCount });
    const pgAt = await _pgAuditBackend.fetchRowBySeq(cp.seq);
    if (!pgAt || String(pgAt).trim() !== cp.hash) return inconsistent('PG_CHECKPOINT_HASH_MISMATCH', { checkpointLength: cp.chainLength, seq: cp.seq });
    const h = _advanceState.hint;
    if (h && h.pos === cp.chainLength && h.hash === cp.hash && h.cursor) {
      // The cursor this process verified last time: confirm the entry there still links from the checkpoint hash.
      const page = await _auditLog.getModernChainPage({ cursor: h.cursor, limit: 1, durable: true });
      const e = page && page.entries ? page.entries[0] : null;
      if (e && e.prevHash === cp.hash && page.startPos === cp.chainLength) { fileCursor = h.cursor; startLocate = 'hint'; }
      else _advanceState.hint = null;
    }
    if (!fileCursor) {
      let loc = null;
      try { loc = await _locateConfirmed(_auditLog, cp.chainLength - 1, cp.hash); } catch { loc = null; }
      if (loc) { fileCursor = loc.next; startLocate = 'newline'; }
      else {
        const fileAt = typeof _auditLog.getModernEntryAt === 'function' ? await _auditLog.getModernEntryAt(cp.chainLength - 1) : null;
        if (!fileAt || fileAt.hash !== cp.hash) return inconsistent('FILE_CHECKPOINT_HASH_MISMATCH', { checkpointLength: cp.chainLength });
        fileCursor = { m: cp.chainLength };
        startLocate = 'parse';
      }
      if (!fileCursor) return skip('NOTHING_TO_VERIFY', { checkpointLength: cp.chainLength });   // checkpoint is the tail
    }
  }

  // Target: the newest signed checkpoint with a confirmed pgSeq inside the bounded window (I-5 when none).
  const upper = Math.min(fileCount, cp.chainLength + maxEntries);
  if (upper <= cp.chainLength) return skip('NOTHING_TO_VERIFY', { checkpointLength: cp.chainLength });
  const s = await _pgAuditBackend.findSignedCheckpointForAdvance(cp.chainLength, upper);
  const p = s && s.payload;
  if (!p || !Number.isInteger(p.chainLength) || !Number.isInteger(p.pgSeq) || typeof p.headHash !== 'string') {
    return skip('NO_TARGET', { checkpointLength: cp.chainLength, fileCount });
  }
  if (p.chainLength <= cp.chainLength || p.chainLength > fileCount) return skip('NO_TARGET', { checkpointLength: cp.chainLength, fileCount });
  if (p.pgSeq <= cp.seq) return refused('TARGET_SEQ_NOT_AFTER_START', { from: cp.chainLength, to: p.chainLength, fromSeq: cp.seq, toSeq: p.pgSeq });
  let signatureChecked = 'not-checked';
  if (typeof _checkpointVerify === 'function') {
    const v = _checkpointVerify(s);
    if (v && v.ok) signatureChecked = 'valid';
    else if (/^CHECKPOINT_(KEY_UNAVAILABLE|VERIFY_ERROR)/.test(String(v && v.reason))) signatureChecked = 'unverifiable';
    else return refused('TARGET_SIGNATURE_INVALID', { to: p.chainLength, checkpointId: p.checkpointId, signatureReason: v && v.reason });
  }
  const pgTarget = await _pgAuditBackend.fetchRowBySeq(p.pgSeq);
  if (!pgTarget || String(pgTarget).trim() !== p.headHash) return refused('TARGET_PG_HASH_MISMATCH', { to: p.chainLength, toSeq: p.pgSeq });

  // The boot fast path's checks, over exactly [cp, target]: both stores walked from cp.hash by the boot's walker, PG rows
  // in seq order (as the boot reads them), compared record by record (hash, prevHash, full canonical).
  const want = p.chainLength - cp.chainLength;
  const pgWalker = _auditLog.createChainWalker(cp.hash);
  const fileWalker = _auditLog.createChainWalker(cp.hash);
  let pgFrom = cp.seq; let pgBuf = []; let pgDone = false;
  let fileBuf = []; let fileRead = 0;
  let checked = 0; let lastFile = null; let lastPg = null; let nextFileCursor = fileCursor;
  while (checked < want) {
    if (pgBuf.length === 0 && !pgDone) {
      const rows = await _pgAuditBackend.fetchChainBatch(pgFrom, ADVANCE_PAGE);
      if (rows.length < ADVANCE_PAGE) pgDone = true;
      if (rows.length) pgFrom = Number(rows[rows.length - 1].seq);
      pgBuf = rows.filter((row) => Number(row.seq) <= p.pgSeq);
      if (pgBuf.length < rows.length) pgDone = true;
    }
    if (fileBuf.length === 0 && fileRead < want && nextFileCursor) {
      const page = await _auditLog.getModernChainPage({ cursor: nextFileCursor, limit: Math.min(ADVANCE_PAGE, want - fileRead), durable: true });
      fileBuf = page.entries;
      fileRead += fileBuf.length;
      nextFileCursor = page.nextCursor || null;
    }
    if (pgBuf.length === 0 || fileBuf.length === 0) {
      return refused(pgBuf.length === 0 ? 'PG_RANGE_SHORT' : 'FILE_RANGE_SHORT', { from: cp.chainLength, to: p.chainLength, at: cp.chainLength + checked });
    }
    const n = Math.min(pgBuf.length, fileBuf.length, want - checked);
    for (let i = 0; i < n; i++) {
      const pr = pgBuf[i]; const f = fileBuf[i];
      const at = cp.chainLength + checked + i;
      if (pgWalker.push(pr)) return refused('PG_RANGE_INVALID', { from: cp.chainLength, to: p.chainLength, at, detail: pgWalker.result().reason });
      if (fileWalker.push(f)) return refused('FILE_RANGE_INVALID', { from: cp.chainLength, to: p.chainLength, at, detail: fileWalker.result().reason });
      if (f.hash !== pr.hash || f.prevHash !== pr.prevHash || f.canonical !== pr.canonical) {
        return refused('RANGE_DIVERGENCE', { from: cp.chainLength, to: p.chainLength, at, fileHash: f.hash, pgHash: pr.hash });
      }
      lastFile = f; lastPg = pr;
    }
    checked += n;
    pgBuf = pgBuf.slice(n); fileBuf = fileBuf.slice(n);
    await _yield();
  }
  if (pgBuf.length > 0) return refused('PG_RANGE_LONG', { from: cp.chainLength, to: p.chainLength, extraRows: pgBuf.length });
  if (!pgWalker.result().valid) return refused('PG_RANGE_INVALID', { from: cp.chainLength, to: p.chainLength, detail: pgWalker.result().reason });
  if (!fileWalker.result().valid) return refused('FILE_RANGE_INVALID', { from: cp.chainLength, to: p.chainLength, detail: fileWalker.result().reason });
  if (lastFile.hash !== p.headHash) return refused('TARGET_FILE_HASH_MISMATCH', { to: p.chainLength });
  if (Number(lastPg.seq) !== p.pgSeq || lastPg.hash !== p.headHash) return refused('TARGET_PG_POSITION_MISMATCH', { to: p.chainLength, toSeq: p.pgSeq, lastSeq: Number(lastPg.seq) });
  // The range form of the boot's count check: exactly `target` PG rows at or below the target seq (a row removed from,
  // or inserted into, the prefix is caught here, as the boot catches it with the total count).
  const through = await _pgAuditBackend.countChainRowsThroughSeq(p.pgSeq);
  if (through !== p.chainLength) return refused('PG_COUNT_MISMATCH', { to: p.chainLength, toSeq: p.pgSeq, pgRowsThroughSeq: through });

  await _pgAuditBackend.insertAuditCheckpoint({ chainLength: p.chainLength, hash: p.headHash, seq: p.pgSeq, createdBy: 'runtime-mirror-advance' }); // I-1, I-10
  _advanceState.hint = { pos: p.chainLength, hash: p.headHash, cursor: nextFileCursor && Number.isInteger(nextFileCursor.o) ? nextFileCursor : null };
  const backlog = fileCount - p.chainLength;
  if (backlog > maxEntries) _emit('WARN', 'AUDIT_MIRROR_CHECKPOINT_BACKLOG', { trigger, checkpointLength: p.chainLength, fileCount, backlog, maxEntriesPerRun: maxEntries });
  return { success: true, advanced: true, trigger, from: cp.chainLength, to: p.chainLength, toSeq: p.pgSeq, entries: checked, startLocate, signatureChecked, backlog };
}

function _resetAdvanceStateForTests() { _advanceState.stopped = null; _advanceState.hint = null; }

function crossValidateRecords(fileEntries, pgEntries) {
  const fileLength = fileEntries.length;
  const pgLength    = pgEntries.length;

  const pgByHash       = new Map();
  const pgByArtifactId = new Map();
  for (const p of pgEntries) {
    if (p && typeof p.hash === 'string' && !pgByHash.has(p.hash)) pgByHash.set(p.hash, p);
    if (p && typeof p.artifactId === 'string' && !pgByArtifactId.has(p.artifactId)) pgByArtifactId.set(p.artifactId, p);
  }

  let firstMismatch     = null;
  let lastCommonRecord   = null;
  let recordsChecked     = 0;
  const matchedPgHashes  = new Set();

  for (let i = 0; i < fileLength; i++) {
    recordsChecked++;
    const f = fileEntries[i];

    let p = pgByHash.get(f.hash);
    let reason = null;

    if (!p) {
      const byArtifactId = typeof f.artifactId === 'string' ? pgByArtifactId.get(f.artifactId) : undefined;
      if (byArtifactId) {
        p = byArtifactId;
        reason = i === 0 ? MISMATCH_REASON.GENESIS_MISMATCH : MISMATCH_REASON.HASH_MISMATCH;
      } else {
        reason = MISMATCH_REASON.MISSING_IN_PG;
      }
    } else if (f.prevHash !== p.prevHash) {
      reason = i === 0 ? MISMATCH_REASON.GENESIS_MISMATCH : MISMATCH_REASON.PREV_HASH_MISMATCH;
    } else if (f.canonical !== p.canonical) {
      reason = MISMATCH_REASON.METADATA_MISMATCH;
    }

    if (reason) {
      firstMismatch = {
        sequence:         i,
        fileHash:         f.hash,
        pgHash:           p ? p.hash : null,
        expectedPrevHash: f.prevHash,
        actualPrevHash:   p ? p.prevHash : null,
        reason,
      };
      break;
    }

    matchedPgHashes.add(p.hash);
    lastCommonRecord = { sequence: i, hash: f.hash };
  }

  if (!firstMismatch) {
    for (const p of pgEntries) {
      if (typeof p.hash === 'string' && !matchedPgHashes.has(p.hash)) {
        firstMismatch = {
          sequence:         fileLength,
          fileHash:         null,
          pgHash:           p.hash,
          expectedPrevHash: null,
          actualPrevHash:   p.prevHash,
          reason:           MISMATCH_REASON.MISSING_IN_FILE,
        };
        break;
      }
    }
  }

  return {
    recordsChecked,
    fileChainLength: fileLength,
    pgChainLength:    pgLength,
    firstMismatch,
    lastCommonRecord,
    divergencePoint:  firstMismatch ? firstMismatch.sequence : null,
  };
}

// crossValidateRecords() line for line, yielding to the event loop every YIELD_EVERY
// iterations of each of its three loops — so a full-chain comparison on the live server never blocks the loop
// for O(n). Same inputs → the same result object (pinned by mirrorConsistencyCheck.test.js against the sync
// version). The sync version stays for the startup check, which runs before the server accepts traffic.
const YIELD_EVERY = 2048;
const _yield = () => require('./verifierPacer').pace(); // setImmediate, or duty-cycled inside the verifier worker

async function crossValidateRecordsAsync(fileEntries, pgEntries) {
  const fileLength = fileEntries.length;
  const pgLength    = pgEntries.length;

  const pgByHash       = new Map();
  const pgByArtifactId = new Map();
  let k = 0;
  for (const p of pgEntries) {
    if (p && typeof p.hash === 'string' && !pgByHash.has(p.hash)) pgByHash.set(p.hash, p);
    if (p && typeof p.artifactId === 'string' && !pgByArtifactId.has(p.artifactId)) pgByArtifactId.set(p.artifactId, p);
    if (++k % YIELD_EVERY === 0) await _yield();
  }

  let firstMismatch     = null;
  let lastCommonRecord   = null;
  let recordsChecked     = 0;
  const matchedPgHashes  = new Set();

  for (let i = 0; i < fileLength; i++) {
    if (i > 0 && i % YIELD_EVERY === 0) await _yield();
    recordsChecked++;
    const f = fileEntries[i];

    let p = pgByHash.get(f.hash);
    let reason = null;

    if (!p) {
      const byArtifactId = typeof f.artifactId === 'string' ? pgByArtifactId.get(f.artifactId) : undefined;
      if (byArtifactId) {
        p = byArtifactId;
        reason = i === 0 ? MISMATCH_REASON.GENESIS_MISMATCH : MISMATCH_REASON.HASH_MISMATCH;
      } else {
        reason = MISMATCH_REASON.MISSING_IN_PG;
      }
    } else if (f.prevHash !== p.prevHash) {
      reason = i === 0 ? MISMATCH_REASON.GENESIS_MISMATCH : MISMATCH_REASON.PREV_HASH_MISMATCH;
    } else if (f.canonical !== p.canonical) {
      reason = MISMATCH_REASON.METADATA_MISMATCH;
    }

    if (reason) {
      firstMismatch = {
        sequence:         i,
        fileHash:         f.hash,
        pgHash:           p ? p.hash : null,
        expectedPrevHash: f.prevHash,
        actualPrevHash:   p ? p.prevHash : null,
        reason,
      };
      break;
    }

    matchedPgHashes.add(p.hash);
    lastCommonRecord = { sequence: i, hash: f.hash };
  }

  if (!firstMismatch) {
    let j = 0;
    for (const p of pgEntries) {
      if (++j % YIELD_EVERY === 0) await _yield();
      if (typeof p.hash === 'string' && !matchedPgHashes.has(p.hash)) {
        firstMismatch = {
          sequence:         fileLength,
          fileHash:         null,
          pgHash:           p.hash,
          expectedPrevHash: null,
          actualPrevHash:   p.prevHash,
          reason:           MISMATCH_REASON.MISSING_IN_FILE,
        };
        break;
      }
    }
  }

  return {
    recordsChecked,
    fileChainLength: fileLength,
    pgChainLength:    pgLength,
    firstMismatch,
    lastCommonRecord,
    divergencePoint:  firstMismatch ? firstMismatch.sequence : null,
  };
}

/**
 * Verifies the append-only file chain and the PostgreSQL audit mirror
 * represent the same logical chain. Must be called once at startup, after
 * pgPool.initialize().
 *
 * All dependencies are injectable for testing.
 *
 * @param {object}   [opts]
 * @param {object}   [opts._env]            Environment variables (default: process.env)
 * @param {object}   [opts._pgPool]         PG pool module (default: src/infra/postgres/pool.js)
 * @param {object}   [opts._pgAuditBackend] PG audit backend module (default: pg-audit-backend.js)
 * @param {object}   [opts._auditLog]       audit-log.js module (default: ./audit-log)
 * @param {object}   [opts._metrics]        observability/metrics.js module (default: src/observability/metrics.js)
 * @param {function} [opts._exit]           Exit function (default: process.exit)
 * @param {function} [opts._emit]           Logger emit function (default: services/logger emit)
 * @param {function} [opts._now]            Clock function returning ms since epoch (default: Date.now)
 * @returns {Promise<boolean>} true if startup may proceed (false only after
 *   this function has already called _exit(1) — the caller should treat a
 *   false return as "stop starting", exactly like multiInstanceGuard's
 *   checkDistributedPreconditions()).
 */
async function verifyMirrorConsistency({
  _env            = process.env,
  _pgPool         = require('../../infra/postgres/pool'),
  _pgAuditBackend = require('../../infra/postgres/pg-audit-backend'),
  _auditLog       = require('./audit-log'),
  _metrics        = require('../../observability/metrics'),
  _exit           = (code) => process.exit(code),
  _emit           = emit,
  _now            = () => Date.now(),
} = {}) {
  const orderingMode = _env.QODIQA_AUDIT_ORDERING_MODE === 'distributed' ? 'distributed' : 'single-node';

  if (orderingMode === 'distributed') return true;

  if (!_pgPool.isEnabled()) {
    _emit('INFO', 'AUDIT_MIRROR_CHECK_SKIPPED', {
      reason: 'QODIQA_PG_ENABLED is not "true" — no PostgreSQL mirror to verify the audit chain against.',
    });
    return true;
  }

  const recoveryMode = _env.QODIQA_AUDIT_MIRROR_RECOVERY_MODE === 'true';
  const startedAt = _now();

  const fileStats = _auditLog.getChainStats();
  const fileCount = fileStats.modernLength;
  // M3: after a prune the file starts at the signed base record (audit-log.js getChainStart()); both sides are then
  // compared from its head, and counts are base + suffix.
  const start = typeof _auditLog.getChainStart === 'function' ? _auditLog.getChainStart() : { state: 'none', startHash: 'GENESIS', startCount: 0 };
  const rebased = start.startCount > 0;   // the file starts after a signed base record's head (rebased, or an interrupted second prune)
  let fileHead  = _normalizedHash(fileStats.headHash, fileCount);
  const fileTail  = _normalizedHash(fileStats.tailHash, fileCount);

  // verify from the latest checkpoint when one exists (see
  // _checkpointFastPath). Recovery mode always runs the full diagnostic check.
  if (!recoveryMode) {
    let fast = null;
    try {
      fast = await _checkpointFastPath({ _auditLog, _pgAuditBackend, fileCount, start });
    } catch (err) {
      fast = { ok: false, reason: `FAST_PATH_ERROR: ${err.message}` };
    }
    if (fast && fast.ok) {
      _metrics.auditCrosscheckSuccessTotal.inc({});
      _metrics.auditCrosscheckRecordsChecked.set({}, fast.suffixChecked);
      _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
      _metrics.auditCrosscheckLastVerifiedTimestamp.set({}, Math.floor(_now() / 1000));
      _emit('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', {
        entryCount: fileCount, tailHash: fileTail,
        mode: 'checkpoint', checkpointLength: fast.checkpointLength, suffixChecked: fast.suffixChecked,
        ...(fast.locate ? { locate: fast.locate } : {}),
      });
      await _recordCheckpoint({ _pgAuditBackend, _emit, fileCount, fileTail, tailSeq: fast.tailSeq });
      return true;
    }
    if (fast) _emit('INFO', 'AUDIT_MIRROR_CHECKPOINT_FALLBACK', { reason: fast.reason, action: 'running the full mirror consistency check' });
  }

  let pgRows;
  try {
    pgRows = await _pgAuditBackend.loadChainFromPg();
  } catch (err) {
    _writeDiagnostic('FATAL', 'AUDIT_MIRROR_PG_UNREACHABLE', {
      reason: 'Could not load the PostgreSQL audit mirror to perform the startup consistency check.',
      error:  err.message,
      action: 'Verify QODIQA_PG_* connectivity, then restart. The service will not accept requests until ' +
              'the file chain and PostgreSQL mirror are confirmed consistent.',
      ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _metrics.auditCrosscheckFailureTotal.inc({ reason: 'PG_UNREACHABLE' });
    _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
    _exit(1);
    return false;
  }

  // Re-derive the PG side's own hash chain — a corrupted or hand-edited PG
  // row (broken prevHash link, tampered canonical/hash) must never be trusted
  // as a reference just because it came from the "other" store.
  //
  // reordered into true logical order first (_reorderByHashChain) —
  // loadChainFromPg()'s own `ORDER BY seq ASC` is insertion order, not
  // necessarily logical order (see that function's own helper comment).
  const pgChain  = _reorderByHashChain(pgRows, rebased ? start.startHash : 'GENESIS');
  const pgDetail = rebased ? _auditLog.verifyAuditChainDetailed(pgChain, start.startHash) : _auditLog.verifyAuditChainDetailed(pgChain);
  if (!pgDetail.valid) {
    _writeDiagnostic('FATAL', 'AUDIT_MIRROR_PG_CHAIN_INVALID', {
      reason:           'The PostgreSQL audit mirror failed its own hash-chain verification.',
      validationReason: pgDetail.reason,
      entriesVerified:  pgDetail.entriesVerified,
      action: 'Investigate the audit_chain table for tampering or corruption before restarting. This is a ' +
              'fatal integrity violation — no automatic repair will be attempted.',
      ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
    });
    _metrics.auditCrosscheckFailureTotal.inc({ reason: 'PG_CHAIN_INVALID' });
    _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
    _exit(1);
    return false;
  }

  // Symmetric with the PG side above: re-derive the file chain's own hash
  // chain rather than trusting only the cached summary counters. Requires
  // raw entries (getModernChain()); older/minimal audit-log module stand-ins
  // (or hand-rolled test doubles) that don't expose it fall back to the
  // count/head/tail-only comparison further below, preserving backward
  // compatibility.
  const fileEntries = typeof _auditLog.getModernChain === 'function' ? await _auditLog.getModernChain() : null;

  if (fileEntries !== null) {
    const fileDetail = rebased ? _auditLog.verifyAuditChainDetailed(fileEntries, start.startHash) : _auditLog.verifyAuditChainDetailed(fileEntries);
    if (!fileDetail.valid) {
      _writeDiagnostic('FATAL', 'AUDIT_MIRROR_FILE_CHAIN_INVALID', {
        reason:           'The file-based audit chain failed its own hash-chain verification during the startup cross-check.',
        validationReason: fileDetail.reason,
        entriesVerified:  fileDetail.entriesVerified,
        action: 'Investigate data/audit-log.ndjson for tampering or corruption before restarting. This is a ' +
                'fatal integrity violation — no automatic repair will be attempted.',
        ref:    'docs/protocol/AUDIT-SCHEMA-V8.md',
      });
      _metrics.auditCrosscheckFailureTotal.inc({ reason: 'FILE_CHAIN_INVALID' });
      _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
      _exit(1);
      return false;
    }
  }

  const pgCount = (rebased ? start.startCount : 0) + pgDetail.entriesVerified;
  const pgHead  = pgDetail.head;
  if (rebased) fileHead = fileEntries && fileEntries.length ? fileEntries[0].hash : null;   // suffix heads (lifetime head is prefix statistics)
  const pgTail  = pgDetail.tail;

  const mismatches = [];
  if (fileCount !== pgCount) mismatches.push({ field: 'entryCount', file: fileCount, pg: pgCount });
  if (fileHead  !== pgHead)  mismatches.push({ field: 'headHash',   file: fileHead,  pg: pgHead });
  if (fileTail  !== pgTail)  mismatches.push({ field: 'tailHash',   file: fileTail,  pg: pgTail });

  // Duplicate-hash detection — independent of the content-addressed walk below.
  // Always checked on the PG side (pgRows is always available); checked on
  // the file side whenever raw entries could be obtained.
  const pgDuplicates   = _findDuplicateHashes(pgRows);
  const fileDuplicates = fileEntries !== null ? _findDuplicateHashes(fileEntries) : [];

  // Full content-addressed record-by-record diagnostics. Only
  // runs when raw file entries are available; the summary `mismatches` above
  // already covers detection when they are not.
  const crossValidation = fileEntries !== null ? crossValidateRecords(fileEntries, rebased ? pgChain : pgRows) : null;

  const hasDivergence =
    mismatches.length > 0 ||
    pgDuplicates.length > 0 ||
    fileDuplicates.length > 0 ||
    (crossValidation !== null && crossValidation.firstMismatch !== null);

  const recordsChecked = crossValidation !== null ? crossValidation.recordsChecked : Math.max(fileCount, pgCount);

  if (hasDivergence) {
    const diagnostics = {
      reason: 'The append-only audit chain file and the PostgreSQL audit mirror have diverged.',
      mismatches,
      fileEntryCount:  fileCount,
      pgEntryCount:    pgCount,
      fileChainLength: crossValidation ? crossValidation.fileChainLength : fileCount,
      pgChainLength:    crossValidation ? crossValidation.pgChainLength    : pgCount,
      firstMismatchSequence: crossValidation?.firstMismatch?.sequence ?? null,
      fileHash:              crossValidation?.firstMismatch?.fileHash ?? null,
      pgHash:                crossValidation?.firstMismatch?.pgHash ?? null,
      expectedPrevHash:      crossValidation?.firstMismatch?.expectedPrevHash ?? null,
      actualPrevHash:        crossValidation?.firstMismatch?.actualPrevHash ?? null,
      lastCommonRecord:      crossValidation?.lastCommonRecord ?? null,
      divergencePoint:       crossValidation?.divergencePoint ?? null,
      mismatchReason:        crossValidation?.firstMismatch?.reason ?? null,
      duplicateHashesInFile: fileDuplicates,
      duplicateHashesInPg:   pgDuplicates,
      action: 'Do not restart until this is resolved by an operator. Possible causes: a truncated, replaced, ' +
              'or restored-from-backup audit.log; a PostgreSQL mirror that has not caught up (check the ' +
              'Persistence Recovery Queue and PG_AUDIT_PERSIST_FAILED logs); a mirror that was never ' +
              'backfilled after enabling QODIQA_PG_ENABLED (run scripts/migrate-files-to-pg.js); or a ' +
              'duplicate/corrupted row on one side. This check never repairs or reconciles automatically.',
      ref: 'docs/protocol/AUDIT-SCHEMA-V8.md',
    };

    _metrics.auditCrosscheckFailureTotal.inc({ reason: 'DIVERGENCE' });
    _metrics.auditCrosscheckRecordsChecked.set({}, recordsChecked);
    _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);

    if (recoveryMode) {
      _writeDiagnostic('WARN', 'AUDIT_MIRROR_RECOVERY_MODE_ENGAGED', {
        ...diagnostics,
        recoveryMode: true,
        action: 'QODIQA_AUDIT_MIRROR_RECOVERY_MODE=true — startup is proceeding DESPITE the divergence above. ' +
                'No automatic reconciliation, overwrite, or repair has occurred. This is a supervised, ' +
                'degraded state: fix the divergence and unset this flag as soon as possible. ' + diagnostics.action,
      });
      return true;
    }

    _writeDiagnostic('FATAL', 'AUDIT_MIRROR_CONSISTENCY_VIOLATION', diagnostics);
    _exit(1);
    return false;
  }

  _metrics.auditCrosscheckSuccessTotal.inc({});
  _metrics.auditCrosscheckRecordsChecked.set({}, recordsChecked);
  _metrics.auditCrosscheckDurationSeconds.observe({}, (_now() - startedAt) / 1000);
  _metrics.auditCrosscheckLastVerifiedTimestamp.set({}, Math.floor(_now() / 1000));

  _emit('INFO', 'AUDIT_MIRROR_CONSISTENCY_VERIFIED', {
    entryCount: fileCount,
    tailHash:   fileTail,
  });
  await _recordCheckpoint({ _pgAuditBackend, _emit, fileCount, fileTail });
  return true;
}

module.exports = { verifyMirrorConsistency, MISMATCH_REASON, crossValidateRecords, crossValidateRecordsAsync, _reorderByHashChain,
  _checkpointFastPath, _checkpointSuffixMaterialised, _locateConfirmed,
  advanceMirrorCheckpoint, MAX_ADVANCE_ENTRIES, _resetAdvanceStateForTests };   //
