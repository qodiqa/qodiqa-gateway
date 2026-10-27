'use strict';

/**
 * Audit Checksum Anchor Isolation — #2 (finding #109).
 *
 * The checksum anchor (audit.log.sum) has always lived on the same
 * filesystem/directory as audit.log itself — the exact file it exists to
 * tamper-evidence. A fault or attacker capable of corrupting or truncating
 * the log directory can trivially corrupt or roll back the anchor in
 * lockstep, giving it no independent protection value (single-compromise
 * failure).
 *
 * This module keeps the existing file-based anchor completely unchanged —
 * including at startup, where audit-log.js's loadFromDisk() IIFE runs
 * SYNCHRONOUSLY at module require-time, before pgPool.initialize() has run
 * (see that IIFE's own header comment). The synchronous fail-closed startup
 * gate therefore cannot depend on a live PG connection and must keep using
 * the file anchor exactly as before — loadChecksum()/saveChecksum() below
 * are byte-for-byte the same file I/O audit-log.js always did, just
 * extracted into this module and given an optional path override.
 *
 * Isolation is added ADDITIVELY: audit-log.js's _saveChecksumAsync() (called
 * only on the hot append path, well after startup, when pgPool IS available)
 * calls this module's saveChecksumFileAsync() (unchanged file write) and
 * then saveChecksumPg() (fire-and-forget), which dual-writes the identical
 * {count, tailHash} into a NEW, separate-failure-domain
 * PostgreSQL table (audit_checksum_anchor, migration 036) whenever
 * QODIQA_PG_ENABLED=true — best-effort, matching the existing
 * pg-audit-backend.js dual-write philosophy (never blocks or fails the
 * audit append if the PG write fails). audit-log.js's
 * verifyChecksumAnchorIsolation() reads that PG row back independently of
 * the audit-log filesystem entirely (via this module's loadChecksumPg()), so it can
 * still detect divergence even if the log directory itself has been
 * corrupted or is unavailable — the actual isolation guarantee this finding
 * asks for.
 *
 * Two independent isolation mechanisms, both opt-in / additive:
 *   1. QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH — point the FILE anchor at a
 *      different directory/mount than audit.log's own (still filesystem-
 *      based, but no longer necessarily the same filesystem — works without
 *      PostgreSQL). Defaults to the historical co-located `<LOG_PATH>.sum`
 *      path, so omitting this env var is 100% backward compatible.
 *   2. The PG-backed audit_checksum_anchor table (above) — a genuinely
 *      separate failure domain, used whenever QODIQA_PG_ENABLED=true.
 *
 * Neither replaces the other; both are dual-written when available. Existing
 * audit chains with only a legacy co-located `.sum` file continue to work
 * unchanged — nothing here requires or performs a one-time migration; the PG
 * anchor simply starts populating from the first append after this WP lands.
 */

const fs  = require('fs');
const fsp = fs.promises;

/**
 * @param {string} logPath  audit-log.js's LOG_PATH — used to derive the
 *                           default co-located anchor path.
 * @returns {string} the file anchor path (env override or co-located default)
 */
function resolveFileAnchorPath(logPath) {
  return process.env.QODIQA_AUDIT_CHECKSUM_ANCHOR_PATH || (logPath + '.sum');
}

// ── File anchor — unchanged behavior, just extracted from audit-log.js ───────

function loadChecksum(checksumPath) {
  if (!fs.existsSync(checksumPath)) return null;
  return JSON.parse(fs.readFileSync(checksumPath, 'utf8'));
}

// the optional `v2` block (lifetime counters + byteLength) is additive
// — {count, tailHash} keep their exact historical meaning and position, and
// any earlier reader that only knows those two fields still works.
function saveChecksum(checksumPath, count, tailHash, v2 = undefined) {
  const tmp = checksumPath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(v2 ? { count, tailHash, v2 } : { count, tailHash }), 'utf8');
  try { fs.renameSync(tmp, checksumPath); }
  catch { fs.copyFileSync(tmp, checksumPath); try { fs.unlinkSync(tmp); } catch {} }
}

async function saveChecksumFileAsync(checksumPath, count, tailHash, v2 = undefined) {
  const tmp = checksumPath + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(v2 ? { count, tailHash, v2 } : { count, tailHash }), 'utf8');
  try { await fsp.rename(tmp, checksumPath); }
  catch {
    await fsp.copyFile(tmp, checksumPath);
    try { await fsp.unlink(tmp); } catch {}
  }
}

// ── PG anchor — isolated failure domain, additive/best-effort ────────────────

let _lastPgWriteAt = null;
let _lastPgWriteOk = null;

// ordered, coalescing PG anchor writer.
//
// audit-log.js calls saveChecksumPg() fire-and-forget after every durable batch. Each call used to issue its own
// pgPool.query() on whatever pool connection it got, so consecutive upserts (e.g. 26653 then 26654) could COMMIT in
// reverse order; migration 062's forward-only trigger then refused the stale one ("count 26654 -> 26653 refused").
// The anchor stayed correct — the guard did its job — but the refusal went down the failure path below
// (AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED, backend gauge 0): a false durability signal.
//
// Fix, without touching the guard or the upsert:
//   1. Writes are issued strictly in call order, one at a time (_queue / _drain), so reordering between connections
//      cannot happen. A queued write that a LATER, strictly higher write supersedes before it was issued is dropped
//      (counted in _pgWritesCoalesced): the anchor is "the latest tail", the newer write carries it, and the queue
//      stays bounded (one in flight + one queued) however slow PostgreSQL is.
//   2. If the guard still refuses a write as stale, it is classified as EXPECTED only when the anchor the database
//      holds is one THIS process durably wrote (currentCount <= _highestPgCount) and the incoming count is strictly
//      lower: the newer anchor is committed, nothing was lost, so it is an INFO diagnostic and the health state is
//      left as it is. Everything else stays a failure exactly as before — any error that is not the forward-only
//      trigger, a refusal against an anchor this process never wrote (another writer, a rolled-back log), and an
//      equal count with a different tail hash (a fork).
const FORWARD_ONLY_RE = /^audit_checksum_anchor is forward-only: count (\d+) -> (\d+) refused/;
let _queue = [];                // [{ count, tailHash, waiters: [resolve] }], in call order; [0] is the in-flight write
let _draining = false;
let _highestPgCount = null;     // highest count this process has durably committed to the PG anchor
let _pgWritesCoalesced = 0;
let _pgStaleWritesRefused = 0;

// with writes serialized, ONE query that never settles —
// a silent partition: the server stops answering on an established connection, so its statement_timeout cannot fire
// and the pool has no client-side timeout — stopped the writer for good: no failure, gauge stuck at 1, callers
// pending. Each write is therefore bounded by a deadline derived from the pool's OWN timeouts
// (src/infra/postgres/pool.js): QODIQA_PG_STATEMENT_TIMEOUT_MS (default 30,000) + QODIQA_PG_ACQUIRE_TIMEOUT_MS
// (default 1,500) + 2,000 ms grace = 33,500 ms by default. A healthy server cancels any statement at
// statement_timeout and answers with an error, and acquisition is itself bounded, so a write still unanswered after
// both plus the grace is not slow — it is lost. At the deadline it goes down the existing failure path (WARN
// AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED, gauge 0, lastPgWriteOk false), its callers settle, and the writer moves on.
// The abandoned query is not cancelled (its connection is not killed); if it ever answers, that LATE result is only
// recorded (INFO AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT): it never touches lastPgWriteOk/lastPgWriteAt/the gauge, so it
// cannot restore health or mask a newer state. A late success did commit — the guard still kept the anchor monotonic
// — so it may raise _highestPgCount (true: this process wrote it); a late failure is just recorded.
const ANCHOR_WRITE_GRACE_MS = 2000;
let _attemptSeq = 0;              // identity of each issued write; a late settle compares against it, never the queue
let _pgWritesTimedOut = 0;
let _pgLateResults = 0;

function _envMs(name, dflt) {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) && v > 0 ? v : dflt;
}

function _anchorWriteDeadlineMs() {
  return _envMs('QODIQA_PG_STATEMENT_TIMEOUT_MS', 30000) + _envMs('QODIQA_PG_ACQUIRE_TIMEOUT_MS', 1500) + ANCHOR_WRITE_GRACE_MS;
}

class AnchorWriteTimeoutError extends Error {
  constructor(count, ms) {
    super(`audit_checksum_anchor write (count ${count}) did not complete within ${ms} ms — treated as failed`);
    this.code = 'QODIQA_ANCHOR_WRITE_TIMEOUT';
  }
}

/** Await `queryPromise` for at most the deadline; on expiry, route its eventual outcome to _onLateResult and throw. */
function _withDeadline(queryPromise, attempt, count) {
  const ms = _anchorWriteDeadlineMs();
  let timer;
  let timedOut = false;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => { timedOut = true; reject(new AnchorWriteTimeoutError(count, ms)); }, ms);
    if (timer.unref) timer.unref();
  });
  // Whatever happens, the original query's outcome is observed exactly once (no unhandled rejection).
  queryPromise.then(
    () => { if (timedOut) _onLateResult(attempt, count, 'committed', null); },
    (err) => { if (timedOut) _onLateResult(attempt, count, 'failed', err); },
  );
  return Promise.race([queryPromise, deadline]).finally(() => clearTimeout(timer));
}

function _onLateResult(attempt, count, outcome, err) {
  _pgLateResults++;
  if (outcome === 'committed' && (_highestPgCount === null || count > _highestPgCount)) _highestPgCount = count;
  try {
    require('../../../services/logger').emit('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT', {
      attempt, count, outcome, currentAttempt: _attemptSeq, ...(err ? { error: err.message } : {}),
    });
  } catch { /* logging must never throw */ }
}

function _isExpectedStale(err) {
  if (!err || err.code !== '42501' || typeof err.message !== 'string') return null;
  const m = FORWARD_ONLY_RE.exec(err.message);
  if (!m) return null;
  const currentCount = Number(m[1]);
  const incomingCount = Number(m[2]);
  if (!(incomingCount < currentCount)) return null;                         // equal count = a fork: never expected
  if (_highestPgCount === null || currentCount > _highestPgCount) return null; // not an anchor this process wrote
  return { currentCount, incomingCount };
}

/**
 * Best-effort UPSERT of {count, tailHash} into audit_checksum_anchor.
 * Never throws — a PG write failure here must never affect the audit append
 * it was called from (matches pg-audit-backend.js's persistEntry() dual-write
 * philosophy). No-op if PostgreSQL is not enabled/reachable.
 *
 * writes are ordered and coalesced (see above); the returned promise resolves once this value — or a newer
 * one that superseded it — has been written or has failed.
 */
function saveChecksumPg(count, tailHash) {
  let pgPool;
  try {
    pgPool = require('../../infra/postgres/pool');
  } catch {
    return Promise.resolve();
  }
  if (!pgPool.isEnabled()) return Promise.resolve();

  return new Promise((resolve) => {
    const last = _queue[_queue.length - 1];
    // Only a write that has not been issued yet (index >= 1) may be superseded, and only by a strictly higher count;
    // anything else keeps its place so the database judges it in call order.
    if (_queue.length >= 2 && last.count < count) {
      _queue.pop();
      _pgWritesCoalesced++;
      _queue.push({ count, tailHash, waiters: [...last.waiters, resolve] });
    } else {
      _queue.push({ count, tailHash, waiters: [resolve] });
    }
    if (!_draining) _drain(pgPool);
  });
}

async function _drain(pgPool) {
  _draining = true;
  try {
    while (_queue.length) {
      const w = _queue[0];
      await _writePg(pgPool, w.count, w.tailHash);
      _queue.shift();
      for (const r of w.waiters) r();
    }
  } finally {
    _draining = false;
  }
}

async function _writePg(pgPool, count, tailHash) {
  const attempt = ++_attemptSeq;
  try {
    await _withDeadline(pgPool.query(
      `INSERT INTO audit_checksum_anchor (id, count, tail_hash, updated_at)
       VALUES (TRUE, $1, $2, now())
       ON CONFLICT (id) DO UPDATE SET count = $1, tail_hash = $2, updated_at = now()`,
      [count, tailHash],
      'audit_checksum_anchor_upsert',
    ), attempt, count);
    _lastPgWriteAt = new Date().toISOString();
    _lastPgWriteOk = true;
    if (_highestPgCount === null || count > _highestPgCount) _highestPgCount = count;
    _refreshMetrics(true);
  } catch (err) {
    const stale = _isExpectedStale(err);
    if (stale) {
      // The newer anchor this process wrote is already committed and was kept by the guard: not a durability failure.
      _pgStaleWritesRefused++;
      try {
        require('../../../services/logger').emit('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_STALE_WRITE_REFUSED', {
          incomingCount: stale.incomingCount, currentCount: stale.currentCount, highestWrittenCount: _highestPgCount,
        });
      } catch { /* logging must never throw */ }
      return;
    }
    if (err && err.code === 'QODIQA_ANCHOR_WRITE_TIMEOUT') _pgWritesTimedOut++;
    _lastPgWriteAt = new Date().toISOString();
    _lastPgWriteOk = false;
    _refreshMetrics(false);
    try {
      // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
      require('../../observability/aggregatedEmit').failureEmit(require('../../../services/logger').emit, 'WARN', 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED', {
        error: err.message,
      });
    } catch { /* logging must never throw */ }
  }
}

/** Push current anchor-backend state into the Prometheus gauges. Never throws. */
function _refreshMetrics(pgWriteOk) {
  try {
    const metrics = require('../../observability/metrics');
    metrics.auditChecksumAnchorBackend.set({}, pgWriteOk ? 1 : 0);
    metrics.auditChecksumAnchorLastWriteTimestamp.set({}, Date.now() / 1000);
  } catch { /* metrics must never affect the anchor write */ }
}

/**
 * Reads the isolated PG anchor row directly — independent of the audit.log
 * filesystem entirely (no fs.* calls in this function). Returns null if PG
 * is disabled/unreachable or the table has no row yet (e.g. fresh install,
 * or PG enabled after this process already had chain history).
 *
 * @returns {Promise<{count: number, tailHash: string|null}|null>}
 */
async function loadChecksumPg() {
  let pgPool;
  try {
    pgPool = require('../../infra/postgres/pool');
  } catch {
    return null;
  }
  if (!pgPool.isEnabled()) return null;

  try {
    const result = await pgPool.query(
      'SELECT count, tail_hash FROM audit_checksum_anchor WHERE id = TRUE',
      [],
      'audit_checksum_anchor_read',
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return { count: Number(row.count), tailHash: row.tail_hash };
  } catch (err) {
    try {
      require('../../../services/logger').emit('WARN', 'AUDIT_CHECKSUM_ANCHOR_PG_READ_FAILED', {
        error: err.message,
      });
    } catch { /* logging must never throw */ }
    return null;
  }
}

/**
 * Diagnostics-friendly status snapshot — never throws.
 */
function getBackendStatus() {
  let pgEnabled = false;
  try { pgEnabled = require('../../infra/postgres/pool').isEnabled(); } catch { /* pool not available */ }
  return {
    pgEnabled,
    lastPgWriteAt: _lastPgWriteAt,
    lastPgWriteOk: _lastPgWriteOk,
    // diagnostics
    pgHighestWrittenCount: _highestPgCount,
    pgWritesQueued: _queue.length,
    pgWritesCoalesced: _pgWritesCoalesced,
    pgStaleWritesRefused: _pgStaleWritesRefused,
    // diagnostics
    pgWriteDeadlineMs: _anchorWriteDeadlineMs(),
    pgWritesTimedOut: _pgWritesTimedOut,
    pgLateResults: _pgLateResults,
  };
}

module.exports = {
  resolveFileAnchorPath,
  loadChecksum,
  saveChecksum,
  saveChecksumFileAsync,
  saveChecksumPg,
  loadChecksumPg,
  getBackendStatus,
  _anchorWriteDeadlineMs,   // exported for tests
};
