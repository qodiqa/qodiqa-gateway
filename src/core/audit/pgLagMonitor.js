'use strict';

/**
 * PostgreSQL Audit Lag Monitor — Component #11
 *
 * Tracks the difference between the authoritative file-based audit chain and
 * the PostgreSQL replica.  PG writes are fire-and-forget (best-effort); under
 * PG outages or heavy load, PG may fall behind without any visible signal.
 *
 * This monitor runs on a background interval (default: 60 s) and emits
 * structured events so operators can detect and respond to lag before it
 * becomes operationally significant.
 *
 * Events emitted:
 *   AUDIT_PG_SYNC_LAG    — PG count is more than lagThreshold entries behind file
 *   AUDIT_PG_UNAVAILABLE — PG query failed (first failure after recovery only)
 *   AUDIT_PG_RECOVERED   — PG is reachable again after a prior unavailability
 *
 * IMPORTANT: this module NEVER blocks the audit append path and NEVER changes
 * the authoritative chain state.  It is observability only.
 */

const { emit } = require('../../../services/logger');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

const DEFAULT_LAG_THRESHOLD = (() => {
  const v = parseInt(process.env.QODIQA_PG_LAG_THRESHOLD, 10);
  return Number.isFinite(v) && v > 0 ? v : 5;
})();

const DEFAULT_INTERVAL_MS = (() => {
  const v = parseInt(process.env.QODIQA_PG_LAG_INTERVAL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 60_000;
})();

let _timer          = null;
let _pgWasAvailable = true;

/**
 * Core check function.  Fully injectable for testing — no module-level state
 * is read other than _pgWasAvailable (reset via _resetState()).
 *
 * @param {object} opts
 * @param {function(): number} opts.getFileCount  Returns current file chain length
 * @param {function(): Promise} opts.queryFn      PG query returning { rows: [{ cnt }] }
 * @param {function}            opts.emitFn       Emit function (default: logger.emit)
 * @param {number}              opts.lagThreshold Entries-behind threshold for SYNC_LAG
 */
async function _checkOnce({
  getFileCount,
  queryFn,
  emitFn        = emit,
  lagThreshold  = DEFAULT_LAG_THRESHOLD,
} = {}) {
  const fileCount = getFileCount();
  let pgCount;

  try {
    const result = await queryFn();
    pgCount = Number(result.rows[0]?.cnt ?? 0);
  } catch (err) {
    if (_pgWasAvailable) {
      emitFn('WARN', 'AUDIT_PG_UNAVAILABLE', {
        error:     err.message,
        fileCount,
        message:   'PostgreSQL audit replica is unreachable — file chain remains authoritative',
      });
      _pgWasAvailable = false;
    }
    return;
  }

  if (!_pgWasAvailable) {
    emitFn('INFO', 'AUDIT_PG_RECOVERED', {
      pgCount,
      fileCount,
      lag:     fileCount - pgCount,
      message: 'PostgreSQL audit replica is reachable again',
    });
    _pgWasAvailable = true;
  }

  const lag = fileCount - pgCount;
  try { require('../../observability/metrics').auditPgLagEntries.set({}, Math.max(0, lag)); } catch { /* best-effort metric */ }
  if (lag > lagThreshold) {
    emitFn('WARN', 'AUDIT_PG_SYNC_LAG', {
      fileCount,
      pgCount,
      lag,
      lagThreshold,
      message: `PG audit replica is ${lag} entries behind the authoritative file chain`,
    });
  }
}

/**
 * the PG side of the lag comparison. It was `SELECT count(*) FROM audit_chain` on the app pool,
 * which the per-tenant RLS policy reduces — with no tenant context — to the NULL-tenant rows only, so it read 0
 * and raised a false AUDIT_PG_SYNC_LAG every interval while being unable to see real lag (the defect class).
 * It then counted the whole mirror through countChainRows(): qodiqa_audit_chain_full_read() as qodiqa_system — every
 * row materialised and spilled to temp every 60 s.
 *
 * S2: it reads the migration 073 counter (mirrorRowCount(), O(1), the same number as count(*) in every
 * committed state; all tenants — the counter is maintained by triggers, not read through RLS). A missing counter row is
 * reported (AUDIT_MIRROR_COUNT_UNAVAILABLE) and the check fails for that tick; it is never replaced by another count.
 * Rollback without a deploy: QODIQA_AUDIT_LAG_COUNT=exact restores the previous full count.
 */
async function pgCountQuery() {
  const backend = require('../../infra/postgres/pg-audit-backend');
  if (process.env.QODIQA_AUDIT_LAG_COUNT === 'exact') return { rows: [{ cnt: await backend.countChainRows() }] };
  const n = await backend.mirrorRowCount();
  if (n === null) {
    emit('WARN', 'AUDIT_MIRROR_COUNT_UNAVAILABLE', {
      message: 'audit_chain_mirror_count has no row — the lag check cannot run (migration 073; it is rebuilt only by the owner-only DR rebuild function, never automatically)',
    });
    throw new Error('AUDIT_MIRROR_COUNT_UNAVAILABLE');
  }
  return { rows: [{ cnt: n }] };
}

/**
 * Start the background lag monitoring interval.
 * Safe to call multiple times — subsequent calls are no-ops if already running.
 *
 * @param {object} opts
 * @param {function(): number} opts.getFileCount  Supplier for current file chain length
 * @param {number}             opts.intervalMs    Check interval in ms (default: 60 000)
 */
function startMonitoring({ getFileCount, intervalMs = DEFAULT_INTERVAL_MS, _taskRunner = _defaultTaskRunner } = {}) {
  if (_timer) return;
  if (typeof getFileCount !== 'function') {
    throw new Error('pgLagMonitor.startMonitoring: getFileCount must be a function');
  }

  // Lazy-require pool so the guard runs even when PG is not configured.
  const pgPool = require('../../infra/postgres/pool');

  _timer = setInterval(() => {
    if (!pgPool.isEnabled()) return;
    // Finding 3.6: runs through BackgroundTaskRunner (replaces the previous
    // local .catch(err => emit('ERROR', 'AUDIT_PG_LAG_MONITOR_ERROR', ...)))
    // for consistent isolation, structured logging, and metrics across every
    // background job — this monitor is observability-only, never fatal.
    _taskRunner.runTask('audit-pg-lag-monitor', () => _checkOnce({
      getFileCount,
      queryFn: pgCountQuery,
    }));
  }, intervalMs);

  // Don't hold the event loop open just for monitoring.
  if (typeof _timer.unref === 'function') _timer.unref();
}

/**
 * Stop the background interval.  Resets availability state so the next
 * startMonitoring() call begins with a clean slate.
 */
function stopMonitoring() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
  _pgWasAvailable = true;
}

/**
 * Reset module-level availability state.  For testing only — call between
 * test cases to ensure _pgWasAvailable starts at true.
 */
function _resetState() {
  _pgWasAvailable = true;
}

module.exports = { startMonitoring, stopMonitoring, _checkOnce, _resetState, pgCountQuery };
