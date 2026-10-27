'use strict';

/**
 * S4 — audit_chain row-counter reconciliation (design decision OD-5, 2026-10-02; design
 *).
 *
 * The 60 s PG lag monitor reads the migration 073 counter (O(1), S2). A trigger-maintained counter cannot see a change
 * made with its triggers bypassed (table owner DISABLE TRIGGER / superuser session_replication_role = replica), so this
 * module re-derives the exact count on a schedule and at boot, through the S2 cross-check
 * qodiqa_audit_chain_mirror_count_check() (stored, exact count(*), in_sync — one snapshot; O(n), no temp).
 *
 * Outcomes:
 *   in sync                  → INFO  AUDIT_MIRROR_COUNT_RECONCILED (+ INFO AUDIT_MIRROR_COUNT_DRIFT_CLEARED after a drift)
 *   stored != exact          → CRITICAL AUDIT_MIRROR_COUNT_DRIFT {reason: 'MISMATCH'} — re-raised on EVERY run while it
 *                              persists, with consecutiveDriftRuns (escalation without healing)
 *   counter row missing      → CRITICAL AUDIT_MIRROR_COUNT_DRIFT {reason: 'COUNTER_MISSING'}
 *   check could not run      → WARN  AUDIT_MIRROR_COUNT_RECONCILE_FAILED (no conclusion; never thrown)
 *
 * NO AUTOMATIC REPAIR (OD-5, the S2 rule): this module never writes. The only recovery is the owner-only
 * qodiqa_audit_chain_mirror_count_rebuild() (DR / operator). It never runs on the 60 s lag path.
 * Interval QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS (default 6 h); QODIQA_AUDIT_MIRROR_RECONCILE=off disables the boot
 * run and the schedule (rollback without a deploy).
 */

const { emit } = require('../../../services/logger');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

const TASK_NAME = 'audit-mirror-count-reconcile';
const DEFAULT_INTERVAL_MS = 6 * 60 * 60 * 1000;

function intervalFromEnv() {
  const v = parseInt(process.env.QODIQA_AUDIT_MIRROR_RECONCILE_INTERVAL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : DEFAULT_INTERVAL_MS;
}
const isDisabled = () => process.env.QODIQA_AUDIT_MIRROR_RECONCILE === 'off';

// Per-process drift streak (not persisted: every run re-derives the truth from PostgreSQL).
let _drift = null;   // { firstDetectedAt, consecutiveDriftRuns } while drifted
let _timer = null;

function _defaultCheck() { return require('../../infra/postgres/pg-audit-backend').mirrorCountCheck(); }
function _pgEnabled() { try { return require('../../infra/postgres/pool').isEnabled(); } catch { return false; } }

/**
 * One reconciliation. Never throws. Returns the outcome (also emitted).
 * @param {object} [opts]
 * @param {string} [opts.trigger]          'BOOT' | 'SCHEDULED' | 'MANUAL'
 * @param {function} [opts.check]          () => Promise<{stored:number|null, exact:number, inSync:boolean}>
 * @param {function} [opts.emitFn]
 * @param {function} [opts.pgEnabled]
 */
async function reconcileOnce({ trigger = 'SCHEDULED', check = _defaultCheck, emitFn = emit, pgEnabled = _pgEnabled } = {}) {
  if (!pgEnabled()) return { status: 'SKIPPED', reason: 'PG_DISABLED', trigger };
  const t0 = Date.now();
  let r;
  try {
    r = await check();
  } catch (err) {
    const out = { status: 'FAILED', trigger, error: err.message, durationMs: Date.now() - t0 };
    emitFn('WARN', 'AUDIT_MIRROR_COUNT_RECONCILE_FAILED', { ...out,
      message: 'The audit_chain counter cross-check could not run; drift is neither confirmed nor excluded for this run.' });
    return out;
  }
  const durationMs = Date.now() - t0;
  if (r.stored !== null && r.inSync === true && r.stored === r.exact) {
    const cleared = _drift;
    _drift = null;
    const out = { status: 'IN_SYNC', trigger, stored: r.stored, exact: r.exact, durationMs };
    if (cleared) emitFn('INFO', 'AUDIT_MIRROR_COUNT_DRIFT_CLEARED', { trigger, stored: r.stored, exact: r.exact, firstDetectedAt: cleared.firstDetectedAt, driftRuns: cleared.consecutiveDriftRuns });
    emitFn('INFO', 'AUDIT_MIRROR_COUNT_RECONCILED', out);
    return out;
  }
  _drift = _drift ? { ..._drift, consecutiveDriftRuns: _drift.consecutiveDriftRuns + 1 } : { firstDetectedAt: new Date().toISOString(), consecutiveDriftRuns: 1 };
  const reason = r.stored === null ? 'COUNTER_MISSING' : 'MISMATCH';
  try { require('../../observability/metrics').auditMirrorCountDriftTotal.inc({ reason }); } catch { /* best-effort metric */ }
  const out = { status: 'DRIFT', reason, trigger, stored: r.stored, exact: r.exact, delta: r.stored === null ? null : r.stored - r.exact,
    consecutiveDriftRuns: _drift.consecutiveDriftRuns, firstDetectedAt: _drift.firstDetectedAt, durationMs };
  emitFn('CRITICAL', 'AUDIT_MIRROR_COUNT_DRIFT', { ...out,
    message: 'audit_chain_mirror_count does not equal count(*) of audit_chain. Not repaired automatically: the 60 s lag value is wrong until the owner runs the owner-only counter rebuild (migration 073) after investigating how audit_chain changed with its triggers bypassed.' });
  return out;
}

/**
 * Boot validation: one reconcile with trigger 'BOOT'. Non-fatal by design (the counter is derived observability data;
 * the fail-closed boot authorities are the mirror consistency check, the verifier watermark and the signed checkpoint).
 */
async function validateAtBoot(opts = {}) {
  if (isDisabled()) return { status: 'SKIPPED', reason: 'DISABLED', trigger: 'BOOT' };
  return reconcileOnce({ ...opts, trigger: 'BOOT' });
}

/** Start the periodic reconciliation (default every 6 h). No-op if already running or disabled. */
function startReconciler({ intervalMs = intervalFromEnv(), _taskRunner = _defaultTaskRunner, ...opts } = {}) {
  if (_timer || isDisabled()) return false;
  _timer = setInterval(() => {
    _taskRunner.runTask(TASK_NAME, () => reconcileOnce({ ...opts, trigger: 'SCHEDULED' })).catch(() => { /* reconcileOnce never throws; runner reports */ });
  }, intervalMs);
  if (typeof _timer.unref === 'function') _timer.unref();
  return true;
}

function stopReconciler() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}

/** Testing only. */
function _resetState() { _drift = null; stopReconciler(); }

module.exports = { reconcileOnce, validateAtBoot, startReconciler, stopReconciler, _resetState, TASK_NAME, DEFAULT_INTERVAL_MS };
