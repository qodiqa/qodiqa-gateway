'use strict';

/**
 * Periodic Redis Durability Validator — #1 (finding #108).
 *
 * checkRedisPersistence() (persistenceCheck.js) has always been available,
 * but until this module the only caller was server/startup.js's one-shot
 * check at boot (via nonceStore.checkPersistence()). If an operator (or an
 * unmanaged config-management tool) flips `appendonly` from `yes` to `no` on
 * the live Redis instance after the process has started, QODIQA had no way
 * to notice — the startup gate (including STRICT_REPLAY_PROTECTION) only
 * runs once, before the first request is ever served.
 *
 * This module re-runs the identical check on a background interval, against
 * the SAME live Redis connection nonceStore.checkPersistence() already uses
 * (not a separate diagnostic connection — matches the finding's requirement
 * to detect the actual runtime store's configuration, and avoids opening an
 * extra connection just to poll CONFIG GET periodically).
 *
 * Modeled directly on src/runtime/eventLoopMonitor.js: unref'd
 * setInterval, background-only (no request-path instrumentation),
 * state-transition-only logging to avoid log flooding under sustained
 * drift, gauges refreshed every tick, initialize()/shutdown() idempotent.
 *
 * Deliberately observational, not enforcing: a drift detected mid-run does
 * NOT itself trip a kill-switch or reject in-flight requests — the existing
 * STRICT_REPLAY_PROTECTION startup gate remains the sole hard-enforcement
 * point for persistence safety. Turning a live background check into a live
 * kill-switch risks flapping-induced outages (a transient CONFIG GET
 * failure or a brief Redis reconfiguration window would otherwise be able
 * to take the gateway down); this module's job is to make drift visible to
 * operators and the alerting pipeline, not to self-enforce.
 *
 * Environment variables:
 *   QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED    — 'false' to disable entirely (default: enabled)
 *   QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS  — background tick interval, in ms
 *                                                   (default: 60000 — a real Redis
 *                                                   CONFIG GET/INFO round-trip, so
 *                                                   deliberately coarser than the 5s
 *                                                   event-loop check)
 *
 * State transitions (safe -> unsafe -> safe, and -> unknown on connection
 * loss) are logged once per actual change, never per tick.
 */

const { emit } = require('../../../services/logger');

function _envInt(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const CHECK_INTERVAL_MS = _envInt('QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS', 60_000);

let _timer               = null;
let _state                = 'unknown'; // 'safe' | 'unsafe' | 'unknown'
let _lastDiagnostics      = null;
let _lastCheckedAt        = null;
let _consecutiveUnsafe    = 0;

const _STATE_CODE = { safe: 1, unsafe: 0, unknown: -1 };

/** Current readiness classification: 'safe' | 'unsafe' | 'unknown'. */
function getState() { return _state; }

/** True once the monitor has been initialized and its timer is active. */
function isEnabled() { return !!_timer; }

/**
 * Current diagnostics, read directly off the last completed check. Never
 * triggers a new check — safe to call as often as needed (every /diagnostics
 * hit).
 */
function getStats() {
  return {
    state:                _state,
    lastCheckedAt:        _lastCheckedAt,
    consecutiveUnsafeChecks: _consecutiveUnsafe,
    diagnostics:          _lastDiagnostics,
  };
}

/** Incremented once per safe→unsafe transition (not per tick). Never throws. */
function _incrementDriftCounter() {
  try {
    require('../../observability/metrics').redisPersistenceDriftTotal.inc({});
  } catch { /* metrics must never affect the monitor */ }
}

/** Push current state into the Prometheus gauges/histogram. Never throws. */
function _refreshMetrics(diag, durationMs) {
  try {
    const metrics = require('../../observability/metrics');
    metrics.redisPersistenceSafe.set({}, _STATE_CODE[_state] ?? -1);
    metrics.redisPersistenceAofEnabled.set({}, diag.aofEnabled === true ? 1 : diag.aofEnabled === false ? 0 : -1);
    metrics.redisPersistenceLastCheckTimestamp.set({}, Date.now() / 1000);
    metrics.redisPersistenceCheckDurationMs.observe({}, durationMs);
  } catch { /* metrics must never affect the monitor */ }
}

/**
 * Classify a PersistenceDiagnostics result into 'safe' | 'unsafe' | 'unknown'.
 * 'unknown' is distinct from 'unsafe': a not-connected/check-failed result
 * (diag.error set) means durability could not be verified at all, which is
 * a different operational condition than a confirmed-unsafe configuration.
 */
function _classify(diag) {
  if (diag.error) return 'unknown';
  return diag.safe ? 'safe' : 'unsafe';
}

/**
 * Evaluate the latest check against the previous state and log/alert only on
 * an actual state change — prevents log flooding under sustained drift.
 */
function _evaluateState(diag) {
  const next = _classify(diag);
  const prev = _state;

  if (next === 'unsafe') _consecutiveUnsafe += 1;
  else _consecutiveUnsafe = 0;

  if (next === prev) return;
  _state = next;

  const payload = {
    fromState:   prev,
    toState:     next,
    aofEnabled:  diag.aofEnabled,
    appendfsync: diag.appendfsync,
    warnings:    diag.warnings?.length ?? 0,
  };

  if (prev === 'safe' && next === 'unsafe') {
    _incrementDriftCounter();
    emit('WARN', 'REDIS_PERSISTENCE_DRIFT_DETECTED', {
      ...payload,
      message: 'Redis persistence configuration changed from safe to unsafe after startup — ' +
               'runtime configuration drift detected. Nonce state may no longer survive a Redis ' +
               'restart or crash.',
    });
    return;
  }

  if (next === 'safe') {
    emit('INFO', 'REDIS_PERSISTENCE_RECOVERED', payload);
    return;
  }

  if (next === 'unknown') {
    emit('WARN', 'REDIS_PERSISTENCE_MONITOR_DEGRADED', {
      ...payload,
      error: diag.error ?? null,
      message: 'Periodic Redis persistence check could not verify durability configuration.',
    });
    return;
  }

  // unsafe (from unknown), or any other transition into 'unsafe' not already
  // handled above (e.g. first-ever check landing on 'unsafe').
  emit('WARN', 'REDIS_PERSISTENCE_DRIFT_DETECTED', payload);
}

async function _tick() {
  const nonceStore = require('../../validation/nonceStore');
  const startNs = process.hrtime.bigint();
  let diag;
  try {
    diag = await nonceStore.checkPersistence();
  } catch (err) {
    // checkPersistence() itself never throws (see persistenceCheck.js), but
    // background monitoring must never affect the process even if that
    // contract is ever violated.
    diag = { safe: false, aofEnabled: null, appendfsync: null, warnings: [], error: err.message };
  }
  const durationMs = Number(process.hrtime.bigint() - startNs) / 1e6;

  _lastDiagnostics = diag;
  _lastCheckedAt   = new Date().toISOString();

  try { _evaluateState(diag); } catch { /* never let evaluation crash the timer */ }
  _refreshMetrics(diag, durationMs);
}

/**
 * Start the periodic Redis durability validator. Idempotent — safe to call
 * multiple times; only the first call has any effect. Call once from
 * server/startup.js, after the one-shot startup check confirms the nonce
 * store is ready (mirrors that check's own precondition).
 */
function initialize() {
  if (_timer) return;
  if (process.env.QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED === 'false') {
    emit('WARN', 'REDIS_PERSISTENCE_MONITOR_DISABLED', {
      message: 'Periodic Redis persistence validation disabled via QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED=false',
    });
    return;
  }

  _state             = 'unknown';
  _lastDiagnostics   = null;
  _lastCheckedAt     = null;
  _consecutiveUnsafe = 0;

  _timer = setInterval(() => { _tick(); }, CHECK_INTERVAL_MS);
  if (typeof _timer.unref === 'function') _timer.unref();

  emit('INFO', 'REDIS_PERSISTENCE_MONITOR_STARTED', {
    checkIntervalMs: CHECK_INTERVAL_MS,
  });
}

/** Stop monitoring. Safe to call multiple times. */
function shutdown() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
  _state             = 'unknown';
  _lastDiagnostics   = null;
  _lastCheckedAt     = null;
  _consecutiveUnsafe = 0;
}

module.exports = {
  initialize,
  shutdown,
  getStats,
  getState,
  isEnabled,
};
