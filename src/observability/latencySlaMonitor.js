'use strict';

/**
 * Request Latency SLA/p99 Breach Monitor — #9 ("complete alert coverage").
 *
 * requestDurationMs (metrics.js) has always recorded every request's
 * latency, but nothing periodically evaluated it against a threshold or
 * emitted an event — the histogram only stores cumulative bucket counts,
 * with no built-in percentile computation and no alerting hook.
 *
 * This module reads requestDurationMs (label {decision: 'EXECUTE'} — served,
 * non-blocked requests are what "SLA" means to a caller) on a background
 * interval, via the Histogram class's new getMean()/estimatePercentile()
 * helpers, and emits a structured event on each threshold
 * crossing. Modeled on src/runtime/eventLoopMonitor.js's pattern: unref'd
 * setInterval, env-configurable interval/thresholds, state-transition-only
 * logging, background-only (no request-path instrumentation — it reads the
 * histogram's already-recorded data, it doesn't time anything itself).
 *
 * Two independent breach conditions, each with its own healthy/breached
 * state so a sustained p99 breach doesn't get masked by a healthy mean or
 * vice versa:
 *   - SLA (mean latency) breach — a broad, sustained latency regression.
 *   - p99 breach — a minority of requests suffering severe latency even
 *     when the mean looks fine (the "long tail").
 *
 * Environment variables:
 *   QODIQA_LATENCY_SLA_MONITOR_ENABLED    — 'false' to disable (default: enabled)
 *   QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS  — background tick interval, ms (default: 30000)
 *   QODIQA_SLA_LATENCY_MS                 — mean-latency breach threshold, ms (default: 2000)
 *   QODIQA_P99_LATENCY_MS                 — p99-latency breach threshold, ms (default: 5000)
 */

const { emit } = require('../../services/logger');

function _envInt(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const CHECK_INTERVAL_MS = _envInt('QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS', 30_000);
const SLA_THRESHOLD_MS  = _envInt('QODIQA_SLA_LATENCY_MS', 2_000);
const P99_THRESHOLD_MS  = _envInt('QODIQA_P99_LATENCY_MS', 5_000);

let _timer          = null;
let _slaState        = 'healthy'; // 'healthy' | 'breached'
let _p99State         = 'healthy'; // 'healthy' | 'breached'

/** True once the monitor has been initialized and its timer is active. */
function isEnabled() { return !!_timer; }

/** Current classification of both breach conditions. */
function getState() { return { sla: _slaState, p99: _p99State }; }

function _tick() {
  try {
    const metrics = require('./metrics');
    const meanMs = metrics.requestDurationMs.getMean({ decision: 'EXECUTE' });
    const p99Ms  = metrics.requestDurationMs.estimatePercentile({ decision: 'EXECUTE' }, 99);

    const nextSlaState = meanMs >= SLA_THRESHOLD_MS ? 'breached' : 'healthy';
    if (nextSlaState !== _slaState) {
      const prev = _slaState;
      _slaState = nextSlaState;
      emit(nextSlaState === 'breached' ? 'WARN' : 'INFO',
        nextSlaState === 'breached' ? 'REQUEST_LATENCY_SLA_BREACH' : 'REQUEST_LATENCY_SLA_RECOVERED',
        { fromState: prev, toState: nextSlaState, meanMs, slaThresholdMs: SLA_THRESHOLD_MS });
    }

    const nextP99State = p99Ms >= P99_THRESHOLD_MS ? 'breached' : 'healthy';
    if (nextP99State !== _p99State) {
      const prev = _p99State;
      _p99State = nextP99State;
      emit(nextP99State === 'breached' ? 'WARN' : 'INFO',
        nextP99State === 'breached' ? 'REQUEST_LATENCY_P99_BREACH' : 'REQUEST_LATENCY_P99_RECOVERED',
        { fromState: prev, toState: nextP99State, p99Ms, p99ThresholdMs: P99_THRESHOLD_MS });
    }
  } catch { /* background monitoring must never affect the process */ }
}

/**
 * Start the periodic latency SLA/p99 monitor. Idempotent — safe to call
 * multiple times; only the first call has any effect.
 */
function initialize() {
  if (_timer) return;
  if (process.env.QODIQA_LATENCY_SLA_MONITOR_ENABLED === 'false') {
    emit('WARN', 'LATENCY_SLA_MONITOR_DISABLED', {
      message: 'Latency SLA/p99 monitoring disabled via QODIQA_LATENCY_SLA_MONITOR_ENABLED=false',
    });
    return;
  }

  _slaState = 'healthy';
  _p99State = 'healthy';

  _timer = setInterval(_tick, CHECK_INTERVAL_MS);
  if (typeof _timer.unref === 'function') _timer.unref();

  emit('INFO', 'LATENCY_SLA_MONITOR_STARTED', {
    checkIntervalMs: CHECK_INTERVAL_MS,
    slaThresholdMs:  SLA_THRESHOLD_MS,
    p99ThresholdMs:  P99_THRESHOLD_MS,
  });
}

/** Stop monitoring. Safe to call multiple times. */
function shutdown() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
  _slaState = 'healthy';
  _p99State = 'healthy';
}

module.exports = { initialize, shutdown, getState, isEnabled };
