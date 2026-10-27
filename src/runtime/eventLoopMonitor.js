'use strict';

/**
 * Event Loop Delay Monitor —.
 *
 * QODIQA's enforcement path intentionally performs synchronous durability
 * operations (audit fsync, key store I/O). Event-loop delay is the earliest
 * and most accurate signal that this synchronous work — or GC, or CPU
 * starvation from anywhere else in the process — is starting to affect
 * request latency, well before /health or /ready would ever notice.
 *
 * This module wraps Node's native perf_hooks.monitorEventLoopDelay(), which
 * samples the event loop on its own libuv-driven cadence with no user code
 * running per sample. There is nothing to instrument on the request path:
 * initialize() is called once at startup, and everything after that is a
 * background timer (unref'd, so it never keeps the process alive) reading
 * the histogram's own running statistics.
 *
 * Environment variables:
 *   QODIQA_EVENT_LOOP_MONITOR_ENABLED    — 'false' to disable entirely (default: enabled)
 *   QODIQA_EVENT_LOOP_RESOLUTION_MS      — histogram sampling resolution in ms (default: 10)
 *   QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS  — how often the background tick refreshes
 *                                           metrics and evaluates state, in ms (default: 5000)
 *   QODIQA_EVENT_LOOP_WARN_MS            — mean delay (ms) at/above which state becomes
 *                                           'degraded' (default: 100)
 *   QODIQA_EVENT_LOOP_CRITICAL_MS        — mean delay (ms) at/above which state becomes
 *                                           'unhealthy' (default: 500)
 *
 * State transitions (healthy -> degraded -> unhealthy, and back) are logged
 * once per actual change, never per tick — see _evaluateState().
 */

const { monitorEventLoopDelay } = require('perf_hooks');
const { emit } = require('../../services/logger');

const NS_PER_MS = 1e6;

function _envInt(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const RESOLUTION_MS         = _envInt('QODIQA_EVENT_LOOP_RESOLUTION_MS', 10);
const CHECK_INTERVAL_MS     = _envInt('QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS', 5_000);
const WARN_THRESHOLD_MS     = _envInt('QODIQA_EVENT_LOOP_WARN_MS', 100);
const CRITICAL_THRESHOLD_MS = _envInt('QODIQA_EVENT_LOOP_CRITICAL_MS', 500);

let _histogram = null;
let _window = null; // RT-08: interval histogram, reset on every tick
let _timer     = null;
let _state     = 'healthy'; // 'healthy' | 'degraded' | 'unhealthy'

function _toMs(nsValue) {
  return Number.isFinite(nsValue) ? nsValue / NS_PER_MS : 0;
}

/**
 * Current event-loop delay statistics, in milliseconds, read directly off
 * the live histogram. Never resets the histogram — safe to call as often as
 * needed (every /diagnostics hit, every background tick).
 */
function getStats() {
  if (!_histogram) {
    return { meanMs: 0, maxMs: 0, minMs: 0, stddevMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0 };
  }
  try {
    return {
      meanMs:   _toMs(_histogram.mean),
      maxMs:    _toMs(_histogram.max),
      minMs:    _toMs(_histogram.min),
      stddevMs: _toMs(_histogram.stddev),
      p50Ms:    _toMs(_histogram.percentile(50)),
      p95Ms:    _toMs(_histogram.percentile(95)),
      p99Ms:    _toMs(_histogram.percentile(99)),
    };
  } catch {
    return { meanMs: 0, maxMs: 0, minMs: 0, stddevMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0 };
  }
}

/** Current readiness classification: 'healthy' | 'degraded' | 'unhealthy'. */
function getState() { return _state; }

/** True once the monitor has been initialized and is actively sampling. */
function isEnabled() { return !!_histogram; }

const _STATE_CODE = { healthy: 0, degraded: 1, unhealthy: 2 };

/** Push current stats into the Prometheus gauges. Never throws. */
function _refreshMetrics() {
  try {
    const metrics = require('../observability/metrics');
    const s = getStats();
    metrics.eventLoopDelayMeanMs.set({}, s.meanMs);
    metrics.eventLoopDelayMaxMs.set({}, s.maxMs);
    metrics.eventLoopDelayMinMs.set({}, s.minMs);
    metrics.eventLoopDelayStddevMs.set({}, s.stddevMs);
    metrics.eventLoopDelayP50Ms.set({}, s.p50Ms);
    metrics.eventLoopDelayP95Ms.set({}, s.p95Ms);
    metrics.eventLoopDelayP99Ms.set({}, s.p99Ms);
    metrics.eventLoopDelayStateCode.set({}, _STATE_CODE[_state] ?? 0);
    // RT-08: the interval histogram — read, then reset, so these gauges cover only the last interval.
    if (_window) {
      metrics.eventLoopDelayWindowMaxMs.set({}, _toMs(_window.max));
      metrics.eventLoopDelayWindowP99Ms.set({}, _toMs(_window.percentile(99)));
      _window.reset();
    }
  } catch { /* metrics must never affect the monitor */ }
}

/**
 * Evaluate mean delay against the configured thresholds and log only on an
 * actual state change — prevents log flooding under sustained degradation.
 */
function _evaluateState() {
  const meanMs = _toMs(_histogram.mean);
  let next = 'healthy';
  if (meanMs >= CRITICAL_THRESHOLD_MS) next = 'unhealthy';
  else if (meanMs >= WARN_THRESHOLD_MS) next = 'degraded';

  if (next === _state) return;
  const prev = _state;
  _state = next;

  const payload = {
    fromState: prev,
    toState:   next,
    meanMs,
    warnThresholdMs:     WARN_THRESHOLD_MS,
    criticalThresholdMs: CRITICAL_THRESHOLD_MS,
  };

  if (next === 'healthy') {
    emit('INFO', 'EVENT_LOOP_DELAY_RECOVERED', payload);
  } else if (next === 'degraded') {
    emit('WARN', 'EVENT_LOOP_DELAY_WARNING', payload);
  } else {
    emit('ERROR', 'EVENT_LOOP_DELAY_CRITICAL', payload);
  }
}

function _tick() {
  try {
    if (!_histogram) return;
    _refreshMetrics();
    _evaluateState();
  } catch { /* background monitoring must never affect the process */ }
}

/**
 * Start continuous event-loop delay monitoring. Idempotent — safe to call
 * multiple times; only the first call has any effect. Call once from
 * server.js's startup sequence.
 */
function initialize() {
  if (_histogram) return;
  if (process.env.QODIQA_EVENT_LOOP_MONITOR_ENABLED === 'false') {
    emit('WARN', 'EVENT_LOOP_MONITOR_DISABLED', {
      message: 'Event loop delay monitoring disabled via QODIQA_EVENT_LOOP_MONITOR_ENABLED=false',
    });
    return;
  }

  _histogram = monitorEventLoopDelay({ resolution: RESOLUTION_MS });
  _histogram.enable();
  _window = monitorEventLoopDelay({ resolution: RESOLUTION_MS }); // RT-08: reset every tick
  _window.enable();
  _state = 'healthy';

  _timer = setInterval(_tick, CHECK_INTERVAL_MS);
  if (typeof _timer.unref === 'function') _timer.unref();

  emit('INFO', 'EVENT_LOOP_MONITOR_STARTED', {
    resolutionMs:        RESOLUTION_MS,
    checkIntervalMs:     CHECK_INTERVAL_MS,
    warnThresholdMs:     WARN_THRESHOLD_MS,
    criticalThresholdMs: CRITICAL_THRESHOLD_MS,
  });
}

/** Stop monitoring and release the histogram. Safe to call multiple times. */
function shutdown() {
  if (_timer) {
    clearInterval(_timer);
    _timer = null;
  }
  if (_histogram) {
    _histogram.disable();
    _histogram = null;
  }
  if (_window) {
    _window.disable();
    _window = null;
  }
  _state = 'healthy';
}

module.exports = {
  initialize,
  shutdown,
  getStats,
  getState,
  isEnabled,
};
