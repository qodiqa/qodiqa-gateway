'use strict';

/**
 * Signing Provider Health Monitor —.
 *
 * Tracks the live health of a single KMS/Vault/HSM provider from two inputs:
 *
 *   1. Passive observation — every call the resilient provider wrapper makes
 *      reports its outcome here (recordSuccess/recordFailure), so health
 *      reflects real traffic with zero extra I/O.
 *   2. Active probing — a periodic background timer (SIGNING_HEALTH_INTERVAL_MS)
 *      calls the provider's own healthCheck() (via a caller-supplied,
 *      already timeout-wrapped probe function) so health recovers even
 *      during a lull in real signing traffic, and so a provider that comes
 *      back up is detected without waiting for the next real request.
 *
 * Health states:
 *   healthy     — no more than a handful of recent failures.
 *   degraded    — consecutiveFailures >= healthDegradedThreshold: the provider
 *                 is having trouble but has not yet crossed the circuit
 *                 breaker's own failure threshold.
 *   unavailable — consecutiveFailures >= cbFailureThreshold (the same
 *                 threshold that opens the circuit breaker) or the circuit
 *                 breaker itself is reported OPEN by the caller.
 *
 * This module never opens sockets and never throws — it is pure bookkeeping,
 * exactly like src/observability/metrics.js's "infallible" contract, so a bug
 * here can never turn into a signing outage.
 */

const { emit } = require('../../../../services/logger');
let _metrics = null;
function _getMetrics() {
  if (!_metrics) _metrics = require('../../../observability/metrics');
  return _metrics;
}

const STATE_HEALTHY     = 'healthy';
const STATE_DEGRADED    = 'degraded';
const STATE_UNAVAILABLE = 'unavailable';

const HEALTH_STATE_CODE = Object.freeze({
  [STATE_UNAVAILABLE]: 0,
  [STATE_DEGRADED]:    1,
  [STATE_HEALTHY]:     2,
});

const MAX_WINDOW_SAMPLES = 100;

class SigningHealthMonitor {
  /**
   * @param {string} providerName
   * @param {object} config  { cbFailureThreshold, healthDegradedThreshold, healthIntervalMs }
   */
  constructor(providerName, config) {
    this._providerName        = providerName;
    this._config               = config;
    this._state                = STATE_HEALTHY;
    this._consecutiveFailures  = 0;
    this._consecutiveSuccesses = 0;
    this._lastError            = null;
    this._lastSuccessAt        = null;
    this._lastFailureAt        = null;
    this._window                = []; // { ts, ok, timedOut, latencyMs }
    this._probeTimer            = null;

    this._publishGauges();
  }

  get state() { return this._state; }
  get consecutiveFailures() { return this._consecutiveFailures; }

  recordSuccess(latencyMs) {
    this._consecutiveFailures  = 0;
    this._consecutiveSuccesses++;
    this._lastSuccessAt = new Date().toISOString();
    this._pushWindow({ ok: true, timedOut: false, latencyMs });
    this._recompute('successful call/probe');
  }

  /** @param {{ timedOut?: boolean, error?: any }} [info] */
  recordFailure({ timedOut = false, error } = {}) {
    this._consecutiveFailures++;
    this._consecutiveSuccesses = 0;
    this._lastFailureAt = new Date().toISOString();
    this._lastError      = error ? error.message : 'unknown error';
    this._pushWindow({ ok: false, timedOut, latencyMs: null });
    this._recompute(timedOut ? 'timeout observed' : 'failure observed');
  }

  _pushWindow(sample) {
    this._window.push({ ts: Date.now(), ...sample });
    if (this._window.length > MAX_WINDOW_SAMPLES) this._window.shift();
  }

  _classify() {
    if (this._consecutiveFailures >= this._config.cbFailureThreshold) return STATE_UNAVAILABLE;
    if (this._consecutiveFailures >= this._config.healthDegradedThreshold) return STATE_DEGRADED;
    return STATE_HEALTHY;
  }

  _recompute(reason) {
    const prev = this._state;
    const next = this._classify();
    this._state = next;
    this._publishGauges();

    if (next === prev) return;

    if (next === STATE_HEALTHY && (prev === STATE_DEGRADED || prev === STATE_UNAVAILABLE)) {
      emit('INFO', 'SIGNING_HEALTH_RECOVERED', {
        provider: this._providerName, from: prev, to: next, reason,
      });
    } else if (next === STATE_DEGRADED || next === STATE_UNAVAILABLE) {
      emit('WARN', 'SIGNING_HEALTH_DEGRADED', {
        provider: this._providerName, from: prev, to: next, reason,
        consecutiveFailures: this._consecutiveFailures, lastError: this._lastError,
      });
    }
  }

  _publishGauges() {
    try {
      const m = _getMetrics();
      m.signingHealthState.set({ provider: this._providerName }, HEALTH_STATE_CODE[this._state]);
      m.signingConsecutiveFailures.set({ provider: this._providerName }, this._consecutiveFailures);
    } catch { /* metrics must never break the resilience path */ }
  }

  /** Fraction (0..1) of recent samples that timed out — informational only. */
  timeoutRate() {
    if (this._window.length === 0) return 0;
    const timeouts = this._window.filter(s => s.timedOut).length;
    return timeouts / this._window.length;
  }

  /** Mean latency (ms) of recent successful samples — informational only. */
  averageLatencyMs() {
    const successes = this._window.filter(s => s.ok && typeof s.latencyMs === 'number');
    if (successes.length === 0) return null;
    return successes.reduce((sum, s) => sum + s.latencyMs, 0) / successes.length;
  }

  snapshot() {
    return {
      provider:            this._providerName,
      state:               this._state,
      consecutiveFailures: this._consecutiveFailures,
      consecutiveSuccesses: this._consecutiveSuccesses,
      lastError:           this._lastError,
      lastSuccessAt:       this._lastSuccessAt,
      lastFailureAt:       this._lastFailureAt,
      timeoutRate:         this.timeoutRate(),
      averageLatencyMs:    this.averageLatencyMs(),
      sampleCount:         this._window.length,
    };
  }

  /**
   * Start periodic active probing. `probeFn` is expected to be the resilient
   * provider's own wrapped healthCheck() — it already applies the timeout,
   * circuit breaker gate, and recordSuccess/recordFailure bookkeeping on this
   * same monitor (see resilientSigningProvider.js#_execute), so this timer's
   * only job is to trigger it on a schedule and never let a rejection escape
   * as an unhandled promise rejection.
   *
   * @param {() => Promise<any>} probeFn
   */
  startActiveProbing(probeFn) {
    this.stopActiveProbing();
    this._probeTimer = setInterval(() => {
      Promise.resolve().then(() => probeFn()).catch(() => { /* bookkeeping already done by probeFn */ });
    }, this._config.healthIntervalMs);
    if (this._probeTimer.unref) this._probeTimer.unref();
  }

  stopActiveProbing() {
    if (this._probeTimer) {
      clearInterval(this._probeTimer);
      this._probeTimer = null;
    }
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

const _registry = new Map();

/**
 * @param {string} providerName
 * @param {object} config
 * @returns {SigningHealthMonitor}
 */
function getHealthMonitor(providerName, config) {
  if (!_registry.has(providerName)) {
    _registry.set(providerName, new SigningHealthMonitor(providerName, config));
  }
  return _registry.get(providerName);
}

function resetAll() {
  for (const monitor of _registry.values()) monitor.stopActiveProbing();
  _registry.clear();
}

function snapshotAll() {
  const out = {};
  for (const [providerName, monitor] of _registry) out[providerName] = monitor.snapshot();
  return out;
}

module.exports = {
  SigningHealthMonitor,
  getHealthMonitor,
  resetAll,
  snapshotAll,
  STATE_HEALTHY,
  STATE_DEGRADED,
  STATE_UNAVAILABLE,
  HEALTH_STATE_CODE,
};
