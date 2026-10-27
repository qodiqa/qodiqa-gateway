'use strict';

/**
 * Signing Circuit Breaker —.
 *
 * Per-provider circuit breaker with three states: CLOSED, OPEN, HALF_OPEN.
 * Structurally identical to src/core/webhooks/webhookCircuitBreaker.js (that
 * implementation is the proven pattern already in production for outbound
 * webhook delivery); this module is a separate instance keyed by signing
 * provider name rather than webhook host, with its own registry and event
 * names so the two subsystems remain independently observable.
 *
 * State transitions:
 *   CLOSED    -> OPEN       after cbFailureThreshold consecutive failures
 *                            within cbWindowMs
 *   OPEN      -> HALF_OPEN  after cbRecoveryMs has elapsed
 *   HALF_OPEN -> CLOSED     after cbSuccessThreshold consecutive successes
 *   HALF_OPEN -> OPEN       on any failure
 *
 * While OPEN, allowRequest() returns false and the caller must reject
 * immediately without ever invoking the provider — this is what prevents a
 * degraded KMS/Vault instance from accumulating waiting requests.
 */

const { emit } = require('../../../../services/logger');
const { monoNowMs, wallFromMono } = require('../../time/monotonicClock'); // monotonic (same-process) deadlines/windows
let _metrics = null;
function _getMetrics() {
  if (!_metrics) _metrics = require('../../../observability/metrics');
  return _metrics;
}

const STATE_CLOSED    = 'CLOSED';
const STATE_OPEN      = 'OPEN';
const STATE_HALF_OPEN = 'HALF_OPEN';

class SigningCircuitBreaker {
  /**
   * @param {string} providerName
   * @param {object} config  signing resilience config fields
   */
  constructor(providerName, config) {
    this._providerName     = providerName;
    this._config           = config;
    this._state            = STATE_CLOSED;
    this._consecutiveFails = 0;
    this._consecutiveOks   = 0;
    this._openedAt         = null;
    this._failWindow       = [];
    // Tracks whether a HALF_OPEN probe is currently in flight so that,
    // unlike a naive port of this pattern, concurrent callers are actually
    // serialized to a single probe (requires this to be race-free
    // under concurrent callers).
    this._halfOpenProbeInFlight = false;
  }

  get state() { return this._state; }

  /**
   * Returns true if a request may proceed, false if it must be rejected
   * immediately without contacting the provider. In HALF_OPEN, exactly one
   * concurrent caller is allowed through as the recovery probe; every other
   * concurrent caller is rejected until that probe resolves via
   * onSuccess()/onFailure().
   */
  allowRequest() {
    if (this._state === STATE_CLOSED) return true;

    if (this._state === STATE_OPEN) {
      const elapsed = monoNowMs() - this._openedAt; // monotonic (same-process)
      if (elapsed >= this._config.cbRecoveryMs) {
        this._transition(STATE_HALF_OPEN, 'recovery timeout elapsed');
        this._halfOpenProbeInFlight = true;
        return true; // allow exactly one probe
      }
      return false;
    }

    // HALF_OPEN: allow exactly one in-flight probe; reject concurrent callers.
    if (this._halfOpenProbeInFlight) return false;
    this._halfOpenProbeInFlight = true;
    return true;
  }

  onSuccess() {
    if (this._state === STATE_HALF_OPEN) {
      this._halfOpenProbeInFlight = false;
      this._consecutiveOks++;
      if (this._consecutiveOks >= this._config.cbSuccessThreshold) {
        this._consecutiveFails = 0;
        this._consecutiveOks   = 0;
        this._failWindow       = [];
        this._transition(STATE_CLOSED, 'success threshold reached in half-open');
      }
      return;
    }
    this._consecutiveFails = 0;
    this._failWindow       = [];
  }

  onFailure() {
    const now = monoNowMs(); // monotonic (same-process)

    if (this._state === STATE_HALF_OPEN) {
      this._halfOpenProbeInFlight = false;
      this._consecutiveOks = 0;
      this._transition(STATE_OPEN, 'failure in half-open probe');
      return;
    }

    const windowStart = now - this._config.cbWindowMs;
    this._failWindow = this._failWindow.filter(ts => ts >= windowStart);
    this._failWindow.push(now);
    this._consecutiveFails++;

    if (this._consecutiveFails >= this._config.cbFailureThreshold) {
      this._transition(STATE_OPEN, 'failure threshold reached');
    }
  }

  _transition(newState, reason) {
    const prev = this._state;
    this._state = newState;

    if (newState === STATE_OPEN) {
      this._openedAt              = monoNowMs(); // monotonic (same-process)
      this._consecutiveOks         = 0;
      this._halfOpenProbeInFlight = false;
    } else if (newState === STATE_HALF_OPEN) {
      this._consecutiveOks = 0;
    }

    emit('INFO', 'SIGNING_CIRCUIT_BREAKER_STATE', {
      provider: this._providerName,
      from:     prev,
      to:       newState,
      reason,
    });

    try {
      const m = _getMetrics();
      if (newState === STATE_OPEN)      m.signingCircuitOpensTotal.inc({ provider: this._providerName });
      if (newState === STATE_CLOSED)    m.signingCircuitClosesTotal.inc({ provider: this._providerName });
      if (newState === STATE_HALF_OPEN) m.signingCircuitHalfOpenTotal.inc({ provider: this._providerName });
    } catch { /* metrics must never break the resilience path */ }
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

const _registry = new Map();

/**
 * @param {string} providerName
 * @param {object} config
 * @returns {SigningCircuitBreaker}
 */
function getCircuitBreaker(providerName, config) {
  if (!_registry.has(providerName)) {
    _registry.set(providerName, new SigningCircuitBreaker(providerName, config));
  }
  return _registry.get(providerName);
}

/** Clear all circuit breakers. Used in tests to reset state between runs. */
function resetAll() {
  _registry.clear();
}

/** Snapshot of all circuit breaker states for observability. */
function snapshot() {
  const out = {};
  for (const [providerName, cb] of _registry) {
    out[providerName] = {
      state:            cb.state,
      consecutiveFails: cb._consecutiveFails,
      consecutiveOks:   cb._consecutiveOks,
      openedAt:         wallFromMono(cb._openedAt), // wall-clock equivalent for display
    };
  }
  return out;
}

module.exports = {
  SigningCircuitBreaker,
  getCircuitBreaker,
  resetAll,
  snapshot,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
};
