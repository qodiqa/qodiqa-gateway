'use strict';

/**
 * Provider Circuit Breaker (Register #107).
 *
 * Per-provider circuit breaker with three states: CLOSED, OPEN, HALF_OPEN.
 * Structurally identical to src/infra/keys/resilience/circuitBreaker.js's
 * SigningCircuitBreaker and src/core/webhooks/webhookCircuitBreaker.js's
 * CircuitBreaker — the same proven pattern already in production for two
 * other outbound-call subsystems — instantiated a third time here, keyed by
 * LLM provider name, with its own registry and event name so all three
 * subsystems remain independently observable and independently revertible.
 *
 * State transitions:
 *   CLOSED    -> OPEN       after cbFailureThreshold consecutive failures
 *                            within cbWindowMs
 *   OPEN      -> HALF_OPEN  after cbRecoveryMs has elapsed
 *   HALF_OPEN -> CLOSED     after cbSuccessThreshold consecutive successes
 *   HALF_OPEN -> OPEN       on any failure
 *
 * While OPEN, allowRequest() returns false and the caller must fast-fail
 * without ever invoking the provider — see services/providers/router.js's
 * _dispatch() and router.stream.js's native-streaming call sites for the two
 * (and only two) integration points.
 */

const { emit } = require('../logger');
const { monoNowMs, wallFromMono } = require('../../src/infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const STATE_CLOSED    = 'CLOSED';
const STATE_OPEN      = 'OPEN';
const STATE_HALF_OPEN = 'HALF_OPEN';

class ProviderCircuitBreaker {
  /**
   * @param {string} providerName
   * @param {object} config  { cbFailureThreshold, cbWindowMs, cbRecoveryMs, cbSuccessThreshold }
   */
  constructor(providerName, config) {
    this._providerName     = providerName;
    this._config           = config;
    this._state            = STATE_CLOSED;
    this._consecutiveFails = 0;
    this._consecutiveOks   = 0;
    this._openedAt         = null;
    this._failWindow       = [];
    // Serializes HALF_OPEN so exactly one concurrent caller is allowed
    // through as the recovery probe; every other concurrent caller is
    // rejected until that probe resolves via onSuccess()/onFailure().
    this._halfOpenProbeInFlight = false;
    this._probeStartedAt = null;
    this._probeSeq = 0; // identifies the current half-open probe so a late release from an expired probe cannot free a newer one
  }

  get state() { return this._state; }

  _startProbe() {
    this._halfOpenProbeInFlight = true;
    this._probeStartedAt = monoNowMs();
    this._probeSeq++;
  }

  /**
   * Returns true if a request may proceed, false if it must be rejected
   * immediately without contacting the provider.
   */
  allowRequest() { return this.acquire().allowed; }

  /**
   * Like allowRequest(), but tells the caller whether it was admitted as THE half-open recovery probe.
   * a probe whose outcome is never reported (an error that does not count against the
   * breaker — 404, auth, cancellation, a skip before the call — or an abandoned stream) used to leave the probe slot
   * taken forever, so every later request was refused without contacting the provider until restart. The caller now
   * calls releaseProbe() for such outcomes, and a probe that never resolves is treated as lost after cbRecoveryMs.
   * @returns {{ allowed: boolean, probe: boolean }}
   */
  acquire() {
    if (this._state === STATE_CLOSED) return { allowed: true, probe: false };

    if (this._state === STATE_OPEN) {
      const elapsed = monoNowMs() - this._openedAt; // monotonic (same-process)
      if (elapsed >= this._config.cbRecoveryMs) {
        this._transition(STATE_HALF_OPEN, 'recovery timeout elapsed');
        this._startProbe();
        return { allowed: true, probe: true, probeId: this._probeSeq }; // allow exactly one probe
      }
      return { allowed: false, probe: false };
    }

    // HALF_OPEN: allow exactly one in-flight probe; reject concurrent callers — unless that probe was lost.
    if (this._halfOpenProbeInFlight
        && (monoNowMs() - (this._probeStartedAt ?? 0)) < this._config.cbRecoveryMs) {
      return { allowed: false, probe: false };
    }
    this._startProbe();
    return { allowed: true, probe: true, probeId: this._probeSeq };
  }

  /** The admitted probe ended with an outcome that is neither a success nor a breaker-counted failure. */
  releaseProbe(probeId) {
    if (probeId !== undefined && probeId !== this._probeSeq) return; // stale release from an expired probe
    if (this._state === STATE_HALF_OPEN) {
      this._halfOpenProbeInFlight = false;
      this._probeStartedAt = null;
    }
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

    emit('INFO', 'PROVIDER_CIRCUIT_BREAKER_STATE', {
      provider: this._providerName,
      from:     prev,
      to:       newState,
      reason,
    });
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

const _registry = new Map();

/**
 * @param {string} providerName
 * @param {object} config
 * @returns {ProviderCircuitBreaker}
 */
function getCircuitBreaker(providerName, config) {
  if (!_registry.has(providerName)) {
    _registry.set(providerName, new ProviderCircuitBreaker(providerName, config));
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
  ProviderCircuitBreaker,
  getCircuitBreaker,
  resetAll,
  snapshot,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
};
