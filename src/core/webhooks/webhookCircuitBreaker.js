'use strict';

/**
 * Webhook Circuit Breaker — Component 44.6
 *
 * Per-host circuit breaker with three states: CLOSED, OPEN, HALF_OPEN.
 *
 * State transitions:
 *   CLOSED    → OPEN       after cbFailureThreshold consecutive failures
 *                           within cbWindowMs
 *   OPEN      → HALF_OPEN  after cbRecoveryMs has elapsed
 *   HALF_OPEN → CLOSED     after cbSuccessThreshold consecutive successes
 *   HALF_OPEN → OPEN       on any failure
 *
 * Behavior:
 *   • CLOSED:    requests proceed normally
 *   • OPEN:      requests are rejected immediately; no outbound connection is made
 *   • HALF_OPEN: one probe request is allowed; outcome decides next state
 *
 * Instances are keyed by hostname and held in a module-level registry.
 * The registry is cleared between test runs via reset().
 */

const { emit } = require('../../../services/logger');
const { monoNowMs, wallFromMono } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows

const STATE_CLOSED    = 'CLOSED';
const STATE_OPEN      = 'OPEN';
const STATE_HALF_OPEN = 'HALF_OPEN';

// ── CircuitBreaker class ──────────────────────────────────────────────────────

class CircuitBreaker {
  /**
   * @param {string} host
   * @param {object} config  webhookSecurityConfig fields
   */
  constructor(host, config) {
    this._host             = host;
    this._config           = config;
    this._state            = STATE_CLOSED;
    this._consecutiveFails = 0;
    this._consecutiveOks   = 0;
    this._openedAt         = null;
    // Rolling window of failure timestamps
    this._failWindow       = [];
  }

  // ── State queries ───────────────────────────────────────────────────────────

  get state() { return this._state; }

  /**
   * Returns true if a request may proceed, false if it must be rejected.
   * In HALF_OPEN exactly one probe is permitted; subsequent calls return false
   * until the probe resolves via onSuccess() / onFailure().
   */
  allowRequest() {
    if (this._state === STATE_CLOSED) return true;

    if (this._state === STATE_OPEN) {
      const elapsed = monoNowMs() - this._openedAt; // monotonic (same-process)
      if (elapsed >= this._config.cbRecoveryMs) {
        this._transition(STATE_HALF_OPEN, 'recovery timeout elapsed');
        return true; // allow the probe
      }
      return false;
    }

    // HALF_OPEN: only the single probe is allowed; block all concurrent requests
    return true;
  }

  // ── Outcome recording ───────────────────────────────────────────────────────

  onSuccess() {
    if (this._state === STATE_HALF_OPEN) {
      this._consecutiveOks++;
      if (this._consecutiveOks >= this._config.cbSuccessThreshold) {
        this._consecutiveFails = 0;
        this._consecutiveOks   = 0;
        this._failWindow       = [];
        this._transition(STATE_CLOSED, 'success threshold reached in half-open');
      }
      return;
    }
    // CLOSED: reset failure tracking on success
    this._consecutiveFails = 0;
    this._failWindow       = [];
  }

  onFailure() {
    const now = monoNowMs(); // monotonic (same-process)

    if (this._state === STATE_HALF_OPEN) {
      this._consecutiveOks = 0;
      this._transition(STATE_OPEN, 'failure in half-open');
      return;
    }

    // Prune failures outside the rolling window
    const windowStart = now - this._config.cbWindowMs;
    this._failWindow = this._failWindow.filter(ts => ts >= windowStart);
    this._failWindow.push(now);
    this._consecutiveFails++;

    if (this._consecutiveFails >= this._config.cbFailureThreshold) {
      this._transition(STATE_OPEN, 'failure threshold reached');
    }
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  _transition(newState, reason) {
    const prev = this._state;
    this._state = newState;

    if (newState === STATE_OPEN) {
      this._openedAt       = monoNowMs(); // monotonic (same-process)
      this._consecutiveOks = 0;
    } else if (newState === STATE_HALF_OPEN) {
      this._consecutiveOks = 0;
    }

    emit('INFO', 'WEBHOOK_CIRCUIT_BREAKER_STATE', {
      host:     this._host,
      from:     prev,
      to:       newState,
      reason,
    });
  }
}

// ── Registry ──────────────────────────────────────────────────────────────────

const _registry = new Map();

/**
 * Return (creating if needed) the CircuitBreaker for a given host.
 *
 * @param {string} host
 * @param {object} config
 * @returns {CircuitBreaker}
 */
function getCircuitBreaker(host, config) {
  if (!_registry.has(host)) {
    _registry.set(host, new CircuitBreaker(host, config));
  }
  return _registry.get(host);
}

/**
 * Clear all circuit breakers. Used in tests to reset state between runs.
 */
function resetAll() {
  _registry.clear();
}

/**
 * Snapshot of all circuit breaker states for observability.
 *
 * @returns {object}
 */
function snapshot() {
  const out = {};
  for (const [host, cb] of _registry) {
    out[host] = {
      state:             cb.state,
      consecutiveFails:  cb._consecutiveFails,
      consecutiveOks:    cb._consecutiveOks,
      openedAt:          wallFromMono(cb._openedAt), // wall-clock equivalent for display
    };
  }
  return out;
}

module.exports = { CircuitBreaker, getCircuitBreaker, resetAll, snapshot, STATE_CLOSED, STATE_OPEN, STATE_HALF_OPEN };
