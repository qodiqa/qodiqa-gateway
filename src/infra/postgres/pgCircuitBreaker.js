'use strict';

/**
 * PostgreSQL Query Circuit Breaker (FAILOVER-2).
 *
 * Single process-wide CLOSED/OPEN/HALF_OPEN breaker guarding pool.js's
 * query()/withTransaction() entry points. Structurally identical to the same
 * proven pattern already in production for three other outbound-call
 * subsystems — src/core/webhooks/webhookCircuitBreaker.js,
 * src/infra/keys/resilience/circuitBreaker.js (signing/KMS), and
 * services/providers/providerCircuitBreaker.js (LLM providers) — a single
 * unkeyed instance here rather than a name-keyed registry, since a process
 * has exactly one PostgreSQL backend (one connection string), unlike the
 * per-provider/per-signing-backend/per-webhook-host cases those use a
 * Map-keyed registry for.
 *
 * State transitions (identical to the sibling breakers):
 *   CLOSED    -> OPEN       after cbFailureThreshold consecutive
 *                            failures/timeouts within cbWindowMs
 *   OPEN      -> HALF_OPEN  after cbRecoveryMs has elapsed
 *   HALF_OPEN -> CLOSED     after cbSuccessThreshold consecutive successes
 *   HALF_OPEN -> OPEN       on any failure
 *
 * While OPEN, allowRequest() returns false and pool.js fast-fails with
 * PG_CIRCUIT_OPEN without ever touching the pool — this is what prevents a
 * sustained PostgreSQL outage from cascading into every caller independently
 * stalling for the full connectionTimeoutMillis/statement_timeout on every
 * request (FAILOVER-2's "avoid cascading stalls" requirement).
 *
 * Environment variables:
 *   QODIQA_PG_CB_FAILURE_THRESHOLD  — consecutive failures before OPEN (default 5)
 *   QODIQA_PG_CB_WINDOW_MS          — sliding window for failure counting (default 30000)
 *   QODIQA_PG_CB_RECOVERY_MS        — time OPEN must elapse before HALF_OPEN (default 30000)
 *   QODIQA_PG_CB_SUCCESS_THRESHOLD  — consecutive HALF_OPEN successes to close (default 2)
 */

const { emit } = require('../../../services/logger');
const { monoNowMs } = require('../time/monotonicClock'); // monotonic (same-process) deadlines/windows
// canonical codeless-connection-message set, owned by Core — see the
// usage site below for why this is the sanctioned import direction.
const { CODELESS_CONNECTION_MESSAGES } = require('../../core/persistenceRecovery/persistenceOperation');
let _metrics = null;
function _getMetrics() {
  if (!_metrics) _metrics = require('../../observability/metrics');
  return _metrics;
}

const STATE_CLOSED    = 'CLOSED';
const STATE_OPEN      = 'OPEN';
const STATE_HALF_OPEN = 'HALF_OPEN';

function _parseInt(val, fallback) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function _loadConfig() {
  return Object.freeze({
    cbFailureThreshold: _parseInt(process.env.QODIQA_PG_CB_FAILURE_THRESHOLD, 5),
    cbWindowMs:          _parseInt(process.env.QODIQA_PG_CB_WINDOW_MS,         30_000),
    cbRecoveryMs:        _parseInt(process.env.QODIQA_PG_CB_RECOVERY_MS,       30_000),
    cbSuccessThreshold:  _parseInt(process.env.QODIQA_PG_CB_SUCCESS_THRESHOLD, 2),
  });
}

// PostgreSQL error classes that count as "repeated failures / connection
// timeouts" for breaker purposes — deliberately narrower than "every query
// error": a syntax error or constraint violation is a caller bug, not
// evidence PostgreSQL itself is degraded, and must never trip the breaker.
// Codes: Node-level connection errors (no `code` from `pg` itself — these
// come from the underlying socket/net layer) plus PostgreSQL SQLSTATE
// classes 08 (connection exception), 57 (operator intervention — includes
// 57014 query_canceled from statement_timeout), and 53 (insufficient
// resources — e.g. too_many_connections on the SERVER side).
const _CONNECTION_ERROR_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENOTFOUND', 'EPIPE',
]);

// pg-pool's own connection-ACQUISITION failures (pool exhausted and the
// queued caller's connectionTimeoutMillis elapsed, or a brand-new client's
// handshake itself times out) — and a couple of related `pg` client-liveness
// errors — are plain `new Error(...)` with no `.code` at all (see
// node_modules/pg-pool/index.js and node_modules/pg/lib/client.js). Without
// this, sustained pool exhaustion — the exact "every caller independently
// stalls" scenario this breaker exists to prevent — never trips it (
// #114/5.9). Matched on exact message text, not a broad regex, so an
// unrelated caller-thrown Error can never accidentally trip the breaker.
//
// this used to be a private copy of just the first two of these
// messages, checked here for breaker-failure counting only — a sibling,
// independently-maintained list in persistenceOperation.js (Core) decided
// retry-queue eligibility from a different, only-partially-overlapping set of
// substrings, and 'timeout exceeded when trying to connect' fell in the gap
// between the two: correctly counted against this breaker, but never
// recognized as retryable by the persistence-recovery classifier, so a
// pool-exhaustion failure during an audit-chain write was silently dropped
// instead of queued. Now imported from Core's own canonical set instead of
// duplicated here — Infrastructure importing Core is the one cross-layer
// edge the target layered architecture sanctions in this pair (see
// .dependency-cruiser.js's `no-core-to-infra` rule comment), so this is the
// convergence direction, not the reverse. See the top-of-file import.
function isCircuitBreakerFailure(err) {
  if (!err) return false;

  const code = err.code;
  if (typeof code === 'string') {
    if (_CONNECTION_ERROR_CODES.has(code)) return true;
    if (code.startsWith('08') || code.startsWith('57') || code.startsWith('53')) return true;
  }

  return typeof err.message === 'string' && CODELESS_CONNECTION_MESSAGES.has(err.message);
}

class PgCircuitBreaker {
  constructor(config) {
    this._config            = config;
    this._state              = STATE_CLOSED;
    this._consecutiveFails   = 0;
    this._consecutiveOks     = 0;
    this._openedAt           = null;
    this._failWindow         = [];
    this._halfOpenProbeInFlight = false;
    this._probeStartedAt     = null;
  }

  get state() { return this._state; }

  /** Returns true if a request may proceed, false to fast-fail without touching the pool. */
  allowRequest() {
    if (this._state === STATE_CLOSED) return true;

    if (this._state === STATE_OPEN) {
      const elapsed = monoNowMs() - this._openedAt; // monotonic (same-process)
      if (elapsed >= this._config.cbRecoveryMs) {
        this._transition(STATE_HALF_OPEN, 'recovery timeout elapsed');
        this._halfOpenProbeInFlight = true;
        this._probeStartedAt = monoNowMs(); // monotonic (same-process)
        return true; // allow exactly one probe
      }
      this._recordRejected();
      return false;
    }

    // HALF_OPEN: allow exactly one in-flight probe; reject concurrent callers.
    if (this._halfOpenProbeInFlight) {
      // PH16-D1: probe LEASE. A probe that never settles (a silently partitioned socket) used to
      // hold the half-open slot forever, refusing every later caller until restart. After cbRecoveryMs it counts as a
      // failed probe: back to OPEN, which re-arms the recovery timer, so a fresh probe follows.
      if (this._probeStartedAt && monoNowMs() - this._probeStartedAt >= this._config.cbRecoveryMs) { // monotonic (same-process)
        this._transition(STATE_OPEN, 'half-open probe did not settle within the recovery window');
      }
      this._recordRejected();
      return false;
    }
    this._halfOpenProbeInFlight = true;
    this._probeStartedAt = monoNowMs(); // monotonic (same-process)
    return true;
  }

  /**
   * PH16-D1: classify ANY error a gated call settled with. Previously only
   * connection-class errors reached the breaker; every other error left a half-open probe "in flight" forever, so a
   * single caller-class error (unique violation, 22P02, 40001) or an unclassified driver error ("Connection terminated
   * unexpectedly") on the first call after an outage wedged the breaker until restart.
   *   connection-class            → onFailure()
   *   any other SQLSTATE reply    → onSuccess(): the server answered, so it is up
   *   anything else (unclassified) → a failure only while it is the half-open probe; ignored in CLOSED as before
   */
  onError(err) {
    if (isCircuitBreakerFailure(err)) return this.onFailure();
    if (err && typeof err.code === 'string' && /^[0-9A-Z]{5}$/.test(err.code)) return this.onSuccess();
    if (this._state === STATE_HALF_OPEN && this._halfOpenProbeInFlight) return this.onFailure();
    return undefined;
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

  _recordRejected() {
    try { _getMetrics().pgCircuitRejectedTotal.inc({}); } catch { /* metrics must never break the resilience path */ }
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

    emit('INFO', 'PG_CIRCUIT_BREAKER_STATE', { from: prev, to: newState, reason });

    try {
      const m = _getMetrics();
      if (newState === STATE_OPEN)      m.pgCircuitOpensTotal.inc({});
      if (newState === STATE_CLOSED)    m.pgCircuitClosesTotal.inc({});
      if (newState === STATE_HALF_OPEN) m.pgCircuitHalfOpenTotal.inc({});
    } catch { /* metrics must never break the resilience path */ }
  }
}

let _instance = new PgCircuitBreaker(_loadConfig());

/** The single process-wide PostgreSQL circuit breaker instance. */
function getCircuitBreaker() {
  return _instance;
}

/** Rebuilds the breaker from current env + resets state. Tests only. */
function reset() {
  _instance = new PgCircuitBreaker(_loadConfig());
}

/**
 * A SEPARATE breaker instance (same config, own state) — audit 2026-10-20: the dedicated role pools (system / reporting /
 * control) had none, so a degraded database made every consumer wait out connectionTimeoutMillis on each call. One instance per
 * pool keeps their failure domains independent of the request-serving breaker above.
 */
function createBreaker() {
  return new PgCircuitBreaker(_loadConfig());
}

function circuitOpenError() {
  return Object.assign(new Error('PostgreSQL circuit breaker is OPEN — fast-failing without contacting the database'), { code: 'PG_CIRCUIT_OPEN' });
}

/** Run `fn` through `breaker`: fast-fail while OPEN, classify the outcome otherwise (expected refusals count as "the server answered"). */
async function runGated(breaker, fn) {
  if (!breaker.allowRequest()) throw circuitOpenError();
  try {
    const out = await fn();
    breaker.onSuccess();
    return out;
  } catch (e) {
    if (e && e.expectedRefusal) breaker.onSuccess(); else breaker.onError(e);
    throw e;
  }
}

module.exports = {
  getCircuitBreaker,
  createBreaker,
  circuitOpenError,
  runGated,
  isCircuitBreakerFailure,
  reset,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
};
