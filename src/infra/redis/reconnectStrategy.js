'use strict';

/**
 * Shared bounded reconnect strategy — exponential backoff + jitter + circuit
 * breaking.
 *
 * This is used for the per-node socket-level reconnectStrategy inside
 * Sentinel/Cluster mode (managedClient.js) — it bounds how hard a single node
 * connection is hammered, while the Sentinel/Cluster topology layer above it
 * is what actually provides failover (re-resolving to a new master/node
 * rather than retrying a dead one forever).
 *
 * Existing single-mode stores (nonceStore.js, anomalyStore.js, etc.) keep
 * their own long-standing bespoke reconnectStrategy functions unchanged —
 * they are already tested and this module does not replace them. Backward
 * compatibility for single-instance deployments is therefore total: nothing
 * about their retry behavior changes by installing.
 *
 * Circuit breaker: once `maxAttempts` consecutive failures accumulate against
 * one node, the breaker "opens" — createStrategy's returned function reports
 * exhaustion (returns `false`, matching node-redis's "stop reconnecting"
 * contract) for `circuitBreakerCooldownMs`, then resets and allows a fresh
 * attempt cycle. This prevents a single unreachable node from being retried
 * in a tight loop indefinitely (a "reconnect storm") while still eventually
 * giving it another chance once the cooldown elapses, in case it comes back.
 */

const { monoNowMs } = require('../time/monotonicClock'); // monotonic (same-process) deadlines/windows

/**
 * @param {object} opts
 * @param {string} [opts.source]                Label used only in log/telemetry callbacks below.
 * @param {number} [opts.maxAttempts=5]
 * @param {number} [opts.baseDelayMs=100]
 * @param {number} [opts.maxDelayMs=2000]
 * @param {number} [opts.jitterRatio=0.2]      0..1 — ± this fraction of the computed delay
 * @param {number} [opts.circuitBreakerCooldownMs=30000]
 * @param {(info: {source:string, retries:number, delayMs:number}) => void} [opts.onRetry]
 * @param {(info: {source:string, retries:number}) => void} [opts.onExhausted]
 * @param {() => number} [opts._now]           injectable clock for tests
 * @param {() => number} [opts._random]        injectable RNG (0..1) for deterministic tests
 * @returns {(retries: number) => number|false} a node-redis compatible reconnectStrategy
 */
function createBoundedReconnectStrategy({
  source,
  maxAttempts = 5,
  baseDelayMs = 100,
  maxDelayMs = 2_000,
  jitterRatio = 0.2,
  circuitBreakerCooldownMs = 30_000,
  onRetry,
  onExhausted,
  _now = () => monoNowMs(), // monotonic (same-process) — the cooldown stamp never leaves this closure
  _random = () => Math.random(),
} = {}) {
  let circuitOpenedAt = null;

  return function boundedReconnectStrategy(retries) {
    // Circuit breaker: if we tripped open, refuse to retry until the cooldown
    // elapses — then reset and allow a fresh attempt cycle.
    if (circuitOpenedAt !== null) {
      if (_now() - circuitOpenedAt < circuitBreakerCooldownMs) {
        return false;
      }
      circuitOpenedAt = null; // cooldown elapsed — give it another cycle
    }

    if (retries >= maxAttempts) {
      circuitOpenedAt = _now();
      onExhausted?.({ source, retries });
      return false;
    }

    const exponential = Math.min(baseDelayMs * Math.pow(2, retries), maxDelayMs);
    const jitterSpan  = exponential * jitterRatio;
    // Uniform jitter in [-jitterSpan, +jitterSpan], clamped to a sane floor so
    // the delay never goes to (or below) zero.
    const jitter      = (_random() * 2 - 1) * jitterSpan;
    const delayMs      = Math.max(1, Math.round(exponential + jitter));

    onRetry?.({ source, retries, delayMs });
    return delayMs;
  };
}

/**
 * remediation — infinite-retry variant for single-instance stores.
 *
 * Unlike createBoundedReconnectStrategy above (HA/Sentinel per-node retries,
 * where a circuit-breaker false is safe because the Sentinel/Cluster
 * topology layer above it re-resolves to a different node), a single-
 * instance store has no other node to fail over to — returning false here
 * means "give up until the process is restarted," which is exactly the
 * defect Findings Register documents across all four Redis-backed
 * enforcement stores (rate-limit, nonce, anomaly, idempotency): each
 * independently implemented MAX_RECONNECTS=5 then gave up permanently.
 *
 * This strategy NEVER returns false. It matches the earlier curve for the
 * first ~4 retries (same base/exponent), then keeps climbing to the higher
 * 30s cap instead of flat-lining at 2s and giving up — the two curves are
 * NOT identical past that point, only the early shape matches. Past
 * `oldMaxReconnects` every callback is marked `pastOldThreshold: true` —
 * loud, not silent — instead of the client going dark. Callers own their
 * own emit()/counter side effects via onRetry, so each store's existing
 * event shape (source, extra fields) is preserved exactly; this module
 * only owns the delay/give-up policy.
 *
 * @param {object} opts
 * @param {string} [opts.source]
 * @param {number} [opts.oldMaxReconnects=5]  where the old bounded strategies used to give up
 * @param {number} [opts.baseDelayMs=100]
 * @param {number} [opts.maxDelayMs=30000]     hard ceiling — jitter is clamped, never exceeds this
 * @param {number} [opts.jitterRatio=0.2]
 * @param {(info: {source:string, retries:number, delayMs:number, pastOldThreshold:boolean}) => void} [opts.onRetry]
 * @param {() => number} [opts._random]  injectable RNG (0..1) for deterministic tests
 * @returns {(retries: number) => number} a node-redis compatible reconnectStrategy — NEVER returns false
 */
function createInfiniteReconnectStrategy({
  source,
  oldMaxReconnects = 5,
  baseDelayMs = 100,
  maxDelayMs = 30_000,
  jitterRatio = 0.2,
  onRetry,
  _random = () => Math.random(),
} = {}) {
  if (!source) throw new Error('createInfiniteReconnectStrategy: opts.source is required');

  return function infiniteReconnectStrategy(retries) {
    const exponential = Math.min(baseDelayMs * Math.pow(2, retries), maxDelayMs);
    const jitterSpan  = exponential * jitterRatio;
    const jitter      = (_random() * 2 - 1) * jitterSpan;
    const delayMs     = Math.min(maxDelayMs, Math.max(1, Math.round(exponential + jitter)));
    const pastOldThreshold = retries >= oldMaxReconnects;

    onRetry?.({ source, retries, delayMs, pastOldThreshold });
    return delayMs; // never false — infinite retry, capped + jittered
  };
}

module.exports = { createBoundedReconnectStrategy, createInfiniteReconnectStrategy };
