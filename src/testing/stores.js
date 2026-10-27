'use strict';

/**
 * Shared in-memory store factories for test suites.
 *
 * Each factory returns an object that satisfies the same interface as the
 * production Redis-backed stores (nonceStore, anomalyStore) so that tests
 * exercise identical validation logic without a real Redis connection.
 *
 * Interface contracts:
 *
 *   NonceStore
 *     register(requestId, expiryMs)  → Promise<{ registered: boolean }>
 *     isRegistered(requestId)        → Promise<boolean>
 *
 *   AnomalyStore
 *     record(key, nowMs, windowMs)   → Promise<{ count: number }>
 *     peek(key, nowMs, windowMs)     → Promise<{ count: number }>
 *
 * NOT imported by any production code.
 */

const { buildNonceKey } = require('../validation/nonceStore');

/**
 * In-memory nonce store backed by a Map.
 * register() writes; isRegistered() reads; both are synchronous under the hood.
 * Keys are built via buildNonceKey() — the same canonical builder the real
 * Redis-backed store uses — so tests exercise the real key format
 * (QODIQA-PROTOCOL-SPEC.md §27.11), not an ad-hoc approximation of it.
 */
function makeNonceStore() {
  const map = new Map();
  return {
    async register(requestId, expiryMs, tenantId) {
      const key = buildNonceKey(requestId, tenantId);
      if (map.has(key)) return { registered: false };
      map.set(key, expiryMs);
      return { registered: true };
    },
    async isRegistered(requestId, tenantId) { return map.has(buildNonceKey(requestId, tenantId)); },
    _map: map,
  };
}

/**
 * Always-open anomaly store — never triggers rate limits.
 * Returns { count: 0 } from both record() and peek() so it is safe to use
 * in both the runtime path (record) and the dry-run path (peek).
 */
function makeOpenAnomalyStore() {
  return {
    async record() { return { count: 0 }; },
    async peek()   { return { count: 0 }; },
  };
}

/**
 * Real counting anomaly store — increments per-key counters.
 * Implements the same sliding-window interface as the production Redis store
 * so that threshold enforcement logic can be tested without Redis.
 */
function makeCountingAnomalyStore() {
  const counts = new Map();
  const inc = (key) => {
    const n = (counts.get(key) || 0) + 1;
    counts.set(key, n);
    return { count: n };
  };
  return {
    async record(key) { return inc(key); },
    async peek(key)   { return { count: counts.get(key) || 0 }; },
    _counts: counts,
  };
}

/**
 * Dead store — every method throws, simulating a Redis/backend outage.
 * Implements all store interfaces so a single instance can replace either
 * a nonce store or an anomaly store in tests.
 *
 * @param {string} [msg] — error message thrown by all methods
 */
function makeDeadStore(msg = 'ECONNREFUSED') {
  const fail = async () => { throw new Error(msg); };
  return { register: fail, isRegistered: fail, record: fail, peek: fail };
}

/**
 * In-memory idempotency store — mirrors src/core/idempotency/idempotencyStore.js's
 * interface (reserve/complete/release/get) and its buildIdempotencyKey
 * tenant-scoping convention, without a real Redis connection.
 *
 * reserve() is atomic in the sense that matters for single-process tests:
 * synchronous Map.has()/Map.set() with no `await` between them, so no two
 * "concurrent" in-process calls can interleave between the check and the
 * write — the same guarantee Redis's SET NX gives across processes.
 */
function makeIdempotencyStore() {
  const map = new Map();
  const _key = (tenantId, idempotencyKey) => (tenantId ? `${tenantId}:${idempotencyKey}` : idempotencyKey);

  return {
    async reserve(tenantId, idempotencyKey, fingerprint, _reservationTtlMs) {
      const key = _key(tenantId, idempotencyKey);
      if (map.has(key)) return { reserved: false, existing: map.get(key) };
      map.set(key, { status: 'pending', fingerprint, tenantId: tenantId || null, createdAt: Date.now() });
      return { reserved: true };
    },
    async complete(tenantId, idempotencyKey, record, _retentionTtlMs) {
      const key = _key(tenantId, idempotencyKey);
      if (!map.has(key)) return { completed: false };
      map.set(key, { ...record, status: 'completed', tenantId: tenantId || null, completedAt: Date.now() });
      return { completed: true };
    },
    async release(tenantId, idempotencyKey) {
      map.delete(_key(tenantId, idempotencyKey));
    },
    async get(tenantId, idempotencyKey) {
      return map.has(_key(tenantId, idempotencyKey)) ? map.get(_key(tenantId, idempotencyKey)) : null;
    },
    _map: map,
  };
}

module.exports = {
  makeNonceStore,
  makeOpenAnomalyStore,
  makeCountingAnomalyStore,
  makeDeadStore,
  makeIdempotencyStore,
};
