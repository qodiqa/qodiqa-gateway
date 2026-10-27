'use strict';

/**
 * QODIQA V2 — Dry-run store wrappers for /verify/v2.
 *
 * These stores let validateBoundRequest run the full V2 pipeline without
 * mutating any persistent state.  They are the ONLY mechanism by which
 * /verify/v2 achieves "same decision as runtime, no side effects".
 *
 * ── Dry-run nonce store ───────────────────────────────────────────────────────
 *
 *   register(requestId, expiryMs)
 *     → reads  nonceStore.isRegistered(requestId)
 *     → NEVER  writes to the nonce store
 *     → returns { registered: false } if requestId already exists (REPLAY)
 *     → returns { registered: true  } if requestId is new (would succeed)
 *     → throws if Redis is unavailable (fail-closed — same as production)
 *
 * ── Dry-run anomaly store ─────────────────────────────────────────────────────
 *
 *   record(key, nowMs, windowMs)
 *     → reads  anomalyStore.peek(key, nowMs, windowMs) — current window count
 *     → NEVER  increments the sorted set
 *     → returns { count: current + 1 } — simulates what the next real write
 *       would see, so threshold comparisons in checkAnomaly produce the same
 *       decision as runtime would produce for this request
 *     → throws if Redis is unavailable (fail-closed — same as production)
 *
 * ── Lazy loading ─────────────────────────────────────────────────────────────
 *
 *   Production stores are loaded on first use, not at module import time.
 *   This prevents Redis connection attempts when the module is required in
 *   test environments that inject their own stores.
 */

/**
 * Create a dry-run nonce store.
 *
 * @param {{ isRegistered: (id: string, tenantId?: string|null) => Promise<boolean> }} [injectedStore]
 *   In tests, inject a fake nonceStore.  Omit in production.
 * @returns {{ register: (requestId: string, expiryMs: number, tenantId?: string|null) => Promise<{ registered: boolean }> }}
 */
function makeDryRunNonceStore(injectedStore) {
  return {
    async register(requestId, _expiryMs, tenantId) {
      const store       = injectedStore !== undefined ? injectedStore : require('./nonceStore');
      const alreadyUsed = await store.isRegistered(requestId, tenantId);
      // If already registered → replay → { registered: false }
      // If not registered    → would succeed but we don't write → { registered: true }
      return { registered: !alreadyUsed };
    },
  };
}

/**
 * Create a dry-run anomaly store.
 *
 * @param {{ peek: (key: string, nowMs: number, windowMs: number) => Promise<{ count: number }> }} [injectedStore]
 *   In tests, inject a fake anomalyStore.  Omit in production.
 * @returns {{ record: (key: string, nowMs: number, windowMs: number) => Promise<{ count: number }> }}
 */
function makeDryRunAnomalyStore(injectedStore) {
  return {
    async record(key, nowMs, windowMs) {
      const store          = injectedStore !== undefined ? injectedStore : require('./anomalyStore');
      const { count: cur } = await store.peek(key, nowMs, windowMs);
      // Return current + 1: simulates what checkAnomaly would see after this
      // request is recorded, without actually recording it.
      return { count: cur + 1 };
    },
  };
}

/**
 * Create a dry-run policy store for /verify.
 *
 * checkAndIncrement() peeks the real store's counter via getCount() (a pure
 * read) and computes the same admit/deny decision the runtime's atomic
 * check-and-increment would make — but it NEVER calls the real store's
 * write path, so /verify can never consume rate-limit quota. This mirrors
 * what the runtime would decide (identical BLOCK/ALLOW at threshold) without
 * the side effect.
 *
 * Stateless policies (BLOCK_IP, REQUIRE_CONSENT, TIME_WINDOW) are unaffected —
 * they do not use the store at all.
 *
 * @param {{ getCount: function }} [realStore]
 *   Pass the production policy store.  Omit or pass undefined in tests that
 *   do not exercise RATE_LIMIT policies.
 * @returns {{ checkAndIncrement: function }}
 */
function makeDryRunPolicyStore(realStore) {
  return {
    async checkAndIncrement(key, windowSeconds, maxRequests) {
      const count = (realStore && typeof realStore.getCount === 'function')
        ? await realStore.getCount(key, windowSeconds)
        : 0;
      return { allowed: count < maxRequests, count };
    },
  };
}

module.exports = { makeDryRunNonceStore, makeDryRunAnomalyStore, makeDryRunPolicyStore };
