'use strict';

/**
 * QODIQA V2 — Atomic nonce registration.
 *
 * registerNonce() is the single enforcement point for execution uniqueness.
 * It translates artifact-level semantics (requestId + expiry) into a single
 * atomic nonce-store operation and returns a structured result.
 *
 * Design rules:
 *   • The production nonce store is loaded lazily so tests that inject _store
 *     never trigger a Redis connection attempt at module load time.
 *   • Any store error (unavailable, I/O failure) returns NONCE_STORE_ERROR —
 *     the request is blocked.  There is no fallback or degraded mode.
 *   • An expired TTL is caught before the store call — prevents storing a key
 *     that would expire immediately and leave a false "used" signal.
 *   • requestId and tenantId are passed to the store SEPARATELY — the store
 *     (nonceStore.buildNonceKey) is the single source of truth for how they
 *     combine into a key (QODIQA-PROTOCOL-SPEC.md §27.11). This function must
 *     never pre-concatenate them itself.
 */

const { isValidRequestId } = require('./requestId');

/**
 * Register a requestId in the persistent nonce store (atomic).
 *
 * @param {string} requestId  UUID v4 — from verifyRequestBinding result
 * @param {number} expiryMs   Artifact expiry in epoch-ms — determines TTL
 * @param {{ _store?: object, tenantId?: string|null, issuedAtMs?: number }} [opts]
 *   _store: nonce store override for testing; omit in production.
 *
 * @returns {Promise<
 *   { ok: true,  requestId: string } |
 *   { ok: false, reason: 'REPLAY_DETECTED' | 'EXPIRED' |
 *                        'MALFORMED_REQUEST_ID' | 'INVALID_EXPIRY' |
 *                        'NONCE_STORE_ERROR' | 'REPLAY_STATE_UNPROVABLE',
 *     details?: object }
 * >}
 */
async function registerNonce(requestId, expiryMs, { _store, tenantId, issuedAtMs = 0 } = {}) {
  // Lazy-load the production store only when no test store is injected.
  // This prevents Redis connection attempts during tests.
  const store = _store !== undefined ? _store : require('./nonceStore');

  // ── Input validation ────────────────────────────────────────────────────────
  if (!isValidRequestId(requestId)) {
    return { ok: false, reason: 'MALFORMED_REQUEST_ID', details: { requestId } };
  }
  if (!Number.isFinite(expiryMs) || expiryMs <= 0) {
    return { ok: false, reason: 'INVALID_EXPIRY', details: { expiryMs } };
  }

  // ── TTL pre-check ───────────────────────────────────────────────────────────
  // Catch already-expired artifacts before writing to the store.
  // validateArtifact checked expiry at parse time, but skew between that check
  // and this point could cause a near-zero TTL to reach the store.
  const ttlMs = expiryMs - Date.now();
  if (ttlMs <= 0) {
    return { ok: false, reason: 'EXPIRED', details: { expiryMs, nowMs: Date.now() } };
  }

  // ── Atomic registration ─────────────────────────────────────────────────────
  // requestId and tenantId are forwarded separately — the store owns key
  // construction (namespacing two tenants that share a requestId is the
  // store's responsibility, not this function's).
  try {
    const result = await store.register(requestId, expiryMs, tenantId, issuedAtMs);

    if (!result.registered && result.unprovable) {
      // issued before the Redis server's last start — replay state unprovable.
      return { ok: false, reason: 'REPLAY_STATE_UNPROVABLE', details: { requestId } };
    }
    if (!result.registered) {
      return { ok: false, reason: 'REPLAY_DETECTED', details: { requestId } };
    }

    return { ok: true, requestId };

  } catch (err) {
    // Store unavailable, I/O failure, or invalid TTL — fail-closed: block.
    // details reach the client in the BLOCK body — a stable generic code goes
    // out, the raw store error text stays in the server log.
    _logStoreError('registerNonce', err);
    return {
      ok:      false,
      reason:  'NONCE_STORE_ERROR',
      details: { error: NONCE_STORE_ERROR_DETAIL },
    };
  }
}

// the only value a client ever sees in NONCE_STORE_ERROR details.error.
const NONCE_STORE_ERROR_DETAIL = 'NONCE_STORE_UNAVAILABLE';

function _logStoreError(where, err) {
  try {
    require('../../services/logger').emit('ERROR', 'NONCE_STORE_ERROR', { where, error: err?.message ?? String(err), code: err?.code ?? null });
  } catch { /* logging must never change the fail-closed result */ }
}

module.exports = { registerNonce, NONCE_STORE_ERROR_DETAIL, _logStoreError };
