'use strict';

/**
 * QODIQA V2 — Combined nonce registration + anomaly detection (item 17).
 *
 * Same external contract as calling registerNonce() then checkAnomaly() in
 * sequence: same input validation, same fail-closed behavior, same result
 * shapes. Collapses the underlying Redis work into one round trip via
 * nonceStore.registerAndCheckAnomaly() (a single combined Lua EVAL) instead
 * of three sequential calls.
 *
 * Design rules (mirrors registerNonce.js):
 *   • The production nonce store is loaded lazily so tests that inject
 *     _store never trigger a Redis connection attempt at module load time.
 *   • Any store error blocks the request — fail-closed, no fallback.
 *   • An expired TTL is caught before the store call.
 */

const { isValidRequestId }  = require('./requestId');
const { resolveThresholds } = require('./checkAnomaly');

/**
 * @param {string} requestId    UUID v4 — from verifyRequestBinding result
 * @param {number} expiryMs     Artifact expiry in epoch-ms — determines nonce TTL
 * @param {string} publicKeyId  Signature-verified public key ID — anomaly tracking key
 * @param {{ _store?: object, tenantId?: string|null, _clock?: () => number, _thresholds?: object, issuedAtMs?: number }} [opts]
 *
 * @returns {Promise<{
 *   nonceResult:   { ok: true, requestId: string } |
 *                  { ok: false, reason: 'REPLAY_DETECTED'|'EXPIRED'|'MALFORMED_REQUEST_ID'|'INVALID_EXPIRY'|'NONCE_STORE_ERROR'|'REPLAY_STATE_UNPROVABLE', details?: object },
 *   anomalyResult: { block: false } | { block: true, reason: 'ANOMALY_DETECTED', type: 'SIGNATURE_BURST'|'RATE_BURST' } | null,
 * }>}
 *   anomalyResult is null whenever nonceResult.ok is false — the combined
 *   script never reaches the anomaly windows once the nonce check fails,
 *   exactly like the sequential path never calling checkAnomaly() in that
 *   case.
 */
async function registerNonceAndCheckAnomaly(requestId, expiryMs, publicKeyId, { _store, tenantId, _clock, _thresholds, issuedAtMs = 0 } = {}) {
  const store = _store !== undefined ? _store : require('./nonceStore');

  // ── Input validation — same checks and same order as registerNonce.js ──────
  if (!isValidRequestId(requestId)) {
    return { nonceResult: { ok: false, reason: 'MALFORMED_REQUEST_ID', details: { requestId } }, anomalyResult: null };
  }
  if (!Number.isFinite(expiryMs) || expiryMs <= 0) {
    return { nonceResult: { ok: false, reason: 'INVALID_EXPIRY', details: { expiryMs } }, anomalyResult: null };
  }
  const ttlMs = expiryMs - Date.now();
  if (ttlMs <= 0) {
    return { nonceResult: { ok: false, reason: 'EXPIRED', details: { expiryMs, nowMs: Date.now() } }, anomalyResult: null };
  }

  const thresholds = resolveThresholds(tenantId, _thresholds);
  const nowMs      = (_clock || Date.now)();

  try {
    const result = await store.registerAndCheckAnomaly(requestId, expiryMs, tenantId, {
      publicKeyId,
      nowMs,
      windowMs:  thresholds.WINDOW_MS,
      perKeyMax: thresholds.PER_KEY_MAX,
      globalMax: thresholds.GLOBAL_MAX,
      issuedAtMs, // the restart barrier
    });

    if (result.phase === 'REPLAY') {
      return { nonceResult: { ok: false, reason: 'REPLAY_DETECTED', details: { requestId } }, anomalyResult: null };
    }
    if (result.phase === 'REPLAY_UNPROVABLE') {
      // issued before the Redis server's last start — its nonce may have
      // been lost with the restart, so "not used before" cannot be proven.
      return { nonceResult: { ok: false, reason: 'REPLAY_STATE_UNPROVABLE', details: { requestId, redisStartedMs: result.redisStartedMs } }, anomalyResult: null };
    }
    if (result.phase === 'SIGNATURE_BURST') {
      return {
        nonceResult:   { ok: true, requestId },
        anomalyResult: { block: true, reason: 'ANOMALY_DETECTED', type: 'SIGNATURE_BURST' },
      };
    }
    if (result.phase === 'RATE_BURST') {
      return {
        nonceResult:   { ok: true, requestId },
        anomalyResult: { block: true, reason: 'ANOMALY_DETECTED', type: 'RATE_BURST' },
      };
    }
    return { nonceResult: { ok: true, requestId }, anomalyResult: { block: false } };

  } catch (err) {
    // Fail-closed. Because the combined script is one atomic Redis EVAL, a
    // thrown error here means NEITHER the nonce write NOR any anomaly write
    // happened (see ITEM-17-REMEDIATION-REPORT.md §4) — so NONCE_STORE_ERROR
    // (nonce not registered) is the correct classification for every error
    // from this call, unlike the sequential path where a post-nonce anomaly
    // failure reports ANOMALY_DETECTED/STORE_ERROR with the nonce already
    // burned. See the report for why that specific sub-case no longer has a
    // direct equivalent once both checks share one connection.
    // these details reach the client in the BLOCK body — never the raw store
    // error text (it can carry Redis host/port/script internals). A stable generic code goes out; the detail stays
    // in the server log.
    _logStoreError('registerNonceAndCheckAnomaly', err);
    return {
      nonceResult:   { ok: false, reason: 'NONCE_STORE_ERROR', details: { error: NONCE_STORE_ERROR_DETAIL } },
      anomalyResult: null,
    };
  }
}

const { NONCE_STORE_ERROR_DETAIL, _logStoreError } = require('./registerNonce');

module.exports = { registerNonceAndCheckAnomaly };
