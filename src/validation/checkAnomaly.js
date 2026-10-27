'use strict';

/**
 * QODIQA V2 — Anomaly detection enforcement.
 *
 * Checks two sliding windows in sequence:
 *   1. Per-publicKeyId (SIGNATURE_BURST) — prevents a single key from flooding
 *   2. Global (RATE_BURST)               — prevents fleet-wide request floods
 *
 * Both windows use the same duration (WINDOW_MS).  The per-key check runs first
 * because it is the tighter constraint and consumes no global quota on burst.
 *
 * Fail-closed: any store error immediately returns block: true.
 *
 * Thresholds (injectable for tests):
 *   WINDOW_MS       — sliding window duration in ms   (default: 60_000)
 *   PER_KEY_MAX     — max events per key per window   (default: 100)
 *   GLOBAL_MAX      — max events globally per window  (default: 5_000)
 */

const { emit }                = require('../../services/logger');
const { getQuotasForTenant }  = require('../core/organizations/organizationRegistry');

const DEFAULT_THRESHOLDS = Object.freeze({
  WINDOW_MS:   60_000,
  PER_KEY_MAX: 100,
  GLOBAL_MAX:  5_000,
});

/**
 * Resolve effective anomaly thresholds for a tenant.
 * Priority: test override > per-org quotas > platform defaults.
 */
function _resolveThresholds(tenantId, _thresholds) {
  if (_thresholds !== undefined) return _thresholds;
  try {
    const q = getQuotasForTenant(tenantId || '');
    return Object.freeze({
      WINDOW_MS:   DEFAULT_THRESHOLDS.WINDOW_MS,
      PER_KEY_MAX: q.maxRequestsPerKeyPerMin ?? DEFAULT_THRESHOLDS.PER_KEY_MAX,
      GLOBAL_MAX:  q.maxRequestsPerMinute    ?? DEFAULT_THRESHOLDS.GLOBAL_MAX,
    });
  } catch {
    return DEFAULT_THRESHOLDS;
  }
}

/**
 * Record the current event and decide whether to block.
 *
 * @param {string} publicKeyId
 * @param {{
 *   _store?:      { record: (key: string, nowMs: number, windowMs: number) => Promise<{ count: number }> },
 *   _clock?:      () => number,
 *   _thresholds?: { WINDOW_MS: number, PER_KEY_MAX: number, GLOBAL_MAX: number },
 *   tenantId?:    string|null,
 * }} [opts]
 *
 * @returns {Promise<
 *   { block: false } |
 *   { block: true, reason: 'ANOMALY_DETECTED', type: 'SIGNATURE_BURST' | 'RATE_BURST' | 'STORE_ERROR', error?: string }
 * >}
 */
async function checkAnomaly(publicKeyId, { _store, _clock, _thresholds, tenantId } = {}) {
  if (typeof publicKeyId !== 'string' || !publicKeyId) {
    return { block: true, reason: 'ANOMALY_DETECTED', type: 'STORE_ERROR', error: 'publicKeyId must be a non-empty string' };
  }

  const store      = _store !== undefined ? _store : require('./anomalyStore');
  const thresholds = _resolveThresholds(tenantId, _thresholds);
  const nowMs      = (_clock || Date.now)();
  const windowMs   = thresholds.WINDOW_MS;

  // Prefix store keys with tenant namespace to isolate anomaly counters
  // per-tenant.  Without a tenantId the keys are unscoped (legacy behaviour).
  const prefix = tenantId ? `tenant:${tenantId}:` : '';

  try {
    // ── 1. Per-key sliding window (SIGNATURE_BURST) ──────────────────────────
    const perKeyStoreKey = `${prefix}key:${publicKeyId}`;
    const keyResult = await store.record(perKeyStoreKey, nowMs, windowMs);
    emit('INFO', 'ANOMALY_STATE_INCREMENTED', {
      key:       perKeyStoreKey,
      count:     keyResult.count,
      threshold: thresholds.PER_KEY_MAX,
      windowMs,
      type:      'SIGNATURE_BURST',
    });
    if (keyResult.count > thresholds.PER_KEY_MAX) {
      emit('WARN', 'ANOMALY_THRESHOLD_EXCEEDED', {
        publicKeyId,
        key:             perKeyStoreKey,
        count:           keyResult.count,
        threshold:       thresholds.PER_KEY_MAX,
        type:            'SIGNATURE_BURST',
        executionBlocked: true,
      });
      return { block: true, reason: 'ANOMALY_DETECTED', type: 'SIGNATURE_BURST' };
    }

    // ── 2. Global sliding window (RATE_BURST) ────────────────────────────────
    const globalStoreKey = `${prefix}global`;
    const globalResult = await store.record(globalStoreKey, nowMs, windowMs);
    emit('INFO', 'ANOMALY_STATE_INCREMENTED', {
      key:       globalStoreKey,
      count:     globalResult.count,
      threshold: thresholds.GLOBAL_MAX,
      windowMs,
      type:      'RATE_BURST',
    });
    if (globalResult.count > thresholds.GLOBAL_MAX) {
      emit('WARN', 'ANOMALY_THRESHOLD_EXCEEDED', {
        publicKeyId,
        key:             globalStoreKey,
        count:           globalResult.count,
        threshold:       thresholds.GLOBAL_MAX,
        type:            'RATE_BURST',
        executionBlocked: true,
      });
      return { block: true, reason: 'ANOMALY_DETECTED', type: 'RATE_BURST' };
    }

    return { block: false };

  } catch (err) {
    emit('ERROR', 'ANOMALY_STORE_UNAVAILABLE', {
      error:           err.message,
      executionBlocked: true,
    });
    return { block: true, reason: 'ANOMALY_DETECTED', type: 'STORE_ERROR', error: err.message };
  }
}

module.exports = { checkAnomaly, DEFAULT_THRESHOLDS, resolveThresholds: _resolveThresholds };
