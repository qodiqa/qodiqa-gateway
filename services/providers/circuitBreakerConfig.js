'use strict';

/**
 * Provider circuit breaker thresholds (Register #107).
 *
 * Deliberately separate from services/providers/config.js's per-provider
 * CONFIGS table: breaker behavior is provider-independent (one shared state
 * machine, keyed by provider name — see providerCircuitBreaker.js), not a
 * per-provider setting, so it has no business living inside each provider's
 * config block.
 *
 * Environment variables:
 *   PROVIDER_CB_FAILURE_THRESHOLD  — consecutive failures before OPEN (default 5)
 *   PROVIDER_CB_WINDOW_MS          — sliding window for failure counting (default 30000)
 *   PROVIDER_CB_RECOVERY_MS        — time OPEN must elapse before HALF_OPEN (default 30000)
 *   PROVIDER_CB_SUCCESS_THRESHOLD  — consecutive HALF_OPEN successes to close (default 2)
 */

function _parseInt(val, fallback) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

const CIRCUIT_BREAKER_CONFIG = Object.freeze({
  cbFailureThreshold: _parseInt(process.env.PROVIDER_CB_FAILURE_THRESHOLD, 5),
  cbWindowMs:          _parseInt(process.env.PROVIDER_CB_WINDOW_MS,         30_000),
  cbRecoveryMs:        _parseInt(process.env.PROVIDER_CB_RECOVERY_MS,       30_000),
  cbSuccessThreshold:  _parseInt(process.env.PROVIDER_CB_SUCCESS_THRESHOLD, 2),
});

module.exports = { CIRCUIT_BREAKER_CONFIG };
