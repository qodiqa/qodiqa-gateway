'use strict';

/**
 * Signing Resilience Configuration —
 *
 * Centralized configuration for the resilience layer wrapped around every
 * KMS/Vault/HSM signing and KEK provider (src/infra/keys/providers/*.js).
 * Every setting has a safe production default; operators override via env vars.
 *
 * Environment variables:
 *
 *   SIGNING_TIMEOUT_MS                 Hard deadline for a single provider
 *                                       operation (sign, getPublicKey, getWrappingKey,
 *                                       generateKeyPair, revokeKey, deprecateKey,
 *                                       rotateWrappingKey, healthCheck). Default: 3000.
 *   SIGNING_INIT_TIMEOUT_MS            Deadline for provider.initialize() — allowed to be
 *                                       longer since it includes auth handshake. Default: 10000.
 *
 *   SIGNING_MAX_RETRIES                Maximum attempts (including the first) for
 *                                       retry-eligible operations. Default: 3.
 *   SIGNING_INITIAL_BACKOFF_MS         Base exponential backoff delay. Default: 200.
 *   SIGNING_MAX_BACKOFF_MS             Backoff delay cap. Default: 2000.
 *   SIGNING_RETRY_JITTER               Full jitter on backoff delays. Default: true.
 *
 *   SIGNING_CIRCUIT_FAILURE_THRESHOLD  Consecutive failures before circuit opens. Default: 5.
 *   SIGNING_CIRCUIT_SUCCESS_THRESHOLD  Consecutive half-open successes before closing. Default: 2.
 *   SIGNING_CIRCUIT_WINDOW_MS          Rolling failure window. Default: 60000.
 *   SIGNING_CIRCUIT_RESET_TIMEOUT_MS   Open -> half-open delay. Default: 30000.
 *
 *   SIGNING_HEALTH_INTERVAL_MS         Active health probe interval. Default: 15000.
 *   SIGNING_HEALTH_DEGRADED_THRESHOLD  Consecutive failures to mark health "degraded". Default: 2.
 *
 * Retry-eligible operations are limited to read-only / side-effect-free calls:
 * sign(), getPublicKey(), getWrappingKey(), healthCheck(). Mutating operations
 * (generateKeyPair, deprecateKey, revokeKey, rotateWrappingKey) are NEVER
 * automatically retried by this layer — a timeout on those is inherently
 * ambiguous (the provider may have already applied the mutation), and
 * retrying blindly could create duplicate keys or inconsistent state. See
 * resilientSigningProvider.js / resilientKekProvider.js for the per-method
 * retry eligibility table.
 */

function _envInt(name, defaultVal, min, max) {
  const raw = process.env[name];
  if (!raw) return defaultVal;
  const v = parseInt(raw, 10);
  if (!Number.isFinite(v) || v < min || v > max) return defaultVal;
  return v;
}

function _envBool(name, defaultVal) {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return defaultVal;
  return raw.trim() === 'true';
}

function buildConfig() {
  return Object.freeze({
    // Deadlines (all in ms)
    timeoutMs:     _envInt('SIGNING_TIMEOUT_MS',      3_000,  50, 60_000),
    initTimeoutMs: _envInt('SIGNING_INIT_TIMEOUT_MS', 10_000, 50, 120_000),

    // Bounded retry (read-only operations only — see module doc above)
    maxRetries:       _envInt('SIGNING_MAX_RETRIES',          3,     1, 10),
    initialBackoffMs: _envInt('SIGNING_INITIAL_BACKOFF_MS',   200,   1, 60_000),
    maxBackoffMs:     _envInt('SIGNING_MAX_BACKOFF_MS',       2_000, 1, 120_000),
    retryJitter:      _envBool('SIGNING_RETRY_JITTER', true),

    // Circuit breaker
    cbFailureThreshold: _envInt('SIGNING_CIRCUIT_FAILURE_THRESHOLD', 5,      1, 100),
    cbSuccessThreshold: _envInt('SIGNING_CIRCUIT_SUCCESS_THRESHOLD', 2,      1, 50),
    cbWindowMs:         _envInt('SIGNING_CIRCUIT_WINDOW_MS',         60_000, 1_000, 3_600_000),
    cbRecoveryMs:       _envInt('SIGNING_CIRCUIT_RESET_TIMEOUT_MS',  30_000, 1_000, 3_600_000),

    // Health monitoring
    healthIntervalMs:       _envInt('SIGNING_HEALTH_INTERVAL_MS',        15_000, 1_000, 3_600_000),
    healthDegradedThreshold: _envInt('SIGNING_HEALTH_DEGRADED_THRESHOLD', 2,      1, 100),
  });
}

// Singleton — evaluated once at module load; tests may call buildConfig() directly
// to pick up env var overrides set inside a test.
const defaultConfig = buildConfig();

module.exports = { buildConfig, defaultConfig };
