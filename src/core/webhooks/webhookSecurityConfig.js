'use strict';

/**
 * Webhook Security Configuration — Component 44.6
 *
 * Centralized configuration for all webhook outbound security controls.
 * Every setting has a safe production default; operators override via env vars.
 *
 * Environment variables:
 *
 *   WEBHOOK_DNS_TIMEOUT_MS          DNS resolution timeout per phase (default: 5000)
 *   WEBHOOK_CONNECT_TIMEOUT_MS      TCP connection timeout (default: 10000)
 *   WEBHOOK_TLS_TIMEOUT_MS          TLS handshake timeout (default: 10000)
 *   WEBHOOK_RESPONSE_HEADER_MS      Response headers timeout (default: 30000)
 *   WEBHOOK_RESPONSE_BODY_MS        Response body drain timeout (default: 30000)
 *   WEBHOOK_IDLE_TIMEOUT_MS         Socket idle timeout (default: 30000)
 *   WEBHOOK_TOTAL_TIMEOUT_MS        Hard total-request timeout (default: 60000)
 *
 *   WEBHOOK_MAX_REDIRECTS           Maximum redirect hops (default: 5)
 *   WEBHOOK_TLS_MIN_VERSION         Minimum TLS version (default: TLSv1.2)
 *
 *   WEBHOOK_CB_FAILURE_THRESHOLD    Failures before circuit opens (default: 5)
 *   WEBHOOK_CB_SUCCESS_THRESHOLD    Successes in half-open before closing (default: 2)
 *   WEBHOOK_CB_RECOVERY_MS          Open→half-open delay in ms (default: 60000)
 *   WEBHOOK_CB_WINDOW_MS            Rolling failure window in ms (default: 60000)
 *
 *   WEBHOOK_ALLOWED_HOSTS           Comma-separated exact hostnames (optional allowlist)
 *   WEBHOOK_ALLOWED_DOMAINS         Comma-separated wildcard domains, e.g. *.example.com
 *   WEBHOOK_ALLOWED_CIDRS           Comma-separated CIDR ranges
 *   WEBHOOK_DENIED_HOSTS            Comma-separated exact hostnames (denylist)
 *   WEBHOOK_DENIED_DOMAINS          Comma-separated wildcard domains
 *   WEBHOOK_DENIED_CIDRS            Comma-separated CIDR ranges
 *
 *   WEBHOOK_MAX_RETRY_ATTEMPTS      Webhook-level retry attempt cap (default: 5, range: 1-10)
 *                                   Applied inside retryHandler; overrides queue MAX_RETRIES
 *                                   for webhook operations. POST requests are never retried
 *                                   unless the operation is explicitly marked isIdempotent.
 *   WEBHOOK_RETRY_BASE_DELAY_MS     Exponential backoff base delay in ms (default: 5000)
 *   WEBHOOK_RETRY_MAX_DELAY_MS      Maximum backoff delay cap in ms (default: 300000)
 *   WEBHOOK_RETRY_JITTER            Enable full jitter on backoff delays (default: true)
 *
 * Retry policy rules (safe retry):
 *   • POST requests are never retried unless isIdempotent = true is set on the operation.
 *   • 4xx status codes (except 408, 409, 429) are treated as permanent failures (no retry).
 *   • 5xx, 429, 408, 409, null (network/timeout) are treated as transient (may retry).
 *   • Retries stop when attempt >= WEBHOOK_MAX_RETRY_ATTEMPTS regardless of queue state.
 *
 * Allowlist/denylist rules:
 *   • Deny rules always override allow rules.
 *   • If no allow rules are configured, all non-blocked destinations are permitted.
 *   • If any allow rule is configured, the destination MUST match at least one.
 */

// ── Helpers ───────────────────────────────────────────────────────────────────

function _envInt(name, defaultVal, min, max) {
  const raw = process.env[name];
  if (!raw) return defaultVal;
  const v = parseInt(raw, 10);
  if (!Number.isFinite(v) || v < min || v > max) return defaultVal;
  return v;
}

function _envList(name) {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

function _envString(name, defaultVal) {
  const raw = process.env[name];
  return (raw && raw.trim()) ? raw.trim() : defaultVal;
}

function _envBool(name, defaultVal) {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return defaultVal;
  return raw.trim() === 'true';
}

// ── Configuration factory ─────────────────────────────────────────────────────

function buildConfig() {
  return Object.freeze({
    // Timeouts (all in ms)
    dnsTimeoutMs:            _envInt('WEBHOOK_DNS_TIMEOUT_MS',          5_000,   100, 30_000),
    connectTimeoutMs:        _envInt('WEBHOOK_CONNECT_TIMEOUT_MS',      10_000,  100, 60_000),
    tlsTimeoutMs:            _envInt('WEBHOOK_TLS_TIMEOUT_MS',          10_000,  100, 60_000),
    responseHeaderTimeoutMs: _envInt('WEBHOOK_RESPONSE_HEADER_MS',      30_000,  100, 300_000),
    responseBodyTimeoutMs:   _envInt('WEBHOOK_RESPONSE_BODY_MS',        30_000,  100, 300_000),
    idleTimeoutMs:           _envInt('WEBHOOK_IDLE_TIMEOUT_MS',         30_000,  100, 300_000),
    totalTimeoutMs:          _envInt('WEBHOOK_TOTAL_TIMEOUT_MS',        60_000,  100, 600_000),

    // Redirect policy
    maxRedirects: _envInt('WEBHOOK_MAX_REDIRECTS', 5, 0, 20),

    // TLS
    tlsMinVersion: _envString('WEBHOOK_TLS_MIN_VERSION', 'TLSv1.2'),

    // Circuit breaker
    cbFailureThreshold: _envInt('WEBHOOK_CB_FAILURE_THRESHOLD',  5,  1,  100),
    cbSuccessThreshold: _envInt('WEBHOOK_CB_SUCCESS_THRESHOLD',  2,  1,  50),
    cbRecoveryMs:       _envInt('WEBHOOK_CB_RECOVERY_MS',        60_000, 1_000, 3_600_000),
    cbWindowMs:         _envInt('WEBHOOK_CB_WINDOW_MS',          60_000, 1_000, 3_600_000),

    // Allowlist (empty = no restriction beyond SSRF blocking)
    allowedHosts:   _envList('WEBHOOK_ALLOWED_HOSTS'),
    allowedDomains: _envList('WEBHOOK_ALLOWED_DOMAINS'),
    allowedCidrs:   _envList('WEBHOOK_ALLOWED_CIDRS'),

    // Denylist (always overrides allowlist)
    deniedHosts:    _envList('WEBHOOK_DENIED_HOSTS'),
    deniedDomains:  _envList('WEBHOOK_DENIED_DOMAINS'),
    deniedCidrs:    _envList('WEBHOOK_DENIED_CIDRS'),

    // Safe retry policy
    maxRetryAttempts:   _envInt('WEBHOOK_MAX_RETRY_ATTEMPTS',  5,       1,   10),
    retryBaseDelayMs:   _envInt('WEBHOOK_RETRY_BASE_DELAY_MS', 5_000,   100, 60_000),
    retryMaxDelayMs:    _envInt('WEBHOOK_RETRY_MAX_DELAY_MS',  300_000, 1_000, 3_600_000),
    retryJitter:        _envBool('WEBHOOK_RETRY_JITTER', true),
  });
}

// Singleton — evaluated once at module load; tests may call buildConfig() directly.
const defaultConfig = buildConfig();

module.exports = { buildConfig, defaultConfig };
