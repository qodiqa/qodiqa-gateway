'use strict';

/**
 * Logging Sanitizer Configuration — Component 44.7
 *
 * Centralized configuration for the log sanitization pipeline.
 * Every setting has a safe production default; operators override via env vars.
 *
 * Environment variables:
 *
 *   LOG_SANITIZER_SCAN_PII      Enable PII pattern scanning in string values (default: true)
 *   LOG_SANITIZER_SCAN_TOKENS   Enable token/credential pattern scanning (default: true)
 *   LOG_SANITIZER_SCAN_CRYPTO   Enable cryptographic material scanning (default: true)
 *   LOG_SANITIZER_REDACT_IP     Redact IPv4 and IPv6 addresses from string values (default: false; IPv6 since S-02)
 *   LOG_SANITIZER_MAX_DEPTH     Maximum object recursion depth (default: 10, range: 1-50)
 *   LOG_SANITIZER_MAX_STRING    Maximum string length before truncation (default: 10000)
 *
 * Sensitive field detection:
 *   Any field whose normalized name (lowercase, non-alphanumeric stripped) matches a
 *   known sensitive stem has its entire value replaced with placeholderRedacted.
 *   This covers: authorization headers, passwords, API keys, tokens, secrets, private
 *   keys, and PII field names (email, phone, ssn, iban, creditCard, etc.).
 *
 * Value-based pattern scanning:
 *   String values are scanned for PII, credential, and cryptographic patterns
 *   regardless of field name.  Scanning runs after field-name redaction, so
 *   already-redacted values are never scanned.
 *
 * Placeholder values by category:
 *   [REDACTED]    — sensitive field (by name)
 *   [EMAIL]       — email address detected in value
 *   [PHONE]       — phone number detected in value
 *   [PII]         — SSN, IBAN, credit card, or other PII in value
 *   [TOKEN]       — JWT, Bearer token, or OAuth credential in value
 *   [CRYPTO]      — PEM block or cryptographic key material in value
 *   [IP]          — IPv4 address (when redactIpAddresses = true)
 *   [BUFFER]      — Buffer instance (never log raw bytes)
 *   [CIRCULAR]    — circular reference detected
 *   [MAX_DEPTH]   — recursion depth limit reached
 *   ...[TRUNCATED] — string exceeded maxStringLength
 */

// ── Helpers (same pattern as webhookSecurityConfig.js) ────────────────────────

function _envBool(name, defaultVal) {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return defaultVal;
  return raw.trim() === 'true';
}

// a redaction SAFETY switch fails closed — only the exact string 'false' turns it off; unset
// or ANY other value (TRUE, 1, yes, a typo) keeps redaction on. (The boot validator additionally refuses any spelling
// other than 'true'/'false' for these switches, in every profile.)
function _envSafetyBool(name) {
  const raw = process.env[name];
  return !(typeof raw === 'string' && raw.trim() === 'false');
}

function _envInt(name, defaultVal, min, max) {
  const raw = process.env[name];
  if (!raw) return defaultVal;
  const v = parseInt(raw, 10);
  if (!Number.isFinite(v) || v < min || v > max) return defaultVal;
  return v;
}

// ── Configuration factory ─────────────────────────────────────────────────────

function buildConfig() {
  return Object.freeze({
    // Scanning categories (all default: enabled)
    scanPii:           _envSafetyBool('LOG_SANITIZER_SCAN_PII'),
    scanTokens:        _envSafetyBool('LOG_SANITIZER_SCAN_TOKENS'),
    scanCrypto:        _envSafetyBool('LOG_SANITIZER_SCAN_CRYPTO'),
    redactIpAddresses: _envBool('LOG_SANITIZER_REDACT_IP',   false),

    // Recursion and size bounds
    maxDepth:        _envInt('LOG_SANITIZER_MAX_DEPTH',  10,    1,  50),
    maxStringLength: _envInt('LOG_SANITIZER_MAX_STRING', 10000, 100, 1_000_000),

    // Placeholder values (immutable)
    placeholderRedacted:      '[REDACTED]',
    placeholderEmail:         '[EMAIL]',
    placeholderPhone:         '[PHONE]',
    placeholderPii:           '[PII]',
    placeholderToken:         '[TOKEN]',
    placeholderCrypto:        '[CRYPTO]',
    placeholderIp:            '[IP]',
    placeholderBuffer:        '[BUFFER]',
    placeholderCircular:      '[CIRCULAR]',
    placeholderDepthExceeded: '[MAX_DEPTH]',
    placeholderTruncated:     '...[TRUNCATED]',
  });
}

// Singleton — evaluated once at module load; tests may call buildConfig() directly.
const defaultConfig = buildConfig();

module.exports = { buildConfig, defaultConfig };
