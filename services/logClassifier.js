'use strict';

/**
 * Log Classification — Component 44.7
 *
 * Assigns every log entry to one of three categories:
 *
 *   SECURITY    — anomalies, attacks, authentication failures, security invariant
 *                 violations, and anything at CRITICAL or FATAL level.
 *
 *   AUDIT       — expected, authorized enforcement decisions and their outcomes:
 *                 allow/block decisions, delivery records, policy decisions,
 *                 stream lifecycle events, and compliance records.
 *
 *   OPERATIONAL — normal system lifecycle: startup, shutdown, configuration,
 *                 initialization, health checks, and background maintenance.
 *
 * Classification is deterministic: the same (level, event) pair always produces
 * the same category regardless of call order.
 *
 * Public API:
 *   classify(level, event) → 'AUDIT' | 'SECURITY' | 'OPERATIONAL'
 */

// ── Security events ───────────────────────────────────────────────────────────
//
// Events that represent anomalies, attacks, or security invariant violations.

const SECURITY_EVENTS = new Set([
  'WEBHOOK_DNS_REBINDING_DETECTED',
  'WEBHOOK_DNS_REVALIDATION_BLOCKED',
  'WEBHOOK_DELIVERY_BLOCKED',
  'RBAC_DENY',
  'RBAC_RESOLVE_NO_IDENTITY',
  'RBAC_PERMISSION_ENGINE_ERROR',
  'OPS_AUTH_INVALID_TOKEN',
  'OPS_AUTH_MISSING_CREDENTIALS',
  'OPS_ALLOWLIST_BLOCKED',
  'OPS_ALLOWLIST_MISCONFIGURED',
  'OPS_ALLOWLIST_COMPILE_ERROR',
  'OPS_DISABLED_ACCESS_ATTEMPT',
  // Auth-failure lockout (AUTH-2) — a growing failure streak, an active
  // lockout being hit again, and backoff kicking in are all attack-shaped
  // signals, even though none of them is itself a hard denial the way
  // OPS_AUTH_INVALID_TOKEN's underlying 401 is.
  'AUTH_LOCKOUT_TRIGGERED',
  'AUTH_LOCKOUT_ACTIVE',
  'AUTH_LOCKOUT_BACKOFF_APPLIED',
  // A revoked key's local state and its native provider (Vault Transit / HSM)
  // state have diverged — the key may still be usable at the provider
  // boundary even though QODIQA considers it revoked. Treat as an incident.
  'KEY_REVOKED_NATIVE_FAILED',
  'KEY_REVOCATION_CAPABILITY_UNSUPPORTED',
]);

// Substring patterns whose presence in an event name indicates a security event.
const SECURITY_SUBSTRINGS = [
  'SSRF',
  'REBINDING',
  'INVARIANT_VIOLATED',
  'CIRCUIT_BREAKER',
  'INVALID_TOKEN',
  'MISSING_CREDENTIALS',
];

// Suffix patterns that indicate a security event.
const SECURITY_SUFFIXES = ['_REJECTED', '_UNAUTHORIZED', '_FORBIDDEN'];

// ── Audit events ──────────────────────────────────────────────────────────────
//
// Events representing expected enforcement decisions and their outcomes.

const AUDIT_EVENTS = new Set([
  'GATEWAY_ALLOW',
  'GATEWAY_BLOCK',
  'RBAC_ALLOW',
  'WEBHOOK_DELIVERY_SENT',
  'WEBHOOK_DELIVERY_FAILED',
  'WEBHOOK_RETRY_SCHEDULED',
  'WEBHOOK_RETRY_SUPPRESSED',
  'WEBHOOK_DISPATCH_QUEUED',
  'WEBHOOK_DELIVERY_ENDPOINT_GONE',
  'STREAM_STARTED',
  'STREAM_TERMINATED',
  'STREAM_AUDIT_RECORDED',
  // Key lifecycle — expected, operator-authorized revocation outcomes.
  'KEY_REVOKED',
  'KEY_REVOCATION_STARTED',
  'KEY_REVOKED_NATIVE_SUCCESS',
  'KEY_ADMIN_REVOKED',
  // Auth-failure lockout (AUTH-2) — a successful authentication that clears
  // a prior failure streak is an expected, authorized outcome record, not
  // an anomaly in itself.
  'AUTH_LOCKOUT_RESET',
]);

// Event name prefixes that are always AUDIT decisions.
const AUDIT_PREFIXES = ['GATEWAY_'];

// ── Classification ────────────────────────────────────────────────────────────

function _isSecurityEvent(event) {
  if (SECURITY_EVENTS.has(event)) return true;
  for (const sub of SECURITY_SUBSTRINGS) {
    if (event.includes(sub)) return true;
  }
  for (const suf of SECURITY_SUFFIXES) {
    if (event.endsWith(suf)) return true;
  }
  return false;
}

function _isAuditEvent(event) {
  if (AUDIT_EVENTS.has(event)) return true;
  for (const pfx of AUDIT_PREFIXES) {
    if (event.startsWith(pfx)) return true;
  }
  return false;
}

// ── Memoization ───────────────────────────────────────────────────────────────
//
// classify() is a pure function of (level, event) by its own contract above
// ("the same (level, event) pair always produces the same category regardless
// of call order") — that's exactly the precondition that makes caching safe.
// Event names are a small, fixed vocabulary of string literals from call
// sites in this codebase (never derived from request/user input), so the
// cache's key space is bounded in practice; _MAX_CACHE_SIZE is a defensive
// cap only, not a correctness requirement.
const _MAX_CACHE_SIZE = 2000;
const _cache = new Map();

function _classifyUncached(level, event) {
  if (level === 'CRITICAL' || level === 'FATAL') return 'SECURITY';
  if (typeof event === 'string' && _isSecurityEvent(event)) return 'SECURITY';
  if (typeof event === 'string' && _isAuditEvent(event)) return 'AUDIT';
  return 'OPERATIONAL';
}

/**
 * Classify a log entry into a category.
 *
 * Priority order: SECURITY > AUDIT > OPERATIONAL.
 * CRITICAL and FATAL levels are always SECURITY.
 *
 * @param {string} level  Log level (INFO, WARN, ERROR, CRITICAL, FATAL)
 * @param {string} event  Event name (e.g. 'GATEWAY_ALLOW')
 * @returns {'SECURITY' | 'AUDIT' | 'OPERATIONAL'}
 */
function classify(level, event) {
  const key = level + '|' + event;
  const cached = _cache.get(key);
  if (cached !== undefined) return cached;

  const result = _classifyUncached(level, event);
  if (_cache.size < _MAX_CACHE_SIZE) _cache.set(key, result);
  return result;
}

module.exports = { classify };
