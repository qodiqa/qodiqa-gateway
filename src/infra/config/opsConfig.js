'use strict';

// Centralized configuration for all operational visibility endpoints.
//
// Reads from environment variables once and returns a frozen config object.
// Called at server startup; the result is passed to all ops middleware factories.
//
// Environment variables:
//   QODIQA_OPS_TOKEN                    — required bearer/API-key token for all ops endpoints
//   QODIQA_OPS_IP_ALLOWLIST_ENABLED     — "true" to enable IP allowlisting
//   QODIQA_OPS_IP_ALLOWLIST             — comma-separated IPs and/or CIDRs (IPv4 or IPv6)
//   QODIQA_OPS_TRUST_PROXY — DEPRECATED: ignored; the admin IP allowlist
//                                         resolves the client IP with TRUSTED_PROXY like every other
//                                         consumer (it used to mean "trust every peer"). Still read
//                                         only so the boot report and validator can name it.
//   QODIQA_DIAGNOSTICS_ENABLED          — "true" to expose metrics/diagnostics/audit
//                                         defaults to false in production, true otherwise
//
//   -- /health and /ready (liveness + readiness probes) --
//   These two endpoints are intentionally excluded from QODIQA_OPS_TOKEN by
//   default: Kubernetes httpGet probes and Docker HEALTHCHECK cannot supply
//   a bearer credential, and both routes are contractually restricted to
//   minimal, non-sensitive output (see src/api/routes/health.js, ready.js).
//   See docs/deployment/kubernetes-probes.md for the full security rationale.
//   QODIQA_HEALTH_PROBE_AUTH_REQUIRED  — "true" to require the same
//                                         QODIQA_OPS_TOKEN/RBAC credential on
//                                         /health and /ready. Default: false.
//   QODIQA_HEALTH_REQUIRE_LOOPBACK     — "true" to additionally reject any
//                                         /health or /ready request whose TCP
//                                         socket address is not loopback.
//                                         Only appropriate for Docker/bare-metal
//                                         deployments — Kubernetes probes never
//                                         originate from loopback. Default: false.
//   QODIQA_HEALTH_RATE_LIMIT_MAX        — max /health + /ready requests per
//                                         client IP per window. Default: 240.
//   QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS  — window size in ms. Default: 60000.
//
//   -- Admin/Ops endpoints (defense-in-depth, Task #27) --
//   Applied ahead of IP allowlist/auth/RBAC on every Admin route so a stolen
//   or guessed credential cannot be brute-forced at an unbounded rate. This
//   is an additive network-layer control — it narrows request throughput,
//   it does not grant or substitute for RBAC.
//   QODIQA_OPS_RATE_LIMIT_MAX           — max requests per client IP per
//                                         window across all Admin endpoints.
//                                         Default: 120.
//   QODIQA_OPS_RATE_LIMIT_WINDOW_MS     — window size in ms. Default: 60000.
//
//   -- Auth-failure lockout (AUTH-2) --
//   The rate limiter above throttles overall throughput; it does not treat a
//   wrong credential any differently from a correct one, so a shared
//   QODIQA_OPS_TOKEN can still be brute-forced within its budget (e.g. 120
//   guesses/minute/IP forever). This is a SEPARATE, credential-outcome-aware
//   control: it tracks consecutive authentication FAILURES per source and
//   applies escalating friction — exponential backoff, then a temporary
//   lockout — independent of general request throughput. See
//   src/core/authLockout and docs/security/AUTH_LOCKOUT.md.
//   QODIQA_OPS_AUTH_LOCKOUT_ENABLED       — "false" to disable (default: true)
//   QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES  — consecutive failures before a
//                                           source is locked out. Default: 5.
//   QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS   — lockout duration once triggered.
//                                           Default: 900000 (15 minutes).
//   QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MIN_MS — delay applied before evaluating
//                                           credentials after the 1st failure.
//                                           Default: 250.
//   QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MAX_MS — backoff ceiling; delay never
//                                           exceeds this. Default: 5000.
//   QODIQA_OPS_AUTH_LOCKOUT_FAILURE_WINDOW_MS — how long a failure streak is
//                                           remembered with no further
//                                           activity before it is forgotten
//                                           (bounds storage; not a reset on
//                                           success, which is immediate).
//                                           Default: same as DURATION_MS.
//
//   -- Credential-identity secondary counter --
//   In addition to the IP-scoped counter above, a second counter is keyed by
//   a truncated, one-way SHA-256 hash of the presented credential itself
//   (never the raw credential — see src/core/authLockout/index.js's
//   _credentialIdentity()). This closes the residual gap where a
//   distributed attacker rotates source IPs while repeating the same
//   guessed credential: that credential's hash accumulates failures across
//   every IP it was tried from, independent of how thin any single IP's
//   share of the attempts is. The lockout triggers if EITHER counter
//   exceeds policy. Both counters share the MAX_FAILURES/DURATION_MS/
//   FAILURE_WINDOW_MS settings above — no separate thresholds, to avoid
//   unnecessary configuration surface.
//   QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES — truncation length, in
//                                           bytes, of the credential hash
//                                           used as its lockout identity.
//                                           1..32 (SHA-256 digest size).
//                                           Default: 16 (128 bits).

const net  = require('net');
const { emit } = require('../../../services/logger');

const _DIGITS_RE = /^\d{1,3}$/;

function _isValidOctet(s) {
  if (!_DIGITS_RE.test(s)) return false;
  const n = parseInt(s, 10);
  return n >= 0 && n <= 255;
}

function _isValidIpv4(ip) {
  const parts = ip.split('.');
  return parts.length === 4 && parts.every(_isValidOctet);
}

function _isValidEntry(entry) {
  if (!entry) return false;
  const slash = entry.indexOf('/');

  // IPv6 path: entries containing ':' are treated as IPv6.
  // Entries that also contain '.' are IPv4-mapped forms (::ffff:x.x.x.x);
  // those must be configured as plain IPv4 instead — reject them here so
  // the matcher and validator stay consistent.
  if (entry.includes(':')) {
    if (entry.includes('.')) return false;
    const ipPart = slash === -1 ? entry : entry.slice(0, slash);
    if (!net.isIPv6(ipPart)) return false;
    if (slash === -1) return true;
    const prefixPart = entry.slice(slash + 1);
    if (!/^\d{1,3}$/.test(prefixPart)) return false;
    const prefix = parseInt(prefixPart, 10);
    return prefix >= 0 && prefix <= 128;
  }

  // IPv4 path (original logic — unchanged)
  if (slash === -1) return _isValidIpv4(entry);
  const ipPart     = entry.slice(0, slash);
  const prefixPart = entry.slice(slash + 1);
  if (!/^\d{1,2}$/.test(prefixPart)) return false;
  const prefix = parseInt(prefixPart, 10);
  return _isValidIpv4(ipPart) && prefix >= 0 && prefix <= 32;
}

function _parseAllowlist(raw) {
  if (!raw || !raw.trim()) return { valid: [], invalid: [] };
  const entries = raw.split(',').map(s => s.trim()).filter(Boolean);
  const valid   = entries.filter(_isValidEntry);
  const invalid = entries.filter(e => !_isValidEntry(e));
  return { valid, invalid };
}

function loadOpsConfig() {
  const isProduction = process.env.NODE_ENV === 'production';

  const token = process.env.QODIQA_OPS_TOKEN || null;

  const ipAllowlistEnabled = process.env.QODIQA_OPS_IP_ALLOWLIST_ENABLED === 'true';
  const trustProxy         = process.env.QODIQA_OPS_TRUST_PROXY === 'true';

  const { valid: allowlistEntries, invalid: invalidEntries } =
    _parseAllowlist(process.env.QODIQA_OPS_IP_ALLOWLIST || '');

  // Diagnostics default: off in production unless explicitly enabled.
  const diagnosticsEnabled = process.env.QODIQA_DIAGNOSTICS_ENABLED !== undefined
    ? process.env.QODIQA_DIAGNOSTICS_ENABLED === 'true'
    : !isProduction;

  // the admin plane (every adminStack() mount —
  // /audit, /rbac, /key-admin, /consent, /v1/admin/*, …) has its OWN switch,
  // independent of diagnostics. Same default shape: off in production unless
  // explicitly enabled. Strict from day one — QODIQA_DIAGNOSTICS_ENABLED no
  // longer opens the admin surface.
  const adminEnabled = process.env.QODIQA_ADMIN_ENABLED !== undefined
    ? process.env.QODIQA_ADMIN_ENABLED === 'true'
    : !isProduction;

  // #4: a second, independent kill switch for CPU/GC/heap profiling
  // (GET /diagnostics/profile/*) — deliberately opt-in in every environment
  // (no !isProduction default, unlike diagnosticsEnabled above), since a
  // profiler run carries materially more performance impact and information-
  // disclosure risk than the health-style /diagnostics endpoint. Both gates
  // must pass — this is not a substitute for diagnosticsEnabled/opsOnlyStack,
  // it is an additional, narrower requirement layered on top of them.
  const profilingDiagnosticsEnabled = process.env.QODIQA_PROFILING_DIAGNOSTICS_ENABLED === 'true';

  // /health and /ready: unauthenticated and reachable from any source by
  // default (required for Kubernetes/Docker/ECS probe compatibility — see
  // module header). Both knobs are opt-in hardening for operators who can
  // guarantee their orchestrator can meet the stricter requirement.
  const healthAuthRequired     = process.env.QODIQA_HEALTH_PROBE_AUTH_REQUIRED === 'true';
  const healthRequireLoopback  = process.env.QODIQA_HEALTH_REQUIRE_LOOPBACK === 'true';

  const _healthRateLimitMaxRaw = parseInt(process.env.QODIQA_HEALTH_RATE_LIMIT_MAX, 10);
  const healthRateLimitMax     = Number.isFinite(_healthRateLimitMaxRaw) && _healthRateLimitMaxRaw > 0
    ? _healthRateLimitMaxRaw
    : 240;

  const _healthRateLimitWindowRaw = parseInt(process.env.QODIQA_HEALTH_RATE_LIMIT_WINDOW_MS, 10);
  const healthRateLimitWindowMs   = Number.isFinite(_healthRateLimitWindowRaw) && _healthRateLimitWindowRaw > 0
    ? _healthRateLimitWindowRaw
    : 60_000;

  const _opsRateLimitMaxRaw = parseInt(process.env.QODIQA_OPS_RATE_LIMIT_MAX, 10);
  const opsRateLimitMax     = Number.isFinite(_opsRateLimitMaxRaw) && _opsRateLimitMaxRaw > 0
    ? _opsRateLimitMaxRaw
    : 120;

  const _opsRateLimitWindowRaw = parseInt(process.env.QODIQA_OPS_RATE_LIMIT_WINDOW_MS, 10);
  const opsRateLimitWindowMs   = Number.isFinite(_opsRateLimitWindowRaw) && _opsRateLimitWindowRaw > 0
    ? _opsRateLimitWindowRaw
    : 60_000;

  // -- Auth-failure lockout (AUTH-2) --
  const authLockoutEnabled = process.env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED !== undefined
    ? process.env.QODIQA_OPS_AUTH_LOCKOUT_ENABLED !== 'false'
    : true;

  const _authLockoutMaxFailuresRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_MAX_FAILURES, 10);
  const authLockoutMaxFailures     = Number.isFinite(_authLockoutMaxFailuresRaw) && _authLockoutMaxFailuresRaw > 0
    ? _authLockoutMaxFailuresRaw
    : 5;

  const _authLockoutDurationRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_DURATION_MS, 10);
  const authLockoutDurationMs   = Number.isFinite(_authLockoutDurationRaw) && _authLockoutDurationRaw > 0
    ? _authLockoutDurationRaw
    : 900_000;

  const _authLockoutBackoffMinRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MIN_MS, 10);
  const authLockoutBackoffMinMs   = Number.isFinite(_authLockoutBackoffMinRaw) && _authLockoutBackoffMinRaw > 0
    ? _authLockoutBackoffMinRaw
    : 250;

  const _authLockoutBackoffMaxRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MAX_MS, 10);
  const authLockoutBackoffMaxMs   = Number.isFinite(_authLockoutBackoffMaxRaw) && _authLockoutBackoffMaxRaw > 0
    ? _authLockoutBackoffMaxRaw
    : 5_000;

  const _authLockoutFailureWindowRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_FAILURE_WINDOW_MS, 10);
  const authLockoutFailureWindowMs   = Number.isFinite(_authLockoutFailureWindowRaw) && _authLockoutFailureWindowRaw > 0
    ? _authLockoutFailureWindowRaw
    : authLockoutDurationMs;

  // Credential-identity secondary counter — truncation length of
  // the SHA-256 hash used as the credential's lockout identity. Bounded to
  // [1, 32] (32 = the full digest); an out-of-range or unparseable value
  // falls back to the default rather than failing startup, matching this
  // file's established posture for every other numeric knob here.
  const _authLockoutCredentialHashBytesRaw = parseInt(process.env.QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES, 10);
  const authLockoutCredentialHashBytes     =
    Number.isFinite(_authLockoutCredentialHashBytesRaw) &&
    _authLockoutCredentialHashBytesRaw >= 1 && _authLockoutCredentialHashBytesRaw <= 32
      ? _authLockoutCredentialHashBytesRaw
      : 16;

  // Fail-safe, not fail-closed: a misconfigured min>max must not turn into an
  // unbounded or negative delay (requirement: "delay must never become
  // unbounded"). Clamp rather than reject so a config typo degrades to "no
  // backoff growth" instead of taking every ops endpoint offline.
  const _authLockoutBackoffMinMsSafe = Math.min(authLockoutBackoffMinMs, authLockoutBackoffMaxMs);
  if (authLockoutBackoffMinMs > authLockoutBackoffMaxMs) {
    emit('ERROR', 'OPS_CONFIG_INVALID_LOCKOUT_BACKOFF', {
      authLockoutBackoffMinMs, authLockoutBackoffMaxMs,
      message: 'QODIQA_OPS_AUTH_LOCKOUT_BACKOFF_MIN_MS exceeds MAX_MS — clamped min to max',
    });
  }

  const allowlistConfigValid = invalidEntries.length === 0;

  if (!token) {
    emit('WARN', 'OPS_CONFIG_NO_TOKEN', {
      message: 'QODIQA_OPS_TOKEN is not set — all operational endpoints will return 401',
    });
  }

  if (invalidEntries.length > 0) {
    emit('ERROR', 'OPS_CONFIG_INVALID_ALLOWLIST', {
      invalidEntries,
      message: 'Invalid QODIQA_OPS_IP_ALLOWLIST entries — fail-closed, all IP-based access denied',
    });
  }

  if (ipAllowlistEnabled && allowlistEntries.length === 0 && allowlistConfigValid) {
    emit('WARN', 'OPS_CONFIG_EMPTY_ALLOWLIST', {
      message: 'QODIQA_OPS_IP_ALLOWLIST_ENABLED=true but no entries configured — all requests will be denied',
    });
  }

  return Object.freeze({
    token,
    diagnosticsEnabled,
    adminEnabled,
    profilingDiagnosticsEnabled,
    ipAllowlistEnabled,
    allowlistEntries: Object.freeze(allowlistEntries),
    allowlistConfigValid,
    trustProxy,
    healthAuthRequired,
    healthRequireLoopback,
    healthRateLimitMax,
    healthRateLimitWindowMs,
    opsRateLimitMax,
    opsRateLimitWindowMs,
    authLockoutEnabled,
    authLockoutMaxFailures,
    authLockoutDurationMs,
    authLockoutBackoffMinMs: _authLockoutBackoffMinMsSafe,
    authLockoutBackoffMaxMs,
    authLockoutFailureWindowMs,
    authLockoutCredentialHashBytes,
  });
}

module.exports = { loadOpsConfig, _isValidEntry, _parseAllowlist };
