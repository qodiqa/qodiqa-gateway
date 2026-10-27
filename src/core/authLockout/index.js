'use strict';

/**
 * Auth-Failure Lockout — AUTH-2, extended (credential-identity
 * scoped secondary counter).
 *
 * Dedicated, credential-outcome-aware protection for the shared ops token
 * (and, incidentally, the per-operator API key path — a source guessing
 * blindly cannot tell which credential type it's up against), independent
 * of the general-purpose request-throughput rate limiter
 * (src/core/rateLimit, middleware/publicRateLimit.js). See
 * docs/security/AUTH_LOCKOUT.md for the full design writeup.
 *
 * Usage (wired into src/middleware/opsAuth.js):
 *   const { createAuthLockout } = require('../../core/authLockout');
 *   const authLockout = createAuthLockout(opsConfig);
 *   const pre = await authLockout.precheck(req, presentedCredential);
 *   if (pre.locked) { ...429... }
 *   if (pre.backoffDelayMs > 0) await sleep(pre.backoffDelayMs);
 *   // ...evaluate credential...
 *   if (valid) await authLockout.recordSuccess(req, presentedCredential);
 *   else       await authLockout.recordFailure(req, presentedCredential);
 *
 * `presentedCredential` is the second, OPTIONAL argument to all three
 * methods — omitting it (every pre-WP-012 call site, every existing test)
 * preserves the original IP-only behavior exactly. When supplied, it is
 * used ONLY to derive a one-way, truncated SHA-256 identity (`_credential
 * Identity()` below) for a second lockout counter that closes the residual
 * gap where a distributed attacker rotates source IPs while repeating the
 * same guessed credential. The raw credential itself is never stored,
 * logged, placed in Redis, included in telemetry, embedded in evidence, or
 * surfaced in any exception — it exists only as a local variable for the
 * duration of the hash computation below.
 *
 * Lifecycle (server.js startup/shutdown, mirrors src/core/rateLimit):
 *   const authLockout = require('./src/core/authLockout');
 *   await authLockout.initialize();
 *   await authLockout.disconnect();
 *
 * Storage mode: Redis-backed when REDIS_URL is set (required for consistent
 * enforcement across multiple instances — requirement 5); falls back to a
 * single-process in-memory store otherwise (dev/test only, same posture as
 * src/core/rateLimit/middleware.js's _isRlEnabled()).
 *
 * storage mode is now unconditionally Redis-backed in production,
 * matching nonceStore.js/anomalyStore.js's unconditional pattern (default
 * redis://localhost:6379 when REDIS_URL is unset — see clientConfig.js) —
 * not gated on REDIS_URL being explicitly set. The old gate (_useRedis())
 * silently routed to a single-process, non-durable counter in any
 * deployment that runs Redis without setting REDIS_URL explicitly, which
 * is exactly this deployment's own default posture (Findings Register).
 * MemoryStorage remains available, but only via explicit test injection
 * (opts._storage) — see src/core/authLockout/__tests__/authLockout.test.js.
 */

const crypto          = require('crypto');
const { emit }       = require('../../../services/logger');
const storage         = require('./storage');
const { computeBackoffDelayMs, computeKeyTtlSeconds } = require('./algorithm');
const promMetrics     = require('../../observability/metrics');

// Default truncation length for the credential-identity hash — 16 bytes
// (128 bits) is far beyond brute-force reach for an identifier that isn't
// even secret (it doesn't need to resist guessing, only collisions), while
// keeping Redis key names short. Configurable via
// QODIQA_OPS_AUTH_LOCKOUT_CREDENTIAL_HASH_BYTES (see opsConfig.js); this
// constant is only the fallback when that field is absent (e.g. hand-built
// config objects in tests).
const _DEFAULT_CREDENTIAL_HASH_BYTES = 16;

// RT-04: Retry-After (s) when the lockout store cannot be consulted — a transient backend state.
const STORAGE_UNAVAILABLE_RETRY_AFTER_S = 2;

function _identity(req) {
  const ip = req.clientIp ?? req.ip ?? null;
  return ip ? `ip:${ip}` : 'ip:unknown';
}

/**
 * Derives the credential-scoped lockout identity: a truncated, one-way
 * SHA-256 hash of the presented credential — never the credential itself,
 * never reversible, never logged or persisted anywhere but as this short
 * hex identifier. Returns null when no credential was presented (nothing
 * to scope a credential-identity counter to), in which case the caller
 * evaluates the IP counter alone — byte-for-byte the pre-WP-012 behavior.
 *
 * @param {string|null|undefined} credential — the raw presented credential
 * @param {number} hashBytes — truncation length, 1..32 (SHA-256 digest size)
 * @returns {string|null}
 */
function _credentialIdentity(credential, hashBytes) {
  if (!credential) return null;
  const digest = crypto.createHash('sha256').update(credential, 'utf8').digest();
  const safeBytes = Number.isInteger(hashBytes) && hashBytes >= 1 && hashBytes <= digest.length
    ? hashBytes
    : _DEFAULT_CREDENTIAL_HASH_BYTES;
  return `cred:${digest.subarray(0, safeBytes).toString('hex')}`;
}

/**
 * @param {object} opsConfig — result of loadOpsConfig() (authLockout* fields)
 * @param {object} [opts]
 * @param {object} [opts._storage] — injectable storage backend (tests)
 */
function createAuthLockout(opsConfig, { _storage, namespace = null } = {}) {
  const enabled = opsConfig.authLockoutEnabled;
  // an optional key namespace gives a second, independent lockout (e.g.
  // /sign's auth-failure bucket) its own counters. Without one, keys are
  // exactly as before.
  const _ns = namespace ? `${namespace}:` : '';

  function _backend() {
    return _storage || storage.getProductionStorage();
  }

  function _keyTtlSeconds() {
    return computeKeyTtlSeconds(opsConfig.authLockoutFailureWindowMs, opsConfig.authLockoutDurationMs);
  }

  // Resolves both lockout identities for a request and builds the storage
  // key array. `credIdentity` (and therefore the second key) is null
  // whenever no credential was presented — the counter simply isn't
  // consulted for that call, matching pre-WP-012 behavior exactly. Never
  // returns or retains the raw `credential` itself beyond this call frame.
  function _keysFor(req, credential) {
    const ipIdentity   = _identity(req);
    const credIdentity = _credentialIdentity(credential, opsConfig.authLockoutCredentialHashBytes);
    const ipKey        = `${storage.KEY_PREFIX}${_ns}${ipIdentity}`;
    const credKey      = credIdentity ? `${storage.KEY_PREFIX}${_ns}${credIdentity}` : null;
    return {
      ipIdentity, credIdentity, ipKey, credKey,
      keys: credKey ? [ipKey, credKey] : [ipKey],
    };
  }

  // Which counter(s) crossed their threshold / are active — a bounded,
  // non-sensitive value (never the credential or its hash) safe for logs
  // and metric labels.
  function _scopeOf(result) {
    const ipHit  = !!(result.ip ? result.ip.locked ?? result.ip.triggered : result.locked ?? result.triggered);
    const hasCred = !!result.credential;
    const credHit = hasCred && !!(result.credential.locked ?? result.credential.triggered);
    if (!hasCred) return 'ip';
    if (ipHit && credHit) return 'both';
    if (credHit) return 'credential';
    return 'ip';
  }

  /**
   * Call before evaluating any credential. Never throws — a storage outage
   * fails closed (locked: true) rather than silently disabling the control,
   * matching this codebase's established posture for every other security
   * store (rate limiter, nonce store, idempotency store).
   *
   * @param {object} req
   * @param {string} [presentedCredential] — raw credential, used only to
   *   derive a hash identity; never stored, logged, or retained.
   */
  async function precheck(req, presentedCredential) {
    if (!enabled) return { locked: false, backoffDelayMs: 0 };

    const { ipIdentity, keys } = _keysFor(req, presentedCredential);
    const now        = Date.now();
    const requestId  = req.requestId ?? null;

    let result;
    try {
      result = await _backend().precheck(keys, now);
    } catch (err) {
      promMetrics.authLockoutStorageFailuresTotal.inc();
      emit('ERROR', 'AUTH_LOCKOUT_STORAGE_FAILURE', {
        identity: ipIdentity, requestId, path: req.path, error: err.message,
      });
      // RT-04: still fail CLOSED (locked: true), but this is "cannot
      // decide", not "this credential is locked out". Callers answer 503 AUTH_BACKEND_UNAVAILABLE
      // with a short Retry-After — not 429 AUTH_LOCKED_OUT with the full lockout duration, which
      // told valid callers to stand down for minutes after a brief Redis blip.
      return { locked: true, backoffDelayMs: 0, retryAfterSeconds: STORAGE_UNAVAILABLE_RETRY_AFTER_S, storageUnavailable: true };
    }

    if (result.expired) {
      promMetrics.authLockoutActiveGauge.dec();
      emit('INFO', 'AUTH_LOCKOUT_EXPIRED', { identity: ipIdentity, requestId, lockScope: _scopeOf(result) });
    }

    if (result.locked) {
      const retryAfterSeconds = Math.max(1, Math.ceil((result.lockedUntil - now) / 1000));
      emit('WARN', 'AUTH_LOCKOUT_ACTIVE', {
        identity: ipIdentity, requestId, path: req.path, retryAfterSeconds, lockScope: _scopeOf(result),
      });
      return { locked: true, backoffDelayMs: 0, retryAfterSeconds };
    }

    // Backoff remains driven by the IP counter alone — unchanged from
    // pre-WP-012 behavior; `result.count` is the primary (IP) field on both
    // the legacy and dual-key return shapes (see storage.js).
    const backoffDelayMs = computeBackoffDelayMs(
      result.count, opsConfig.authLockoutBackoffMinMs, opsConfig.authLockoutBackoffMaxMs,
    );
    if (backoffDelayMs > 0) {
      promMetrics.authLockoutBackoffAppliedTotal.inc();
      emit('INFO', 'AUTH_LOCKOUT_BACKOFF_APPLIED', {
        identity: ipIdentity, requestId, failureCount: result.count, backoffDelayMs,
      });
    }
    return { locked: false, backoffDelayMs };
  }

  /**
   * Call after an invalid credential was presented. Never throws.
   * @param {object} req
   * @param {string} [presentedCredential]
   */
  async function recordFailure(req, presentedCredential) {
    if (!enabled) return;

    const { ipIdentity, keys } = _keysFor(req, presentedCredential);
    const now        = Date.now();
    const requestId  = req.requestId ?? null;

    let result;
    try {
      result = await _backend().recordFailure(
        keys, now, opsConfig.authLockoutMaxFailures, opsConfig.authLockoutDurationMs, _keyTtlSeconds(),
      );
    } catch (err) {
      promMetrics.authLockoutStorageFailuresTotal.inc();
      emit('ERROR', 'AUTH_LOCKOUT_STORAGE_FAILURE', {
        identity: ipIdentity, requestId, path: req.path, error: err.message,
      });
      return;
    }

    promMetrics.authLockoutFailuresTotal.inc();

    if (result.triggered) {
      const lockScope = _scopeOf(result);
      promMetrics.authLockoutTriggeredTotal.inc({ scope: lockScope });
      promMetrics.authLockoutActiveGauge.inc();
      emit('WARN', 'AUTH_LOCKOUT_TRIGGERED', {
        identity: ipIdentity, requestId, path: req.path,
        failureCount: result.count, lockoutDurationMs: opsConfig.authLockoutDurationMs, lockScope,
      });
    }
  }

  /**
   * Call after a valid credential was presented. Never throws.
   * @param {object} req
   * @param {string} [presentedCredential]
   */
  async function recordSuccess(req, presentedCredential) {
    if (!enabled) return;

    const { ipIdentity, keys } = _keysFor(req, presentedCredential);
    const requestId  = req.requestId ?? null;

    let result;
    try {
      result = await _backend().recordSuccess(keys, Date.now());
    } catch (err) {
      promMetrics.authLockoutStorageFailuresTotal.inc();
      emit('ERROR', 'AUTH_LOCKOUT_STORAGE_FAILURE', {
        identity: ipIdentity, requestId, path: req.path, error: err.message,
      });
      return;
    }

    if (result.priorCount > 0) {
      promMetrics.authLockoutRecoveriesTotal.inc();
      emit('INFO', 'AUTH_LOCKOUT_RESET', { identity: ipIdentity, requestId, priorFailureCount: result.priorCount });
    }
  }

  return { precheck, recordFailure, recordSuccess };
}

// No-op lockout — used wherever an authLockout instance is optional (keeps
// createOpsAuthMiddleware's existing 2-arg call sites, and every existing
// test that constructs it that way, behaved exactly as before this change).
const NOOP_LOCKOUT = Object.freeze({
  precheck:      async () => ({ locked: false, backoffDelayMs: 0 }),
  recordFailure: async () => {},
  recordSuccess: async () => {},
});

module.exports = {
  createAuthLockout,
  NOOP_LOCKOUT,
  // Lifecycle — used by server.js startup/shutdown.
  initialize: storage.initialize,
  disconnect: storage.disconnect,
  isReady:    storage.isReady,
  KEY_PREFIX: storage.KEY_PREFIX,
  // Internals exported for testing.
  _identity,
  _credentialIdentity,
};
