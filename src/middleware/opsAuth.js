'use strict';

// Authentication middleware for operational visibility endpoints.
//
// Authentication priority:
//   1. Per-operator API key  (ok_<64-hex> prefix, looked up via rbacStore)
//   2. Shared ops token      (QODIQA_OPS_TOKEN — deprecated migration path)
//
// Per-operator keys:
//   - Issued via POST /rbac/users/:id/api-key
//   - Stored as SHA-256 hashes in the RBAC user store (never plaintext)
//   - Authenticated operator identity is attached to req.rbacUser
//   - Downstream RBAC resolve middleware sees req.rbacUser and calls next()
//
// Shared token (deprecated):
//   - Kept for zero-downtime migration; emits WARN on every use
//   - Remove QODIQA_OPS_TOKEN once all operators have individual keys
//
// Fail-closed:
//   - Missing credential       → 401
//   - Invalid/unknown key      → 401
//   - Disabled operator's key  → 401
//   - Store lookup error       → 401
//
// AUTH-2 — auth-failure lockout:
//   The general-purpose rate limiter in front of this middleware
//   (adminProtection.js) throttles overall throughput but treats a wrong
//   credential no differently from a correct one, so a shared token can
//   still be brute-forced within that budget. `authLockout` (optional 3rd
//   param, see src/core/authLockout) is a separate, credential-outcome-aware
//   control: it is consulted BEFORE any credential is evaluated (so it can
//   reject or delay a probe before doing any comparison work) and updated
//   AFTER the outcome is known. A failure is only ever recorded for the one
//   branch below that represents an actually-invalid token being presented
//   (`OPS_AUTH_INVALID_TOKEN`) — never for a missing credential (nothing was
//   guessed), a disabled operator's otherwise-correct key (the credential
//   itself was valid), or a store lookup error (not a credential outcome at
//   all) — matching the requirement that the counter track invalid-token
//   presentations specifically, not authentication failures in general.
//   Omitting the param (existing call sites, existing tests) disables it via
//   NOOP_LOCKOUT — behavior is byte-for-byte unchanged.
//
//   credential-identity scoped secondary counter:
//   The raw credential is extracted from the request BEFORE calling
//   `precheck()` (moved ahead of where it used to be parsed) so the lockout
//   control can also consult a counter scoped to a hash of the presented
//   credential itself — closing the gap where a distributed attacker
//   rotates source IPs while repeating the same guessed credential. This
//   reorder is safe: header parsing is not "credential work" in the sense
//   this comment warned about above (no comparison, no store lookup — that
//   still only happens after precheck() clears the request). The raw
//   credential is passed to `precheck()`/`recordFailure()`/`recordSuccess()`
//   purely so authLockout can hash it locally; it is never logged, stored,
//   or returned by this middleware.

const crypto = require('crypto');
const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

function _defaultSleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Inert placeholder used whenever no real authLockout instance is injected —
// mirrors src/core/authLockout's own NOOP_LOCKOUT shape exactly, but defined
// locally so this middleware never needs to reach into src/core for a
// default value (see .dependency-cruiser.js's no-middleware-to-core rule).
// The real control (src/core/authLockout's createAuthLockout()) is always
// constructed by the composition root (server/startup.js) and passed in
// explicitly; this is only the fallback shape for callers that omit it.
//
// This is a DELIBERATE duplication, not drift — do NOT "simplify" it by
// re-importing NOOP_LOCKOUT (or authLockout generally) from src/core/authLockout.
// That edge was removed on purpose in item 13 / commits a12f979, f57ad78 (Track D)
// to satisfy the no-middleware-to-core rule, which is CI-blocking (error severity,
// not warn-budgeted). Re-adding the import reintroduces that violation.
const NOOP_LOCKOUT = Object.freeze({
  precheck:      async () => ({ locked: false, backoffDelayMs: 0 }),
  recordFailure: async () => {},
  recordSuccess: async () => {},
});

/**
 * @param {object} opsConfig       — result of loadOpsConfig() (may have .token)
 * @param {object} [rbacStore]     — the RBAC user store singleton
 * @param {object} [authLockout]   — result of createAuthLockout(opsConfig); see
 *                                   src/core/authLockout. Defaults to a no-op.
 * @param {object} [opts]
 * @param {(ms: number) => Promise<void>} [opts._sleep] — injectable for tests
 * @param {{accepts: Function, resolve: Function}} [opts.federation] — OIDC bearer tokens for operators (single sign-on); injected by the composition root
 */
function createOpsAuthMiddleware(opsConfig, rbacStore, authLockout = NOOP_LOCKOUT, { _sleep = _defaultSleep, federation: initialFederation = null } = {}) {
  let federation = initialFederation;
  const opsAuth = async function opsAuth(req, res, next) {
    const reqId = req.requestId ?? null;
    const ip    = req.clientIp  ?? req.ip ?? null;

    // ── Extract credential ──────────────────────────────────────────────────
    // Done before consulting the lockout control so its optional
    // credential-identity counter is available whenever a credential is
    // present — this is header parsing only, not the "credential work"
    // (comparison, store lookup) that precheck() is meant to gate.
    let provided = null;
    const authHeader = req.headers['authorization'];
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
      provided = authHeader.slice(7);
    } else if (typeof req.headers['x-ops-token'] === 'string') {
      provided = req.headers['x-ops-token'];
    }

    // ── AUTH-2: consult the lockout control before doing any credential
    // work. A locked-out source never reaches the comparison below at all;
    // a source with a recent-but-below-threshold failure streak is delayed
    // first (deterministic exponential backoff — see src/core/authLockout).
    const _lock = await authLockout.precheck(req, provided);
    if (_lock.locked && _lock.storageUnavailable) {
      // RT-04: lockout store unreachable — fail closed, reported as a backend outage, not a lockout.
      res.set('Retry-After', String(_lock.retryAfterSeconds ?? 2));
      return failure(
        res, 'AUTH_BACKEND_UNAVAILABLE',
        'The authentication lockout store is temporarily unavailable — retry shortly',
        503,
        { retryAfterSeconds: _lock.retryAfterSeconds ?? 2 },
      );
    }
    if (_lock.locked) {
      if (_lock.retryAfterSeconds != null) res.set('Retry-After', String(_lock.retryAfterSeconds));
      return failure(
        res, 'AUTH_LOCKED_OUT',
        'Too many failed authentication attempts from this source — temporarily locked out',
        429,
        { retryAfterSeconds: _lock.retryAfterSeconds ?? null },
      );
    }
    if (_lock.backoffDelayMs > 0) await _sleep(_lock.backoffDelayMs);

    if (!provided) {
      emit('WARN', 'OPS_AUTH_MISSING_CREDENTIALS', { path: req.path, ip, requestId: reqId });
      try { require('../observability/metrics').opsAuthFailuresTotal.inc({ reason: 'missing_credentials' }); } catch { /* best-effort metric */ }
      return failure(res, 'UNAUTHORIZED', 'Missing authentication credentials', 401);
    }

    // ── 0. Single sign-on: an OIDC bearer token linked to an operator account ──────────────
    if (federation && federation.accepts(provided)) {
      const f = await federation.resolve(provided);
      if (!f.ok) {
        if (f.unavailable) {
          res.set('Retry-After', '5');
          emit('WARN', 'OPS_AUTH_CONTROL_PLANE_UNAVAILABLE', { path: req.path, ip, requestId: reqId, via: 'oidc', reason: f.reason });
          return failure(res, 'AUTH_BACKEND_UNAVAILABLE', 'The identity provider or the control plane is temporarily unavailable', 503);
        }
        emit('WARN', 'OPS_AUTH_INVALID_TOKEN', { path: req.path, ip, requestId: reqId, via: 'oidc', reason: f.reason });
        await authLockout.recordFailure(req, provided);
        return failure(res, 'UNAUTHORIZED', 'Invalid or missing authentication credentials', 401);
      }
      const ssoUser = f.operator;
      if (!ssoUser.enabled) {
        emit('WARN', 'OPS_AUTH_KEY_USER_DISABLED', { path: req.path, ip, requestId: reqId, userId: ssoUser.id, via: 'oidc' });
        return failure(res, 'UNAUTHORIZED', 'Operator account is disabled', 401);
      }
      req.rbacUser = Object.freeze({ id: ssoUser.id, username: ssoUser.username, role: ssoUser.role, enabled: ssoUser.enabled });
      req.operatorAuthMethod = f.via === 'session' ? 'sso-session' : 'oidc';   // F10V-10: a SAML/LDAP session token is not an OIDC bearer
      // what the identity provider vouched for: lets the MFA step-up accept a recent second-factor authentication instead of a TOTP code (only where the provider declares an assurance)
      req.operatorSso = Object.freeze({ providerId: f.providerId, assured: f.assured === true });
      emit('INFO', 'OPS_AUTH_OK', { path: req.path, ip, requestId: reqId, userId: ssoUser.id, username: ssoUser.username, role: ssoUser.role, authMethod: f.via === 'session' ? 'sso-session' : 'oidc', providerId: f.providerId, assured: f.assured === true });
      await authLockout.recordSuccess(req, provided);
      return next();
    }

    // ── 1. Per-operator API key ─────────────────────────────────────────────
    if (rbacStore) {
      let keyUser;
      let keyState = null;
      try {
        // (D5): the detailed resolver also reports expiry / rotation-grace
        // state; the plain one (test doubles, older stores) stays supported.
        if (typeof rbacStore.resolveOperatorKeyDetailed === 'function') {
          keyState = rbacStore.resolveOperatorKeyDetailed(provided);
          keyUser  = keyState ? keyState.user : null;
        } else {
          keyUser = rbacStore.resolveOperatorKey(provided);
        }
      } catch (e) {
        // stale control-plane snapshot → 503, not a credential failure.
        if (e && e.name === 'ControlPlaneError') {
          emit('WARN', 'OPS_AUTH_CONTROL_PLANE_UNAVAILABLE', { path: req.path, ip, requestId: reqId, code: e.code });
          return failure(res, e.code, 'The control plane is temporarily unavailable', e.status || 503);
        }
        emit('ERROR', 'OPS_AUTH_KEY_LOOKUP_ERROR', {
          path: req.path, ip, requestId: reqId, error: e.message,
        });
        return failure(res, 'UNAUTHORIZED', 'Authentication failed', 401);
      }

      if (keyUser && keyState && keyState.status === 'expired') {
        // (D5): an expired key (or a previous key past its rotation grace)
        // is refused with a distinct reason, audited, and counted as a failure.
        emit('WARN', 'RBAC_API_KEY_EXPIRED_USED', {
          path: req.path, ip, requestId: reqId, userId: keyUser.id, username: keyUser.username,
          expiredAt: keyState.expiresAt, via: keyState.via,
        });
        await authLockout.recordFailure(req, provided);
        return failure(res, 'API_KEY_EXPIRED', 'The API key has expired — rotate it via POST /rbac/users/:id/api-key', 401);
      }

      if (keyUser) {
        if (keyState && (keyState.status === 'expiring' || keyState.status === 'grace')) {
          res.set('X-QODIQA-Key-Expires', String(keyState.expiresAt));
          emit('WARN', keyState.status === 'grace' ? 'RBAC_API_KEY_GRACE_USED' : 'RBAC_API_KEY_EXPIRING', {
            path: req.path, ip, requestId: reqId, userId: keyUser.id, username: keyUser.username, expiresAt: keyState.expiresAt,
          });
        }
        if (!keyUser.enabled) {
          emit('WARN', 'OPS_AUTH_KEY_USER_DISABLED', {
            path: req.path, ip, requestId: reqId, userId: keyUser.id,
          });
          return failure(res, 'UNAUTHORIZED', 'Operator account is disabled', 401);
        }

        // Attach operator identity — downstream RBAC resolve sees req.rbacUser
        // and proceeds without consulting any request header.
        req.rbacUser = Object.freeze({
          id:       keyUser.id,
          username: keyUser.username,
          role:     keyUser.role,
          enabled:  keyUser.enabled,
        });
        req.operatorAuthMethod = 'api-key';

        emit('INFO', 'OPS_AUTH_OK', {
          path:       req.path,
          ip,
          requestId:  reqId,
          userId:     keyUser.id,
          username:   keyUser.username,
          role:       keyUser.role,
          authMethod: 'api-key',
        });
        await authLockout.recordSuccess(req, provided);
        return next();
      }
    }

    // ── 2. Shared token (deprecated migration path) ─────────────────────────
    if (opsConfig.token) {
      const a = Buffer.from(provided,        'utf8');
      const b = Buffer.from(opsConfig.token, 'utf8');
      const valid = a.length === b.length && crypto.timingSafeEqual(a, b);

      if (valid) {
        req.operatorAuthMethod = 'shared-token';
        emit('WARN', 'OPS_AUTH_SHARED_TOKEN_USED', {
          path:      req.path,
          ip,
          requestId: reqId,
          message:   'QODIQA_OPS_TOKEN is deprecated — issue per-operator API keys ' +
                     'via POST /rbac/users/:id/api-key and remove QODIQA_OPS_TOKEN',
        });
        await authLockout.recordSuccess(req, provided);
        return next();
      }
    }

    // ── 3. Authentication failed ────────────────────────────────────────────
    if (!opsConfig.token && !rbacStore) {
      emit('WARN', 'OPS_AUTH_NOT_CONFIGURED', {
        path:      req.path,
        ip,
        requestId: reqId,
        message:   'No authentication configured — operational endpoint access denied',
      });
    } else {
      emit('WARN', 'OPS_AUTH_INVALID_TOKEN', { path: req.path, ip, requestId: reqId });
      try { require('../observability/metrics').opsAuthFailuresTotal.inc({ reason: 'invalid_token' }); } catch { /* best-effort metric */ }
      // Only this branch represents an actually-invalid credential being
      // presented — see the AUTH-2 header comment above for why the other
      // failure branches (missing credential, disabled account, store
      // error) deliberately do not call recordFailure.
      await authLockout.recordFailure(req, provided);
    }

    return failure(res, 'UNAUTHORIZED', 'Invalid or missing authentication credentials', 401);
  };
  /** installs (or removes, with null) the single-sign-on source after construction - the composition root wires it so the factory call stays unchanged. */
  opsAuth.useFederation = (f) => { federation = f || null; };
  return opsAuth;
}

module.exports = { createOpsAuthMiddleware };
