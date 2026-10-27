'use strict';

/**
 * Signing Authentication + Authorization middleware — TRUST-1 remediation.
 *
 * Replaces the single static QODIQA_SIGN_TOKEN shared-secret check that used
 * to live inline in src/api/routes/sign.js. Every caller now authenticates
 * with an individually-issued, individually-revocable signing API key (see
 * src/core/signing/signingIdentityStore.js), carried the same way every
 * other authenticated credential in this codebase is carried —
 * `Authorization: Bearer <token>` — rather than the bespoke
 * `x-qodiqa-sign-token` header the shared secret used. There is no header
 * fallback and no shared-secret fallback: a caller with no valid, enabled,
 * unrevoked, SIGN_ARTIFACT-permitted identity cannot sign, period.
 *
 * Authentication vs. authorization are deliberately two separate checks
 * (mirrors src/middleware/rbac.js's rbacResolve / requirePermission split):
 *   - Credential does not resolve to any identity           → 401 (authn)
 *   - Credential resolves but identity is disabled/revoked,
 *     or lacks the SIGN_ARTIFACT permission                 → 403 (authz)
 * This distinction matters for accountability: 401 tells an operator "this
 * credential is unknown/wrong"; 403 tells them "this credential is real but
 * not currently allowed to sign" — two different incident-response paths.
 *
 * Fail-closed: any missing credential, unresolvable credential, disabled
 * identity, revoked identity, missing permission, or internal store error
 * denies the request. There is no degraded-mode path and no configuration
 * flag that changes this.
 *
 * On success, attaches:
 *   req.signingIdentity — frozen, minimal projection of the identity record
 *   req.signingKeyId    — identity.id (rate limiter per-identity bucket key
 *                          — see src/core/rateLimit/middleware.js's
 *                          extractIdentity(), which now checks this field)
 *   req.tenantId        — identity.tenantId (scope; also a rate-limit
 *                          dimension already supported by resolvePolicies())
 *
 * Every outcome — allow or deny — emits a structured SIGN_AUTH_* audit event
 * via services/logger.js's emit(), which is this codebase's general-purpose
 * operational/audit sink (dashboard SSE + optional central Postgres store).
 * This is deliberately NOT routed into the cryptographic hash-chained
 * execution audit chain (src/core/audit/audit-log.js) — that chain's entry
 * shape and dedup/replay invariants are specific to AI execution decisions,
 * not credential-issuance-time signing requests; see its header comment.
 */

const crypto = require('crypto');
const { emit } = require('../../services/logger');

const AUTH_HEADER = 'authorization';
const BEARER_PREFIX = 'Bearer ';

function _extractToken(req) {
  const header = req.headers[AUTH_HEADER];
  if (typeof header === 'string' && header.startsWith(BEARER_PREFIX)) {
    return header.slice(BEARER_PREFIX.length).trim();
  }
  return null;
}

function _deny(res, req, status, reason) {
  const requestId = req.requestId ?? null;
  return res.status(status).json({
    decision:  'BLOCK',
    reason,
    details:   {},
    requestId,
  });
}

/**
 * @param {object} options
 * @param {object} options.store — the signing identity store (see
 *   src/core/signing/signingIdentityStore.js); injected by the caller
 *   (src/api/routes/sign.js) rather than defaulted here, so this middleware
 *   never depends on src/core directly (see .dependency-cruiser.js's
 *   no-middleware-to-core rule).
 * @param {(permissions: string[], permission: string) => boolean} options.isSigningPermitted
 *   — see src/core/signing/signingPermissions.js; injected for the same reason.
 * @returns {import('express').RequestHandler}
 */
// while a source is locked out every further request would log a WARN (and so a
// platform_audit_events row) — sampled per source like the limiter's deny path.
const { createEventSampler } = require('../observability/eventSampler');
const _lockedSampler = createEventSampler({ summaryEvent: 'SIGN_AUTH_LOCKED_OUT_SUPPRESSED' });

// (D2): no-op lockout for standalone use; src/api/routes/sign.js injects the real one.
const NOOP_LOCKOUT = Object.freeze({
  precheck: async () => ({ locked: false, backoffDelayMs: 0 }),
  recordFailure: async () => {},
  recordSuccess: async () => {},
});

// `federation` (optional, injected by sign.js) is `{ accepts(token), resolve(token) }` - an OIDC bearer token is verified by the identity module and mapped to the signing identity
// linked to its (issuer, subject); everything after the lookup (enabled, revoked, permission, scope) is the same code path as for an API key.
function createSignAuthMiddleware({ store, isSigningPermitted, authLockout = NOOP_LOCKOUT, federation = null }) {
  return async function signAuth(req, res, next) {
    const requestId = req.requestId ?? null;
    const ip        = req.clientIp  ?? req.ip ?? null;

    const token = _extractToken(req);
    if (!token) {
      emit('WARN', 'SIGN_AUTH_MISSING_CREDENTIALS', { requestId, ip, path: req.path });
      return _deny(res, req, 401, 'UNAUTHORIZED');
    }

    // the auth-failure bucket — too many failed credentials
    // from this source (or for this credential) → 429 until the lock expires.
    const _lock = await authLockout.precheck(req, token);
    if (_lock.locked && _lock.storageUnavailable) {
      // RT-04: the lockout store is unreachable — fail CLOSED, but say so truthfully (503, short
      // Retry-After). This is not an authentication failure and not a lockout of this caller.
      res.set('Retry-After', String(_lock.retryAfterSeconds ?? 2));
      const _s = _lockedSampler.sample(`backend:${ip}`);
      if (_s.log) emit('WARN', 'SIGN_AUTH_BACKEND_UNAVAILABLE', { requestId, ip, path: req.path, deniedThisMinute: _s.countThisWindow });
      return _deny(res, req, 503, 'AUTH_BACKEND_UNAVAILABLE');
    }
    if (_lock.locked) {
      if (_lock.retryAfterSeconds != null) res.set('Retry-After', String(_lock.retryAfterSeconds));
      const _s = _lockedSampler.sample(String(ip));
      if (_s.log) emit('WARN', 'SIGN_AUTH_LOCKED_OUT', { requestId, ip, path: req.path, retryAfterSeconds: _lock.retryAfterSeconds ?? null, deniedThisMinute: _s.countThisWindow });
      return _deny(res, req, 429, 'AUTH_LOCKED_OUT');
    }

    let identity;
    let keyState = null;
    let federated = null;
    if (federation && federation.accepts(token)) {
      const f = await federation.resolve(token);
      if (!f.ok) {
        if (f.unavailable) {
          // the IdP (or the identity store) cannot be reached: fail closed, but this is not the caller's authentication failure
          res.set('Retry-After', '5');
          emit('WARN', 'SIGN_AUTH_BACKEND_UNAVAILABLE', { requestId, ip, path: req.path, via: 'oidc', reason: f.reason });
          return _deny(res, req, 503, 'AUTH_BACKEND_UNAVAILABLE');
        }
        emit('WARN', 'SIGN_AUTH_INVALID_CREDENTIAL', { requestId, ip, path: req.path, via: 'oidc', reason: f.reason });
        await authLockout.recordFailure(req, token);
        return _deny(res, req, 401, 'UNAUTHORIZED');
      }
      identity = f.identity; federated = f;
    } else try {
      if (typeof store.resolveSigningIdentityDetailed === 'function') {
        keyState = store.resolveSigningIdentityDetailed(token);
        identity = keyState ? keyState.identity : null;
      } else {
        identity = store.resolveSigningIdentity(token);
      }
    } catch (e) {
      // a stale control-plane snapshot is "cannot decide", never
      // "bad credential" — 503, and no auth-failure count against the caller.
      if (e && e.name === 'ControlPlaneError') {
        emit('WARN', 'SIGN_AUTH_CONTROL_PLANE_UNAVAILABLE', { requestId, ip, code: e.code });
        return _deny(res, req, e.status || 503, e.code);
      }
      emit('ERROR', 'SIGN_AUTH_LOOKUP_ERROR', { requestId, ip, error: e.message });
      return _deny(res, req, 401, 'UNAUTHORIZED');
    }

    if (!identity) {
      emit('WARN', 'SIGN_AUTH_INVALID_CREDENTIAL', { requestId, ip, path: req.path });
      await authLockout.recordFailure(req, token);
      return _deny(res, req, 401, 'UNAUTHORIZED');
    }

    // (D5): expired signing key (or a previous key past its rotation grace).
    if (keyState && keyState.status === 'expired') {
      emit('WARN', 'SIGNING_KEY_EXPIRED_USED', { requestId, ip, identityId: identity.id, name: identity.name, expiredAt: keyState.expiresAt, via: keyState.via });
      await authLockout.recordFailure(req, token);
      return _deny(res, req, 401, 'API_KEY_EXPIRED');
    }
    if (keyState && (keyState.status === 'expiring' || keyState.status === 'grace')) {
      res.set('X-QODIQA-Key-Expires', String(keyState.expiresAt));
      emit('WARN', keyState.status === 'grace' ? 'SIGNING_KEY_GRACE_USED' : 'SIGNING_KEY_EXPIRING', { requestId, ip, identityId: identity.id, name: identity.name, expiresAt: keyState.expiresAt });
    }

    if (!identity.enabled || identity.revoked) {
      emit('WARN', 'SIGN_AUTH_IDENTITY_DISABLED', {
        requestId, ip, identityId: identity.id, name: identity.name,
        enabled: identity.enabled, revoked: identity.revoked,
      });
      return _deny(res, req, 403, 'FORBIDDEN');
    }

    // an identity that demands the identity provider's second-factor assurance is refused a token that does not carry it
    if (federated && identity.requireAssurance === true && federated.assured !== true) {
      emit('WARN', 'SIGN_AUTHZ_DENIED', { requestId, ip, identityId: identity.id, name: identity.name, reason: 'ASSURANCE_REQUIRED', via: 'oidc' });
      return _deny(res, req, 403, 'FORBIDDEN');
    }

    if (!isSigningPermitted(identity.permissions, 'SIGN_ARTIFACT')) {
      emit('WARN', 'SIGN_AUTHZ_DENIED', {
        requestId, ip, identityId: identity.id, name: identity.name,
        permissions: identity.permissions, reason: 'MISSING_SIGN_ARTIFACT_PERMISSION',
      });
      return _deny(res, req, 403, 'FORBIDDEN');
    }

    req.signingIdentity = Object.freeze({
      id:               identity.id,
      name:             identity.name,
      tenantId:         identity.tenantId,
      environment:      identity.environment,
      allowedProviders: identity.allowedProviders,
      permissions:      identity.permissions,
      maxTtlMs:         identity.maxTtlMs,
      credentialType:   identity.credentialType,
      ...(federated ? { federated: Object.freeze({ providerId: federated.providerId, issuer: federated.issuer, subject: federated.subject, expiresAt: federated.expiresAt }) } : {}),
    });
    req.signingKeyId = identity.id;
    req.tenantId     = identity.tenantId;

    emit('INFO', 'SIGN_AUTH_OK', {
      requestId, ip, identityId: identity.id, name: identity.name,
      tenantId: identity.tenantId, environment: identity.environment, ...(federated ? { via: 'oidc', providerId: federated.providerId } : {}),
    });
    await authLockout.recordSuccess(req, token);

    // Best-effort, non-blocking — never delays or fails the request.
    try { store.touchLastUsed(identity.id); } catch (_) { /* observability only */ }

    next();
  };
}

module.exports = { createSignAuthMiddleware, AUTH_HEADER, BEARER_PREFIX };
