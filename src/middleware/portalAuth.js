'use strict';

/**
 * Tenant Portal Authentication Middleware —
 *
 * Populates req.rbacUser and req.tenantContext from a validated portal
 * session bearer token — the tenant-portal analogue of
 * src/middleware/opsAuth.js (which does the same for per-operator ok_ API
 * keys). Once req.rbacUser is set, the EXISTING, UNCHANGED
 * src/middleware/rbac.js (createRbacResolveMiddleware +
 * createRequirePermission) works identically for portal routes as it
 * already does for admin routes — this file adds no second authorization
 * mechanism, only a second AUTHENTICATION source feeding the same
 * req.rbacUser.role contract createRequirePermission() already reads.
 *
 * DEPENDENCY INJECTION, not a direct src/core require: mirrors
 * src/middleware/rbac.js's createRequirePermission({isPermitted,
 * isValidPermission}) pattern exactly, for the same reason —
 * .dependency-cruiser.js's no-middleware-to-core rule (CI-blocking)
 * forbids src/middleware/**  from importing src/core/**  directly. The
 * composition root (server/startup.js) passes in verifySessionToken (from
 * services/portal/portalSessionToken.js — services/ is NOT src/core, so
 * that one IS a safe direct require, matching opsAuth.js's own direct
 * require of services/logger) and getPortalUserById (from
 * src/core/portal/tenantPortalUserStore.js, which DOES live under
 * src/core and therefore MUST be injected).
 *
 * req.tenantContext IS THE SERVER-DERIVED, AUTHORITATIVE TENANT — set
 * exclusively from the validated token's own tenantId field, which was
 * itself set at MINT time from the tenant the OIDC callback resolved
 * (never from anything client-supplied at verify time). No header,
 * query string, or request body field is EVER consulted here or anywhere
 * downstream for tenant identity — see src/api/routes/tenantPortal.js's
 * route handlers, none of which read req.headers['x-tenant-id'] or
 * similar. A client that sends such a header gets it silently ignored,
 * exactly like src/middleware/rbac.js already does for X-Ops-Actor.
 */

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

function _extractToken(req) {
  const header = req.headers.authorization;
  if (typeof header === 'string' && header.startsWith('Bearer ')) {
    return header.slice('Bearer '.length).trim();
  }
  return null;
}

function _deny401(res, req, reason) {
  emit('WARN', 'PORTAL_AUTH_DENIED', {
    requestId: req.requestId ?? null,
    ip:        req.clientIp  ?? req.ip ?? null,
    path:      req.path,
    method:    req.method,
    reason,
  });
  return failure(res, 'UNAUTHORIZED', 'Authentication required', 401);
}

/**
 * @param {object} deps
 * @param {(token: string) => ({portalUserId, tenantId, role, issuedAt, expiresAt, sessionVersion}|null)} deps.verifySessionToken
 *   — services/portal/portalSessionToken.js's verifySessionToken, injected.
 * @param {(id: string) => (object|null)} deps.getPortalUserById
 *   — src/core/portal/tenantPortalUserStore.js's getById, injected. Used to
 *   re-check `enabled` on every request (defense in depth: an operator
 *   disabling a tenant-portal user takes effect on their NEXT request,
 *   without waiting for the up-to-8h session token to expire) — the token
 *   itself remains the sole source of tenantId/role, never re-derived from
 *   the store, so a stale store read can only ever narrow access (a
 *   disabled/missing user denies) and never widen it.
 * @returns {import('express').RequestHandler}
 */
function createPortalSessionMiddleware({ verifySessionToken, getPortalUserById }) {
  if (typeof verifySessionToken !== 'function') {
    throw new Error('createPortalSessionMiddleware: verifySessionToken function is required');
  }
  if (typeof getPortalUserById !== 'function') {
    throw new Error('createPortalSessionMiddleware: getPortalUserById function is required');
  }

  return function portalSessionAuth(req, res, next) {
    const token = _extractToken(req);
    if (!token) {
      return _deny401(res, req, 'MISSING_CREDENTIAL');
    }

    let claims;
    try {
      claims = verifySessionToken(token);
    } catch (e) {
      emit('ERROR', 'PORTAL_AUTH_VERIFY_ERROR', { requestId: req.requestId ?? null, error: e.message });
      return _deny401(res, req, 'VERIFY_ERROR');
    }

    if (!claims) {
      return _deny401(res, req, 'INVALID_OR_EXPIRED_TOKEN');
    }

    let portalUser;
    try {
      portalUser = getPortalUserById(claims.portalUserId);
    } catch (e) {
      emit('ERROR', 'PORTAL_AUTH_LOOKUP_ERROR', { requestId: req.requestId ?? null, error: e.message });
      return _deny401(res, req, 'LOOKUP_ERROR');
    }

    if (!portalUser || !portalUser.enabled) {
      return _deny401(res, req, 'USER_DISABLED_OR_UNKNOWN');
    }

    // server-side revocation. The token is bound to the
    // record it was minted from — its session version, tenant and role.
    // Any difference means the session was revoked (operator "sign out
    // everywhere", self-service logout, disable) or the identity it was
    // issued for changed (role/tenant), and the session is refused; the user
    // signs in again to get a token for the record as it is now. A pre-
    // token (no `sv`) verifies as version 0 and a never-revoked record
    // reads as 0, so existing sessions survive the upgrade until expiry or
    // revocation. The record's value is normalised exactly like
    // tenantPortalUserStore.sessionVersionOf() (not imported: middleware may
    // not require src/core — see this file's header).
    const recordVersion = Number.isSafeInteger(portalUser.sessionVersion) && portalUser.sessionVersion >= 0
      ? portalUser.sessionVersion : 0;
    const tokenVersion = Number.isSafeInteger(claims.sessionVersion) ? claims.sessionVersion : 0;
    if (tokenVersion !== recordVersion) {
      return _deny401(res, req, 'SESSION_REVOKED');
    }
    if (claims.tenantId !== portalUser.tenantId) {
      return _deny401(res, req, 'SESSION_TENANT_CHANGED');
    }
    if (claims.role !== portalUser.role) {
      return _deny401(res, req, 'SESSION_ROLE_CHANGED');
    }

    // req.rbacUser: the SAME shape createRequirePermission() already
    // expects from opsAuth.js — role is read from the STORE record (and,
    // must also equal the token's role, so a role change ends
    // the session rather than silently re-scoping it).
    req.rbacUser = Object.freeze({
      id:       portalUser.id,
      username: portalUser.email || portalUser.idpSubject,
      role:     portalUser.role,
      enabled:  portalUser.enabled,
    });
    req.operatorAuthMethod = 'portal-session';
    // the session version this request authenticated under (used by
    // the self-service logout to revoke exactly the caller's own sessions).
    req.portalSession = Object.freeze({ portalUserId: portalUser.id, sessionVersion: recordVersion });

    // req.tenantContext: the ONLY place tenant scope enters the request.
    // Server-derived exclusively from the validated token — see this
    // file's header comment.
    req.tenantContext = Object.freeze({ tenantId: claims.tenantId });

    next();
  };
}

module.exports = { createPortalSessionMiddleware };
