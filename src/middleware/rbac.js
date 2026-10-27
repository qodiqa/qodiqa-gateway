'use strict';

/**
 * RBAC Middleware
 *
 * Two exports:
 *
 *   createRbacResolveMiddleware({ store })
 *     Runs after _opsAuth.  Verifies that req.rbacUser has been populated by
 *     the authentication layer (createOpsAuthMiddleware via per-operator API
 *     key).  If no authenticated identity is present the request is rejected
 *     with 403 — no header-based fallback exists, no configuration flag can
 *     change this outcome.
 *
 *   createRequirePermission({ isPermitted, isValidPermission })
 *     Returns a curried function: requirePermission(permission) → middleware.
 *     Use at the route or mount-point level. Always evaluates the real
 *     permission matrix against req.rbacUser.role, via the injected
 *     isPermitted/isValidPermission — the caller (server/startup.js) passes
 *     src/core/rbac/authorize.js's functions, which compose the fixed
 *     five-role matrix (src/core/rbac/roles.js) with operator-defined custom
 * roles. This middleware
 *     itself never requires src/core directly (see .dependency-cruiser.js's
 *     no-middleware-to-core rule). Canonical-role behavior is unchanged; a
 *     custom-role user is evaluated against that role's own configured
 *     permission set instead.
 *
 * Fail-closed contract (unconditional — there is no configuration that
 * changes any of the following):
 *   - If req.rbacUser is not set by authentication → 403
 *   - If req.rbacUser.role is missing, unknown, or not permitted → 403
 *   - If permission check fails for any reason (including an internal
 *     exception) → 403 (never 500, never next())
 *   - X-Ops-Actor and all other identity headers are NEVER consulted
 *   - There is no "RBAC disabled" mode, no synthetic identity, no implicit
 *     administrator, and no default-allow path of any kind. Every
 *     administrative action requires a real user record with role="admin"
 *     in the RBAC store (src/core/rbac/store.js), created either by
 *     bootstrapAdmin() at first startup (logged at WARN) or by an existing
 *     admin via POST /rbac/users (logged at INFO) — never implicitly.
 *
 * History: prior to this remediation, QODIQA_RBAC_ENABLED=false (or unset)
 * caused this module to attach a synthetic admin identity to every request
 * and turn every permission check into a no-op — a fail-OPEN default that
 * granted full administrative access to any caller who passed authentication
 * (including the deprecated shared QODIQA_OPS_TOKEN) with no RBAC assignment
 * at all. That code path has been removed entirely; it cannot be
 * re-introduced via configuration. See docs/security/RBAC_MODEL.md.
 */

const { emit } = require('../../services/logger');
const { failure } = require('../api/response');

// ── Deny helper ───────────────────────────────────────────────────────────────

function _deny403(res, req, action, actor, role, reason) {
  const requestId = req.requestId ?? null;
  const ip        = req.clientIp  ?? req.ip ?? null;

  emit('WARN', 'RBAC_DENY', {
    requestId,
    ip,
    action,
    actor:  actor ?? null,
    role:   role  ?? null,
    reason,
    path:   req.path,
    method: req.method,
  });
  try { require('../observability/metrics').rbacDenialsTotal.inc({ action: String(action ?? 'unknown'), reason: String(reason ?? 'unknown') }); } catch { /* best-effort metric */ }

  return failure(res, 'FORBIDDEN', 'Insufficient permissions', 403);
}

// ── RBAC resolve middleware ───────────────────────────────────────────────────

/**
 * @param {{ store?: object }} [options] — store is accepted for interface
 *   stability with callers that pass it; it is not consulted at request
 *   time (identity resolution happens exclusively in createOpsAuthMiddleware).
 * @returns {import('express').RequestHandler}
 */
function createRbacResolveMiddleware(_options) {
  return function rbacResolve(req, res, next) {
    const requestId = req.requestId ?? null;
    const ip        = req.clientIp  ?? req.ip ?? null;

    // req.rbacUser is set exclusively by the authentication layer
    // (createOpsAuthMiddleware via per-operator API key).
    // No identity header — including X-Ops-Actor — is consulted here.
    // No fallback identity of any kind is ever attached here.
    if (req.rbacUser) {
      return next();
    }

    // No authenticated identity present — fail closed. Unconditional: there
    // is no configuration flag that causes this branch to be skipped.
    emit('WARN', 'RBAC_RESOLVE_NO_IDENTITY', {
      requestId,
      ip,
      path:   req.path,
      method: req.method,
    });
    return failure(res, 'FORBIDDEN', 'Insufficient permissions', 403);
  };
}

// ── requirePermission factory ─────────────────────────────────────────────────

/**
 * @param {object} options
 * @param {(role: string, permission: string) => boolean} options.isPermitted
 * @param {(permission: string) => boolean} options.isValidPermission
 *   — both from src/core/rbac/authorize.js; injected by the caller (the
 *   composition root, server/startup.js) rather than required directly here,
 *   so this middleware never depends on src/core (see .dependency-cruiser.js's
 *   no-middleware-to-core rule).
 * @returns {(permission: string) => import('express').RequestHandler}
 */
function createRequirePermission({ isPermitted, isValidPermission }) {
  return function requirePermission(permission) {
    // Validate the permission name at middleware-creation time for fail-fast
    // developer feedback — a typo in a route file shows up immediately.
    if (!isValidPermission(permission)) {
      throw new Error(`requirePermission: unknown permission "${permission}"`);
    }

    return function rbacPermissionCheck(req, res, next) {
      const user = req.rbacUser;
      const requestId = req.requestId ?? null;

      // Fail-closed: if rbacResolve did not run, or found no identity, deny.
      if (!user) {
        return _deny403(res, req, permission, null, null, 'RBAC_NOT_RESOLVED');
      }

      let permitted = false;
      try {
        permitted = isPermitted(user.role, permission);
      } catch (e) {
        emit('ERROR', 'RBAC_PERMISSION_ENGINE_ERROR', { requestId, error: e.message });
        // Fail closed — engine error → deny
        return _deny403(res, req, permission, user.username, user.role, 'ENGINE_ERROR');
      }

      if (!permitted) {
        return _deny403(res, req, permission, user.username, user.role, 'INSUFFICIENT_ROLE');
      }

      emit('INFO', 'RBAC_ALLOW', {
        requestId,
        userId:     user.id,
        username:   user.username,
        role:       user.role,
        permission,
        path:       req.path,
        method:     req.method,
      });

      next();
    };
  };
}

// ── Config loader ─────────────────────────────────────────────────────────────

/**
 * Load RBAC configuration from environment variables.
 * Called once at startup; result is passed to middleware factories.
 *
 * RBAC enforcement is unconditional and cannot be disabled. This function no
 * longer reads QODIQA_RBAC_ENABLED to gate behavior — it exists solely to
 * emit a clear startup diagnostic for operators upgrading from a version
 * where that variable had an effect, so a config change from before this
 * remediation never silently changes what it appears to do.
 */
function loadRbacConfig() {
  const rawValue = process.env.QODIQA_RBAC_ENABLED;

  if (rawValue === 'false') {
    emit('WARN', 'RBAC_ALWAYS_ENFORCED', {
      message: 'QODIQA_RBAC_ENABLED=false has no effect — RBAC authorization is ' +
                'always enforced and can no longer be disabled by configuration. ' +
                'Every administrative action requires an explicit RBAC user record ' +
                'with role="admin" (see docs/security/RBAC_MODEL.md). Remove this ' +
                'variable from your configuration.',
    });
  } else if (rawValue !== undefined && rawValue !== 'true') {
    emit('WARN', 'RBAC_ALWAYS_ENFORCED', {
      message: `QODIQA_RBAC_ENABLED="${rawValue}" is not a recognised value and has ` +
                'no effect — RBAC authorization is always enforced. Remove this ' +
                'variable from your configuration.',
    });
  }

  return Object.freeze({});
}

module.exports = {
  createRbacResolveMiddleware,
  createRequirePermission,
  loadRbacConfig,
};
