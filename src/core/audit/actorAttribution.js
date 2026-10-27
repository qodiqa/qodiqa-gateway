'use strict';

/**
 * Canonical actor-attribution helper for audit/log events emitted from HTTP
 * route handlers (AUTH-3 remediation).
 *
 * Root cause: authentication (src/middleware/opsAuth.js) attaches the
 * authenticated operator's identity to `req.rbacUser` — nothing in this
 * codebase has ever populated `req.user`. A handful of route handlers
 * (src/api/routes/admin/organizations.js, src/api/routes/admin/tenants.js,
 * src/api/routes/compliance.js) nonetheless read `req.user?.field` when
 * building audit/log events. Since that property is always undefined, those
 * call sites unconditionally took their `?? 'system'` / `?? 'api'` fallback
 * on *every* request — including fully-authenticated admin requests —
 * collapsing real operator actions into an audit identity indistinguishable
 * from a genuine system-generated event.
 *
 * This module is the single source of truth for turning an HTTP request
 * into an audit actor. Route handlers must call resolveOperatorActor(req)
 * rather than reading req.rbacUser (or req.user) inline, so there is exactly
 * one rule for "who performed this action" and no route can silently regress
 * to a dead property again.
 *
 * This does NOT change authentication or authorization — every route that
 * calls this helper is expected to already be mounted behind opsAuth +
 * rbacResolve (see src/middleware/adminProtection.js), which populate
 * req.rbacUser and fail the request closed (401/403) before any handler
 * runs if authentication didn't succeed. req.rbacUser being absent here
 * therefore is not a normal "anonymous caller" case — it means the route's
 * middleware stack itself is misconfigured (e.g. missing rbacResolve). That
 * must never be papered over as `operator: "system"`: it is reported via
 * an AUDIT_ATTRIBUTION_FAILED event and surfaced with a sentinel value that
 * can never be confused with either a real authenticated operator or a real
 * system-generated event.
 */

const { emit } = require('../../../services/logger');

// Emitted whenever resolveOperatorActor() cannot find an authenticated
// identity on a request that reached an audit-logging call site. Under
// correct routing this should never fire in production — see module
// docblock — so any occurrence indicates a middleware regression and is
// worth alerting on.
const AUDIT_ATTRIBUTION_FAILED = 'AUDIT_ATTRIBUTION_FAILED';

// Distinct from any authenticated username AND from genuine system-generated
// events (SYSTEM_ACTOR below) — this string can only appear in the audit
// trail if a route lost its rbacResolve gate, making the gap grep-able and
// impossible to confuse with a real operator or a real system event.
const UNATTRIBUTED_OPERATOR = 'unattributed-operator';

// Used only by code paths that have no HTTP request at all — background
// jobs, scheduled sweeps, startup/shutdown hooks. Never used as a fallback
// for a request that should have carried an authenticated identity.
const SYSTEM_ACTOR = 'system';

/**
 * Resolve the audit-trail actor for an authenticated HTTP request.
 *
 * @param {object} req — Express request. Expected to carry req.rbacUser,
 *   populated by createOpsAuthMiddleware + rbacResolve.
 * @returns {string} the authenticated operator's username/id, or the
 *   UNATTRIBUTED_OPERATOR sentinel if no authenticated identity is present.
 */
function resolveOperatorActor(req) {
  const user = req && req.rbacUser;
  const identity = user && (user.username || user.id);
  if (identity) return identity;

  emit('WARN', AUDIT_ATTRIBUTION_FAILED, {
    path:      req?.path ?? null,
    method:    req?.method ?? null,
    requestId: req?.requestId ?? null,
    reason:    'req.rbacUser missing at audit-attribution time — route is ' +
               'missing rbacResolve or is being invoked outside the admin stack',
  });
  return UNATTRIBUTED_OPERATOR;
}

module.exports = {
  resolveOperatorActor,
  SYSTEM_ACTOR,
  UNATTRIBUTED_OPERATOR,
  AUDIT_ATTRIBUTION_FAILED,
};
