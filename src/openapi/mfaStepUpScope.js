'use strict';

/**
 * / API-04: which operations require the operator MFA step-up
 * (src/middleware/mfaStepUp.js), so the generated OpenAPI can declare the `X-QODIQA-OTP` header and the step-up
 * responses on exactly those operations.
 *
 * This restates the mounts in src/app.js (the `_stepUp*` arguments). It cannot
 * drift silently: src/openapi/mfaStepUpScope.test.js builds the REAL app, finds every mounted `mfaStepUp` middleware in
 * each route's chain, invokes it, and requires the set of operations it actually gates to equal the set this module
 * declares.
 *
 * Reads (GET/HEAD/OPTIONS) are never gated (mfaStepUp.js SAFE_METHODS).
 */

const { RBAC_SELF_ENROLL, isStepUpExempt } = require('../middleware/mfaStepUp');

const SAFE_METHODS = new Set(['get', 'head', 'options']);

// { prefix, when?(relativePath) } — `when` mirrors the createMfaStepUp({ when }) predicate, which sees req.path
// relative to the mount prefix. Every mount is ALSO subject to the exemption registry (isStepUpExempt, the same
// function src/app.js's admin-plane mounts use), so a approved verify/simulate endpoint is never declared step-up.
const STEP_UP_MOUNTS = Object.freeze([
  { prefix: '/policy-ui' },
  { prefix: '/key-admin' },
  { prefix: '/rbac', when: (rel) => !RBAC_SELF_ENROLL.test(rel) },
  { prefix: '/signing-identities' },
  { prefix: '/v1/webhooks' },
  { prefix: '/v1/prq' },
  { prefix: '/v1/admin/organizations' },
  { prefix: '/v1/admin/tenants' },
  { prefix: '/v1/admin/kill-switch' },
  { prefix: '/v1/admin/providers' },
  { prefix: '/v1/admin/artifact-revocations' },
  { prefix: '/v1/policy/governance' },
  { prefix: '/v1/admin/dsr' },
  // every remaining admin-plane mount (src/app.js `_stepUpAdmin`).
  { prefix: '/audit' },
  { prefix: '/audit-viewer' },
  { prefix: '/v1/proofs' },
  { prefix: '/v1/agents' },   //
  { prefix: '/v1/tool-registry' }, //
  { prefix: '/v1/mcp/servers' }, //
  { prefix: '/v1/approvals' }, //
  { prefix: '/v1/sessions' }, //   // (read only: no step-up is ever demanded for a GET)
  { prefix: '/provenance' },
  { prefix: '/evidence-chain' },
  { prefix: '/evidence' },
  { prefix: '/v1/evidence' },
  { prefix: '/transparency' },
  { prefix: '/v1/transparency' },
  { prefix: '/v1/certification' },
  { prefix: '/v1/certifications' },
  { prefix: '/dashboard' },
  { prefix: '/audit-store' },
  { prefix: '/compliance' },
  { prefix: '/alerts' },
  { prefix: '/consent' },
  { prefix: '/v1/policy/visual' },
  { prefix: '/v1/policy' },
]);

// Route-level step-up inside a router (not a mount). Empty since /alerts/{id}/suppress is now
// covered by the /alerts mount-level step-up, and the router's own route-level one is no longer injected.
const STEP_UP_ROUTES = Object.freeze(new Set());

/** Concrete path for a predicate test: OpenAPI `{param}` segments become a placeholder value. */
const _concrete = (p) => p.replace(/\{[^}]+\}/g, 'x');

/** True when `method path` (OpenAPI form, e.g. 'post', '/v1/webhooks/{id}') requires an X-QODIQA-OTP code. */
function requiresStepUp(method, path) {
  const m = String(method).toLowerCase();
  if (SAFE_METHODS.has(m)) return false;
  if (isStepUpExempt(m, _concrete(path))) return false;
  if (STEP_UP_ROUTES.has(`${m} ${path}`)) return true;
  for (const { prefix, when } of STEP_UP_MOUNTS) {
    if (path !== prefix && !path.startsWith(`${prefix}/`)) continue;
    const rel = _concrete(path.slice(prefix.length)) || '/';
    return when ? when(rel) : true;
  }
  return false;
}

module.exports = { STEP_UP_MOUNTS, STEP_UP_ROUTES, requiresStepUp };
