'use strict';

const { isControlPlaneError } = require('../../../core/controlPlane');

/**
 * Tenant Administration API — Component #39.
 *
 * All routes require ops-level authentication (mounted behind _opsIpAllow +
 * _opsAuth in server.js).
 *
 * Routes:
 *   POST   /v1/admin/tenants              — create/register tenant
 *   GET    /v1/admin/tenants              — list all tenants
 *   GET    /v1/admin/tenants/:tenantId    — get tenant
 *   PATCH  /v1/admin/tenants/:tenantId    — update tenant (status, name, quotas, minProtocolVersion)
 *   POST   /v1/admin/tenants/:tenantId/portal-users/:portalUserId/revoke-sessions
 * — revoke a portal user's sessions
 */

const { Router } = require('express');
const {
  registerTenant,
  getTenant,
  updateTenant,
  listTenants,
}                = require('../../../core/tenancy/tenantRegistry');
const { getOrganizationForTenant } = require('../../../core/organizations/organizationRegistry');
const { emit }                     = require('../../../../services/logger');
const { resolveOperatorActor }     = require('../../../core/audit/actorAttribution');
const { success, failure }         = require('../../response');
const {
  parsePagination, paginateArray, requiresPagination,
} = require('../../../utils/pagination');

// tenantPolicyRegistry.getPoliciesForTenant() now returns entries
// preprocessed for evaluate() (policyId + evaluator-derived fields like
// BLOCK_IP's _blocklistSet/_cidrRanges — see tenantPolicyFloor.js). Those
// derived fields are internal to the engine, and a couple (Set instances)
// serialize to '{}' over JSON — stripping every underscore-prefixed config
// key here keeps this admin read showing exactly the declared config a
// governance request would have carried, unaffected by that internal detail.
function _publicPolicyView(policy) {
  const config = policy && policy.config && typeof policy.config === 'object' ? policy.config : {};
  const cleanConfig = {};
  for (const key of Object.keys(config)) {
    if (!key.startsWith('_')) cleanConfig[key] = config[key];
  }
  return { ...policy, config: cleanConfig };
}

const TENANT_ID_RE   = /^[A-Za-z0-9_-]{1,64}$/;
const VALID_STATUSES = new Set(['active', 'suspended', 'disabled']);
const PORTAL_USER_ID_RE = /^[A-Za-z0-9_-]{1,128}$/; // pu_<uuid>; seeds may use other safe ids

function createTenantsAdminRouter() {
  const router = Router();

  // POST /v1/admin/tenants — register a tenant
  router.post('/', async (req, res) => {
    const { tenantId, tenantName, organizationId, status, quotas } = req.body || {};

    if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'tenantId must match [A-Za-z0-9_-]{1,64}', 400);
    }
    if (status !== undefined && !VALID_STATUSES.has(status)) {
      return failure(res, 'INVALID_STATUS', `status must be one of: ${[...VALID_STATUSES].join(', ')}`, 400);
    }

    try {
      const tenant = await registerTenant(tenantId, { tenantName, organizationId, status, quotas });
      emit('INFO', 'TENANT_CREATED', {
        tenantId,
        organizationId: organizationId ?? null,
        requestId: req.requestId ?? null,
        operator: resolveOperatorActor(req),
      });
      if (organizationId) {
        // (Findings Register): organizationId here is stored/echoed but
        // does not call assignTenantToOrg() — assertActiveOrganization()
        // stays inert for this tenant until it is also linked via
        // POST /v1/admin/organizations/:orgId/tenants/:tenantId.
        emit('WARN', 'TENANT_ORG_NOT_ENFORCEMENT_LINKED', {
          tenantId,
          organizationId,
          requestId: req.requestId ?? null,
          message: 'organizationId supplied at tenant creation is stored and echoed, but organization-status enforcement is NOT active for this tenant until POST /v1/admin/organizations/:orgId/tenants/:tenantId is also called.',
        });
      }
      return success(res, tenant, 201);
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'TENANT_CREATE_FAILED', { tenantId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'TENANT_REGISTRATION_FAILED', 'Unable to register tenant', 400);
    }
  });

  // GET /v1/admin/tenants — list all tenants
  //
  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them switches to sliced output with
  // canonical pagination metadata.
  router.get('/', (req, res) => {
    const tenants = listTenants().map(t => ({
      ...t,
      organization: getOrganizationForTenant(t.tenantId) || null,
    }));
    // API-1: forces pagination once the unbounded response would exceed the
    // safety ceiling, even if the caller didn't ask for it.
    if (!requiresPagination(req.query, tenants.length)) {
      return success(res, { tenants, total: tenants.length });
    }
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
    const { items, ...meta } = paginateArray(tenants, { page, pageSize });
    return success(res, { tenants: items, total: tenants.length, ...meta });
  });

  // GET /v1/admin/tenants/:tenantId — get single tenant
  router.get('/:tenantId', (req, res) => {
    const { tenantId } = req.params;
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }
    const tenant = getTenant(tenantId);
    if (!tenant) return failure(res, 'TENANT_NOT_FOUND', 'Tenant not found', 404);

    return success(res, {
      ...tenant,
      organization: getOrganizationForTenant(tenantId) || null,
    });
  });

  // GET /v1/admin/tenants/:tenantId/policy-config — the tenant's EFFECTIVE
  // per-tenant configuration: the policy set and semantic config
  // currently enforced by this instance's registries (hydrated from the PG
  // authority — tenant_policy_sets / tenant_semantic_configs, migration 051).
  // READ-ONLY by design: every write goes through the governed
  // change-request flow (/v1/policy/governance with a tenantId; reserved
  // policyId TENANT-SEMANTIC-CONFIG for the semantic overlay) — there is no
  // ungoverned write path to expose here. Behind the same adminStack as the
  // rest of this router.
  router.get('/:tenantId/policy-config', (req, res) => {
    const { tenantId } = req.params;
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }
    // Lazy requires keep this admin router loadable in suites that stub the
    // tenancy layer (same style as the registries' own consumers).
    const tenantPolicyRegistry   = require('../../../core/tenancy/tenantPolicyRegistry');
    const tenantSemanticRegistry = require('../../../core/tenancy/tenantSemanticRegistry');

    const policies = tenantPolicyRegistry.getPoliciesForTenant(tenantId);
    const semantic = tenantSemanticRegistry.getConfig(tenantId);
    const tenant   = getTenant(tenantId);
    if (!tenant && !policies && !semantic) {
      return failure(res, 'TENANT_NOT_FOUND', 'Tenant not found and no per-tenant configuration exists', 404);
    }

    return success(res, {
      tenantId,
      registered: Boolean(tenant),
      policySet: policies
        ? { source: 'TENANT', policyCount: policies.length, policies: policies.map(_publicPolicyView) }
        : { source: 'GLOBAL_FALLBACK', policyCount: null, policies: null },
      semanticConfig: semantic
        ? { source: 'TENANT', hash: semantic.hash, version: semantic.version, config: semantic.config }
        : { source: 'PINNED_DEFAULTS', hash: null, version: null, config: null },
    });
  });

  // PATCH /v1/admin/tenants/:tenantId — update tenant
  router.patch('/:tenantId', async (req, res) => {
    const { tenantId } = req.params;
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }
    if (!getTenant(tenantId)) {
      return failure(res, 'TENANT_NOT_FOUND', 'Tenant not found', 404);
    }

    const { tenantName, status, quotas, minProtocolVersion } = req.body || {};
    if (status !== undefined && !VALID_STATUSES.has(status)) {
      return failure(res, 'INVALID_STATUS', `status must be one of: ${[...VALID_STATUSES].join(', ')}`, 400);
    }
    if (minProtocolVersion !== undefined && minProtocolVersion !== 1 && minProtocolVersion !== 2) {
      return failure(res, 'INVALID_MIN_PROTOCOL_VERSION', 'minProtocolVersion must be 1 or 2', 400);
    }

    try {
      const updated = await updateTenant(tenantId, { tenantName, status, quotas, minProtocolVersion });
      emit('INFO', 'TENANT_UPDATED', {
        tenantId,
        updates: { tenantName, status, minProtocolVersion },
        requestId: req.requestId ?? null,
        operator: resolveOperatorActor(req),
      });
      return success(res, updated);
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'TENANT_UPDATE_FAILED', { tenantId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'UPDATE_FAILED', 'Unable to update tenant', 400);
    }
  });

  // POST /v1/admin/tenants/:tenantId/portal-users/:portalUserId/revoke-sessions
  //
  // operator "sign out everywhere" for one tenant-portal
  // user — increments the user's session version, so every portal session
  // token issued to them before this call is refused on its next request
  // (src/middleware/portalAuth.js). The user is NOT disabled and can sign in
  // again through the IdP; to also block re-login, disable the user.
  // Authorization is the mount's: adminStack('MANAGE_USERS') + _stepUp (MFA
  // step-up on every mutation under /v1/admin/tenants — src/app.js;
  // src/openapi/mfaStepUpScope.js lists this prefix). The portal user must
  // belong to :tenantId (404 otherwise — never acts across tenants, and does
  // not reveal whether the id exists under another tenant).
  router.post('/:tenantId/portal-users/:portalUserId/revoke-sessions', async (req, res) => {
    const { tenantId, portalUserId } = req.params;
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }
    if (!PORTAL_USER_ID_RE.test(portalUserId)) {
      return failure(res, 'INVALID_PORTAL_USER_ID', 'Invalid portalUserId', 400);
    }
    // Lazy require, same style as /policy-config above.
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');
    try {
      const user = portalUserStore.getById(portalUserId);
      if (!user || user.tenantId !== tenantId) {
        return failure(res, 'PORTAL_USER_NOT_FOUND', 'Portal user not found for this tenant', 404);
      }
      const updated = await portalUserStore.revokeSessions(portalUserId, { reason: 'admin_revoke' });
      if (!updated) {
        return failure(res, 'PORTAL_USER_NOT_FOUND', 'Portal user not found for this tenant', 404);
      }
      emit('INFO', 'PORTAL_USER_SESSIONS_REVOKED_BY_OPERATOR', {
        tenantId,
        portalUserId,
        sessionVersion: updated.sessionVersion,
        requestId: req.requestId ?? null,
        operator: resolveOperatorActor(req),
      });
      return success(res, {
        portalUserId,
        tenantId,
        sessionVersion: updated.sessionVersion,
        sessionsRevokedAt: updated.sessionsRevokedAt,
      });
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'PORTAL_USER_SESSION_REVOKE_FAILED', { tenantId, portalUserId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'PORTAL_SESSION_REVOKE_FAILED', 'Unable to revoke portal sessions', 500);
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createTenantsAdminRouter };
