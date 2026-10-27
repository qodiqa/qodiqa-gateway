'use strict';

const { isControlPlaneError } = require('../../../core/controlPlane');

/**
 * Organization Administration API — Component #39.
 *
 * All routes require ops-level authentication (handled by the caller — the
 * router is mounted behind _opsIpAllow + _opsAuth in server.js).
 *
 * Routes:
 *   POST   /v1/admin/organizations           — create organization
 *   GET    /v1/admin/organizations           — list organizations
 *   GET    /v1/admin/organizations/:orgId    — get organization
 *   PATCH  /v1/admin/organizations/:orgId    — update organization
 *   POST   /v1/admin/organizations/:orgId/tenants/:tenantId  — assign tenant
 *   DELETE /v1/admin/organizations/:orgId/tenants/:tenantId  — remove tenant
 *
 * All mutating operations emit a structured audit event via the logger.
 */

const { Router } = require('express');
const {
  registerOrganization,
  getOrganization,
  updateOrganization,
  publishOrganizationStatus,
  assignTenantToOrg,
  removeTenantFromOrg,
  listOrganizations,
}                = require('../../../core/organizations/organizationRegistry');
const { getTenant, registerTenant, updateTenant } = require('../../../core/tenancy/tenantRegistry');
const { emit }   = require('../../../../services/logger');
const { resolveOperatorActor } = require('../../../core/audit/actorAttribution');
const { success, failure } = require('../../response');
const {
  parsePagination, paginateArray, requiresPagination,
} = require('../../../utils/pagination');

const ORG_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TENANT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const VALID_STATUSES = new Set(['active', 'suspended', 'disabled']);

function createOrganizationsAdminRouter() {
  const router = Router();

  // POST /v1/admin/organizations — create organization
  router.post('/', async (req, res) => {
    const { organizationId, organizationName, status, metadata, quotas } = req.body || {};

    if (organizationId !== undefined && !ORG_ID_RE.test(organizationId)) {
      return failure(res, 'INVALID_ORG_ID', 'organizationId must be a valid UUID v4', 400);
    }
    if (status !== undefined && !VALID_STATUSES.has(status)) {
      return failure(res, 'INVALID_STATUS', `status must be one of: ${[...VALID_STATUSES].join(', ')}`, 400);
    }

    try {
      const org = await registerOrganization({ organizationId, organizationName, status, metadata, quotas });
      emit('INFO', 'ORG_CREATED', {
        organizationId: org.organizationId,
        organizationName: org.organizationName,
        requestId: req.requestId ?? null,
        operator: resolveOperatorActor(req),
      });
      return success(res, org, 201);
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'ORG_CREATE_FAILED', { error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'ORG_CONFLICT', 'Unable to create organization', 409);
    }
  });

  // GET /v1/admin/organizations — list all organizations
  //
  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them switches to sliced output with
  // canonical pagination metadata.
  router.get('/', (req, res) => {
    const orgs = listOrganizations();
    // API-1: forces pagination once the unbounded response would exceed the
    // safety ceiling, even if the caller didn't ask for it.
    if (!requiresPagination(req.query, orgs.length)) {
      return success(res, { organizations: orgs, total: orgs.length });
    }
    const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
    const { items, ...meta } = paginateArray(orgs, { page, pageSize });
    return success(res, { organizations: items, total: orgs.length, ...meta });
  });

  // GET /v1/admin/organizations/:orgId — get single organization
  router.get('/:orgId', (req, res) => {
    const { orgId } = req.params;
    if (!ORG_ID_RE.test(orgId)) {
      return failure(res, 'INVALID_ORG_ID', 'Invalid organizationId', 400);
    }
    const org = getOrganization(orgId);
    if (!org) return failure(res, 'ORG_NOT_FOUND', 'Organization not found', 404);
    return success(res, org);
  });

  // PATCH /v1/admin/organizations/:orgId — update organization
  //
  // a `status` change is routed through publishOrganizationStatus(),
  // which durably writes the new status to the shared Redis-backed
  // authoritative store and broadcasts it before this request is reported
  // successful — see organizationRegistry.js and docs/architecture/multi-tenancy.md for
  // the bounded propagation guarantee this provides across workers. Other
  // fields (organizationName/metadata/quotas) are unaffected by that
  // guarantee and remain purely process-local, exactly as before.
  router.patch('/:orgId', async (req, res) => {
    const { orgId } = req.params;
    if (!ORG_ID_RE.test(orgId)) {
      return failure(res, 'INVALID_ORG_ID', 'Invalid organizationId', 400);
    }

    const { organizationName, status, metadata, quotas } = req.body || {};
    if (status !== undefined && !VALID_STATUSES.has(status)) {
      return failure(res, 'INVALID_STATUS', `status must be one of: ${[...VALID_STATUSES].join(', ')}`, 400);
    }

    if (!getOrganization(orgId)) {
      return failure(res, 'ORG_NOT_FOUND', 'Organization not found', 404);
    }

    const actor = resolveOperatorActor(req);

    try {
      let updated = await updateOrganization(orgId, { organizationName, metadata, quotas });

      if (status !== undefined) {
        updated = await publishOrganizationStatus(orgId, status, {
          updatedBy:     actor,
          correlationId: req.requestId ?? null,
        });
      }

      emit('INFO', 'ORG_UPDATED', {
        organizationId: orgId,
        updates: { organizationName, status },
        requestId: req.requestId ?? null,
        operator: actor,
      });
      return success(res, updated);
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      if (err.message === 'ORG_STATUS_PROPAGATION_UNAVAILABLE') {
        emit('ERROR', 'ORG_STATUS_PROPAGATION_FAILED', {
          organizationId: orgId, status, requestId: req.requestId ?? null,
        });
        return failure(res, 'ORG_STATUS_PROPAGATION_UNAVAILABLE',
          'Unable to durably propagate the organization status change cluster-wide; the change was not applied.', 503);
      }
      emit('ERROR', 'ORG_UPDATE_FAILED', { organizationId: orgId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'UPDATE_FAILED', 'Unable to update organization', 400);
    }
  });

  // POST /v1/admin/organizations/:orgId/tenants/:tenantId — assign tenant to org
  router.post('/:orgId/tenants/:tenantId', async (req, res) => {
    const { orgId, tenantId } = req.params;

    if (!ORG_ID_RE.test(orgId)) {
      return failure(res, 'INVALID_ORG_ID', 'Invalid organizationId', 400);
    }
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }
    if (!getOrganization(orgId)) {
      return failure(res, 'ORG_NOT_FOUND', 'Organization not found', 404);
    }

    // Auto-register tenant if not known (idempotent)
    if (!getTenant(tenantId)) {
      try {
        await registerTenant(tenantId, { organizationId: orgId });
      } catch (err) {
        if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
        emit('ERROR', 'TENANT_REGISTRATION_FAILED', { tenantId, error: err.message, requestId: req.requestId ?? null });
        return failure(res, 'TENANT_REGISTRATION_FAILED', 'Unable to register tenant', 400);
      }
    }

    try {
      await assignTenantToOrg(tenantId, orgId);
      await updateTenant(tenantId, { organizationId: orgId });

      emit('INFO', 'TENANT_ASSIGNED_TO_ORG', {
        tenantId, organizationId: orgId,
        requestId: req.requestId ?? null,
        operator: resolveOperatorActor(req),
      });
      return success(res, { tenantId, organizationId: orgId, assigned: true });
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'TENANT_ASSIGNMENT_FAILED', { tenantId, organizationId: orgId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'ASSIGNMENT_CONFLICT', 'Unable to assign tenant to organization', 409);
    }
  });

  // DELETE /v1/admin/organizations/:orgId/tenants/:tenantId — remove tenant from org
  router.delete('/:orgId/tenants/:tenantId', async (req, res) => {
    const { orgId, tenantId } = req.params;

    if (!ORG_ID_RE.test(orgId)) {
      return failure(res, 'INVALID_ORG_ID', 'Invalid organizationId', 400);
    }
    if (!TENANT_ID_RE.test(tenantId)) {
      return failure(res, 'INVALID_TENANT_ID', 'Invalid tenantId', 400);
    }

    try {
      const removed = await removeTenantFromOrg(tenantId, orgId);
      if (!removed) {
        return failure(res, 'TENANT_NOT_FOUND_IN_ORG', 'Tenant not found in organization', 404);
      }
      await updateTenant(tenantId, { organizationId: null });
    } catch (err) {
      if (isControlPlaneError(err)) return failure(res, err.code, err.message, err.status);
      emit('ERROR', 'TENANT_REMOVAL_FAILED', { tenantId, organizationId: orgId, error: err.message, requestId: req.requestId ?? null });
      return failure(res, 'REMOVAL_FAILED', 'Unable to remove tenant from organization', 500);
    }
    emit('INFO', 'TENANT_REMOVED_FROM_ORG', {
      tenantId, organizationId: orgId,
      requestId: req.requestId ?? null,
      operator: resolveOperatorActor(req),
    });
    return success(res, { tenantId, organizationId: orgId, removed: true });
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createOrganizationsAdminRouter };
