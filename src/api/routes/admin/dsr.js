'use strict';

/**
 * GDPR Data Subject Rights Administration API — Component #44.
 *
 * Mounts at /v1/admin/dsr (ops-protected, RBAC-gated — see server.js).
 *
 * Routes:
 *   GET  /v1/admin/dsr                    — list DSR requests
 *   GET  /v1/admin/dsr/:id                — request detail + lifecycle event trail
 *   POST /v1/admin/dsr                    — create a request (Art. 16/17/18/20)
 *   POST /v1/admin/dsr/:id/verify-identity — record identity verification (required before approval)
 *   POST /v1/admin/dsr/:id/approve        — approve a verified request for execution
 *   POST /v1/admin/dsr/:id/rectify        — execute Article 16 rectification
 *   POST /v1/admin/dsr/:id/erase          — execute Article 17 erasure
 *   POST /v1/admin/dsr/:id/restrict       — execute Article 18 restriction
 *   POST /v1/admin/dsr/:id/lift           — lift an Article 18 restriction
 *   POST /v1/admin/dsr/:id/export         — execute Article 20 portability export
 *
 * RBAC gates:
 *   READ_DSR   — list/inspect requests and events
 *   MANAGE_DSR — create, verify identity, approve, and execute any right
 *
 * Every mutating route delegates to core/dsr/DataSubjectRightsService, which
 * enforces identity verification and approval before any right executes and
 * records every lifecycle transition as a dsr_request_events row plus a
 * structured emit() event (see DataSubjectRightsService.js, DSRStore.js).
 */

const { permissionGuard } = require('../permissionGuard'); // fail-closed permission wiring
const express = require('express');
const {
  createRequest, verifyIdentity, approve,
  rectify, erase, restrict, liftRestriction, generateExport,
  getRequest, listRequests, listEvents,
} = require('../../../core/dsr/DataSubjectRightsService');
const {
  dsrCreateRequestSchema, dsrVerifyIdentitySchema, dsrApproveSchema,
  dsrRectifySchema, dsrEraseSchema, dsrRestrictSchema, dsrLiftSchema, dsrExportSchema,
  dsrIdParamSchema, dsrIdQuerySchema, dsrListQuerySchema,
} = require('../../../validation/schemas/dsr.schema');

const { success, failure, internalError } = require('../../response');
const { emit } = require('../../../../services/logger');
const { parsePagination, buildPaginationMeta } = require('../../../utils/pagination');


// ── Response helpers — thin adapters over the canonical envelope (src/api/response.js) ─

function _ok(res, data, status = 200) {
  success(res, data, status);
}

function _err(res, code, message, status = 400) {
  failure(res, code, message, status);
}

function _actor(req, fallback) {
  return req.rbacUser?.username ?? req.rbacUser?.id ?? fallback ?? 'system';
}

// every operator identity on a DSR — requester, identity
// verifier, approver, executor — is the AUTHENTICATED caller. The body fields
// that used to supply them (requestedBy, verifiedBy, approvedBy, rectifiedBy,
// erasedBy, restrictedBy, liftedBy, generatedBy) are still accepted for client
// compatibility and IGNORED; a differing value is logged, never used.
const BODY_IDENTITY_FIELDS = ['requestedBy', 'verifiedBy', 'approvedBy', 'rectifiedBy', 'erasedBy', 'restrictedBy', 'liftedBy', 'generatedBy'];
function _operator(req, body) {
  const who = req.rbacUser?.username ?? req.rbacUser?.id
    ?? (req.operatorAuthMethod === 'shared-token' ? 'ops:shared-token' : 'system');
  for (const f of BODY_IDENTITY_FIELDS) {
    if (body && body[f] != null && body[f] !== who) {
      emit('WARN', 'DSR_BODY_IDENTITY_IGNORED', { field: f, requestId: req.requestId ?? null, operator: who });
    }
  }
  return who;
}

function _wrap(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      // (D10): typed lifecycle refusals carry their own code/status.
      if (err.code === 'DSR_SELF_APPROVAL_FORBIDDEN' || err.code === 'DSR_INVALID_TRANSITION') {
        return _err(res, err.code, err.message, err.statusCode);
      }
      const notFound = /not found/i.test(err.message);
      // "blocked: an active legal hold" (ErasureService.erase())
      // is the same class of pre-execution gate failure as the existing
      // approval/identity-verification checks — a 409, not a 500.
      const gateFailure = /not (approved|passed identity verification)|blocked: an active legal hold/i.test(err.message);
      if (notFound) return _err(res, 'DSR_REQUEST_NOT_FOUND', err.message, 404);
      if (gateFailure) return _err(res, 'DSR_GATE_FAILED', err.message, 409);
      // Anything else is unclassified — never echo err.message to the
      // client (it may carry DB/driver internals); log it server-side and
      // return the generic sanitized envelope, matching every other route
      // file's unclassified-error convention (prqDlq.js, rbacAdmin.js,
      // policyManagement.js's _storeError, signingIdentities.js).
      return internalError(res, req, err, { label: 'DSR_OPERATION_FAILED', code: 'DSR_OPERATION_FAILED' });
    }
  };
}

function createDsrRouter({ requirePermission } = {}) {
  const router = express.Router();

  const _canRead   = permissionGuard(requirePermission, 'READ_DSR', 'dsr');
  const _canManage = permissionGuard(requirePermission, 'MANAGE_DSR', 'dsr');

  // GET /v1/admin/dsr — list requests
  router.get('/', _canRead, _wrap(async (req, res) => {
    const parsed = dsrListQuerySchema.safeParse(req.query);
    if (!parsed.success) return _err(res, 'INVALID_QUERY', parsed.error.issues[0]?.message ?? 'Invalid query');
    const { actorId, tenantId, status, requestType } = parsed.data;

    // Canonical page/pageSize (API-4 remediation) take precedence over the
    // legacy limit/offset when both are supplied; either still works.
    const { page, pageSize, limit, offset } = parsePagination(parsed.data, { defaultPageSize: 50, maxPageSize: 200 });

    const result = await listRequests({
      actor_id: actorId, tenant_id: tenantId, status, request_type: requestType, limit, offset,
    });
    _ok(res, { ...result, ...buildPaginationMeta({ page, pageSize, totalItems: result.total }) });
  }));

  // GET /v1/admin/dsr/:id — request detail + event trail
  router.get('/:id', _canRead, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const query = dsrIdQuerySchema.safeParse(req.query);
    if (!query.success) return _err(res, 'INVALID_QUERY', query.error.issues[0]?.message ?? 'Invalid query');
    const tenantId = query.data.tenantId ?? null;

    const request = await getRequest(params.data.id, tenantId);
    if (!request) return _err(res, 'DSR_REQUEST_NOT_FOUND', `DSR request not found: ${params.data.id}`, 404);

    const events = await listEvents(params.data.id, tenantId);
    _ok(res, { request, events });
  }));

  // POST /v1/admin/dsr — create request
  router.post('/', _canManage, _wrap(async (req, res) => {
    const body = dsrCreateRequestSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { requestType, actorId, tenantId, requestedBy, legalBasis, justification } = body.data;

    const request = await createRequest({
      request_type: requestType, actor_id: actorId, tenant_id: tenantId ?? null,
      requested_by: _operator(req, { requestedBy }), legal_basis: legalBasis ?? null, justification: justification ?? null,
    });
    _ok(res, request, 201);
  }));

  // POST /v1/admin/dsr/:id/verify-identity
  router.post('/:id/verify-identity', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrVerifyIdentitySchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { tenantId, method, result, evidence, verifiedBy } = body.data;

    const request = await verifyIdentity({
      requestId: params.data.id, tenantId: tenantId ?? null, method, result, evidence: evidence ?? null, verifiedBy: _operator(req, { verifiedBy }),
    });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/approve
  router.post('/:id/approve', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrApproveSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');

    const request = await approve({ requestId: params.data.id, tenantId: body.data.tenantId ?? null, approvedBy: _operator(req, body.data) });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/rectify — Article 16
  router.post('/:id/rectify', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrRectifySchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { tenantId, consentId, fields, rectifiedBy } = body.data;

    const request = await rectify({
      requestId: params.data.id, tenantId: tenantId ?? null, consentId, fields, rectifiedBy: _operator(req, { rectifiedBy }),
    });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/erase — Article 17
  router.post('/:id/erase', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrEraseSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    // (D5-A): the identifier is always pseudonymized — pseudonymizeActorId is accepted and ignored.
    const { tenantId, erasedBy } = body.data;

    const request = await erase({
      requestId: params.data.id, tenantId: tenantId ?? null, erasedBy: _operator(req, { erasedBy }),
    });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/restrict — Article 18
  router.post('/:id/restrict', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrRestrictSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { tenantId, reason, restrictedBy } = body.data;

    const request = await restrict({
      requestId: params.data.id, tenantId: tenantId ?? null, reason: reason ?? null, restrictedBy: _operator(req, { restrictedBy }),
    });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/lift — lift an Article 18 restriction
  router.post('/:id/lift', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrLiftSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');

    const request = await liftRestriction({
      requestId: params.data.id, tenantId: body.data.tenantId ?? null, liftedBy: _operator(req, body.data),
    });
    _ok(res, request);
  }));

  // POST /v1/admin/dsr/:id/export — Article 20
  router.post('/:id/export', _canManage, _wrap(async (req, res) => {
    const params = dsrIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = dsrExportSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { tenantId, format, generatedBy } = body.data;

    const exportResult = await generateExport({
      requestId: params.data.id, tenantId: tenantId ?? null, format, generatedBy: _operator(req, { generatedBy }),
    });
    _ok(res, exportResult);
  }));

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createDsrRouter };
