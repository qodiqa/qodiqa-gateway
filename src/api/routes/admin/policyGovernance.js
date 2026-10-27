'use strict';

/**
 * Policy Governance / Maker-Checker Administration API —
 * Component #45.
 *
 * Mounts at /v1/policy/governance (ops-protected, RBAC-gated — see server.js).
 *
 * Routes:
 *   GET  /                          — list change requests           (READ_POLICY_GOVERNANCE)
 *   GET  /:id                       — request detail + event trail    (READ_POLICY_GOVERNANCE)
 *   GET  /:id/evidence              — evidence package of the change request     (READ_POLICY_GOVERNANCE)
 *   POST /draft                     — create a draft                  (PROPOSE_POLICY_CHANGE)
 *   POST /:id/submit                — DRAFT -> SUBMITTED               (PROPOSE_POLICY_CHANGE, author only)
 *   POST /:id/review                — claim + decide (single call)    (REVIEW_POLICY_CHANGE, != author)
 *   POST /:id/approve               — REVIEWED -> APPROVED             (APPROVE_POLICY_CHANGE, != author, != reviewer*)
 *   POST /:id/reject                — -> REJECTED                     (APPROVE_POLICY_CHANGE or REVIEW_POLICY_CHANGE)
 *   POST /:id/schedule              — APPROVED -> SCHEDULED            (APPROVE_POLICY_CHANGE)
 *   POST /:id/publish               — -> PUBLISHED (live effect)      (PUBLISH_POLICY_CHANGE, != author)
 *   POST /:id/withdraw               — -> WITHDRAWN                    (author or admin)
 *   POST /rollback                  — request a rollback (policyId in body) (REQUEST_POLICY_ROLLBACK)
 *   POST /:id/rollback/approve      — approve + apply rollback        (APPROVE_POLICY_ROLLBACK, != author, != original publisher)
 *   POST /emergency/activate        — emergency bypass activation      (EMERGENCY_POLICY_OVERRIDE)
 *   POST /emergency/:id/retro-approve — retrospective approval         (APPROVE_EMERGENCY_POLICY, != activator)
 *   POST /emergency/sweep-expired   — admin-triggered expiry sweep     (EMERGENCY_POLICY_OVERRIDE)
 *
 * (*strict mode only — see ChangeRequestStateModel / makerCheckerRules)
 *
 * Every mutating route delegates to core/policy/governance services, which
 * enforce state-machine transitions and maker-checker identity separation
 * before any write happens, and record every lifecycle transition as a
 * hash-chained approval_events row (see governanceEvents.js).
 */

const { permissionGuard } = require('../permissionGuard'); // fail-closed permission wiring
const express = require('express');
const { emit }                  = require('../../../../services/logger');
const PolicyGovernanceService   = require('../../../core/policy/governance/PolicyGovernanceService');
const RollbackGovernanceService = require('../../../core/policy/governance/RollbackGovernanceService');
const EmergencyPolicyService    = require('../../../core/policy/governance/EmergencyPolicyService');
const evidenceGenerator         = require('../../../core/policy/governance/evidenceGenerator');
const { ConcurrentModificationError } = require('../../../core/policy/governance/ChangeRequestStore');
const { MakerCheckerViolationError }  = require('../../../core/policy/governance/makerCheckerRules');
const {
  draftSchema, submitSchema, reviewDecisionSchema, approveSchema, rejectSchema,
  scheduleSchema, publishSchema, withdrawSchema, rollbackRequestSchema, rollbackApproveSchema,
  emergencyActivateSchema, emergencyRetroApproveSchema,
  changeRequestIdParamSchema, emergencyIdParamSchema, listQuerySchema,
} = require('../../../validation/schemas/policyGovernance.schema');
const { success, failure, internalError } = require('../../response');
const { parsePagination, buildPaginationMeta } = require('../../../utils/pagination');


// ── Response helpers (matches src/api/routes/admin/dsr.js's local convention) ──

function _ok(res, data, status = 200) {
  success(res, data, status);
}

function _err(res, code, message, status = 400) {
  failure(res, code, message, status);
}

function _actor(req) {
  const user = req.rbacUser;
  if (!user || !user.id || !user.username || !user.role) return null;
  return {
    id: user.id, username: user.username, role: user.role,
    sourceIp: req.clientIp || req.ip || 'unknown',
  };
}

function _errorStatusAndCode(err) {
  if (err instanceof MakerCheckerViolationError) return { status: 403, code: err.rule };
  if (err instanceof ConcurrentModificationError) return { status: 409, code: 'CONCURRENT_MODIFICATION' };
  switch (err.code) {
    case 'NOT_FOUND':
    case 'VERSION_NOT_FOUND':          return { status: 404, code: err.code };
    case 'INVALID_TRANSITION':
    case 'NOT_YET_SCHEDULED':
    case 'EMERGENCY_EXPIRED':          return { status: 409, code: err.code };
    // draft/publish-time validation failures (including the
    // tenant tighten-only invariant) are CLIENT errors with a safe,
    // deliberate message — previously they fell through to the sanitized
    // 500, hiding the reason the draft was refused.
    case 'VALIDATION_FAILED':          return { status: 400, code: err.code };
    case 'POLICY_ALREADY_EXISTS':      return { status: 409, code: err.code };
    default:                            return null;
  }
}

function _wrap(handler) {
  return async (req, res) => {
    try {
      const actor = _actor(req);
      if (!actor) return _err(res, 'IDENTITY_UNRESOLVED', 'No authenticated identity resolved for this request', 401);
      await handler(req, res, actor);
    } catch (err) {
      const classified = _errorStatusAndCode(err);
      if (classified) return _err(res, classified.code, err.message, classified.status);
      // Anything else is unclassified -- never echo err.message to the
      // client (it may carry DB/driver internals); log it server-side and
      // return the generic sanitized envelope, matching every other route
      // file's unclassified-error convention (dsr.js item 8, prqDlq.js,
      // rbacAdmin.js, policyManagement.js's _storeError, signingIdentities.js).
      return internalError(res, req, err, { label: 'POLICY_GOVERNANCE_OPERATION_FAILED', code: 'POLICY_GOVERNANCE_OPERATION_FAILED' });
    }
  };
}

/**
 * Reload the live in-memory policy set after a route has mutated the
 * file-based store (publish / rollback-approve / emergency-activate — the
 * only three places that ever call store.js's mutators). Mirrors the exact
 * RELOAD_FAILED handling the legacy policyManagement.js write endpoints
 * always had: the underlying mutation has already succeeded at this point,
 * so a reload failure is reported distinctly rather than rolled back.
 */
function _reload(res, _reloadPolicies, context) {
  if (!_reloadPolicies) return true;
  try {
    _reloadPolicies();
    return true;
  } catch (reloadErr) {
    _err(
      res, 'RELOAD_FAILED',
      `${context} succeeded but reloading the live policy set failed: ${reloadErr.message}`,
      500,
    );
    return false;
  }
}

function createPolicyGovernanceRouter({ requirePermission, _reloadPolicies } = {}) {
  const router = express.Router();

  const _canRead             = permissionGuard(requirePermission, 'READ_POLICY_GOVERNANCE', 'policyGovernance');
  const _canPropose          = permissionGuard(requirePermission, 'PROPOSE_POLICY_CHANGE', 'policyGovernance');
  const _canReview           = permissionGuard(requirePermission, 'REVIEW_POLICY_CHANGE', 'policyGovernance');
  const _canApprove          = permissionGuard(requirePermission, 'APPROVE_POLICY_CHANGE', 'policyGovernance');
  const _canPublish          = permissionGuard(requirePermission, 'PUBLISH_POLICY_CHANGE', 'policyGovernance');
  const _canRequestRollback  = permissionGuard(requirePermission, 'REQUEST_POLICY_ROLLBACK', 'policyGovernance');
  const _canApproveRollback  = permissionGuard(requirePermission, 'APPROVE_POLICY_ROLLBACK', 'policyGovernance');
  const _canEmergency        = permissionGuard(requirePermission, 'EMERGENCY_POLICY_OVERRIDE', 'policyGovernance');
  const _canApproveEmergency = permissionGuard(requirePermission, 'APPROVE_EMERGENCY_POLICY', 'policyGovernance');

  // ── GET / — list ─────────────────────────────────────────────────────────

  router.get('/', _canRead, _wrap(async (req, res) => {
    const parsed = listQuerySchema.safeParse(req.query);
    if (!parsed.success) return _err(res, 'INVALID_QUERY', parsed.error.issues[0]?.message ?? 'Invalid query');
    const { policyId, tenantId, status, requestType, authorId } = parsed.data;

    // Canonical page/pageSize (API-4 remediation) take precedence over the
    // legacy limit/offset when both are supplied; either still works.
    const { page, pageSize, limit, offset } = parsePagination(parsed.data, { defaultPageSize: 50, maxPageSize: 200 });

    const result = await PolicyGovernanceService.listRequests({ policyId, tenantId, status, requestType, authorId, limit, offset });
    _ok(res, { ...result, ...buildPaginationMeta({ page, pageSize, totalItems: result.total }) });
  }));

  // ── GET /:id — detail + event trail ─────────────────────────────────────

  router.get('/:id', _canRead, _wrap(async (req, res) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const request = await PolicyGovernanceService.getRequest(params.data.id);
    if (!request) return _err(res, 'NOT_FOUND', `Change request not found: ${params.data.id}`, 404);
    _ok(res, { request });
  }));

  // ── GET /:id/evidence ────────────────────────────────────────────────────

  router.get('/:id/evidence', _canRead, _wrap(async (req, res) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const evidence = await evidenceGenerator.generate(params.data.id);
    _ok(res, evidence);
  }));

  // ── POST /draft ──────────────────────────────────────────────────────────

  router.post('/draft', _canPropose, _wrap(async (req, res, actor) => {
    const body = draftSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { policyId, tenantId, requestType, payload, changeReason } = body.data;
    const request = await PolicyGovernanceService.draft({
      policyId, tenantId: tenantId ?? null, requestType, payload, changeReason, actor,
    });
    _ok(res, request, 201);
  }));

  // ── POST /:id/submit ─────────────────────────────────────────────────────

  router.post('/:id/submit', _canPropose, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    if (!submitSchema.safeParse(req.body ?? {}).success) return _err(res, 'INVALID_BODY', 'Invalid body');
    const request = await PolicyGovernanceService.submit({ requestId: params.data.id, actor });
    _ok(res, request);
  }));

  // ── POST /:id/review — claim (if needed) + decide, one call ────────────

  router.post('/:id/review', _canReview, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = reviewDecisionSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');

    const current = await PolicyGovernanceService.getRequest(params.data.id);
    if (!current) return _err(res, 'NOT_FOUND', `Change request not found: ${params.data.id}`, 404);
    if (current.status === 'SUBMITTED') {
      await PolicyGovernanceService.startReview({ requestId: params.data.id, actor });
    }
    const { decision, notes } = body.data;
    const request = await PolicyGovernanceService.review({ requestId: params.data.id, actor, decision, notes: notes ?? null });
    _ok(res, request);
  }));

  // ── POST /:id/approve ────────────────────────────────────────────────────

  router.post('/:id/approve', _canApprove, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = approveSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const request = await PolicyGovernanceService.approve({ requestId: params.data.id, actor, notes: body.data.notes ?? null });
    _ok(res, request);
  }));

  // ── POST /:id/reject ─────────────────────────────────────────────────────

  router.post('/:id/reject', _canApprove, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = rejectSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const request = await PolicyGovernanceService.reject({ requestId: params.data.id, actor, reason: body.data.reason });
    _ok(res, request);
  }));

  // ── POST /:id/schedule ───────────────────────────────────────────────────

  router.post('/:id/schedule', _canApprove, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = scheduleSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const request = await PolicyGovernanceService.schedule({ requestId: params.data.id, actor, scheduledFor: body.data.scheduledFor });
    _ok(res, request);
  }));

  // ── POST /:id/publish ────────────────────────────────────────────────────

  router.post('/:id/publish', _canPublish, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    if (!publishSchema.safeParse(req.body ?? {}).success) return _err(res, 'INVALID_BODY', 'Invalid body');
    const result = await PolicyGovernanceService.publish({ requestId: params.data.id, actor });
    if (!_reload(res, _reloadPolicies, 'Publish')) return;
    _ok(res, result);
  }));

  // ── POST /:id/withdraw ───────────────────────────────────────────────────

  router.post('/:id/withdraw', _canPropose, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    if (!withdrawSchema.safeParse(req.body ?? {}).success) return _err(res, 'INVALID_BODY', 'Invalid body');
    const request = await PolicyGovernanceService.withdraw({ requestId: params.data.id, actor });
    _ok(res, request);
  }));

  // ── POST /rollback — request a rollback (policyId in body, keeping `:id`
  //    consistently meaning "change request id" everywhere else in this router) ──

  router.post('/rollback', _canRequestRollback, _wrap(async (req, res, actor) => {
    const body = rollbackRequestSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { policyId, toVersion, reason } = body.data;
    const result = await RollbackGovernanceService.requestRollback({ policyId, toVersion, reason, actor });
    _ok(res, result, 201);
  }));

  // ── POST /:id/rollback/approve — :id here is the CHANGE REQUEST id ─────

  router.post('/:id/rollback/approve', _canApproveRollback, _wrap(async (req, res, actor) => {
    const params = changeRequestIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = rollbackApproveSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const result = await RollbackGovernanceService.approveAndPublishRollback({
      requestId: params.data.id, actor, notes: body.data.notes ?? null,
    });
    if (!_reload(res, _reloadPolicies, 'Rollback approval')) return;
    _ok(res, result);
  }));

  // ── POST /emergency/activate ─────────────────────────────────────────────

  router.post('/emergency/activate', _canEmergency, _wrap(async (req, res, actor) => {
    const body = emergencyActivateSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');
    const { policyId, tenantId, requestType, payload, incidentReference, justification, ttlHours } = body.data;
    const result = await EmergencyPolicyService.activate({
      policyId, tenantId: tenantId ?? null, requestType, payload, incidentReference, justification, ttlHours, actor,
    });
    if (!_reload(res, _reloadPolicies, 'Emergency activation')) return;
    _ok(res, result, 201);
  }));

  // ── POST /emergency/:id/retro-approve ────────────────────────────────────

  router.post('/emergency/:id/retro-approve', _canApproveEmergency, _wrap(async (req, res, actor) => {
    const params = emergencyIdParamSchema.safeParse(req.params);
    if (!params.success) return _err(res, 'INVALID_ID', 'id must be a valid UUID');
    const body = emergencyRetroApproveSchema.safeParse(req.body ?? {});
    if (!body.success) return _err(res, 'INVALID_BODY', body.error.issues[0]?.message ?? 'Invalid body');

    // retroApprove() may revert the live policy — on a REJECTED decision,
    // or via its own lazy-expiry auto-revert path (which reverts the file
    // THEN throws EMERGENCY_EXPIRED). Reload unconditionally, even on a
    // thrown error, so a thrown response never leaves the in-memory
    // enforcement set stale relative to what was actually written to disk.
    let result, thrown;
    try {
      result = await EmergencyPolicyService.retroApprove({
        emergencyId: params.data.id, tenantId: body.data.tenantId ?? null, actor, decision: body.data.decision, notes: body.data.notes ?? null,
      });
    } catch (err) {
      thrown = err;
    }
    if (_reloadPolicies) {
      try { _reloadPolicies(); } catch (reloadErr) {
        emit('ERROR', 'POLICY_RELOAD_FAILED_AFTER_EMERGENCY_DECISION', { error: reloadErr.message });
      }
    }
    if (thrown) throw thrown;
    _ok(res, result);
  }));

  // ── POST /emergency/sweep-expired ────────────────────────────────────────

  router.post('/emergency/sweep-expired', _canEmergency, _wrap(async (_req, res) => {
    const result = await EmergencyPolicyService.sweepExpired();
    if (result.swept > 0 && _reloadPolicies) {
      try { _reloadPolicies(); } catch (reloadErr) {
        emit('ERROR', 'POLICY_RELOAD_FAILED_AFTER_EMERGENCY_SWEEP', { error: reloadErr.message });
      }
    }
    _ok(res, result);
  }));

  // ── 405 catch-all ────────────────────────────────────────────────────────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createPolicyGovernanceRouter };
