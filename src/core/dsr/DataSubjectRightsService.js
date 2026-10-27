'use strict';

/**
 * DataSubjectRightsService — orchestrates the full DSR request lifecycle:
 *
 *   RECEIVED -> IDENTITY_VERIFIED -> APPROVED -> IN_PROGRESS
 *            -> COMPLETED | REJECTED | FAILED
 *
 * This is the single entry point the admin API
 * (src/api/routes/admin/dsr.js) calls — it does not call
 * Rectification/Erasure/Restriction/PortabilityService directly, so the
 * identity-verification gate, the approval gate, and failure handling are
 * each enforced in exactly one place rather than duplicated per right.
 *
 * It is also the single entry point for operators registering custom DSR
 * extension targets (see ErasureTargetRegistry.js for the
 * ErasureTarget interface): registerErasureTarget/unregisterErasureTarget/
 * listErasureTargets are plain pass-throughs to the registry, kept here so
 * operator startup code has one module to depend on for everything DSR,
 * rather than reaching into ErasureTargetRegistry directly. This file adds
 * no business logic of its own for extension targets — invocation happens
 * in ErasureService.erase()/PortabilityService.generateExport(), the same
 * services that already own erasure/export for the built-in stores.
 */

const DSRStore              = require('./DSRStore');
const identityVerification  = require('./identityVerification');
const RectificationService  = require('./RectificationService');
const RestrictionService    = require('./RestrictionService');
const ErasureService        = require('./ErasureService');
const PortabilityService    = require('./PortabilityService');
const ErasureTargetRegistry = require('./ErasureTargetRegistry');

async function createRequest(opts) {
  return DSRStore.createRequest(opts);
}

async function verifyIdentity(opts) {
  return identityVerification.verifyIdentity(opts);
}

/**
 * Approve a request for execution. Only reachable once identity has been
 * verified (identityVerification.assertVerified) — this is what makes
 * APPROVED a safe single gate for every execution service to check.
 *
 * accepts an optional tenantId so a tenant-scoped request is
 * actually visible to findById (see DSRStore.findById's own comment).
 */
class DSRSelfApprovalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DSRSelfApprovalError';
    this.code = 'DSR_SELF_APPROVAL_FORBIDDEN';
    this.statusCode = 403;
  }
}

async function approve({ requestId, tenantId = null, approvedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!approvedBy) throw new Error('approvedBy is required');

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  identityVerification.assertVerified(request);
  // four-eyes — the approver is neither the requester nor
  // the operator who verified the subject's identity (identities come from the
  // authenticated session, src/api/routes/admin/dsr.js, never a request body).
  if (approvedBy === request.requested_by) {
    throw new DSRSelfApprovalError(`DSR request ${requestId}: the requester (${approvedBy}) may not approve their own request`);
  }
  if (approvedBy === request.identity_verified_by) {
    throw new DSRSelfApprovalError(`DSR request ${requestId}: the operator who verified the identity (${approvedBy}) may not also approve`);
  }
  // Status is enforced by DSRStore.updateStatus: only IDENTITY_VERIFIED → APPROVED;
  // a COMPLETED or FAILED request is never re-approved (a FAILED erasure resumes).

  return DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'APPROVED',
    patch: { approved_by: approvedBy, approved_at: new Date() },
    actor: approvedBy, eventType: 'DSR_REQUEST_APPROVED', eventDetail: {},
  });
}

/**
 * Wraps an execution call so any failure is recorded as a FAILED lifecycle
 * transition (audit trail requirement: "record ... failures") before the
 * original error is re-thrown to the caller.
 *
 * accepts an optional tenantId so this failure-path status
 * update itself isn't RLS-blocked for a tenant-scoped request (previously it
 * never threaded tenant_id at all, so a failed tenant-scoped execution never
 * got its FAILED status/audit event recorded — silently swallowed by the
 * .catch below).
 */
async function _execute(requestId, tenantId, executor, actor) {
  try {
    return await executor();
  } catch (err) {
    await DSRStore.updateStatus({
      id: requestId, tenant_id: tenantId, status: 'FAILED', patch: { error: err.message },
      actor, eventType: 'DSR_REQUEST_FAILED', eventDetail: { error: err.message },
    }).catch(() => {}); // best-effort — never mask the original error with a logging failure
    throw err;
  }
}

async function rectify({ requestId, tenantId = null, consentId, fields, rectifiedBy }) {
  return _execute(
    requestId, tenantId,
    () => RectificationService.rectify({ requestId, tenantId, consentId, fields, rectifiedBy }),
    rectifiedBy,
  );
}

async function erase({ requestId, tenantId = null, erasedBy }) {
  // (D5-A): the identifier is always pseudonymized; the earlier opt-in flag is gone.
  return _execute(
    requestId, tenantId,
    () => ErasureService.erase({ requestId, tenantId, erasedBy }),
    erasedBy,
  );
}

async function restrict({ requestId, tenantId = null, reason, restrictedBy }) {
  return _execute(
    requestId, tenantId,
    () => RestrictionService.restrict({ requestId, tenantId, reason, restrictedBy }),
    restrictedBy,
  );
}

async function liftRestriction({ requestId, tenantId = null, liftedBy }) {
  return _execute(
    requestId, tenantId,
    () => RestrictionService.lift({ requestId, tenantId, liftedBy }),
    liftedBy,
  );
}

async function generateExport({ requestId, tenantId = null, format, generatedBy }) {
  return _execute(
    requestId, tenantId,
    () => PortabilityService.generateExport({ requestId, tenantId, format, generatedBy }),
    generatedBy,
  );
}

async function getRequest(requestId, tenantId = null) {
  return DSRStore.findById(requestId, tenantId);
}

async function listRequests(filters) {
  return DSRStore.list(filters);
}

async function listEvents(requestId, tenantId = null) {
  return DSRStore.listEvents({ request_id: requestId, tenant_id: tenantId });
}

/**
 * Register an operator-defined DSR extension target. Call once per
 * target during application startup — see ErasureTargetRegistry.js for the
 * ErasureTarget interface.
 */
function registerErasureTarget(target) {
  return ErasureTargetRegistry.registerTarget(target);
}

function unregisterErasureTarget(id) {
  return ErasureTargetRegistry.unregisterTarget(id);
}

function listErasureTargets() {
  return ErasureTargetRegistry.getTargets();
}

module.exports = {
  DSRSelfApprovalError,
  createRequest, verifyIdentity, approve,
  rectify, erase, restrict, liftRestriction, generateExport,
  getRequest, listRequests, listEvents,
  registerErasureTarget, unregisterErasureTarget, listErasureTargets,
};
