'use strict';

/**
 * Identity verification and lifecycle gating for DSR requests.
 *
 * QODIQA has no end-user-facing authentication of its own (see
 * docs/guides/dsr.md, "Identity verification model and its limits").
 * "Verifying identity" here means: the RBAC-authenticated operator handling
 * the request explicitly attests, on the record, how they confirmed the
 * requester is who they claim to be, using their own out-of-band channel
 * (support ticket history, prior account verification, a legal request
 * document, etc). This is a real compensating control — it makes the
 * verification decision attributable and auditable — not a claim that
 * QODIQA independently authenticates data subjects.
 *
 * No execution service (Rectification/Erasure/Restriction/Portability)
 * accepts a request that hasn't reached APPROVED status, which itself can
 * only be reached after identity verification (see approve() in
 * DataSubjectRightsService.js) — the gate is enforced at each stage
 * transition, not duplicated ad hoc per right.
 */

const DSRStore = require('./DSRStore');

const VERIFICATION_METHODS = Object.freeze([
  'OPERATOR_ATTESTATION',        // the operator's own support/KYC channel confirmed identity
  'PRIOR_ACCOUNT_VERIFICATION',  // requester previously verified through an existing account/session
  'LEGAL_REQUEST',               // request accompanied by a legal instrument (subpoena, court order, etc.)
]);

function isValidMethod(method) {
  return typeof method === 'string' && VERIFICATION_METHODS.includes(method);
}

/**
 * Record an identity verification outcome for a DSR request.
 *
 * @param {object} opts
 * @param {string} opts.requestId
 * @param {string} [opts.tenantId]
 * @param {string} opts.method - one of VERIFICATION_METHODS
 * @param {string} opts.result - 'VERIFIED' | 'FAILED'
 * @param {string} [opts.evidence] - free-text description of the out-of-band check performed
 * @param {string} opts.verifiedBy
 * @returns {Promise<object>} updated DSR request row
 */
async function verifyIdentity({ requestId, tenantId = null, method, result, evidence = null, verifiedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!isValidMethod(method)) {
    throw new Error(`method must be one of: ${VERIFICATION_METHODS.join(', ')}`);
  }
  if (result !== 'VERIFIED' && result !== 'FAILED') {
    throw new Error("result must be 'VERIFIED' or 'FAILED'");
  }
  if (!verifiedBy) throw new Error('verifiedBy is required');

  const now = new Date();

  return DSRStore.updateStatus({
    id:        requestId,
    tenant_id: tenantId,
    status:    result === 'VERIFIED' ? 'IDENTITY_VERIFIED' : 'REJECTED',
    patch: {
      identity_verification_method:   method,
      identity_verification_result:   result,
      identity_verification_evidence: evidence,
      identity_verified_by:           verifiedBy,
      identity_verified_at:           now,
      ...(result === 'FAILED' ? { error: 'Identity verification failed' } : {}),
    },
    actor:       verifiedBy,
    eventType:   result === 'VERIFIED' ? 'DSR_IDENTITY_VERIFIED' : 'DSR_IDENTITY_VERIFICATION_FAILED',
    eventDetail: { method, evidence },
  });
}

/**
 * Guard used by approve() — throws if the request hasn't passed identity
 * verification yet.
 */
function assertVerified(request) {
  if (!request || request.identity_verification_result !== 'VERIFIED') {
    throw new Error(
      `DSR request ${request?.id ?? '(unknown)'} has not passed identity verification — refusing to proceed`,
    );
  }
}

/**
 * Guard used by every execution service (Rectification/Erasure/Restriction/
 * Portability) — throws unless the request has been explicitly approved.
 * APPROVED is only reachable after identity verification (see approve() in
 * DataSubjectRightsService.js), so this single check enforces both gates.
 */
function assertApproved(request) {
  if (!request || request.status !== 'APPROVED') {
    throw new Error(
      `DSR request ${request?.id ?? '(unknown)'} is not approved for execution (status=${request?.status ?? 'unknown'})`,
    );
  }
}

module.exports = { VERIFICATION_METHODS, isValidMethod, verifyIdentity, assertVerified, assertApproved };
