'use strict';

/**
 * RollbackGovernanceService — Article-18-style independent governance for
 * policy rollbacks: "Rollback must not be executable by the same
 * person who activated the policy."
 *
 * Deliberately a simpler two-stage flow than the general change-request
 * lifecycle (DRAFT -> ... -> PUBLISHED): the finding's rollback-governance
 * requirements are independent approval + reason + affected version +
 * timestamp + evidence + approval chain — not a full multi-round review.
 * requestRollback() creates a ROLLBACK-type change request and immediately
 * auto-submits it (SUBMITTED); approveAndPublishRollback() is the single
 * independent-approval gate that both approves AND applies it in one
 * transactional step. This SUBMITTED -> PUBLISHED hop is therefore checked
 * directly here rather than through ChangeRequestStateModel (which has no
 * such edge for the general workflow, by design) — the general model
 * continues to govern CREATE/UPDATE/ENABLE/DISABLE/ARCHIVE requests
 * unchanged.
 */

const pool               = require('../../../infra/postgres/pool');
const ChangeRequestStore = require('./ChangeRequestStore');
const governanceEvents   = require('./governanceEvents');
const stateModel         = require('./ChangeRequestStateModel');
const rules              = require('./makerCheckerRules');
const { assertIndependentOfAuthor } = require('./independence');
const policyStore        = require('../store');
const { recordPolicyProvenance } = require('./provenanceBridge');

async function _lookupOriginalPublisher(policyId, version) {
  const result = await pool.query(
    `SELECT published_by FROM policy_publications
      WHERE policy_id = $1 AND resulting_policy_version = $2
      ORDER BY id DESC LIMIT 1`,
    [policyId, version], 'pp_lookup_publisher',
  );
  return result.rows[0]?.published_by ?? null;
}

/**
 * Create and auto-submit a rollback request. Does not apply anything to
 * the live store yet — that only happens in approveAndPublishRollback().
 *
 * @returns {Promise<{changeRequest: object, fromVersion: number, toVersion: number, originalPublisherId: string|null}>}
 */
async function requestRollback({ policyId, tenantId = null, toVersion, reason, actor }) {
  if (!policyId || !toVersion || !reason) {
    throw new Error('policyId, toVersion, and reason are required');
  }
  // tenant-targeted ROLLBACK is not implemented — unlike
  // CREATE/UPDATE/ENABLE/DISABLE, PolicyGovernanceService.applyTenantPublish
  // has no ROLLBACK case (tenantConfigStore does not track per-tenant policy
  // version history the way the global file-based policyStore does with
  // getVersion/rollbackPolicy below). Previously `tenantId` was silently
  // accepted and threaded into ChangeRequestStore.create()/governanceEvents,
  // but every write after that point ran with NO tenant context at all
  // (plain pool.withTransaction, never withTenantTransaction) and
  // approveAndPublishRollback() would later apply the rollback to the GLOBAL
  // policy store regardless — the same wrong-blast-radius shape
  // EmergencyPolicyService.activate() had. No route in this codebase
  // currently forwards a tenantId here (confirmed: rollbackRequestSchema has
  // no tenantId field), so this was unreachable, not exploited — refusing
  // explicitly now closes the footgun for any future caller rather than
  // leaving it to fail confusingly (or worse, wrongly) later.
  if (tenantId) {
    const err = new Error('Tenant-targeted policy rollback is not supported — no per-tenant version history exists to roll back to');
    err.code  = 'ROLLBACK_NOT_SUPPORTED_FOR_TENANT';
    throw err;
  }

  const targetVersion = policyStore.getVersion(policyId, toVersion);
  if (!targetVersion) {
    const err = new Error(`Version ${toVersion} not found for policy ${policyId}`);
    err.code  = 'VERSION_NOT_FOUND';
    throw err;
  }

  const currentPolicy = policyStore.getPolicy(policyId);
  if (!currentPolicy) {
    const err = new Error(`Policy not found: ${policyId}`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
  const fromVersion = currentPolicy.currentVersion;
  const originalPublisherId = await _lookupOriginalPublisher(policyId, fromVersion);

  const payload     = { toVersion };
  const payloadHash = governanceEvents.hashPayload(payload);

  const request = await ChangeRequestStore.create({
    policy_id: policyId, tenant_id: tenantId, request_type: 'ROLLBACK',
    payload, payload_hash: payloadHash, change_reason: reason, author: actor,
  });

  const submitted = await pool.withTransaction(async (tx) => {
    await governanceEvents.recordEvent(tx, {
      changeRequestId: request.id, policyId, tenantId, eventType: 'ROLLBACK_REQUESTED',
      previousStatus: null, newStatus: stateModel.STATE.DRAFT, actor, reason,
      detail: { fromVersion, toVersion, originalPublisherId },
    });
    const updated = await ChangeRequestStore.updateStatusInTx(tx, {
      id: request.id, expectedVersion: request.version, status: stateModel.STATE.SUBMITTED,
      patch: { submitted_by: actor.id, submitted_at: new Date() },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: request.id, policyId, tenantId, eventType: 'SUBMITTED',
      previousStatus: stateModel.STATE.DRAFT, newStatus: stateModel.STATE.SUBMITTED, actor,
    });
    return updated;
  });

  return { changeRequest: submitted, fromVersion, toVersion, originalPublisherId };
}

/**
 * The independent approval gate: approves AND applies the rollback in one
 * step. Rejects if the approver is the rollback's own author, or the
 * original publisher of the version being replaced.
 *
 * @returns {Promise<{changeRequest: object, policy: object, fromVersion: number, toVersion: number}>}
 */
async function approveAndPublishRollback({ requestId, actor, notes = null }) {
  const request = await ChangeRequestStore.findById(requestId);
  if (!request) {
    const err = new Error(`Change request not found: ${requestId}`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
  if (request.request_type !== 'ROLLBACK') {
    throw new Error(`Change request ${requestId} is not a ROLLBACK request`);
  }
  if (request.status !== stateModel.STATE.SUBMITTED) {
    throw new Error(`Rollback request ${requestId} is not awaiting approval (status=${request.status})`);
  }

  // (verification): the rollback target is read from request.payload; prove it is still what was drafted (publish() already does).
  if (request.payload_hash && governanceEvents.hashPayload(request.payload) !== request.payload_hash) {
    const err = new Error(`Rollback request ${requestId}: stored payload no longer matches the drafted payload_hash — refusing to apply`);
    err.code  = 'PAYLOAD_HASH_MISMATCH';
    throw err;
  }

  const { toVersion } = request.payload || {};
  const currentPolicy = policyStore.getPolicy(request.policy_id);
  if (!currentPolicy) {
    const err = new Error(`Policy not found: ${request.policy_id}`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
  const fromVersion         = currentPolicy.currentVersion;
  const originalPublisherId = await _lookupOriginalPublisher(request.policy_id, fromVersion);

  rules.assertRollbackApproverNotAuthor(request.author_id, actor.id);
  assertIndependentOfAuthor(request, actor, 'ROLLBACK_APPROVER'); // audit 2026-10-20 (4.3): was skipped here
  if (originalPublisherId) {
    rules.assertRollbackApproverNotOriginalPublisher(originalPublisherId, actor.id);
  }

  const policy = await policyStore.rollbackPolicy(request.policy_id, {
    toVersion, actor: actor.username, comment: request.change_reason,
  });
  const resultingVersion = policy.currentVersion;

  const updated = await pool.withTransaction(async (tx) => {
    const row = await ChangeRequestStore.updateStatusInTx(tx, {
      id: requestId, expectedVersion: request.version, status: stateModel.STATE.PUBLISHED,
      patch: {
        approver_id: actor.id, approver_username: actor.username, approved_at: new Date(),
        publisher_id: actor.id, publisher_username: actor.username, published_at: new Date(),
        resulting_policy_version: resultingVersion,
      },
    });
    await governanceEvents.recordEvent(tx, {
      changeRequestId: requestId, policyId: request.policy_id, tenantId: request.tenant_id,
      eventType: 'ROLLBACK_APPROVED', previousStatus: request.status, newStatus: stateModel.STATE.PUBLISHED,
      actor, reason: notes, detail: { fromVersion, toVersion, resultingVersion },
    });
    await governanceEvents.recordApproval(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, approver: actor, decision: 'APPROVED', notes,
    });
    await governanceEvents.recordRollback(tx, {
      changeRequestId: requestId, tenantId: request.tenant_id, policyId: request.policy_id,
      fromVersion, toVersion, originalPublisherId: originalPublisherId ?? 'unknown',
      requestedBy: request.author_id, rollbackApprover: actor, reason: request.change_reason,
    });
    return row;
  });

  recordPolicyProvenance(policy, {
    eventType: 'POLICY_ROLLED_BACK', actor, sourceIp: actor.sourceIp,
    changeReason: request.change_reason,
    changeNotes: `Rollback approved via governed change request ${requestId}`,
    rolledBackToVersion: toVersion,
  });

  return { changeRequest: updated, policy, fromVersion, toVersion };
}

module.exports = { requestRollback, approveAndPublishRollback };
