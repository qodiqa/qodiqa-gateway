'use strict';

/**
 * governanceEvents — shared evidence-writing helpers for the policy
 * governance workflow.
 *
 * `recordEvent()` writes the unified, hash-chained approval_events trail —
 * one chain per change_request_id, built the same way entryBuilder.js /
 * provenance.js already chain hashes (previous_event_hash -> event_hash),
 * using the domain-separated hash and the single canonical-JSON authority
 * (src/utils/stableStringify.js) the rest of the platform already shares.
 * Timestamps are deliberately excluded from the hashed content (same
 * convention as consent_audit_log / dsr_request_events checksums) so the
 * hash commits to WHAT happened, not to Postgres's own clock.
 *
 * `recordReview`/`recordApproval`/`recordPublication` write to their
 * respective append-only evidence tables with a lighter SHA-256 checksum,
 * mirroring ConsentStore._appendAudit's existing checksum style exactly.
 *
 * All functions take `tx` (a transaction handle from pool.withTransaction)
 * as their first argument — every write here must happen in the same
 * transaction as the policy_change_requests status update it accompanies,
 * so a workflow transition and its evidence record are never partially
 * committed.
 */

const crypto          = require('crypto');
const stableStringify  = require('../../../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

function hashPayload(payload) {
  // F13-GOV-01 / re-audit A2-02: hash the JSON form, because that is what the database stores and what publish re-hashes (undefined members and non-JSON values would
  // otherwise change the hash after a round trip and make an approved change unpublishable).
  return domainSeparatedHash(ARTIFACT_DOMAINS.POLICY_GOVERNANCE, stableStringify(JSON.parse(JSON.stringify(payload ?? {})))).toString('hex');
}

function _checksum(parts) {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
}

async function _lastEventHash(tx, changeRequestId) {
  if (!changeRequestId) return null;
  const result = await tx.query(
    `SELECT event_hash FROM approval_events WHERE change_request_id = $1 ORDER BY id DESC LIMIT 1`,
    [changeRequestId],
  );
  return result.rows[0]?.event_hash ?? null;
}

/**
 * Append one hash-chained event.
 *
 * @param {object} tx
 * @param {object} opts
 * @param {string} [opts.changeRequestId]
 * @param {string} [opts.policyId]
 * @param {string} [opts.tenantId]
 * @param {string} opts.eventType
 * @param {string} [opts.previousStatus]
 * @param {string} [opts.newStatus]
 * @param {{id:string, username:string, role:string}} opts.actor
 * @param {string} [opts.sourceIp]
 * @param {string} [opts.sessionId]
 * @param {string} [opts.reason]
 * @param {object} [opts.detail]
 * @returns {Promise<object>} inserted event row
 */
async function recordEvent(tx, {
  changeRequestId = null, policyId = null, tenantId = null, eventType,
  previousStatus = null, newStatus = null, actor, sourceIp = null, sessionId = null,
  reason = null, detail = {},
}) {
  if (!eventType) throw new Error('eventType is required');
  if (!actor || !actor.id || !actor.username || !actor.role) {
    throw new Error('actor (id, username, role) is required');
  }

  // Callers may thread sourceIp/sessionId either as explicit params or as
  // fields on the actor object (the latter lets every service call site
  // just pass `actor` once and still populate the audit trail's IP/session
  // fields, without every recordEvent() call needing to repeat them).
  const resolvedSourceIp  = sourceIp  ?? actor.sourceIp  ?? null;
  const resolvedSessionId = sessionId ?? actor.sessionId ?? null;

  const previousEventHash = await _lastEventHash(tx, changeRequestId);
  detail = JSON.parse(JSON.stringify(detail ?? {})); // the stored form (verifyChain recomputes from the stored column)
  const canonical = stableStringify({
    changeRequestId, policyId, eventType, previousStatus, newStatus,
    actorId: actor.id, actorUsername: actor.username, actorRole: actor.role,
    reason, detail, previousEventHash,
  });
  const eventHash = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY_GOVERNANCE, canonical).toString('hex');

  const result = await tx.query(
    `INSERT INTO approval_events
       (change_request_id, policy_id, tenant_id, event_type, previous_status, new_status,
        actor_id, actor_username, actor_role, source_ip, session_id, reason, detail,
        previous_event_hash, event_hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     RETURNING *`,
    [
      changeRequestId, policyId, tenantId, eventType, previousStatus, newStatus,
      actor.id, actor.username, actor.role, resolvedSourceIp, resolvedSessionId, reason, JSON.stringify(detail ?? {}),
      previousEventHash, eventHash,
    ],
  );
  return result.rows[0];
}

/**
 * Walk a change request's approval_events chain and verify every
 * previous_event_hash -> event_hash link, plus recompute each hash from
 * its own stored fields (tamper detection, not just chain-linkage).
 *
 * @returns {Promise<{valid: boolean, length: number, brokenAt: number|null}>}
 */
async function verifyChain(changeRequestId) {
  const pool = require('../../../infra/postgres/pool');
  const result = await pool.query(
    `SELECT * FROM approval_events WHERE change_request_id = $1 ORDER BY id ASC`,
    [changeRequestId], 'ae_verify_chain',
  );

  let prevHash = null;
  for (const row of result.rows) {
    if (row.previous_event_hash !== prevHash) {
      return { valid: false, length: result.rows.length, brokenAt: row.id };
    }
    const canonical = stableStringify({
      changeRequestId: row.change_request_id, policyId: row.policy_id, eventType: row.event_type,
      previousStatus: row.previous_status, newStatus: row.new_status,
      actorId: row.actor_id, actorUsername: row.actor_username, actorRole: row.actor_role,
      reason: row.reason, detail: row.detail, previousEventHash: row.previous_event_hash,
    });
    const expectedHash = domainSeparatedHash(ARTIFACT_DOMAINS.POLICY_GOVERNANCE, canonical).toString('hex');
    if (expectedHash !== row.event_hash) {
      return { valid: false, length: result.rows.length, brokenAt: row.id };
    }
    prevHash = row.event_hash;
  }
  return { valid: true, length: result.rows.length, brokenAt: null };
}

async function recordReview(tx, { changeRequestId, tenantId = null, reviewer, decision, notes = null }) {
  const checksum = _checksum([changeRequestId, reviewer.id, decision, notes ?? '']);
  const result = await tx.query(
    `INSERT INTO policy_reviews (change_request_id, tenant_id, reviewer_id, reviewer_username, decision, notes, checksum)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [changeRequestId, tenantId, reviewer.id, reviewer.username, decision, notes, checksum],
  );
  return result.rows[0];
}

async function recordApproval(tx, { changeRequestId, tenantId = null, approver, decision, notes = null }) {
  const checksum = _checksum([changeRequestId, approver.id, decision, notes ?? '']);
  const result = await tx.query(
    `INSERT INTO policy_approvals (change_request_id, tenant_id, approver_id, approver_username, decision, notes, checksum)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [changeRequestId, tenantId, approver.id, approver.username, decision, notes, checksum],
  );
  return result.rows[0];
}

async function recordPublication(tx, {
  changeRequestId, tenantId = null, policyId, publisher, resultingVersion, policyHash = null, emergency = false,
}) {
  const checksum = _checksum([changeRequestId, policyId, publisher.id, String(resultingVersion), emergency ? '1' : '0']);
  const result = await tx.query(
    `INSERT INTO policy_publications
       (change_request_id, tenant_id, policy_id, published_by, published_username,
        resulting_policy_version, policy_hash, emergency, checksum)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [changeRequestId, tenantId, policyId, publisher.id, publisher.username, resultingVersion, policyHash, emergency, checksum],
  );
  return result.rows[0];
}

/**
 * Written once, atomically, at the moment a rollback is approved AND
 * published — every field (including the approver) is already known, so
 * this table is a genuine single-insert evidence record, not a
 * request-then-update row (policy_rollbacks has no UPDATE grant by design
 * — see migration 029).
 */
async function recordRollback(tx, {
  changeRequestId, tenantId = null, policyId, fromVersion, toVersion,
  originalPublisherId, requestedBy, rollbackApprover, reason, evidenceRef = null,
}) {
  const checksum = _checksum([
    changeRequestId, policyId, String(fromVersion), String(toVersion),
    originalPublisherId, requestedBy, rollbackApprover.id,
  ]);
  const result = await tx.query(
    `INSERT INTO policy_rollbacks
       (change_request_id, tenant_id, policy_id, from_version, to_version,
        original_publisher_id, requested_by, rollback_approver_id, rollback_approver_username,
        reason, evidence_ref, approved_at, checksum)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),$12) RETURNING *`,
    [
      changeRequestId, tenantId, policyId, fromVersion, toVersion,
      originalPublisherId, requestedBy, rollbackApprover.id, rollbackApprover.username,
      reason, evidenceRef, checksum,
    ],
  );
  return result.rows[0];
}

module.exports = {
  hashPayload, recordEvent, verifyChain, recordReview, recordApproval, recordPublication, recordRollback,
};
