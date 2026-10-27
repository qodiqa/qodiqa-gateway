'use strict';

/**
 * provenanceBridge — records a policy content change into the existing,
 * unchanged policy_provenance_versions ledger (src/core/policy/provenance.js
 * / provenanceStore.js) from the governance workflow's publish paths.
 *
 * Extracted from policyManagement.js's original _recordProvenance() (same
 * fire-and-forget behavior, same field mapping, same
 * provenance.computePolicyHash(singleObject) — note this is provenance.js's
 * own per-content hash function, distinct from services/policyHash.js's
 * array-only whole-live-set fingerprint of the same name) so
 * PolicyGovernanceService.publish(), RollbackGovernanceService.
 * approveAndPublishRollback(), and EmergencyPolicyService.activate() — the
 * only three places that now ever call src/core/policy/store.js's
 * mutators — share one implementation instead of three copies.
 *
 * Fire-and-forget by design (matches the pre-existing behavior this
 * replaces): a provenance-recording failure never blocks or rolls back the
 * governance workflow transaction that already committed.
 */

const provenanceStore = require('../provenanceStore');
const provenance       = require('../provenance');
const { emit }          = require('../../../../services/logger');

/**
 * @param {object} policyRecord — full record returned by store.js (has versions[])
 * @param {object} ctx
 * @param {string} ctx.eventType
 * @param {{id:string, username:string, role:string}} ctx.actor
 * @param {string} [ctx.sourceIp]
 * @param {string} ctx.changeReason
 * @param {string} [ctx.changeNotes]
 * @param {number} [ctx.rolledBackToVersion]
 */
function recordPolicyProvenance(policyRecord, ctx) {
  try {
    const versions = policyRecord.versions || [];
    if (versions.length === 0) return;

    const currentVer = versions[versions.length - 1];
    const prevVer    = versions.length > 1 ? versions[versions.length - 2] : null;

    const policyContent      = currentVer.snapshot || {};
    const previousContent    = prevVer ? (prevVer.snapshot || null) : null;
    const previousPolicyHash = previousContent ? provenance.computePolicyHash(previousContent) : null;

    const record = provenance.buildProvenanceRecord({
      policyId:           policyRecord.id,
      versionNumber:      currentVer.v,
      parentVersion:      prevVer ? prevVer.v : null,
      rootVersion:        1,
      eventType:          ctx.eventType,
      occurredAt:         new Date(currentVer.createdAt),
      actorId:            ctx.actor.id,
      actorUsername:      ctx.actor.username,
      actorRole:          ctx.actor.role,
      sourceIp:           ctx.sourceIp || 'unknown',
      changeReason:       ctx.changeReason,
      changeNotes:        ctx.changeNotes || '',
      policyContent,
      previousPolicyHash,
      previousContent,
      rolledBackToVersion: ctx.rolledBackToVersion || null,
    });

    provenanceStore.recordVersion(record).catch((e) => {
      emit('ERROR', 'PROVENANCE_RECORD_FAILED', {
        policyId: policyRecord.id, eventType: ctx.eventType, error: e.message,
      });
    });
  } catch (e) {
    emit('ERROR', 'PROVENANCE_RECORD_ASSEMBLY_FAILED', {
      policyId: policyRecord && policyRecord.id, eventType: ctx && ctx.eventType, error: e.message,
    });
  }
}

module.exports = { recordPolicyProvenance };
