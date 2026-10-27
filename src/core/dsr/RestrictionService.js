'use strict';

/**
 * RestrictionService — GDPR Article 18 (right to restriction of processing).
 *
 * Restriction is implemented by transitioning every consent_records row for
 * the actor into the existing SUSPENDED state (ConsentStore.suspend()/
 * resume() — a transition the state machine already supports:
 * ACTIVE <-> SUSPENDED, see ConsentStateModel.js). Every consent
 * verification call in the enforcement pipeline already gates on
 * isActiveNow()/effectiveState(), so a suspended actor is automatically
 * denied at every existing enforcement point — restriction requires no new
 * enforcement-side gate, it reuses the one that already exists everywhere
 * consent is checked ("restriction enforced everywhere personal processing
 * occurs" falls out of the state machine that already exists).
 */

const ConsentStore   = require('../consent/ConsentStore');
const DSRStore       = require('./DSRStore');
const { pageAll }    = require('./pageAll');
const { assertApproved } = require('./identityVerification');

async function _restrictableRecords(actorId, tenantId) {
  const records = await pageAll(({ limit, offset }) => ConsentStore.list({ actor_id: actorId, tenant_id: tenantId, limit, offset }).then((r) => r.records), 200); // audit 4.2: all pages
  return records.filter((r) => r.state === 'ACTIVE' || r.state === 'SUSPENDED');
}

/**
 * @param {object} opts
 * @param {string} opts.requestId - a DSR request of type RESTRICTION, status APPROVED
 * @param {string} [opts.reason]
 * @param {string} opts.restrictedBy
 * @returns {Promise<object>} updated DSR request row
 */
async function restrict({ requestId, tenantId = null, reason, restrictedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!restrictedBy) throw new Error('restrictedBy is required');

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  if (request.request_type !== 'RESTRICTION') {
    throw new Error(`DSR request ${requestId} is not a RESTRICTION request`);
  }
  assertApproved(request);

  await DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'IN_PROGRESS',
    actor: restrictedBy, eventType: 'DSR_RESTRICTION_STARTED', eventDetail: { reason: reason ?? null },
  });

  const candidates = await _restrictableRecords(request.actor_id, request.tenant_id);
  const restricted  = [];
  for (const record of candidates) {
    if (record.state === 'SUSPENDED') {
      restricted.push(record); // already restricted — idempotent
      continue;
    }
    restricted.push(await ConsentStore.suspend({
      id: record.id, tenant_id: request.tenant_id, suspended_by: restrictedBy,
      suspension_reason: `DSR_RESTRICTION:${requestId}${reason ? ` — ${reason}` : ''}`,
      request_id: requestId,
    }));
  }

  return DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'COMPLETED',
    patch: { completed_at: new Date(), result: { consentRecordsRestricted: restricted.map((r) => r.id) } },
    actor: restrictedBy, eventType: 'DSR_RESTRICTION_COMPLETED',
    eventDetail: { consentRecordsRestricted: restricted.map((r) => r.id) },
  });
}

/**
 * Lift a previously-completed restriction. Only resumes consent records
 * whose suspension_reason was tagged by this exact request, so lifting one
 * DSR restriction never accidentally resumes an unrelated, operator-issued
 * suspension on the same actor.
 *
 * @param {object} opts
 * @param {string} opts.requestId - the RESTRICTION request that is currently in force
 * @param {string} opts.liftedBy
 * @returns {Promise<object>} updated DSR request row
 */
async function lift({ requestId, tenantId = null, liftedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!liftedBy) throw new Error('liftedBy is required');

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  if (request.request_type !== 'RESTRICTION') {
    throw new Error(`DSR request ${requestId} is not a RESTRICTION request`);
  }
  if (request.status !== 'COMPLETED') {
    throw new Error(`DSR request ${requestId} has no active restriction to lift (status=${request.status})`);
  }

  const records = await pageAll(({ limit, offset }) => ConsentStore.list({
    actor_id: request.actor_id, tenant_id: request.tenant_id, state: 'SUSPENDED', limit, offset,
  }).then((r) => r.records), 200); // audit 4.2: all pages, collected BEFORE any record is resumed
  const tag = `DSR_RESTRICTION:${requestId}`;
  const resumed = [];
  for (const record of records) {
    if (typeof record.suspension_reason === 'string' && record.suspension_reason.startsWith(tag)) {
      resumed.push(await ConsentStore.resume({
        id: record.id, tenant_id: request.tenant_id, resumed_by: liftedBy, request_id: requestId,
      }));
    }
  }

  return DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'COMPLETED',
    patch: {
      result: {
        ...(request.result ?? {}),
        restrictionLiftedAt:   new Date().toISOString(),
        consentRecordsResumed: resumed.map((r) => r.id),
      },
    },
    actor: liftedBy, eventType: 'DSR_RESTRICTION_LIFTED',
    eventDetail: { consentRecordsResumed: resumed.map((r) => r.id) },
  });
}

module.exports = { restrict, lift };
