'use strict';

/**
 * RectificationService — GDPR Article 16 (right to rectification).
 *
 * Corrects mutable PII on a consent record (subject_name, metadata, tags)
 * via ConsentStore.rectify(), which appends a CONSENT_RECTIFIED entry to
 * the existing consent_audit_log (no new audit primitive). In addition,
 * this service writes an append-only before/after row per field to
 * dsr_rectifications, so Article 16's "preserve history, link superseded
 * values" has its own trail scoped to the DSR request. Immutable audit
 * entries (consent_audit_log, audit.log) are never rewritten — only the
 * current-state fields on consent_records change.
 */

const pool          = require('../../infra/postgres/pool');
const ConsentStore   = require('../consent/ConsentStore');
const DSRStore       = require('./DSRStore');
const { assertApproved } = require('./identityVerification');

/**
 * @param {object} opts
 * @param {string} opts.requestId - a DSR request of type RECTIFICATION, status APPROVED
 * @param {string} [opts.tenantId] - threads tenant context to findById, see DSRStore.findById
 * @param {string} opts.consentId - the consent_records row to correct
 * @param {object} opts.fields - subset of { subject_name, metadata, tags }
 * @param {string} opts.rectifiedBy
 * @returns {Promise<object>} updated DSR request row
 */
async function rectify({ requestId, tenantId = null, consentId, fields, rectifiedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!consentId) throw new Error('consentId is required');
  if (!rectifiedBy) throw new Error('rectifiedBy is required');

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  if (request.request_type !== 'RECTIFICATION') {
    throw new Error(`DSR request ${requestId} is not a RECTIFICATION request`);
  }
  assertApproved(request);

  await DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'IN_PROGRESS',
    actor: rectifiedBy, eventType: 'DSR_RECTIFICATION_STARTED', eventDetail: { consentId },
  });

  const { record, before, after } = await ConsentStore.rectify({
    id: consentId, tenant_id: request.tenant_id, fields, rectified_by: rectifiedBy, request_id: requestId,
  });

  const fieldsRectified = Object.keys(after);
  for (const field of fieldsRectified) {
    await pool.query(
      `INSERT INTO dsr_rectifications
         (request_id, consent_id, actor_id, tenant_id, field_name, old_value, new_value, rectified_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        requestId, consentId, record.actor_id, request.tenant_id, field,
        JSON.stringify(before[field] ?? null), JSON.stringify(after[field] ?? null), rectifiedBy,
      ],
      'dsr_record_rectification',
    );
  }

  return DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'COMPLETED',
    patch: { completed_at: new Date(), result: { consentId, fieldsRectified } },
    actor: rectifiedBy, eventType: 'DSR_RECTIFICATION_COMPLETED', eventDetail: { consentId, fieldsRectified },
  });
}

module.exports = { rectify };
