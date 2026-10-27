'use strict';

/**
 * ErasureService — GDPR Article 17 (right to erasure).
 *
 * replaced
 * the earlier flow, which read at most 200 consent_records rows in one tenant
 * scope, touched no other table, left the Redis consent cache alone, recorded
 * an UNSALTED SHA-256 of the original identifier (dictionary-reversible,
 * NF-10) and set COMPLETED unconditionally. Now, per run:
 *
 *   1. Gate: an APPROVED ERASURE request starts a run; a FAILED one RESUMES
 *      (every step below is idempotent) — it is never re-approved (D10).
 * Refused while an Article 18 restriction is active, checked
 *      over ALL the subject's records, not the first 200.
 *   2. The subject's pseudonym  ap1:HMAC(K_subject, tenant‖actor)
 *      (subjectPseudonym.js; the key is created if the subject has none).
 *   3. consent_records (group a): tombstoned batch by batch, record_hash
 *      recomputed (ConsentStore.eraseSubjectBatch) until none remain.
 *   4. Every other erasable table (group b), derived FROM THE CATALOG
 *      (qodiqa_erasure_targets, migration 063), via the owner-run DEFINER
 *      function qodiqa_erase_subject as qodiqa_system, until every target
 *      reports 0 remaining. The append-only guards stay closed to the app.
 * 5. Operator extension targets, with the plaintext identifier,
 *      BEFORE the key is destroyed.
 *   6. Consent cache: local actor invalidation + a signed actor-level
 *      invalidation to every node.
 *   7. qodiqa_erase_subject_finalize, atomically: refuses unless NOTHING
 *      remains anywhere (COMPLETED only when all tables are done — enforced in
 *      the database), pseudonymizes dsr_requests (group c), marks COMPLETED
 *      with its event, DELETES the subject's key, appends the erasure-ledger
 *      row that scripts/dr/restore.js replays after a restore.
 *
 * Retained by design (reported in result.recordsRetained): hash-protected
 * stores (audit chain, evidence chain, transparency log, audit.log) that
 * still hold the earlier plaintext identifier (H1 — re-anchoring is a
 * input), consent_audit_log.detail and dsr_request_events.detail (checksum-
 * protected accountability records), backups inside their retention window.
 */

const { randomUUID } = require('crypto');
const ConsentStore   = require('../consent/ConsentStore');
const DSRStore       = require('./DSRStore');
const ErasureTargetRegistry = require('./ErasureTargetRegistry');
const subjectPseudonym = require('./subjectPseudonym');
const rolePools      = require('../../infra/postgres/rolePools');
const { assertVerified } = require('./identityVerification');

const TABLE_BATCH = parseInt(process.env.QODIQA_DSR_ERASURE_BATCH || '500', 10);
const MAX_ROUNDS  = parseInt(process.env.QODIQA_DSR_ERASURE_MAX_ROUNDS || '100000', 10);

/**
 * Invoke every registered ErasureTargetRegistry target for one DSR
 * operation ('ERASE' | 'EXPORT'), in registration order. Isolates failures
 * per target (a throwing callback never stops the loop) and records one
 * audit event per invocation via the existing dsr_request_events trail
 * (DSRStore.appendEvent) — no separate audit primitive.
 *
 * @returns {Promise<object[]>} one deterministic result record per target
 */
async function _invokeExtensionTargets(targets, operation, { context, requestId, tenantId, actor }) {
  const results = [];

  for (const target of targets) {
    const startedAt = new Date();
    const startedHr = process.hrtime.bigint();
    let status;
    let detail;
    let error = null;

    if (operation === 'EXPORT' && typeof target.export !== 'function') {
      status = 'NOT_SUPPORTED';
      detail = null;
    } else {
      try {
        const callback = operation === 'ERASE' ? target.erase : target.export;
        detail = (await callback(context)) ?? null;
        status = 'COMPLETED';
      } catch (err) {
        status = 'FAILED';
        detail = null;
        error = err.message;
      }
    }

    const durationMs = Number(process.hrtime.bigint() - startedHr) / 1e6;
    const record = {
      targetId: target.id,
      targetName: target.name,
      operation,
      status,
      success: status === 'COMPLETED',
      startedAt: startedAt.toISOString(),
      durationMs,
      result: detail,
      error,
    };
    results.push(record);

    await DSRStore.appendEvent({
      request_id: requestId,
      tenant_id:  tenantId,
      event_type: operation === 'ERASE' ? 'DSR_EXTENSION_TARGET_ERASED' : 'DSR_EXTENSION_TARGET_EXPORTED',
      actor,
      detail:     record,
    });
  }

  return results;
}

const RECORDS_RETAINED = Object.freeze([
  {
    store: 'audit chain (audit.log, audit_chain), evidence_chain_records, transparency_log_entries',
    reason: 'Hash-protected and signed: entries written before carry the subject identifier inside hashed fields '
          + '(consentProvenance.subject, callerContext.callerId — entryBuilder.js CORE_HASH_FIELDS v3+; transparency '
          + 'payload.callerId under payload_hash). Rewriting them would break verification of every later entry. '
          + 'Re-anchoring historical entries onto the ap1: pseudonym is a input.',
    legalBasis: 'GDPR Art. 17(3)(b) — legal obligation to keep a tamper-evident enforcement record; '
              + 'Art. 17(3)(e) — establishment/exercise/defence of legal claims.',
  },
  {
    store: 'consent_audit_log.detail, dsr_request_events.detail',
    reason: 'Checksum-protected accountability records (ConsentStore._auditChecksum, DSRStore event checksum). '
          + 'Identifier COLUMNS in these tables are pseudonymized; free-form detail JSON written before the erasure '
          + '(e.g. rectification before/after values, the request-received actorId) is kept as recorded.',
    legalBasis: 'GDPR Art. 5(2) accountability; Art. 17(3)(b)/(e).',
  },
  {
    store: 'backups (pg-backup tiers, PITR/WAL, DR bundles)',
    reason: 'Kept for their retention window (up to 12 months, monthly tier). A restore replays this erasure from '
          + 'dsr_erasure_ledger before the service accepts traffic (scripts/dr/restore.js).',
    legalBasis: 'GDPR Art. 32 — availability and resilience.',
  },
]);

async function _eraseConsentRecords({ request, pseudonym, erasedBy, requestId }) {
  let total = 0;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const { erased } = await ConsentStore.eraseSubjectBatch({
      actor_id: request.actor_id, tenant_id: request.tenant_id, pseudonym, erased_by: erasedBy, request_id: requestId,
    });
    total += erased;
    if (erased === 0) return total;
  }
  throw new Error(`erasure of consent_records did not converge after ${MAX_ROUNDS} batches`);
}

async function _eraseCatalogTargets({ request, pseudonym }) {
  const tables = {};
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const { rows } = await rolePools.system.query(
      'SELECT target, rows_updated, remaining FROM qodiqa_erase_subject($1, $2, $3, $4)',
      [request.tenant_id ?? null, request.actor_id, pseudonym, TABLE_BATCH],
      'dsr_erase_subject',
    );
    let remaining = 0;
    for (const r of rows) {
      tables[r.target] = (tables[r.target] || 0) + Number(r.rows_updated);
      remaining += Number(r.remaining);
    }
    if (remaining === 0) return tables;
  }
  throw new Error(`erasure of catalog targets did not converge after ${MAX_ROUNDS} rounds`);
}

async function _hasActiveRestriction(request) {
  for (let offset = 0; ; offset += 200) {
    const { records } = await ConsentStore.list({
      actor_id: request.actor_id, tenant_id: request.tenant_id, state: 'SUSPENDED', limit: 200, offset,
    });
    const hold = records.find((r) => typeof r.suspension_reason === 'string' && r.suspension_reason.startsWith('DSR_RESTRICTION:'));
    if (hold) return hold;
    if (records.length < 200) return null;
  }
}

async function _invalidateConsentCache(request, erasedBy) {
  // Local node now; every other node through the signed revocation channel.
  try { await require('../consent/ConsentCache').invalidateActor(request.actor_id); } catch { /* best-effort */ }
  try {
    await require('../consent/revocation/RevocationPublisher').publish({
      subjectId: request.actor_id, action: null, tenantId: request.tenant_id ?? null,
      revokedBy: erasedBy, revocationReason: 'GDPR_ARTICLE_17_ERASURE',
    });
  } catch { /* best-effort: consent records are already REVOKED; cache entries expire within their TTL */ }
}

/**
 * @param {object} opts
 * @param {string} opts.requestId - a DSR request of type ERASURE, status APPROVED (start) or FAILED (resume)
 * @param {string} opts.erasedBy  - the authenticated operator (never taken from a request body)
 * @returns {Promise<object>} the COMPLETED DSR request row
 */
async function erase({ requestId, tenantId = null, erasedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!erasedBy) throw new Error('erasedBy is required');

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  if (request.request_type !== 'ERASURE') {
    throw new Error(`DSR request ${requestId} is not an ERASURE request`);
  }
  // D10: APPROVED starts a run, FAILED resumes one; nothing else executes.
  if (request.status !== 'APPROVED' && request.status !== 'FAILED') {
    throw new Error(`DSR request ${requestId} is not approved for execution (status=${request.status})`);
  }
  assertVerified(request);
  const resumed = request.status === 'FAILED';

  // refused while an Article 18 restriction is active — before any mutation.
  const activeHold = await _hasActiveRestriction(request);
  if (activeHold) {
    throw new Error(
      `DSR request ${requestId} blocked: an active legal hold (Article 18 restriction, `
      + `${activeHold.suspension_reason}) exists for this actor — lift the restriction before erasing`,
    );
  }

  const runId = randomUUID();
  await DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'IN_PROGRESS',
    actor: erasedBy, eventType: resumed ? 'DSR_ERASURE_RESUMED' : 'DSR_ERASURE_STARTED', eventDetail: { runId },
  });

  const pseudonym = await subjectPseudonym.pseudonymFor(request.tenant_id ?? null, request.actor_id);
  const subjectRef = subjectPseudonym.subjectRef(request.tenant_id ?? null, request.actor_id);

  const consentRecords = await _eraseConsentRecords({ request, pseudonym, erasedBy, requestId });
  const tables = { 'consent_records.actor_id': consentRecords, ...(await _eraseCatalogTargets({ request, pseudonym })) };

  // operator-registered extension targets, after every built-in
  // table and BEFORE the subject key is destroyed.
  const customTargets = await _invokeExtensionTargets(
    ErasureTargetRegistry.getTargets(),
    'ERASE',
    {
      context: {
        actorId: request.actor_id, tenantId: request.tenant_id, requestId,
        requestType: request.request_type, performedBy: erasedBy,
      },
      requestId, tenantId: request.tenant_id, actor: erasedBy,
    },
  );

  await _invalidateConsentCache(request, erasedBy);

  const result = {
    runId,
    resumed,
    pseudonym,
    tables,
    actorIdPseudonymized: true,
    subjectKeyDestroyed: true,
    recordsRetained: RECORDS_RETAINED,
    customTargets,
  };
  const eventDetail = { runId, tables, customTargetsInvoked: customTargets.length };
  const { detailJson, checksum } = DSRStore._eventChecksum({
    request_id: requestId, event_type: 'DSR_ERASURE_COMPLETED', actor: erasedBy, detail: eventDetail,
  });

  const { rows } = await rolePools.system.query(
    'SELECT * FROM qodiqa_erase_subject_finalize($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
    [requestId, request.tenant_id ?? null, request.actor_id, pseudonym, subjectRef, runId,
      JSON.stringify(result), erasedBy, detailJson, checksum],
    'dsr_erase_subject_finalize',
  );
  return rows[0];
}

module.exports = { erase, RECORDS_RETAINED, _invokeExtensionTargets };
