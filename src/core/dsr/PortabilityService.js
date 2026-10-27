'use strict';

/**
 * PortabilityService (ExportGenerator) — GDPR Article 20 (right to data
 * portability).
 *
 * Assembles a machine-readable export of everything QODIQA holds about an
 * actor_id: current + historical consent records (ConsentStore.list()), the
 * full consent audit trail (ConsentStore.getAuditLog()), and the actor's
 * own DSR request history. Computes a SHA-256 checksum over the exact bytes
 * returned to the caller, so the subject can verify their copy matches what
 * was generated. Only the checksum/metadata is persisted (dsr_exports); the
 * payload itself is returned in the response and not stored server-side,
 * avoiding a second at-rest copy of personal data.
 *
 * Excludes: private keys, Ed25519 signatures, API-key material — none of
 * which exist in consent_records/consent_audit_log in the first place.
 * record_hash/checksum fields ARE included: they are non-secret integrity
 * hashes, useful to the subject for verifying their own export, not secrets.
 *
 * Note on scope: the cryptographic audit chain (audit.log) is not indexed
 * by actor_id (no such field exists in its schema — see entryBuilder.js),
 * so it cannot be reliably joined into a per-actor export; this is
 * documented in docs/guides/dsr.md rather than worked around with an
 * approximate join.
 *
 * operator-registered extension targets (ErasureTargetRegistry)
 * that implement `export` are invoked after the built-in package above is
 * assembled, in registration order. Their results are returned in the
 * top-level response (`customTargets`) and persisted in `result` alongside
 * checksum/format — never embedded inside the checksummed JSON/CSV payload
 * bytes, so the existing "checksum covers exactly what's returned" and
 * fixed CSV column schema are both unaffected by how many targets are
 * registered. A target without export support is reported explicitly
 * (`status: 'NOT_SUPPORTED'`), never silently skipped. With zero targets
 * registered, `customTargets` is an empty array and behavior is otherwise
 * unchanged from.
 */

const { pageAll } = require('./pageAll');
const crypto        = require('crypto');
const pool           = require('../../infra/postgres/pool');
const ConsentStore   = require('../consent/ConsentStore');
const DSRStore       = require('./DSRStore');
const ErasureTargetRegistry = require('./ErasureTargetRegistry');
const { assertApproved } = require('./identityVerification');
const { sanitizeCsvCell } = require('../../utils/csvSanitize');

/**
 * Invoke every registered ErasureTargetRegistry target for one DSR
 * operation ('ERASE' | 'EXPORT'), in registration order. Isolates failures
 * per target (a throwing callback never stops the loop) and records one
 * audit event per invocation via the existing dsr_request_events trail
 * (DSRStore.appendEvent) — no separate audit primitive. Mirrors
 * ErasureService.js's identical helper; kept local rather than shared
 * because ErasureTargetRegistry itself must stay pure (registry only, no
 * invocation logic — see that module's header).
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

// INJ-7: centralized sanitizer — neutralizes leading =/+/-/@ (spreadsheet
// formula injection) in addition to the standard quote-escaping this export
// already applied.
const _csvEscape = sanitizeCsvCell;

function _toCsv(records) {
  const header = ['id', 'action', 'state', 'scope', 'granted_at', 'expires_at', 'record_hash'];
  const rows   = records.map((r) => header.map((h) => _csvEscape(r[h])).join(','));
  return [header.join(','), ...rows].join('\n') + '\n';
}

/**
 * @param {object} opts
 * @param {string} opts.requestId - a DSR request of type PORTABILITY, status APPROVED
 * @param {string} [opts.format='JSON'] - 'JSON' | 'CSV'
 * @param {string} opts.generatedBy
 * @returns {Promise<{payload: string, format: string, checksum: string, sizeBytes: number, exportId: string, customTargets: object[]}>}
 */
async function generateExport({ requestId, tenantId = null, format = 'JSON', generatedBy }) {
  if (!requestId) throw new Error('requestId is required');
  if (!generatedBy) throw new Error('generatedBy is required');
  if (format !== 'JSON' && format !== 'CSV') throw new Error("format must be 'JSON' or 'CSV'");

  const request = await DSRStore.findById(requestId, tenantId);
  if (!request) throw new Error(`DSR request not found: ${requestId}`);
  if (request.request_type !== 'PORTABILITY') {
    throw new Error(`DSR request ${requestId} is not a PORTABILITY request`);
  }
  assertApproved(request);

  await DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'IN_PROGRESS',
    actor: generatedBy, eventType: 'DSR_EXPORT_STARTED', eventDetail: { format },
  });

  // every page, not the first 200 / 500 (an export must be complete or fail loudly).
  const consentRecords = await pageAll(
    ({ limit, offset }) => ConsentStore.list({ actor_id: request.actor_id, tenant_id: request.tenant_id, limit, offset }).then((r) => r.records), 200);
  // request.tenant_id already in scope for the ConsentStore.list/
  // DSRStore.list calls immediately around this one -- was never threaded
  // through to getAuditLog, silently returning an empty consent history in
  // every tenant-scoped DSR export.
  const consentHistory = await pageAll(
    ({ limit, offset }) => ConsentStore.getAuditLog({ actor_id: request.actor_id, tenant_id: request.tenant_id, limit, offset }), 500);
  const dsrHistory = await pageAll(
    ({ limit, offset }) => DSRStore.list({ actor_id: request.actor_id, tenant_id: request.tenant_id, limit, offset }).then((r) => r.requests), 200);

  const jsonPackage = {
    exportedAt: new Date().toISOString(),
    subject:    { actorId: request.actor_id, tenantId: request.tenant_id },
    consentRecords,
    consentHistory,
    dsrRequests: dsrHistory,
    metadata: {
      generator: 'QODIQA DataSubjectRightsService — PortabilityService',
      article:   'GDPR Article 20',
      note: 'The cryptographic audit chain (audit.log) is not included: it has no actor_id field and '
          + 'cannot be reliably joined to this subject. See docs/guides/dsr.md.',
    },
  };

  const payload   = format === 'JSON' ? JSON.stringify(jsonPackage, null, 2) : _toCsv(consentRecords);
  const checksum  = crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
  const sizeBytes = Buffer.byteLength(payload, 'utf8');

  // invoked after the payload/checksum are computed so a
  // registered target can never alter the bytes the subject's checksum
  // verifies against; results are reported alongside, not inside, the export.
  const customTargets = await _invokeExtensionTargets(
    ErasureTargetRegistry.getTargets(),
    'EXPORT',
    {
      context: {
        actorId: request.actor_id, tenantId: request.tenant_id, requestId,
        requestType: request.request_type, performedBy: generatedBy,
      },
      requestId, tenantId: request.tenant_id, actor: generatedBy,
    },
  );

  const exportRow = await pool.query(
    `INSERT INTO dsr_exports (request_id, actor_id, tenant_id, format, checksum, size_bytes, generated_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [requestId, request.actor_id, request.tenant_id, format, checksum, sizeBytes, generatedBy],
    'dsr_record_export',
  );

  await DSRStore.updateStatus({
    id: requestId, tenant_id: request.tenant_id, status: 'COMPLETED',
    patch: {
      completed_at: new Date(),
      export_checksum: checksum,
      result: { format, checksum, sizeBytes, recordCount: consentRecords.length, customTargets },
    },
    actor: generatedBy, eventType: 'DSR_EXPORT_COMPLETED',
    eventDetail: { format, checksum, sizeBytes, customTargetsInvoked: customTargets.length },
  });

  return { payload, format, checksum, sizeBytes, exportId: exportRow.rows[0].id, customTargets };
}

module.exports = { generateExport };
