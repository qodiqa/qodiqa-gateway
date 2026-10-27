'use strict';

/**
 * QODIQA Attestation Store — Component #24
 *
 * PostgreSQL persistence layer for attestation records.
 *
 * WRITE PATH:  recordAttestation(record)
 *   Called from the API route after each attestation generation completes.
 *   Returns the persisted row on success, null if PG is disabled.
 *   Throws on unexpected database errors (caller decides on handling).
 *
 * READ PATH:   getByAttestationId(), getByFingerprint(),
 *              listAttestations(), aggregateStats()
 *
 * All reads return empty / null when PG is not enabled.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against attestations.
 *   No UPDATE or DELETE is ever executed.
 */

const pgPool  = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { enqueue, isPersistenceFailure, OPERATION_TYPES } = require('../persistenceRecovery');

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Persist an attestation record.
 *
 * @param {object}  record
 * @param {string}  record.attestationId         — UUID (caller-generated)
 * @param {string}  [record.attestationType='ARTIFACT_VERIFICATION']
 * @param {string}  [record.version='1.0']
 * @param {string}  [record.artifactFingerprint] — 64-char hex SHA-256
 * @param {string}  [record.artifactPublicKeyId]
 * @param {number}  [record.artifactTimestampMs]
 * @param {number}  [record.artifactExpiryMs]
 * @param {string}  [record.artifactId]
 * @param {string}  record.attestationDecision   — ATTESTED|ATTESTED_WITH_WARNINGS|NOT_ATTESTED
 * @param {object}  [record.verificationResult]
 * @param {object}  [record.cryptographicResult]
 * @param {object}  [record.complianceResult]
 * @param {object}  [record.chainResult]
 * @param {object[]} [record.checksPerformed]
 * @param {object[]} [record.warnings]
 * @param {string}  [record.failedCheck]
 * @param {string}  [record.failureReason]
 * @param {string}  [record.transparencyId]
 * @param {string}  [record.evidencePackageHash]
 * @param {string}  [record.requestedBy]
 * @param {string}  [record.requestIp]
 * @param {number}  [record.durationMs]
 * @returns {Promise<object|null>}  Persisted row or null if PG disabled
 */
async function recordAttestation(record) {
  if (!pgPool.isEnabled()) return null;

  const {
    attestationId,
    attestationType      = 'ARTIFACT_VERIFICATION',
    version              = '1.0',
    artifactFingerprint  = null,
    artifactPublicKeyId  = null,
    artifactTimestampMs  = null,
    artifactExpiryMs     = null,
    artifactId           = null,
    attestationDecision,
    verificationResult   = {},
    cryptographicResult  = {},
    complianceResult     = {},
    chainResult          = {},
    checksPerformed      = [],
    warnings             = [],
    failedCheck          = null,
    failureReason        = null,
    transparencyId       = null,
    evidencePackageHash  = null,
    requestedBy          = 'external',
    requestIp            = null,
    durationMs           = null,
  } = record;

  let res;
  try {
    res = await pgPool.query(`
    INSERT INTO attestations (
      attestation_id,
      attestation_type,
      version,
      artifact_fingerprint,
      artifact_public_key_id,
      artifact_timestamp_ms,
      artifact_expiry_ms,
      artifact_id,
      attestation_decision,
      verification_result,
      cryptographic_result,
      compliance_result,
      chain_result,
      checks_performed,
      warnings,
      failed_check,
      failure_reason,
      transparency_id,
      evidence_package_hash,
      requested_by,
      request_ip,
      duration_ms
    ) VALUES (
      $1,  $2,  $3,  $4,  $5,
      $6,  $7,  $8,  $9,  $10,
      $11, $12, $13, $14, $15,
      $16, $17, $18, $19, $20,
      $21, $22
    )
    RETURNING *
  `, [
    attestationId,
    attestationType,
    version,
    artifactFingerprint,
    artifactPublicKeyId,
    artifactTimestampMs  != null ? Number(artifactTimestampMs)  : null,
    artifactExpiryMs     != null ? Number(artifactExpiryMs)     : null,
    artifactId,
    attestationDecision,
    JSON.stringify(verificationResult),
    JSON.stringify(cryptographicResult),
    JSON.stringify(complianceResult),
    JSON.stringify(chainResult),
    JSON.stringify(checksPerformed),
    JSON.stringify(warnings),
    failedCheck,
    failureReason,
    transparencyId,
    evidencePackageHash,
    requestedBy,
    requestIp,
    durationMs != null ? Number(durationMs) : null,
  ], 'attestation_record');
  } catch (err) {
    if (isPersistenceFailure(err)) {
      emit('WARN', 'ATTESTATION_PG_FAILURE_QUEUED', { error: err.message });
      return enqueue(OPERATION_TYPES.ATTESTATION_SAVE, record, err);
    }
    throw err;
  }

  return res.rows[0] ?? null;
}

// ── Read path ─────────────────────────────────────────────────────────────────

/**
 * Fetch a single attestation by its UUID.
 *
 * @param {string} attestationId
 * @returns {Promise<object|null>}
 */
async function getByAttestationId(attestationId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(
    'SELECT * FROM attestations WHERE attestation_id = $1::uuid LIMIT 1',
    [attestationId],
    'attestation_get_by_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Check whether an artifact fingerprint has been attested before.
 * Returns the most recent matching row, or null if unseen.
 *
 * @param {string} fingerprint — 64-char hex SHA-256
 * @returns {Promise<object|null>}
 */
async function getByFingerprint(fingerprint) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT attestation_id, attestation_decision, generated_at
    FROM attestations
    WHERE artifact_fingerprint = $1
      AND attestation_type = 'ARTIFACT_VERIFICATION'
    ORDER BY generated_at DESC
    LIMIT 1
  `, [fingerprint], 'attestation_get_by_fingerprint');

  return res.rows[0] ?? null;
}

/**
 * Return a paginated list of attestations.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.attestationDecision]  — filter by decision
 * @param {string}  [opts.attestationType]      — filter by type
 * @param {string}  [opts.artifactId]           — filter by artifact_id
 * @param {string}  [opts.failedCheck]          — filter by first failed check
 * @param {string}  [opts.startTime]            — ISO date string (lower bound)
 * @param {string}  [opts.endTime]              — ISO date string (upper bound)
 * @param {number}  [opts.page=1]
 * @param {number}  [opts.pageSize=50]
 * @param {string}  [opts.sortOrder='desc']
 * @returns {Promise<{ attestations: object[], total: number, page: number, pageSize: number }>}
 */
async function listAttestations({
  attestationDecision,
  attestationType,
  artifactId,
  failedCheck,
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { attestations: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (attestationDecision) add('attestation_decision = ?', attestationDecision);
  if (attestationType)     add('attestation_type = ?',     attestationType);
  if (artifactId)          add('artifact_id = ?',          artifactId);
  if (failedCheck)         add('failed_check = ?',         failedCheck);
  if (startTime)           add('generated_at >= ?',        new Date(startTime));
  if (endTime)             add('generated_at <= ?',        new Date(endTime));

  const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(pageSize, 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, attestation_id, attestation_type, version,
        artifact_fingerprint, artifact_public_key_id,
        artifact_timestamp_ms, artifact_expiry_ms, artifact_id,
        attestation_decision,
        verification_result, cryptographic_result, compliance_result, chain_result,
        checks_performed, failed_check, failure_reason, warnings,
        transparency_id, evidence_package_hash,
        requested_by, request_ip, duration_ms, generated_at
      FROM attestations
      ${where}
      ORDER BY generated_at ${dir}, id ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'attestation_list'),
    pgPool.query(
      `SELECT count(*) AS total FROM attestations ${where}`,
      params,
      'attestation_list_count',
    ),
  ]);

  return {
    attestations: dataRes.rows,
    total:        Number(cntRes.rows[0]?.total ?? 0),
    page:         pg,
    pageSize:     ps,
  };
}

/**
 * Aggregate statistics across all attestations.
 *
 * @returns {Promise<object|null>}  null if PG not enabled
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT
      count(*)                                                                AS total,
      count(*) FILTER (WHERE attestation_decision = 'ATTESTED')              AS attested_count,
      count(*) FILTER (WHERE attestation_decision = 'ATTESTED_WITH_WARNINGS') AS warnings_count,
      count(*) FILTER (WHERE attestation_decision = 'NOT_ATTESTED')          AS not_attested_count,
      count(*) FILTER (WHERE attestation_type = 'ARTIFACT_VERIFICATION')     AS artifact_verifications,
      count(*) FILTER (WHERE attestation_type = 'EVIDENCE_VERIFICATION')     AS evidence_verifications,
      count(*) FILTER (WHERE attestation_type = 'CHAIN_VERIFICATION')        AS chain_verifications,
      count(*) FILTER (WHERE failed_check = 'SCHEMA')                        AS schema_failures,
      count(*) FILTER (WHERE failed_check = 'SIGNATURE')                     AS signature_failures,
      count(*) FILTER (WHERE failed_check = 'NOT_EXPIRED')                   AS expiry_failures,
      min(generated_at)                                                       AS first_attestation,
      max(generated_at)                                                       AS last_attestation,
      pg_size_pretty(pg_total_relation_size('attestations'))                 AS table_size
    FROM attestations
  `, [], 'attestation_aggregate_stats');

  const r = res.rows[0] ?? {};
  return {
    total:                Number(r.total               ?? 0),
    attestedCount:        Number(r.attested_count      ?? 0),
    warningsCount:        Number(r.warnings_count      ?? 0),
    notAttestedCount:     Number(r.not_attested_count  ?? 0),
    artifactVerifications: Number(r.artifact_verifications ?? 0),
    evidenceVerifications: Number(r.evidence_verifications ?? 0),
    chainVerifications:   Number(r.chain_verifications  ?? 0),
    schemaFailures:       Number(r.schema_failures      ?? 0),
    signatureFailures:    Number(r.signature_failures   ?? 0),
    expiryFailures:       Number(r.expiry_failures      ?? 0),
    firstAttestation:     r.first_attestation           ?? null,
    lastAttestation:      r.last_attestation            ?? null,
    tableSize:            r.table_size                  ?? null,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  recordAttestation,
  getByAttestationId,
  getByFingerprint,
  listAttestations,
  aggregateStats,
};
