'use strict';

/**
 * QODIQA Public Verification Portal Store — Component #23
 *
 * PostgreSQL persistence layer for portal verification runs.
 *
 * WRITE PATH:  recordVerification(record)
 *   Called from the API route after each portal submission completes.
 *   Returns the persisted row on success, null if PG is disabled.
 *   Throws on unexpected database errors (caller decides on handling).
 *
 * READ PATH:   getByVerificationId(), getByFingerprint(), listVerifications(),
 *              aggregateStats()
 *
 * All reads return empty / null when PG is not enabled.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against portal_verifications.
 *   No UPDATE or DELETE is ever executed.
 */

const pgPool = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { enqueue, isPersistenceFailure, OPERATION_TYPES } = require('../persistenceRecovery');

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Persist a portal verification run.
 *
 * @param {object}   record
 * @param {string}   record.verificationId      — UUID (caller-generated)
 * @param {string}   record.artifactFingerprint — 64-char hex SHA-256
 * @param {string}   [record.artifactPublicKeyId]
 * @param {number}   [record.artifactTimestampMs]
 * @param {number}   [record.artifactExpiryMs]
 * @param {string}   [record.artifactId]
 * @param {string}   record.overallResult       — VERIFIED | VERIFIED_WITH_WARNINGS | FAILED
 * @param {object[]} record.checksPerformed     — ordered check results
 * @param {string}   [record.failedCheck]
 * @param {string}   [record.failureReason]
 * @param {object[]} [record.warnings]
 * @param {string}   [record.transparencyId]    — linked transparency log entry
 * @param {string}   [record.submittedBy]
 * @param {string}   [record.submissionIp]
 * @param {number}   [record.durationMs]
 * @returns {Promise<object|null>}  Persisted row or null if PG disabled
 */
async function recordVerification(record) {
  if (!pgPool.isEnabled()) return null;

  const {
    verificationId,
    artifactFingerprint,
    artifactPublicKeyId  = null,
    artifactTimestampMs  = null,
    artifactExpiryMs     = null,
    artifactId           = null,
    overallResult,
    checksPerformed      = [],
    failedCheck          = null,
    failureReason        = null,
    warnings             = [],
    transparencyId       = null,
    submittedBy          = 'public',
    submissionIp         = null,
    durationMs           = null,
  } = record;

  let res;
  try {
    res = await pgPool.query(`
    INSERT INTO portal_verifications (
      verification_id,
      artifact_fingerprint,
      artifact_public_key_id,
      artifact_timestamp_ms,
      artifact_expiry_ms,
      artifact_id,
      overall_result,
      checks_performed,
      failed_check,
      failure_reason,
      warnings,
      transparency_id,
      submitted_by,
      submission_ip,
      duration_ms
    ) VALUES (
      $1,  $2,  $3,  $4,  $5,
      $6,  $7,  $8,  $9,  $10,
      $11, $12, $13, $14, $15
    )
    RETURNING *
  `, [
    verificationId,
    artifactFingerprint,
    artifactPublicKeyId,
    artifactTimestampMs  != null ? Number(artifactTimestampMs)  : null,
    artifactExpiryMs     != null ? Number(artifactExpiryMs)     : null,
    artifactId,
    overallResult,
    JSON.stringify(checksPerformed),
    failedCheck,
    failureReason,
    JSON.stringify(warnings),
    transparencyId,
    submittedBy,
    submissionIp,
    durationMs != null ? Number(durationMs) : null,
  ], 'portal_record_verification');
  } catch (err) {
    if (isPersistenceFailure(err)) {
      emit('WARN', 'PORTAL_PG_FAILURE_QUEUED', { error: err.message });
      return enqueue(OPERATION_TYPES.PORTAL_VERIFICATION_SAVE, record, err);
    }
    throw err;
  }

  return res.rows[0] ?? null;
}

// ── Read path ─────────────────────────────────────────────────────────────────

/**
 * Fetch a single verification run by its UUID.
 *
 * @param {string} verificationId
 * @returns {Promise<object|null>}
 */
async function getByVerificationId(verificationId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(
    'SELECT * FROM portal_verifications WHERE verification_id = $1::uuid LIMIT 1',
    [verificationId],
    'portal_get_by_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Check whether an artifact fingerprint has been seen before.
 * Returns the most recent matching row, or null if unseen.
 *
 * @param {string} fingerprint — 64-char hex SHA-256
 * @returns {Promise<object|null>}
 */
async function getByFingerprint(fingerprint) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT verification_id, overall_result, verified_at
    FROM portal_verifications
    WHERE artifact_fingerprint = $1
    ORDER BY verified_at DESC
    LIMIT 1
  `, [fingerprint], 'portal_get_by_fingerprint');

  return res.rows[0] ?? null;
}

/**
 * Return a paginated list of verification runs, newest first.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.overallResult]     — filter by result
 * @param {string}  [opts.artifactId]        — filter by extracted artifact_id
 * @param {string}  [opts.failedCheck]       — filter by first failed check
 * @param {string}  [opts.startTime]         — ISO date string (lower bound)
 * @param {string}  [opts.endTime]           — ISO date string (upper bound)
 * @param {number}  [opts.page=1]
 * @param {number}  [opts.pageSize=50]
 * @param {string}  [opts.sortOrder='desc']
 * @returns {Promise<{ verifications: object[], total: number, page: number, pageSize: number }>}
 */
async function listVerifications({
  overallResult,
  artifactId,
  failedCheck,
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { verifications: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (overallResult) add('overall_result = ?',            overallResult);
  if (artifactId)    add('artifact_id = ?',               artifactId);
  if (failedCheck)   add('failed_check = ?',              failedCheck);
  if (startTime)     add('verified_at >= ?',              new Date(startTime));
  if (endTime)       add('verified_at <= ?',              new Date(endTime));

  const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(pageSize, 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, verification_id, artifact_fingerprint,
        artifact_public_key_id, artifact_timestamp_ms, artifact_expiry_ms, artifact_id,
        overall_result, checks_performed, failed_check, failure_reason,
        warnings, transparency_id, submitted_by, submission_ip, duration_ms, verified_at
      FROM portal_verifications
      ${where}
      ORDER BY verified_at ${dir}, id ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'portal_list'),
    pgPool.query(
      `SELECT count(*) AS total FROM portal_verifications ${where}`,
      params,
      'portal_list_count',
    ),
  ]);

  return {
    verifications: dataRes.rows,
    total:         Number(cntRes.rows[0]?.total ?? 0),
    page:          pg,
    pageSize:      ps,
  };
}

/**
 * Aggregate statistics across all portal verifications.
 *
 * @returns {Promise<object|null>}  null if PG not enabled
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT
      count(*)                                                            AS total,
      count(*) FILTER (WHERE overall_result = 'VERIFIED')                AS verified_count,
      count(*) FILTER (WHERE overall_result = 'VERIFIED_WITH_WARNINGS')  AS warnings_count,
      count(*) FILTER (WHERE overall_result = 'FAILED')                  AS failed_count,
      count(*) FILTER (WHERE failed_check = 'SCHEMA')                    AS schema_failures,
      count(*) FILTER (WHERE failed_check = 'SIGNATURE')                 AS signature_failures,
      count(*) FILTER (WHERE failed_check = 'NOT_EXPIRED')               AS expiry_failures,
      count(*) FILTER (WHERE failed_check = 'TIMESTAMP')                 AS timestamp_failures,
      count(*) FILTER (WHERE failed_check = 'CLOCK_SKEW')                AS clock_skew_failures,
      count(*) FILTER (WHERE failed_check = 'KEY_VALID')                 AS key_failures,
      min(verified_at)                                                    AS first_verification,
      max(verified_at)                                                    AS last_verification,
      pg_size_pretty(pg_total_relation_size('portal_verifications'))     AS table_size
    FROM portal_verifications
  `, [], 'portal_aggregate_stats');

  const r = res.rows[0] ?? {};
  return {
    total:              Number(r.total              ?? 0),
    verifiedCount:      Number(r.verified_count     ?? 0),
    warningsCount:      Number(r.warnings_count     ?? 0),
    failedCount:        Number(r.failed_count       ?? 0),
    schemaFailures:     Number(r.schema_failures    ?? 0),
    signatureFailures:  Number(r.signature_failures ?? 0),
    expiryFailures:     Number(r.expiry_failures    ?? 0),
    timestampFailures:  Number(r.timestamp_failures ?? 0),
    clockSkewFailures:  Number(r.clock_skew_failures ?? 0),
    keyFailures:        Number(r.key_failures       ?? 0),
    firstVerification:  r.first_verification        ?? null,
    lastVerification:   r.last_verification         ?? null,
    tableSize:          r.table_size                ?? null,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  recordVerification,
  getByVerificationId,
  getByFingerprint,
  listVerifications,
  aggregateStats,
};
