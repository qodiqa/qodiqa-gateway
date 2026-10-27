'use strict';

/**
 * QODIQA Certification Store — Component #25
 *
 * PostgreSQL persistence layer for certification evaluation records.
 *
 * WRITE PATH:  recordCertification(record)
 *   Called from the evaluation engine after each certification run.
 *   Returns the persisted row on success, null if PG is disabled.
 *   Throws on unexpected database errors (caller decides on handling).
 *
 * READ PATH:   getByCertificationId(), listCertifications(), aggregateStats()
 *
 * All reads return empty / null when PG is not enabled.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against certifications.
 *   No UPDATE or DELETE is ever executed.
 */

const pgPool  = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');
const { enqueue, isPersistenceFailure, OPERATION_TYPES } = require('../persistenceRecovery');

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Persist a certification evaluation record.
 *
 * @param {object}  record
 * @param {string}  record.certificationId
 * @param {string}  record.certificationLevel      — NOT_CERTIFIED|CERTIFIED|CERTIFIED_PLUS|CERTIFIED_PREMIUM
 * @param {string}  record.certificationDecision   — CERTIFIED|NOT_CERTIFIED
 * @param {number}  record.score                   — 0–100
 * @param {object}  record.scoreBreakdown
 * @param {Array}   record.criticalControlFailures
 * @param {Array}   record.passedControls
 * @param {Array}   record.failedControls
 * @param {object}  record.evaluationResult
 * @param {Array}   record.attestationReferences
 * @param {Array}   record.evidenceReferences
 * @param {object}  record.verificationReferences
 * @param {string}  [record.transparencyId]
 * @param {string}  [record.evidencePackageHash]
 * @param {number}  [record.artifactsCount]
 * @param {number}  [record.evidencePackagesCount]
 * @param {string}  [record.requestedBy]
 * @param {string}  [record.requestIp]
 * @param {number}  [record.durationMs]
 * @param {string}  [record.expiresAt]   — ISO timestamp; null for NOT_CERTIFIED
 * @param {string}  [record.renewal]     — 'ELIGIBLE' | 'NOT_APPLICABLE'
 * @returns {Promise<object|null>}  Persisted row or null if PG disabled
 */
async function recordCertification(record) {
  if (!pgPool.isEnabled()) return null;

  const {
    certificationId,
    certificationLevel,
    certificationDecision,
    score,
    scoreBreakdown          = {},
    criticalControlFailures = [],
    passedControls          = [],
    failedControls          = [],
    evaluationResult        = {},
    attestationReferences   = [],
    evidenceReferences      = [],
    verificationReferences  = {},
    transparencyId          = null,
    evidencePackageHash     = null,
    artifactsCount          = 0,
    evidencePackagesCount   = 0,
    requestedBy             = 'external',
    requestIp               = null,
    durationMs              = null,
    expiresAt               = null,
    renewal                 = null,
  } = record;

  let res;
  try {
    res = await pgPool.query(`
    INSERT INTO certifications (
      certification_id,
      certification_level,
      certification_decision,
      score,
      score_breakdown,
      critical_control_failures,
      passed_controls,
      failed_controls,
      evaluation_result,
      attestation_references,
      evidence_references,
      verification_references,
      transparency_id,
      evidence_package_hash,
      artifacts_count,
      evidence_packages_count,
      requested_by,
      request_ip,
      duration_ms,
      expires_at,
      renewal
    ) VALUES (
      $1,  $2,  $3,  $4,  $5,
      $6,  $7,  $8,  $9,  $10,
      $11, $12, $13, $14, $15,
      $16, $17, $18, $19, $20,
      $21
    )
    RETURNING *
  `, [
    certificationId,
    certificationLevel,
    certificationDecision,
    score,
    JSON.stringify(scoreBreakdown),
    JSON.stringify(criticalControlFailures),
    JSON.stringify(passedControls),
    JSON.stringify(failedControls),
    JSON.stringify(evaluationResult),
    JSON.stringify(attestationReferences),
    JSON.stringify(evidenceReferences),
    JSON.stringify(verificationReferences),
    transparencyId,
    evidencePackageHash,
    artifactsCount,
    evidencePackagesCount,
    requestedBy,
    requestIp,
    durationMs != null ? Number(durationMs) : null,
    expiresAt   != null ? new Date(expiresAt) : null,
    renewal,
  ], 'certification_record');
  } catch (err) {
    if (isPersistenceFailure(err)) {
      emit('WARN', 'CERTIFICATION_PG_FAILURE_QUEUED', { error: err.message });
      return enqueue(OPERATION_TYPES.CERTIFICATION_SAVE, record, err);
    }
    throw err;
  }

  return res.rows[0] ?? null;
}

// ── Read path ─────────────────────────────────────────────────────────────────

/**
 * Fetch a single certification by its stable UUID.
 *
 * @param {string} certificationId
 * @returns {Promise<object|null>}
 */
async function getByCertificationId(certificationId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(
    'SELECT * FROM certifications WHERE certification_id = $1::uuid LIMIT 1',
    [certificationId],
    'certification_get_by_id',
  );
  return res.rows[0] ?? null;
}

/**
 * Return a paginated list of certifications.
 *
 * @param {object}  [opts]
 * @param {string}  [opts.certificationLevel]    — filter by level
 * @param {string}  [opts.certificationDecision] — filter by decision
 * @param {string}  [opts.requestedBy]           — filter by requester
 * @param {number}  [opts.minScore]              — minimum score (inclusive)
 * @param {number}  [opts.maxScore]              — maximum score (inclusive)
 * @param {string}  [opts.startTime]             — ISO date string (lower bound)
 * @param {string}  [opts.endTime]               — ISO date string (upper bound)
 * @param {number}  [opts.page=1]
 * @param {number}  [opts.pageSize=50]
 * @param {string}  [opts.sortOrder='desc']
 * @returns {Promise<{ certifications: object[], total: number, page: number, pageSize: number }>}
 */
async function listCertifications({
  certificationLevel,
  certificationDecision,
  requestedBy,
  minScore,
  maxScore,
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { certifications: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (certificationLevel)    add('certification_level = ?',    certificationLevel);
  if (certificationDecision) add('certification_decision = ?', certificationDecision);
  if (requestedBy)           add('requested_by = ?',           requestedBy);
  if (minScore != null)      add('score >= ?',                 Number(minScore));
  if (maxScore != null)      add('score <= ?',                 Number(maxScore));
  if (startTime)             add('generated_at >= ?',          new Date(startTime));
  if (endTime)               add('generated_at <= ?',          new Date(endTime));

  const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(pageSize, 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, certification_id, certification_level, certification_decision,
        score, score_breakdown,
        critical_control_failures, passed_controls, failed_controls,
        attestation_references, evidence_references, verification_references,
        transparency_id, evidence_package_hash,
        artifacts_count, evidence_packages_count,
        requested_by, request_ip, duration_ms, generated_at,
        expires_at, renewal
      FROM certifications
      ${where}
      ORDER BY generated_at ${dir}, id ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'certification_list'),
    pgPool.query(
      `SELECT count(*) AS total FROM certifications ${where}`,
      params,
      'certification_list_count',
    ),
  ]);

  return {
    certifications: dataRes.rows,
    total:          Number(cntRes.rows[0]?.total ?? 0),
    page:           pg,
    pageSize:       ps,
  };
}

/**
 * Aggregate statistics across all certifications.
 *
 * @returns {Promise<object|null>}  null if PG not enabled
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT
      count(*)                                                                    AS total,
      count(*) FILTER (WHERE certification_level = 'CERTIFIED_PREMIUM')          AS premium_count,
      count(*) FILTER (WHERE certification_level = 'CERTIFIED_PLUS')             AS plus_count,
      count(*) FILTER (WHERE certification_level = 'CERTIFIED')                  AS certified_count,
      count(*) FILTER (WHERE certification_level = 'NOT_CERTIFIED')              AS not_certified_count,
      count(*) FILTER (WHERE certification_decision = 'CERTIFIED')               AS decision_certified,
      count(*) FILTER (WHERE certification_decision = 'NOT_CERTIFIED')           AS decision_not_certified,
      avg(score)                                                                  AS avg_score,
      min(score)                                                                  AS min_score,
      max(score)                                                                  AS max_score,
      min(generated_at)                                                           AS first_certification,
      max(generated_at)                                                           AS last_certification,
      pg_size_pretty(pg_total_relation_size('certifications'))                   AS table_size
    FROM certifications
  `, [], 'certification_aggregate_stats');

  const r = res.rows[0] ?? {};
  return {
    total:              Number(r.total              ?? 0),
    premiumCount:       Number(r.premium_count      ?? 0),
    plusCount:          Number(r.plus_count         ?? 0),
    certifiedCount:     Number(r.certified_count    ?? 0),
    notCertifiedCount:  Number(r.not_certified_count ?? 0),
    decisionCertified:  Number(r.decision_certified  ?? 0),
    decisionNotCertified: Number(r.decision_not_certified ?? 0),
    avgScore:           r.avg_score != null ? Number(Number(r.avg_score).toFixed(1)) : null,
    minScore:           r.min_score != null ? Number(r.min_score) : null,
    maxScore:           r.max_score != null ? Number(r.max_score) : null,
    firstCertification: r.first_certification ?? null,
    lastCertification:  r.last_certification  ?? null,
    tableSize:          r.table_size          ?? null,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  recordCertification,
  getByCertificationId,
  listCertifications,
  aggregateStats,
};
