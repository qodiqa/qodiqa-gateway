'use strict';

/**
 * QODIQA Policy Provenance Store — Component #20
 *
 * PostgreSQL persistence layer for the policy provenance ledger.
 *
 * WRITE PATH:  recordVersion(record)
 *   Called fire-and-forget after every successful policy mutation.
 *   Looks up the previous version's hash to build the chain, then INSERTs.
 *   Never throws; database failures are absorbed so they cannot disrupt
 *   the policy management operation that triggered them.
 *
 * READ PATH:   getHistory(), getVersion(), getVersionAtTimestamp(),
 *              getTimeline(), compareVersions(), searchHistory(),
 *              getLineage(), verifyIntegrity(), generateReportData()
 *
 * All reads return empty results (null / [] / 0) when PG is not enabled.
 * This preserves backwards compatibility with file-only deployments.
 *
 * Immutability contract:
 *   Only INSERT statements are issued against policy_provenance_versions.
 *   No UPDATE or DELETE is ever executed by this module.
 */

const pgPool    = require('../../infra/postgres/pool');
const provenance = require('./provenance');
const metrics   = require('../../observability/metrics');
const { emit }  = require('../../../services/logger');

// ── Write path ────────────────────────────────────────────────────────────────

/**
 * Persist a provenance record to the database.
 *
 * Designed to be called fire-and-forget (.catch(() => {})) so it cannot
 * disrupt the policy mutation that triggered it.  Any database error is
 * logged and absorbed.
 *
 * When PG is not enabled, this is a silent no-op.
 *
 * @param {object} record — assembled by provenance.buildProvenanceRecord()
 */
async function recordVersion(record) {
  if (!pgPool.isEnabled()) return;

  const {
    policyId,
    versionNumber,
    parentVersion,
    rootVersion,
    eventType,
    occurredAt,
    actorId,
    actorUsername,
    actorRole,
    sourceIp,
    changeReason,
    changeNotes,
    policyContent,
    policyHash,
    previousPolicyHash,
    diffStructured,
    diffHumanReadable,
    rolledBackToVersion,
  } = record;

  // Resolve the previous version's hash from the database if the caller did
  // not provide one.  This is the authoritative chain link.
  let resolvedPrevHash = previousPolicyHash || null;
  if (!resolvedPrevHash && versionNumber > 1) {
    try {
      const res = await pgPool.query(
        `SELECT policy_hash
           FROM policy_provenance_versions
          WHERE policy_id = $1 AND version_number = $2
          LIMIT 1`,
        [policyId, versionNumber - 1],
        'provenance_lookup_prev_hash',
      );
      resolvedPrevHash = res.rows[0]?.policy_hash ?? null;
    } catch (lookupErr) {
      emit('WARN', 'PROVENANCE_PREV_HASH_LOOKUP_FAILED', {
        policyId,
        versionNumber,
        error: lookupErr.message,
      });
      // Proceed without chain link; integrity validation will detect this.
    }
  }

  try {
    await pgPool.query(`
      INSERT INTO policy_provenance_versions (
        policy_id, version_number, parent_version, root_version,
        event_type, occurred_at,
        actor_id, actor_username, actor_role, source_ip,
        change_reason, change_notes,
        policy_content, policy_hash, previous_policy_hash,
        diff_structured, diff_human_readable,
        rolled_back_to_version
      ) VALUES (
        $1,  $2,  $3,  $4,
        $5,  $6,
        $7,  $8,  $9,  $10,
        $11, $12,
        $13, $14, $15,
        $16, $17,
        $18
      )
      ON CONFLICT (policy_id, version_number) DO NOTHING
    `, [
      policyId, versionNumber, parentVersion ?? null, rootVersion ?? 1,
      eventType, occurredAt instanceof Date ? occurredAt : new Date(occurredAt),
      actorId, actorUsername, actorRole, sourceIp,
      changeReason, changeNotes || '',
      JSON.stringify(policyContent), policyHash, resolvedPrevHash,
      JSON.stringify(diffStructured || []), diffHumanReadable || '',
      rolledBackToVersion ?? null,
    ], 'provenance_insert_version');

    metrics.provenanceVersionsTotal.inc({ event_type: eventType });
    if (eventType === 'POLICY_ROLLED_BACK') {
      metrics.provenanceRollbacksTotal.inc({});
    } else if (eventType !== 'POLICY_CREATED' && eventType !== 'POLICY_IMPORTED') {
      metrics.provenanceModificationsTotal.inc({ event_type: eventType });
    }

    emit('INFO', 'PROVENANCE_VERSION_RECORDED', {
      policyId,
      versionNumber,
      eventType,
      actorId,
      actorUsername,
      policyHash,
    });
  } catch (err) {
    emit('ERROR', 'PROVENANCE_RECORD_FAILED', {
      policyId,
      versionNumber,
      error: err.message,
    });
    // Absorbed — never propagated to caller.
  }
}

// ── Read path ─────────────────────────────────────────────────────────────────

/**
 * Paginated history of all versions for a policy.
 * Sorted newest-first by default (sortOrder: 'desc').
 *
 * @param {string} policyId
 * @param {object} [opts]
 * @param {number} [opts.page=1]
 * @param {number} [opts.pageSize=50]
 * @param {'asc'|'desc'} [opts.sortOrder='desc']
 * @param {string} [opts.startTime]  — ISO timestamp
 * @param {string} [opts.endTime]    — ISO timestamp
 * @param {string} [opts.actorId]
 * @param {string} [opts.eventType]
 * @returns {Promise<{ versions: object[], total: number, page: number, pageSize: number }>}
 */
async function getHistory(policyId, {
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
  startTime,
  endTime,
  actorId,
  eventType,
} = {}) {
  if (!pgPool.isEnabled()) return { versions: [], total: 0, page, pageSize };

  const clauses = ['policy_id = $1'];
  const params  = [policyId];
  let   p       = 2;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (startTime) add('occurred_at >= ?', new Date(startTime));
  if (endTime)   add('occurred_at <= ?', new Date(endTime));
  if (actorId)   add('actor_id = ?',     actorId);
  if (eventType) add('event_type = ?',   eventType);

  const where  = 'WHERE ' + clauses.join(' AND ');
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(Math.max(1, pageSize), 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, policy_id, version_number, parent_version, root_version,
        event_type, occurred_at,
        actor_id, actor_username, actor_role, source_ip,
        change_reason, change_notes,
        policy_hash, previous_policy_hash,
        diff_structured, diff_human_readable,
        rolled_back_to_version
      FROM policy_provenance_versions
      ${where}
      ORDER BY occurred_at ${dir}, version_number ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'provenance_history'),

    pgPool.query(
      `SELECT count(*) AS total FROM policy_provenance_versions ${where}`,
      params,
      'provenance_history_count',
    ),
  ]);

  return {
    versions: dataRes.rows,
    total:    Number(cntRes.rows[0]?.total ?? 0),
    page:     pg,
    pageSize: ps,
  };
}

/**
 * Fetch a single specific version of a policy.
 * Returns the full record including policy_content.
 *
 * @param {string} policyId
 * @param {number} versionNumber
 * @returns {Promise<object|null>}
 */
async function getVersion(policyId, versionNumber) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT *
    FROM policy_provenance_versions
    WHERE policy_id = $1 AND version_number = $2
    LIMIT 1
  `, [policyId, versionNumber], 'provenance_get_version');

  return res.rows[0] ?? null;
}

/**
 * Reconstruct the policy state at a given point in time.
 * Returns the provenance version record whose occurred_at is closest to
 * (and not after) the requested timestamp.
 *
 * @param {string}      policyId
 * @param {string|Date} timestamp — ISO string or Date
 * @returns {Promise<object|null>}
 */
async function getVersionAtTimestamp(policyId, timestamp) {
  if (!pgPool.isEnabled()) return null;

  const ts = timestamp instanceof Date ? timestamp : new Date(timestamp);
  if (isNaN(ts.valueOf())) return null;

  const res = await pgPool.query(`
    SELECT *
    FROM policy_provenance_versions
    WHERE policy_id = $1 AND occurred_at <= $2
    ORDER BY occurred_at DESC, version_number DESC
    LIMIT 1
  `, [policyId, ts], 'provenance_at_timestamp');

  return res.rows[0] ?? null;
}

/**
 * Chronological change timeline for a policy.
 * Lightweight view (no policy_content / diff fields) for timeline display.
 *
 * @param {string} policyId
 * @param {object} [opts]
 * @param {string} [opts.startTime]
 * @param {string} [opts.endTime]
 * @returns {Promise<object[]>}
 */
async function getTimeline(policyId, { startTime, endTime } = {}) {
  if (!pgPool.isEnabled()) return [];

  const clauses = ['policy_id = $1'];
  const params  = [policyId];
  let   p       = 2;

  if (startTime) { clauses.push(`occurred_at >= $${p++}`); params.push(new Date(startTime)); }
  if (endTime)   { clauses.push(`occurred_at <= $${p++}`); params.push(new Date(endTime)); }

  const res = await pgPool.query(`
    SELECT
      version_number, parent_version, event_type, occurred_at,
      actor_id, actor_username, actor_role, source_ip,
      change_reason, change_notes,
      policy_hash, previous_policy_hash,
      diff_human_readable, rolled_back_to_version
    FROM policy_provenance_versions
    WHERE ${clauses.join(' AND ')}
    ORDER BY occurred_at ASC, version_number ASC
  `, params, 'provenance_timeline');

  return res.rows;
}

/**
 * Compare two specific versions of a policy.
 * Returns both snapshots, the structured diff, and metadata for each version.
 *
 * @param {string} policyId
 * @param {number} versionA
 * @param {number} versionB
 * @returns {Promise<object|null>} null when either version is not found
 */
async function compareVersions(policyId, versionA, versionB) {
  if (!pgPool.isEnabled()) return null;

  const [resA, resB] = await Promise.all([
    getVersion(policyId, versionA),
    getVersion(policyId, versionB),
  ]);

  if (!resA || !resB) return null;

  const diff = provenance.generateStructuredDiff(
    resA.policy_content,
    resB.policy_content,
  );
  const diffHuman = provenance.generateHumanReadableDiff(diff);

  return {
    policyId,
    versionA: {
      versionNumber:  resA.version_number,
      occurredAt:     resA.occurred_at,
      actorUsername:  resA.actor_username,
      actorRole:      resA.actor_role,
      eventType:      resA.event_type,
      changeReason:   resA.change_reason,
      policyHash:     resA.policy_hash,
      snapshot:       resA.policy_content,
    },
    versionB: {
      versionNumber:  resB.version_number,
      occurredAt:     resB.occurred_at,
      actorUsername:  resB.actor_username,
      actorRole:      resB.actor_role,
      eventType:      resB.event_type,
      changeReason:   resB.change_reason,
      policyHash:     resB.policy_hash,
      snapshot:       resB.policy_content,
    },
    diff: {
      structured:     diff,
      humanReadable:  diffHuman,
    },
  };
}

/**
 * Cross-policy history search with full filtering, pagination, and sorting.
 *
 * @param {object} [opts]
 * @param {string} [opts.policyId]
 * @param {string} [opts.actorId]
 * @param {string} [opts.actorUsername]
 * @param {string} [opts.eventType]
 * @param {string} [opts.sourceIp]
 * @param {string} [opts.changeReason]   — substring search
 * @param {string} [opts.startTime]
 * @param {string} [opts.endTime]
 * @param {number} [opts.page=1]
 * @param {number} [opts.pageSize=50]
 * @param {'asc'|'desc'} [opts.sortOrder='desc']
 * @returns {Promise<{ versions: object[], total: number, page: number, pageSize: number }>}
 */
async function searchHistory({
  policyId,
  actorId,
  actorUsername,
  eventType,
  sourceIp,
  changeReason,
  startTime,
  endTime,
  page      = 1,
  pageSize  = 50,
  sortOrder = 'desc',
} = {}) {
  if (!pgPool.isEnabled()) return { versions: [], total: 0, page, pageSize };

  const clauses = [];
  const params  = [];
  let   p       = 1;

  const add = (clause, value) => {
    clauses.push(clause.replace('?', `$${p++}`));
    params.push(value);
  };

  if (policyId)    add('policy_id = ?',              policyId);
  if (actorId)     add('actor_id = ?',               actorId);
  if (actorUsername) add('actor_username ILIKE ?',   `%${actorUsername}%`);
  if (eventType)   add('event_type = ?',             eventType);
  if (sourceIp)    add('source_ip = ?',              sourceIp);
  if (changeReason) add('change_reason ILIKE ?',     `%${changeReason}%`);
  if (startTime)   add('occurred_at >= ?',           new Date(startTime));
  if (endTime)     add('occurred_at <= ?',           new Date(endTime));

  const where  = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const dir    = sortOrder === 'asc' ? 'ASC' : 'DESC';
  const pg     = Math.max(1, page);
  const ps     = Math.min(Math.max(1, pageSize), 500);
  const offset = (pg - 1) * ps;

  const [dataRes, cntRes] = await Promise.all([
    pgPool.query(`
      SELECT
        id, policy_id, version_number, parent_version,
        event_type, occurred_at,
        actor_id, actor_username, actor_role, source_ip,
        change_reason, change_notes,
        policy_hash, previous_policy_hash,
        diff_human_readable, rolled_back_to_version
      FROM policy_provenance_versions
      ${where}
      ORDER BY occurred_at ${dir}, id ${dir}
      LIMIT $${p++} OFFSET $${p++}
    `, [...params, ps, offset], 'provenance_search'),

    pgPool.query(
      `SELECT count(*) AS total FROM policy_provenance_versions ${where}`,
      params,
      'provenance_search_count',
    ),
  ]);

  return {
    versions: dataRes.rows,
    total:    Number(cntRes.rows[0]?.total ?? 0),
    page:     pg,
    pageSize: ps,
  };
}

/**
 * Return the complete version lineage for a policy: root, all ancestors, current.
 * Ordered by version_number ASC so the chain can be traversed in order.
 *
 * @param {string} policyId
 * @returns {Promise<{ policyId: string, rootVersion: number, currentVersion: number, lineage: object[] }|null>}
 */
async function getLineage(policyId) {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT
      version_number, parent_version, root_version,
      event_type, occurred_at,
      actor_id, actor_username, actor_role,
      change_reason,
      policy_hash, previous_policy_hash,
      rolled_back_to_version
    FROM policy_provenance_versions
    WHERE policy_id = $1
    ORDER BY version_number ASC
  `, [policyId], 'provenance_lineage');

  if (res.rows.length === 0) return null;

  const versions   = res.rows;
  const rootVersion    = versions[0].version_number;
  const currentVersion = versions[versions.length - 1].version_number;

  return {
    policyId,
    rootVersion,
    currentVersion,
    totalVersions: versions.length,
    lineage: versions,
  };
}

/**
 * Run hash-chain integrity verification for a policy and persist the result.
 *
 * Fetches all versions ordered ASC, recomputes hashes, verifies the chain,
 * persists the run result to policy_provenance_integrity_runs, and returns
 * the result.
 *
 * @param {string} policyId
 * @param {string} [checkedBy='system']
 * @returns {Promise<{ valid: boolean, checkedCount: number, failureVersion: number|null, failureDetail: string|null }>}
 */
async function verifyIntegrity(policyId, checkedBy) {
  if (!pgPool.isEnabled()) {
    return { valid: true, checkedCount: 0, failureVersion: null, failureDetail: 'PG not enabled' };
  }

  const res = await pgPool.query(`
    SELECT version_number, policy_hash, previous_policy_hash, policy_content
    FROM policy_provenance_versions
    WHERE policy_id = $1
    ORDER BY version_number ASC
  `, [policyId], 'provenance_integrity_fetch');

  const result = provenance.verifyChainIntegrity(res.rows);

  if (!result.valid) {
    metrics.provenanceIntegrityFailuresTotal.inc({ policy_id: policyId });
    emit('ERROR', 'PROVENANCE_CHAIN_INTEGRITY_FAILURE', {
      policyId,
      failureVersion: result.failureVersion,
      failureDetail:  result.failureDetail,
    });
  }

  // Persist the run record (fire-and-forget)
  pgPool.query(`
    INSERT INTO policy_provenance_integrity_runs
      (policy_id, versions_checked, chain_valid, failure_version, failure_detail, checked_by)
    VALUES ($1, $2, $3, $4, $5, $6)
  `, [
    policyId,
    result.checkedCount,
    result.valid,
    result.failureVersion ?? null,
    result.failureDetail  ?? null,
    checkedBy             || 'system',
  ], 'provenance_integrity_run_insert').catch(e => {
    emit('WARN', 'PROVENANCE_INTEGRITY_RUN_PERSIST_FAILED', { policyId, error: e.message });
  });

  return result;
}

/**
 * Assemble report data for a policy.
 * Fetches complete history and delegates to provenance.assembleReport().
 *
 * @param {string} policyId
 * @param {object} [opts]
 * @param {string} [opts.startTime]
 * @param {string} [opts.endTime]
 * @param {string} [opts.requestedBy]
 * @returns {Promise<object|null>}
 */
async function generateReportData(policyId, opts) {
  if (!pgPool.isEnabled()) return null;

  const { startTime, endTime, requestedBy } = opts || {};

  const { versions } = await getHistory(policyId, {
    page:      1,
    pageSize:  10000,
    sortOrder: 'asc',
    startTime,
    endTime,
  });

  return provenance.assembleReport(policyId, versions, {
    requestedBy: requestedBy || 'system',
    generatedAt: new Date(),
  });
}

/**
 * Aggregate metrics across all policy provenance records.
 * Used for the monitoring dashboard.
 *
 * @returns {Promise<object|null>}
 */
async function aggregateStats() {
  if (!pgPool.isEnabled()) return null;

  const res = await pgPool.query(`
    SELECT
      count(*)                                                          AS total_versions,
      count(DISTINCT policy_id)                                         AS total_policies,
      count(DISTINCT actor_id)                                          AS total_actors,
      count(*) FILTER (WHERE event_type = 'POLICY_ROLLED_BACK')        AS total_rollbacks,
      count(*) FILTER (WHERE event_type = 'POLICY_CREATED')            AS total_creations,
      count(*) FILTER (WHERE event_type = 'POLICY_UPDATED')            AS total_updates,
      count(*) FILTER (WHERE event_type IN ('POLICY_ENABLED','POLICY_DISABLED')) AS total_toggles,
      min(occurred_at)                                                  AS first_event,
      max(occurred_at)                                                  AS last_event
    FROM policy_provenance_versions
  `, [], 'provenance_aggregate_stats');

  const intRes = await pgPool.query(`
    SELECT count(*) AS total_failures
    FROM policy_provenance_integrity_runs
    WHERE chain_valid = FALSE
  `, [], 'provenance_integrity_failure_count');

  const r  = res.rows[0]     ?? {};
  const ir = intRes.rows[0]  ?? {};

  return {
    totalVersions:    Number(r.total_versions   ?? 0),
    totalPolicies:    Number(r.total_policies   ?? 0),
    totalActors:      Number(r.total_actors     ?? 0),
    totalRollbacks:   Number(r.total_rollbacks  ?? 0),
    totalCreations:   Number(r.total_creations  ?? 0),
    totalUpdates:     Number(r.total_updates    ?? 0),
    totalToggles:     Number(r.total_toggles    ?? 0),
    integrityFailures: Number(ir.total_failures ?? 0),
    firstEvent:       r.first_event ?? null,
    lastEvent:        r.last_event  ?? null,
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  recordVersion,
  getHistory,
  getVersion,
  getVersionAtTimestamp,
  getTimeline,
  compareVersions,
  searchHistory,
  getLineage,
  verifyIntegrity,
  generateReportData,
  aggregateStats,
};
