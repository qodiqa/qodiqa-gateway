'use strict';

/**
 * ChangeRequestStore — PostgreSQL persistence for policy_change_requests
 *.
 *
 * Same fail-closed style as src/core/dsr/DSRStore.js / ConsentStore.js.
 *
 * updateStatus() is optimistic-locked (WHERE id=$1 AND version=$2, bumped
 * by the policy_change_requests_updated_at trigger — migration 029) —
 * closes the "two checkers approve the same stale proposal" race that
 * existed nowhere else in the codebase's file-based policy store.
 */

const pool = require('../../../infra/postgres/pool');
const rolePools = require('../../../infra/postgres/rolePools'); // operator by-id fallback runs as qodiqa_reporting
const { emit } = require('../../../../services/logger');

class ConcurrentModificationError extends Error {
  constructor(id) {
    super(`Change request ${id} was modified concurrently by another actor — reload and retry`);
    this.name = 'ConcurrentModificationError';
    this.code = 'CONCURRENT_MODIFICATION';
  }
}

const PATCHABLE_FIELDS = Object.freeze([
  'submitted_by', 'submitted_at',
  'reviewer_id', 'reviewer_username', 'reviewed_at', 'review_decision',
  'approver_id', 'approver_username', 'approved_at',
  'publisher_id', 'publisher_username', 'published_at', 'resulting_policy_version',
  'scheduled_for',
  'rejected_by', 'rejected_at', 'rejection_reason',
  'withdrawn_by', 'withdrawn_at',
  'error',
]);

/**
 * @returns {Promise<object>} created change request row
 */
async function create({ policy_id, tenant_id = null, request_type, payload, payload_hash = null, change_reason, author }) {
  if (!policy_id || !request_type || !change_reason) {
    throw new Error('policy_id, request_type, and change_reason are required');
  }
  if (!author || !author.id || !author.username || !author.role) {
    throw new Error('author (id, username, role) is required');
  }

  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn)
    : (fn) => pool.withTransaction(fn);

  return runInTransaction(async (tx) => {
    const result = await tx.query(
      `INSERT INTO policy_change_requests
         (policy_id, tenant_id, request_type, payload, payload_hash, change_reason,
          author_id, author_username, author_role)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        policy_id, tenant_id, request_type, JSON.stringify(payload ?? {}), payload_hash, change_reason,
        author.id, author.username, author.role,
      ],
    );
    const record = result.rows[0];

    emit('INFO', 'POLICY_CHANGE_REQUEST_CREATED', {
      changeRequestId: record.id, policyId: policy_id, requestType: request_type, actorId: author.id,
    });

    return record;
  });
}

/**
 * @returns {Promise<object|null>}
 */
async function findById(id) {
  const result = await pool.query('SELECT * FROM policy_change_requests WHERE id = $1', [id], 'pcr_find_by_id');
  if (result.rows[0]) return result.rows[0];
  // a TENANT-scoped request row is hidden from this contextless
  // read by migration 029's RLS (nullable model), and the caller cannot set
  // a tenant context it does not know yet. The lifecycle is an operator
  // surface acting across tenants, so the by-id lookup falls back to the
  // narrow SECURITY DEFINER read (migration 051 — the idiom).
  // Platform rows always resolve on the plain read above, byte-identical
  // to the earlier behaviour.
  const definer = await rolePools.reporting.query('SELECT * FROM qodiqa_policy_change_request_by_id($1)', [id], 'pcr_find_by_id_any_tenant');
  return definer.rows[0] ?? null;
}

/**
 * a caller-supplied `tenantId` filter used to be silently RLS-blind —
 * migration 029's nullable-tenant model (`tenant_id IS NULL OR tenant_id =
 * qodiqa_current_tenant()`) hides every tenant-scoped row from a plain,
 * contextless read, so `list({ tenantId: 'x' })` always returned an empty
 * page even when tenant x had real governance history (indistinguishable
 * from "this tenant has none" — worse than no capability at all). Fixed by
 * running the SAME query under that tenant's own transaction-local context
 * (pool.withTenantTransaction — the exact mechanism every other
 * tenant-scoped read in this codebase already uses, e.g. tenantConfigStore.
 * getPolicySet()) rather than a new SECURITY DEFINER bypass: the existing
 * `tenant_id = $N` filter already narrows the result to exactly that
 * tenant's own rows, so setting that tenant's context only ever unlocks
 * rows the WHERE clause was already asking for — no other tenant's data
 * becomes reachable. The no-tenantId path (platform-wide listing) is
 * completely unchanged — still a plain, contextless read, still scoped by
 * RLS to `tenant_id IS NULL` rows only, same as before this fix.
 * @returns {Promise<{requests: object[], total: number}>}
 */
async function list({ policyId, tenantId, status, requestType, authorId, limit = 50, offset = 0 } = {}) {
  const conditions = [];
  const params     = [];

  if (policyId)    { params.push(policyId);    conditions.push(`policy_id = $${params.length}`); }
  if (tenantId)    { params.push(tenantId);    conditions.push(`tenant_id = $${params.length}`); }
  if (status)      { params.push(status);      conditions.push(`status = $${params.length}`); }
  if (requestType) { params.push(requestType); conditions.push(`request_type = $${params.length}`); }
  if (authorId)    { params.push(authorId);    conditions.push(`author_id = $${params.length}`); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  params.push(Math.min(limit, 200));
  const limitParam = params.length;
  params.push(Math.max(offset, 0));
  const offsetParam = params.length;

  const dataSql    = `SELECT * FROM policy_change_requests ${where} ORDER BY created_at DESC, id DESC LIMIT $${limitParam} OFFSET $${offsetParam}`;
  const countSql   = `SELECT count(*) AS total FROM policy_change_requests ${where}`;
  const countParams = params.slice(0, conditions.length);

  let dataResult, countResult;
  if (tenantId) {
    [dataResult, countResult] = await pool.withTenantTransaction(tenantId, async (tx) => Promise.all([
      tx.query(dataSql, params),
      tx.query(countSql, countParams),
    ]));
  } else {
    [dataResult, countResult] = await Promise.all([
      pool.query(dataSql, params, 'pcr_list'),
      pool.query(countSql, countParams, 'pcr_count'),
    ]);
  }

  return {
    requests: dataResult.rows,
    total:    Number(countResult.rows[0]?.total ?? 0),
  };
}

/**
 * Optimistic-locked status transition, composable within a caller-owned
 * transaction. This is the core logic — used directly by
 * PolicyGovernanceService so a status hop and its evidence writes
 * (governanceEvents.recordEvent, policy_reviews/policy_approvals rows,
 * etc.) commit atomically in one transaction ("no partial approvals",
 *). See updateStatus() below for a standalone, self-transacting
 * wrapper for simpler callers that don't need to compose additional writes.
 *
 * @param {object} tx
 * @param {object} opts
 * @param {string} opts.id
 * @param {number} opts.expectedVersion — the `version` the caller last read
 * @param {string} opts.status          — new status
 * @param {object} [opts.patch]         — allow-listed evidence fields to set alongside the status
 * @returns {Promise<object>} updated row
 * @throws {ConcurrentModificationError} if the row's version no longer matches
 */
async function updateStatusInTx(tx, { id, expectedVersion, status, patch = {} }) {
  if (!id || expectedVersion == null || !status) {
    throw new Error('id, expectedVersion, and status are required');
  }

  const setClauses = ['status = $1'];
  const params      = [status];
  let p = 2;

  for (const [key, value] of Object.entries(patch)) {
    if (!PATCHABLE_FIELDS.includes(key)) continue;
    setClauses.push(`${key} = $${p}`);
    params.push(value);
    p += 1;
  }

  params.push(id, expectedVersion);
  const idParam      = p;
  const versionParam = p + 1;

  const result = await tx.query(
    `UPDATE policy_change_requests SET ${setClauses.join(', ')}
      WHERE id = $${idParam} AND version = $${versionParam}
      RETURNING *`,
    params,
  );

  if (result.rows.length) return result.rows[0];

  const existing = await tx.query('SELECT id FROM policy_change_requests WHERE id = $1', [id]);
  if (!existing.rows.length) {
    const err = new Error(`Change request not found: ${id}`);
    err.code  = 'NOT_FOUND';
    throw err;
  }
  throw new ConcurrentModificationError(id);
}

/**
 * Standalone, self-transacting wrapper around updateStatusInTx() for
 * callers that only need the status hop itself (no additional evidence
 * writes to compose atomically alongside it).
 *
 * @returns {Promise<object>} updated row
 */
async function updateStatus(opts) {
  return pool.withTransaction((tx) => updateStatusInTx(tx, opts));
}

module.exports = { create, findById, list, updateStatus, updateStatusInTx, ConcurrentModificationError };
