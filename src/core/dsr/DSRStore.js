'use strict';

/**
 * DSRStore — PostgreSQL persistence for GDPR Data Subject Rights requests.
 *
 * Same fail-closed style as src/core/consent/ConsentStore.js: if PostgreSQL
 * is unavailable, methods throw rather than silently succeed.
 *
 * dsr_requests is mutable in place (status/result progress) but never
 * deleted — the request record is itself permanent DSR evidence.
 * dsr_request_events is append-only — see migration 028_dsr_framework.sql.
 */

const crypto = require('crypto');
const pool   = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');

const PATCHABLE_FIELDS = Object.freeze([
  'identity_verification_method', 'identity_verification_result', 'identity_verification_evidence',
  'identity_verified_by', 'identity_verified_at',
  'approved_by', 'approved_at', 'completed_at',
  'result', 'export_checksum', 'error',
]);

// the lifecycle is enforced here, in the one place
// every status change goes through, not in each caller. any status
// could follow any other — a COMPLETED or FAILED request could be re-approved
// and re-executed. Allowed transitions (from → to):
const TRANSITIONS = Object.freeze({
  RECEIVED:          ['IDENTITY_VERIFIED', 'REJECTED'],
  IDENTITY_VERIFIED: ['APPROVED', 'REJECTED'],
  APPROVED:          ['IN_PROGRESS', 'FAILED'],
  IN_PROGRESS:       ['COMPLETED', 'FAILED'],
  FAILED:            [],   // + IN_PROGRESS for ERASURE: a resumable run (D5), never a re-approval
  COMPLETED:         [],   // + COMPLETED for RESTRICTION: lifting an Article 18 restriction
  REJECTED:          [],
});

function isAllowedTransition(from, to, requestType) {
  if ((TRANSITIONS[from] || []).includes(to)) return true;
  if (from === 'FAILED' && to === 'IN_PROGRESS' && requestType === 'ERASURE') return true;
  if (from === 'COMPLETED' && to === 'COMPLETED' && requestType === 'RESTRICTION') return true;
  return false;
}

class DSRTransitionError extends Error {
  constructor(id, from, to, requestType) {
    super(`DSR request ${id}: status transition ${from} → ${to} is not allowed for a ${requestType} request`);
    this.name = 'DSRTransitionError';
    this.code = 'DSR_INVALID_TRANSITION';
    this.statusCode = 409;
  }
}

// ── Audit helper ──────────────────────────────────────────────────────────────

/** dsr_request_events checksum — the one formula. */
function _eventChecksum({ request_id, event_type, actor, detail }) {
  const detailJson = JSON.stringify(detail ?? {});
  return { detailJson, checksum: crypto.createHash('sha256').update(`${request_id}|${event_type}|${actor}|${detailJson}`).digest('hex') };
}

async function _appendEvent(tx, { request_id, tenant_id, event_type, actor, detail }) {
  const { detailJson, checksum } = _eventChecksum({ request_id, event_type, actor, detail });

  await tx.query(
    `INSERT INTO dsr_request_events (request_id, tenant_id, event_type, actor, detail, checksum)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [request_id, tenant_id ?? null, event_type, actor, detailJson, checksum],
  );
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Create a new DSR request in RECEIVED status. Emits DSR_REQUEST_RECEIVED.
 *
 * @returns {Promise<object>} created request row
 */
async function createRequest({
  request_type, actor_id, tenant_id = null, requested_by,
  legal_basis = null, justification = null,
}) {
  if (!request_type || !actor_id || !requested_by) {
    throw new Error('request_type, actor_id, and requested_by are required');
  }

  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn)
    : (fn) => pool.withTransaction(fn);

  return runInTransaction(async (tx) => {
    const result = await tx.query(
      `INSERT INTO dsr_requests (request_type, actor_id, tenant_id, requested_by, legal_basis, justification)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [request_type, actor_id, tenant_id, requested_by, legal_basis, justification],
    );
    const request = result.rows[0];

    await _appendEvent(tx, {
      request_id: request.id,
      tenant_id,
      event_type: 'DSR_REQUEST_RECEIVED',
      actor:      requested_by,
      detail:     { requestType: request_type, actorId: actor_id },
    });

    emit('INFO', 'DSR_REQUEST_CREATED', {
      requestId: request.id, requestType: request_type, actorId: actor_id, tenantId: tenant_id,
    });

    return request;
  });
}

/**
 * accepts an optional tenant_id so a tenant-scoped request's row
 * is actually visible. Without it (existing callers, unchanged), this stays
 * scoped to platform-level (tenant_id IS NULL) rows only, exactly as before —
 * this is additive, not a widening of any existing caller's visibility.
 *
 * @returns {Promise<object|null>}
 */
async function findById(id, tenant_id = null) {
  const result = tenant_id
    ? await pool.withTenantTransaction(tenant_id, (tx) => tx.query('SELECT * FROM dsr_requests WHERE id = $1', [id]))
    : await pool.query('SELECT * FROM dsr_requests WHERE id = $1', [id], 'dsr_find_by_id');
  return result.rows[0] ?? null;
}

/**
 * List DSR requests with optional filters.
 *
 * when `tenant_id` is supplied, the query now actually runs
 * inside `withTenantTransaction` so RLS unlocks the matching tenant's rows —
 * previously `tenant_id` was applied only as an app-level WHERE filter, which
 * combined with unset RLS context to always return zero rows for a real
 * tenant. The WHERE clause is left in place deliberately: it already matches
 * exactly what RLS now also enforces, so this is redundant-safe, not a
 * second, different filter.
 *
 * @param {{ actor_id?: string, tenant_id?: string, status?: string, request_type?: string, limit?: number, offset?: number }} [opts]
 * @returns {Promise<{requests: object[], total: number}>}
 */
async function list({ actor_id, tenant_id, status, request_type, limit = 50, offset = 0 } = {}) {
  const conditions = [];
  const params     = [];

  if (actor_id)     { params.push(actor_id);     conditions.push(`actor_id = $${params.length}`); }
  if (tenant_id)     { params.push(tenant_id);     conditions.push(`tenant_id = $${params.length}`); }
  if (status)       { params.push(status);       conditions.push(`status = $${params.length}`); }
  if (request_type) { params.push(request_type); conditions.push(`request_type = $${params.length}`); }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  params.push(Math.min(limit, 200));
  const limitParam = params.length;
  params.push(Math.max(offset, 0));
  const offsetParam = params.length;

  // A transaction is bound to ONE connection — its 2 queries must run
  // sequentially (concurrent queries on one client are unsafe/deprecated in
  // node-postgres). The no-tenant-context branch still draws each query from
  // the POOL independently, so those 2 stay parallelized as before this fix.
  const dataSql  = `SELECT * FROM dsr_requests ${where} ORDER BY requested_at DESC, id DESC LIMIT $${limitParam} OFFSET $${offsetParam}`;
  const countSql = `SELECT count(*) AS total FROM dsr_requests ${where}`;
  const countParams = params.slice(0, conditions.length);

  const [dataResult, countResult] = tenant_id
    ? await pool.withTenantTransaction(tenant_id, async (tx) => {
        const data = await tx.query(dataSql, params);
        const count = await tx.query(countSql, countParams);
        return [data, count];
      })
    : await Promise.all([
        pool.query(dataSql, params, 'dsr_list'),
        pool.query(countSql, countParams, 'dsr_count'),
      ]);

  return {
    requests: dataResult.rows,
    total:    Number(countResult.rows[0]?.total ?? 0),
  };
}

/**
 * Fetch the lifecycle event trail for a DSR request.
 *
 * accepts an optional tenant_id — see findById's comment.
 *
 * @returns {Promise<object[]>}
 */
async function listEvents({ request_id, tenant_id = null, limit = 100, offset = 0 }) {
  const sql = `SELECT * FROM dsr_request_events WHERE request_id = $1 ORDER BY occurred_at DESC LIMIT $2 OFFSET $3`;
  const params = [request_id, Math.min(limit, 500), Math.max(offset, 0)];
  const result = tenant_id
    ? await pool.withTenantTransaction(tenant_id, (tx) => tx.query(sql, params))
    : await pool.query(sql, params, 'dsr_list_events');
  return result.rows;
}

/**
 * Append a lifecycle event without changing request status
 * (e.g. a validation note that doesn't itself move the state machine).
 */
async function appendEvent({ request_id, tenant_id = null, event_type, actor, detail = {} }) {
  await pool.withTransaction((tx) => _appendEvent(tx, { request_id, tenant_id, event_type, actor, detail }));
}

/**
 * Transition a DSR request's status, optionally patching evidence fields
 * (identity verification result, approval, result summary, export checksum,
 * error) and appending a matching lifecycle event in the same transaction.
 *
 * @returns {Promise<object>} updated request row
 */
async function updateStatus({ id, tenant_id = null, status, patch = {}, actor, eventType, eventDetail = {} }) {
  if (!id || !status) throw new Error('id and status are required');

  const runInTransaction = tenant_id
    ? (fn) => pool.withTenantTransaction(tenant_id, fn)
    : (fn) => pool.withTransaction(fn);

  return runInTransaction(async (tx) => {
    // (D10): lock the row and check the transition before writing.
    const current = await tx.query('SELECT status, request_type FROM dsr_requests WHERE id = $1 FOR UPDATE', [id]);
    if (!current.rows.length) throw new Error(`DSR request not found: ${id}`);
    const { status: from, request_type: requestType } = current.rows[0];
    if (!isAllowedTransition(from, status, requestType)) throw new DSRTransitionError(id, from, status, requestType);

    const setClauses = ['status = $1'];
    const params      = [status];
    let p = 2;

    for (const [key, value] of Object.entries(patch)) {
      if (!PATCHABLE_FIELDS.includes(key)) continue;
      setClauses.push(`${key} = $${p}`);
      params.push(key === 'result' ? JSON.stringify(value) : value);
      p += 1;
    }
    params.push(id);

    const result = await tx.query(
      `UPDATE dsr_requests SET ${setClauses.join(', ')} WHERE id = $${p} RETURNING *`,
      params,
    );
    if (!result.rows.length) throw new Error(`DSR request not found: ${id}`);
    const request = result.rows[0];

    if (eventType) {
      await _appendEvent(tx, {
        request_id: id,
        tenant_id:  request.tenant_id,
        event_type: eventType,
        actor,
        detail:     eventDetail,
      });
    }

    return request;
  });
}

module.exports = {
  createRequest, findById, list, listEvents, appendEvent, updateStatus,
  TRANSITIONS, isAllowedTransition, DSRTransitionError, _eventChecksum,
};
