'use strict';

/**
 * Persistence Recovery Queue — Component #13 (CHAIN-3 remediation)
 *
 * PostgreSQL-backed durable operation queue — the sole authoritative store
 * for pending recovery work. Redis is not read from or written to anywhere
 * in this module. See docs/protocol/AUDIT-SCHEMA-V8.md, "Decision
 * Update: Durable Postgres-Backed Persistence Recovery Queue (CHAIN-3)".
 *
 * TABLE:  persistence_recovery_queue  (migration 032)
 *   status IN ('PENDING', 'DLQ', 'ARCHIVED') — no 'COMPLETE' row; a
 *   successfully processed operation is DELETEd outright.
 *
 * CLAIM SEMANTICS (mirrors the prior Redis Lua CLAIM_SCRIPT exactly):
 *   `UPDATE ... WHERE operation_id = (SELECT ... FOR UPDATE SKIP LOCKED)`
 *   advances eligible_at forward by CLAIM_TIMEOUT_MS in the same statement
 *   that claims the row — no separate "processing" state or lock column.
 *   If a worker crashes mid-processing, eligible_at simply elapses and the
 *   row becomes claimable again (by this or any other worker instance).
 *
 * MULTI-INSTANCE SAFETY:
 *   `FOR UPDATE SKIP LOCKED` makes concurrent claims by multiple worker
 *   processes mutually exclusive — the same idiom already used by
 *   src/core/audit/retention.js — without any Redis-based locking.
 */

const pgPool  = require('../../infra/postgres/pool');
const { emit } = require('../../../services/logger');

const SOURCE = 'PERSISTENCE_RECOVERY_QUEUE';

const CLAIM_TIMEOUT_MS = 30_000;

// ── Query indirection (test hook) ─────────────────────────────────────────────
//
// Production always goes through the shared pgPool singleton (already
// initialized centrally by server.js before recoveryManager.initialize()
// runs). Tests inject a fake query function so unit tests can assert exact
// SQL/params without a live database, mirroring the style already used by
// src/infra/postgres/__tests__/pg-audit-backend.recovery.test.js
// (jest.mock('../pool')) for callers of this module, but as a direct
// injection point here since this module IS the pool consumer under test.

let _queryFn = null;

function _query(sql, params, label) {
  const fn = _queryFn || pgPool.query;
  return fn(sql, params, label);
}

function __setQueryFnForTest(fn) { _queryFn = fn; }

// ── Lifecycle ─────────────────────────────────────────────────────────────────
//
// The Postgres pool is a shared singleton owned and lifecycle-managed by
// src/infra/postgres/pool.js (initialized once at server startup, shut down
// once at graceful shutdown). This module never opens or closes its own
// connection — _connect()/_disconnect() exist only to preserve the calling
// contract recoveryManager.js already has (initialize()/shutdown() call
// them unconditionally) and are no-ops beyond a readiness check.

async function _connect() {
  if (!pgPool.isEnabled()) {
    throw new Error(`${SOURCE}: PostgreSQL is not enabled (QODIQA_PG_ENABLED)`);
  }
}

async function _disconnect() {
  // No dedicated connection to tear down — the shared pgPool outlives this
  // module and is shut down centrally by server.js.
}

function _isReady() {
  return pgPool.isEnabled();
}

// ── Queue operations ──────────────────────────────────────────────────────────

/**
 * Enqueue an operation for immediate pickup (eligible_at = now()).
 * Durably persists the row before returning — this INSERT is the
 * "persist before acknowledging failure" guarantee CHAIN-3 requires.
 *
 * Idempotent under retry: if this exact operationId was already enqueued
 * (e.g. a duplicate enqueue attempt after a caller-side retry), the
 * existing row's payload/metadata is refreshed rather than producing a
 * second row for the same logical operation.
 *
 * @param {object} operation
 * @param {string} operation.operationId
 * @param {string} operation.operationType
 * @param {string} operation.service
 * @param {object} operation.payload
 * @param {string} [operation.createdAt]   ISO timestamp
 * @param {number} [operation.retryCount]
 * @param {string} [operation.lastError]
 * @param {Array}  [operation.errorHistory]
 */
async function enqueue(operation) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  const {
    operationId,
    operationType,
    service,
    payload,
    createdAt    = new Date().toISOString(),
    retryCount   = 0,
    lastError    = null,
    errorHistory = [],
  } = operation;

  await _query(`
    INSERT INTO persistence_recovery_queue (
      operation_id, operation_type, service, payload,
      status, eligible_at, retry_count, last_error, error_history,
      created_at, updated_at
    ) VALUES (
      $1, $2, $3, $4::jsonb,
      'PENDING', NOW(), $5, $6, $7::jsonb,
      $8, NOW()
    )
    ON CONFLICT (operation_id) DO UPDATE SET
      operation_type = EXCLUDED.operation_type,
      service        = EXCLUDED.service,
      payload        = EXCLUDED.payload,
      status         = 'PENDING',
      eligible_at    = NOW(),
      retry_count    = EXCLUDED.retry_count,
      last_error     = EXCLUDED.last_error,
      error_history  = EXCLUDED.error_history,
      updated_at     = NOW()
  `, [
    operationId, operationType, service, JSON.stringify(payload),
    retryCount, lastError, JSON.stringify(errorHistory),
    createdAt,
  ], 'prq_enqueue');

  emit('INFO', 'QUEUE_ENQUEUED', {
    source: SOURCE, operationId, operationType, service, retryCount,
  });
}

/**
 * Reschedule an operation at a specific time (for scheduled retries).
 *
 * @param {string} operationId
 * @param {number} eligibleAtMs  Unix timestamp (ms)
 */
async function _reschedule(operationId, eligibleAtMs) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);
  await _query(
    `UPDATE persistence_recovery_queue SET eligible_at = to_timestamp($2 / 1000.0), updated_at = NOW() WHERE operation_id = $1`,
    [operationId, eligibleAtMs],
    'prq_reschedule',
  );
}

/**
 * Atomically claim one due operation.
 * Returns the operation or null if the queue is empty / no item due yet.
 *
 * @returns {Promise<object|null>}
 */
async function claimNext() {
  if (!_isReady()) return null;

  const result = await _query(`
    UPDATE persistence_recovery_queue
    SET eligible_at = NOW() + ($1 || ' milliseconds')::interval,
        updated_at  = NOW()
    WHERE operation_id = (
      SELECT operation_id FROM persistence_recovery_queue
      WHERE status = 'PENDING' AND eligible_at <= NOW()
      ORDER BY eligible_at ASC
      LIMIT 1
      FOR UPDATE SKIP LOCKED
    )
    RETURNING operation_id, operation_type, service, payload,
              created_at, retry_count, last_error, error_history
  `, [String(CLAIM_TIMEOUT_MS)], 'prq_claim_next');

  const row = result.rows[0];
  if (!row) return null;

  return _rowToOperation(row);
}

function _rowToOperation(row) {
  return {
    operationId:   row.operation_id,
    operationType: row.operation_type,
    service:       row.service,
    payload:       row.payload ?? {},
    createdAt:     row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    retryCount:    Number(row.retry_count ?? 0),
    lastError:     row.last_error || null,
    errorHistory:  row.error_history ?? [],
  };
}

/**
 * Mark an operation as successfully processed — DELETE the row outright.
 *
 * @param {string} operationId
 */
async function markComplete(operationId) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  await _query(
    `DELETE FROM persistence_recovery_queue WHERE operation_id = $1`,
    [operationId],
    'prq_mark_complete',
  );

  emit('INFO', 'QUEUE_RECOVERED', { source: SOURCE, operationId });
}

/**
 * Record a retry attempt — append to error history and reschedule.
 *
 * @param {string} operationId
 * @param {string} errorMessage
 * @param {number} retryCount     New retry count (after this failure)
 * @param {number} eligibleAtMs   When next retry is allowed
 */
async function markRetry(operationId, errorMessage, retryCount, eligibleAtMs) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  const existing = await _query(
    `SELECT error_history FROM persistence_recovery_queue WHERE operation_id = $1`,
    [operationId],
    'prq_mark_retry_read',
  );
  if (!existing.rows[0]) return;

  const errorHistory = existing.rows[0].error_history ?? [];
  errorHistory.push({ error: errorMessage, timestamp: new Date().toISOString(), retryCount });

  await _query(`
    UPDATE persistence_recovery_queue
    SET retry_count   = $2,
        last_error    = $3,
        error_history = $4::jsonb,
        eligible_at   = to_timestamp($5 / 1000.0),
        updated_at    = NOW()
    WHERE operation_id = $1
  `, [operationId, retryCount, errorMessage, JSON.stringify(errorHistory), eligibleAtMs], 'prq_mark_retry');

  emit('WARN', 'QUEUE_RETRY', {
    source:     SOURCE,
    operationId,
    retryCount,
    eligibleAt: new Date(eligibleAtMs).toISOString(),
    error:      errorMessage,
  });
}

/**
 * Move a failed operation to the Dead Letter Queue.
 *
 * @param {string} operationId
 * @param {string} finalError
 * @param {number} retryCount
 */
async function moveToDlq(operationId, finalError, retryCount) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  const now = Date.now();
  const existing = await _query(
    `SELECT operation_type, service, error_history FROM persistence_recovery_queue WHERE operation_id = $1`,
    [operationId],
    'prq_move_to_dlq_read',
  );
  const row = existing.rows[0];

  let errorHistory = row?.error_history ?? [];
  errorHistory = [...errorHistory, { error: finalError, timestamp: new Date(now).toISOString(), retryCount, final: true }];

  await _query(`
    UPDATE persistence_recovery_queue
    SET status        = 'DLQ',
        retry_count   = $2,
        last_error    = $3,
        error_history = $4::jsonb,
        dlq_at        = to_timestamp($5 / 1000.0),
        updated_at    = NOW()
    WHERE operation_id = $1
  `, [operationId, retryCount, finalError, JSON.stringify(errorHistory), now], 'prq_move_to_dlq');

  emit('ERROR', 'QUEUE_DLQ', {
    source:        SOURCE,
    operationId,
    operationType: row?.operation_type,
    service:       row?.service,
    retryCount,
    error:         finalError,
  });
}

/**
 * Return queue depth and DLQ depth for monitoring.
 *
 * @returns {Promise<{ queueDepth: number, dlqDepth: number }>}
 */
async function getStats() {
  if (!_isReady()) return { queueDepth: 0, dlqDepth: 0 };

  const result = await _query(`
    SELECT
      count(*) FILTER (WHERE status = 'PENDING') AS queue_depth,
      count(*) FILTER (WHERE status = 'DLQ')     AS dlq_depth
    FROM persistence_recovery_queue
  `, [], 'prq_get_stats');

  const r = result.rows[0] ?? {};
  return {
    queueDepth: Number(r.queue_depth ?? 0),
    dlqDepth:   Number(r.dlq_depth   ?? 0),
  };
}

/**
 * depth per (operation_type, status) plus the age of the oldest PENDING
 * item, for the queue-depth monitor (queueMonitor.js). Retry items are
 * PENDING rows with retry_count > 0, so they are reported separately.
 *
 * @returns {Promise<Array<{ operationType: string, status: string, depth: number, retrying: number, oldestAgeSeconds: number }>>}
 */
async function getDepthByType() {
  if (!_isReady()) return [];
  const result = await _query(`
    SELECT operation_type, status,
           count(*)                                  AS depth,
           count(*) FILTER (WHERE retry_count > 0)   AS retrying,
           COALESCE(EXTRACT(EPOCH FROM (NOW() - min(created_at))), 0) AS oldest_age_s
    FROM persistence_recovery_queue
    WHERE status IN ('PENDING', 'DLQ')
    GROUP BY operation_type, status
  `, [], 'prq_depth_by_type');
  return result.rows.map((r) => ({
    operationType:    r.operation_type,
    status:           r.status,
    depth:            Number(r.depth ?? 0),
    retrying:         Number(r.retrying ?? 0),
    oldestAgeSeconds: Number(r.oldest_age_s ?? 0),
  }));
}

/**
 * List items in the DLQ for admin visibility.
 *
 * @param {number} [limit=50]
 * @returns {Promise<object[]>}
 */
async function listDlq(limit = 50) {
  if (!_isReady()) return [];

  const result = await _query(`
    SELECT operation_id, operation_type, service, retry_count, last_error, created_at, dlq_at, error_history
    FROM persistence_recovery_queue
    WHERE status = 'DLQ'
    ORDER BY dlq_at ASC
    LIMIT $1
  `, [limit], 'prq_list_dlq');

  return result.rows.map(r => ({
    operationId:   r.operation_id,
    operationType: r.operation_type,
    service:       r.service,
    retryCount:    Number(r.retry_count ?? 0),
    lastError:     r.last_error || null,
    createdAt:     r.created_at,
    dlqAt:         r.dlq_at ?? null,
    errorHistory:  r.error_history ?? [],
  }));
}

// ── DLQ management operations ─────────────────────────────────────────────────

/**
 * Fetch a single DLQ item by operationId (includes payload).
 * Returns null if operationId is not in the DLQ.
 *
 * @param {string} operationId
 * @returns {Promise<object|null>}
 */
async function getDlqItem(operationId) {
  if (!_isReady()) return null;

  const result = await _query(
    `SELECT * FROM persistence_recovery_queue WHERE operation_id = $1 AND status = 'DLQ'`,
    [operationId],
    'prq_get_dlq_item',
  );
  const row = result.rows[0];
  if (!row) return null;

  return _parseRow(row, true);
}

function _parseRow(row, includePayload) {
  const op = {
    operationId:   row.operation_id,
    operationType: row.operation_type,
    service:       row.service,
    retryCount:    Number(row.retry_count  ?? 0),
    replayCount:   Number(row.replay_count ?? 0),
    lastError:     row.last_error  || null,
    createdAt:     row.created_at  || null,
    dlqAt:         row.dlq_at      || null,
    replayedAt:    row.replayed_at || null,
    archivedAt:    row.archived_at || null,
    status:        row.status     || 'PENDING',
    errorHistory:  row.error_history ?? [],
  };
  if (includePayload) op.payload = row.payload ?? {};
  return op;
}

/**
 * List DLQ items with optional time-range filtering and pagination.
 *
 * @param {object}  opts
 * @param {number}  [opts.offset=0]
 * @param {number}  [opts.limit=50]
 * @param {string}  [opts.after]
 * @param {string}  [opts.before]
 * @param {string}  [opts.operationType]
 * @param {string}  [opts.service]
 * @param {number}  [opts.minRetryCount]
 * @param {string}  [opts.sort='asc']
 * @returns {Promise<{ items: object[], total: number, dlqTotal: number }>}
 */
async function listDlqFull(opts = {}) {
  if (!_isReady()) return { items: [], total: 0, dlqTotal: 0 };

  const {
    offset        = 0,
    limit         = 50,
    after,
    before,
    operationType,
    service,
    minRetryCount,
    sort          = 'asc',
  } = opts;

  const cappedLimit = Math.min(Math.max(1, limit), 200);

  const conditions = [`status = 'DLQ'`];
  const params     = [];

  if (after)  { params.push(after);  conditions.push(`dlq_at > $${params.length}`); }
  if (before) { params.push(before); conditions.push(`dlq_at < $${params.length}`); }
  if (operationType) { params.push(operationType); conditions.push(`operation_type = $${params.length}`); }
  if (service)        { params.push(service);        conditions.push(`service = $${params.length}`); }
  if (minRetryCount != null) { params.push(minRetryCount); conditions.push(`retry_count >= $${params.length}`); }

  const order = sort === 'desc' ? 'DESC' : 'ASC';

  const [itemsResult, totalResult, dlqTotalResult] = await Promise.all([
    _query(`
      SELECT * FROM persistence_recovery_queue
      WHERE ${conditions.join(' AND ')}
      ORDER BY dlq_at ${order}, operation_id ${order}
      OFFSET ${offset} LIMIT ${cappedLimit}
    `, params, 'prq_list_dlq_full_items'),
    _query(`SELECT count(*) AS total FROM persistence_recovery_queue WHERE ${conditions.join(' AND ')}`, params, 'prq_list_dlq_full_count'),
    _query(`SELECT count(*) AS total FROM persistence_recovery_queue WHERE status = 'DLQ'`, [], 'prq_dlq_total'),
  ]);

  return {
    items:    itemsResult.rows.map(r => _parseRow(r, false)),
    total:    Number(totalResult.rows[0]?.total ?? 0),
    dlqTotal: Number(dlqTotalResult.rows[0]?.total ?? 0),
  };
}

/**
 * Atomically replay a DLQ item: move from DLQ back to PENDING, reset retry
 * count, preserve error history with a REPLAY marker, increment replay
 * counter. Returns true if replayed, false if item was not in the DLQ
 * (concurrent replay/archive, or already processed).
 *
 * @param {string} operationId
 * @returns {Promise<boolean>}
 */
async function replayDlqItem(operationId) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  const now    = Date.now();
  const nowIso = new Date(now).toISOString();

  const result = await _query(`
    UPDATE persistence_recovery_queue
    SET status        = 'PENDING',
        eligible_at   = NOW(),
        retry_count   = 0,
        last_error    = NULL,
        replay_count  = replay_count + 1,
        replayed_at   = to_timestamp($2 / 1000.0),
        error_history = error_history || jsonb_build_array(
          jsonb_build_object('event', 'REPLAY', 'timestamp', $3::text, 'replayCount', replay_count + 1)
        ),
        updated_at    = NOW()
    WHERE operation_id = $1 AND status = 'DLQ'
    RETURNING operation_type, service, replay_count
  `, [operationId, now, nowIso], 'prq_replay_dlq_item');

  const row = result.rows[0];
  if (!row) return false;

  emit('INFO', 'DLQ_ITEM_REPLAYED', {
    source:        SOURCE,
    operationId,
    operationType: row.operation_type,
    service:       row.service,
    replayCount:   Number(row.replay_count),
  });

  return true;
}

/**
 * Soft-archive a DLQ item: mark ARCHIVED, never physically removed.
 * Returns true if archived, false if item was not in the DLQ.
 *
 * @param {string} operationId
 * @returns {Promise<boolean>}
 */
async function archiveDlqItem(operationId) {
  if (!_isReady()) throw new Error(`${SOURCE}: PostgreSQL not enabled`);

  const now = Date.now();

  const result = await _query(`
    UPDATE persistence_recovery_queue
    SET status      = 'ARCHIVED',
        archived_at = to_timestamp($2 / 1000.0),
        updated_at  = NOW()
    WHERE operation_id = $1 AND status = 'DLQ'
    RETURNING operation_type, service
  `, [operationId, now], 'prq_archive_dlq_item');

  const row = result.rows[0];
  if (!row) return false;

  emit('INFO', 'DLQ_ITEM_ARCHIVED', {
    source:        SOURCE,
    operationId,
    operationType: row.operation_type,
    service:       row.service,
  });

  return true;
}

/**
 * Return DLQ-specific stats used for Prometheus gauge population.
 *
 * @returns {Promise<{ oldestItemAgeMs: number, averageRetryCount: number }>}
 */
async function getDlqStats() {
  if (!_isReady()) return { oldestItemAgeMs: 0, averageRetryCount: 0 };

  const result = await _query(`
    SELECT
      count(*)                                        AS total,
      min(dlq_at)                                      AS oldest_dlq_at,
      avg(retry_count)                                 AS avg_retry_count
    FROM persistence_recovery_queue
    WHERE status = 'DLQ'
  `, [], 'prq_dlq_stats');

  const r = result.rows[0] ?? {};
  const total = Number(r.total ?? 0);
  if (total === 0) return { oldestItemAgeMs: 0, averageRetryCount: 0 };

  const oldestMs = r.oldest_dlq_at ? new Date(r.oldest_dlq_at).getTime() : Date.now();
  return {
    oldestItemAgeMs:   Math.max(0, Date.now() - oldestMs),
    averageRetryCount: Number(r.avg_retry_count ?? 0),
  };
}

/**
 * List archived items with pagination (newest first).
 *
 * @param {object} [opts]
 * @param {number} [opts.offset=0]
 * @param {number} [opts.limit=50]
 * @returns {Promise<{ items: object[], total: number }>}
 */
async function listArchivedItems({ offset = 0, limit = 50 } = {}) {
  if (!_isReady()) return { items: [], total: 0 };

  const cappedLimit = Math.min(Math.max(1, limit), 200);

  const [itemsResult, totalResult] = await Promise.all([
    _query(`
      SELECT * FROM persistence_recovery_queue
      WHERE status = 'ARCHIVED'
      ORDER BY archived_at DESC, operation_id DESC
      OFFSET $1 LIMIT $2
    `, [offset, cappedLimit], 'prq_list_archived_items'),
    _query(`SELECT count(*) AS total FROM persistence_recovery_queue WHERE status = 'ARCHIVED'`, [], 'prq_list_archived_count'),
  ]);

  return {
    items: itemsResult.rows.map(r => _parseRow(r, false)),
    total: Number(totalResult.rows[0]?.total ?? 0),
  };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  enqueue,
  claimNext,
  markComplete,
  markRetry,
  moveToDlq,
  getStats,
  getDepthByType,
  listDlq,
  getDlqItem,
  listDlqFull,
  replayDlqItem,
  archiveDlqItem,
  getDlqStats,
  listArchivedItems,
  _connect,
  _disconnect,
  _isReady,
  __setQueryFnForTest,
  CLAIM_TIMEOUT_MS,
};
