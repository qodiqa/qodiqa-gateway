'use strict';

/**
 * Persistence Recovery DLQ Manager — Component #32 (CHAIN-3: Postgres-backed)
 *
 * Business logic layer for Dead Letter Queue administration.
 *
 * The underlying store is the `persistence_recovery_queue` PostgreSQL table
 * (migration 032) — see queue.js's header comment for the full CHAIN-3
 * rationale. Nothing in this file talks to Redis.
 *
 * ── Replay lifecycle ────────────────────────────────────────────────────────
 *
 * A DLQ item is replayed by an atomic `UPDATE ... WHERE operation_id = $1
 * AND status = 'DLQ'` that transitions its status from DLQ back to PENDING
 * in a single statement (queue.js's replayDlqItem()).  The worker then picks
 * it up exactly as it would a new job and processes it through the identical
 * handler used for the original attempt.  There is no replay-specific code
 * path; replay cannot bypass any validation, authorization, policy
 * evaluation, evidence generation, or audit generation.
 *
 * retryCount is reset to 0 so the replayed item receives MAX_RETRIES=5 fresh
 * attempts.  errorHistory is preserved and a REPLAY marker is appended so the
 * full failure history remains auditable.
 *
 * ── Archive lifecycle ────────────────────────────────────────────────────────
 *
 * Archiving soft-deletes a DLQ item: an atomic `UPDATE ... WHERE operation_id
 * = $1 AND status = 'DLQ'` transitions its status to ARCHIVED and stamps
 * archived_at.  The row is never physically deleted — it remains in the
 * table (filtered by status) indefinitely for audit purposes.
 *
 * ── Queue state transitions ──────────────────────────────────────────────────
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                    State Machine                            │
 *   │                                                             │
 *   │   [ACTIVE in queue]                                         │
 *   │         │                                                   │
 *   │         │ worker fails × MAX_RETRIES                        │
 *   │         ▼                                                   │
 *   │   [DLQ: PENDING]  ◄────── admin replay ──────┐             │
 *   │         │                                     │             │
 *   │         ├─── admin replay ──► [REPLAYING in queue]         │
 *   │         │                         │                         │
 *   │         │                         ├── worker succeeds       │
 *   │         │                         │     └─► COMPLETE        │
 *   │         │                         │         (removed)       │
 *   │         │                         └── worker fails × MAX_RETRIES
 *   │         │                               └─► [DLQ: PENDING] │
 *   │         │                                                   │
 *   │         └─── admin archive ──► [ARCHIVED]                  │
 *   │                                 (permanent, not deleted)    │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * ── Idempotency guarantees ───────────────────────────────────────────────────
 *
 * The persistence operations handled by the recovery worker are idempotent at
 * the PostgreSQL layer:
 *
 *   ATTESTATION_SAVE:          ON CONFLICT (attestation_id) DO NOTHING
 *   CERTIFICATION_SAVE:        ON CONFLICT (certification_id) DO NOTHING
 *   PORTAL_VERIFICATION_SAVE:  ON CONFLICT (verification_id) DO NOTHING
 *
 * Replaying any of these operations a second time after a successful first
 * attempt is a no-op at the database level — the duplicate INSERT is silently
 * discarded.  No duplicate records, evidence, audit chain entries, or
 * transparency log entries are created.
 *
 * WEBHOOK_DELIVERY is not idempotent by design: each replay attempt makes a
 * new HTTP delivery and logs a new row to webhook_delivery_log.  The receiving
 * endpoint must implement its own idempotency key check on the event payload.
 * The operation hash uses operationId = 'whd:<endpointId>:<eventId>' so the
 * event identity is stable across replay attempts.
 *
 * ── Replay atomicity and race-condition safety ───────────────────────────────
 *
 * queue.js's replayDlqItem() is a single `UPDATE persistence_recovery_queue
 * SET status = 'PENDING', ... WHERE operation_id = $1 AND status = 'DLQ'`.
 * PostgreSQL's row-level locking makes the `WHERE status = 'DLQ'` guard
 * exclusive: if two admin requests attempt to replay the same item
 * simultaneously,
 *
 *   Request A: UPDATE matches the row (still DLQ) → commits → status = PENDING
 *   Request B: UPDATE runs after A commits → row no longer matches (status
 *              is now PENDING, not DLQ) → 0 rows affected → NOT_IN_DLQ
 *
 * The item ends up in PENDING exactly once — no Lua script or separate lock
 * is needed; the WHERE clause itself is the compare-and-swap. The worker
 * only claims PENDING rows, so there is no worker/replay race.
 *
 * ── Multi-tenant isolation model ─────────────────────────────────────────────
 *
 * The DLQ contains platform-level operations (attestations, certifications,
 * portal verifications, webhook deliveries).  None of the current operation
 * types carry a tenantId at the queue-row level; tenant context is embedded
 * inside the operation payload and is only relevant at the PG persistence layer
 * where RLS enforces isolation.
 *
 * Access to the DLQ management API is restricted to MANAGE_RECOVERY_QUEUE
 * (admin role only) and READ_RECOVERY_QUEUE (admin + auditor).  There is no
 * tenant-scoped role in the RBAC model that could provide partial DLQ access.
 * Platform administrators have full cross-tenant visibility by design.
 *
 * If tenant-scoped operations are added to the recovery queue in future,
 * tenantId must be stored as a top-level hash field so this layer can enforce
 * per-tenant filtering before serving results.
 *
 * ── Operational recovery procedure ──────────────────────────────────────────
 *
 * 1. GET /v1/prq/stats — assess current queue/DLQ depth and PostgreSQL readiness.
 * 2. GET /v1/prq/dlq?sort=asc — inspect oldest failing items first.
 * 3. GET /v1/prq/dlq/:operationId — inspect payload and full error history.
 * 4. Diagnose root cause from lastError / errorHistory.
 * 5a. If root cause is resolved (PG back up, network restored):
 *       POST /v1/prq/dlq/replay { operationIds: [...] }
 *       Monitor worker logs for QUEUE_RECOVERED events.
 * 5b. If item is permanently unrecoverable (data error, invalid payload):
 *       DELETE /v1/prq/dlq/:operationId { reason: "..." }
 * 6. Re-check GET /v1/prq/stats until dlqDepth reaches 0.
 *
 * ── Administrative workflow ──────────────────────────────────────────────────
 *
 * Bulk replay:
 *   POST /v1/prq/dlq/replay { operationIds: [ids...] }
 *   Returns { total, replayed, skipped, results[] } — per-item outcomes.
 *   Max 100 items per request to prevent thundering herd on PG.
 *
 * Targeted archive:
 *   DELETE /v1/prq/dlq/:operationId { reason: "non-retryable constraint violation" }
 *   Returns { archived: true, operationId }.
 *   Row transitions to status = ARCHIVED, never physically deleted from PostgreSQL.
 */

const queue   = require('./queue');
const journal = require('./journal');
const metrics = require('./metrics');
const { emit } = require('../../../services/logger');
const obsMetrics = require('../../observability/metrics');

const SOURCE         = 'DLQ_MANAGER';
const MAX_BATCH_SIZE = 100;

// ── Validation ────────────────────────────────────────────────────────────────

function _validateOperationId(id) {
  if (typeof id !== 'string' || !id.trim()) {
    throw Object.assign(new Error('operationId must be a non-empty string'), { code: 'INVALID_OPERATION_ID' });
  }
}

// ── List ──────────────────────────────────────────────────────────────────────

/**
 * List DLQ items with optional filtering and pagination.
 *
 * @param {object}  [opts]
 * @param {number}  [opts.offset=0]
 * @param {number}  [opts.limit=50]
 * @param {string}  [opts.after]          ISO date — only items dlqAt > after
 * @param {string}  [opts.before]         ISO date — only items dlqAt < before
 * @param {string}  [opts.operationType]  Exact match on operationType
 * @param {string}  [opts.service]        Exact match on service
 * @param {number}  [opts.minRetryCount]  Minimum retryCount
 * @param {string}  [opts.sort='asc']     'asc' = oldest first, 'desc' = newest first
 * @returns {Promise<{ items: object[], total: number, dlqTotal: number, offset: number, limit: number }>}
 */
async function listItems(opts = {}) {
  if (!queue._isReady()) {
    return { items: [], total: 0, dlqTotal: 0, offset: opts.offset ?? 0, limit: opts.limit ?? 50 };
  }

  const result = await queue.listDlqFull(opts);
  return {
    ...result,
    offset: opts.offset ?? 0,
    limit:  opts.limit  ?? 50,
  };
}

// ── Get single item ───────────────────────────────────────────────────────────

/**
 * Retrieve a single DLQ item with full payload for admin inspection.
 *
 * @param {string} operationId
 * @returns {Promise<object|null>}
 */
async function getItem(operationId) {
  _validateOperationId(operationId);
  if (!queue._isReady()) return null;
  return queue.getDlqItem(operationId);
}

// ── Replay ────────────────────────────────────────────────────────────────────

/**
 * Replay a single DLQ item — re-enqueues it into the main recovery queue
 * for processing through the standard persistence pipeline.
 *
 * Idempotent: if the item has already been replayed (moved out of DLQ), returns
 * { replayed: false, reason: 'NOT_IN_DLQ' }.
 *
 * Prometheus metrics updated:
 *   qodiqa_prq_dlq_replay_total{result="success|failure"} +1
 *   qodiqa_prq_dlq_replay_duration_ms (histogram)
 *
 * @param {string} operationId
 * @param {object} [meta]
 * @param {string} [meta.actor]  Operator username for audit
 * @returns {Promise<{ replayed: boolean, durationMs: number, reason?: string }>}
 */
async function replayItem(operationId, { actor = 'operator' } = {}) {
  _validateOperationId(operationId);

  if (!queue._isReady()) {
    throw Object.assign(new Error('PostgreSQL not ready — cannot replay DLQ item'), { code: 'PG_UNAVAILABLE' });
  }

  const startMs  = Date.now();
  const replayed = await queue.replayDlqItem(operationId);
  const durationMs = Date.now() - startMs;

  obsMetrics.prqDlqReplayDurationMs.observe({}, durationMs);

  if (!replayed) {
    obsMetrics.prqDlqReplayTotal.inc({ result: 'failure' });
    metrics.inc('dlq_replay_failed_total');

    emit('WARN', 'DLQ_REPLAY_NOT_FOUND', {
      source:    SOURCE,
      operationId,
      actor,
      durationMs,
      outcome:   'NOT_IN_DLQ',
      reason:    'item not in DLQ (may have been processed, replayed, or archived)',
    });
    return { replayed: false, durationMs, reason: 'NOT_IN_DLQ' };
  }

  obsMetrics.prqDlqReplayTotal.inc({ result: 'success' });
  obsMetrics.prqDlqDepth.dec({});
  metrics.inc('dlq_replay_total');

  emit('INFO', 'DLQ_ITEM_REPLAYED', {
    source:        SOURCE,
    operationId,
    actor,
    durationMs,
    outcome:       'SUCCESS',
    auditCategory: 'LIFECYCLE',
    auditOutcome:  'SUCCESS',
  });

  return { replayed: true, durationMs };
}

/**
 * Replay multiple DLQ items in a single request.
 * Processes items sequentially to avoid thundering herd against PostgreSQL.
 * Capped at MAX_BATCH_SIZE items per request.
 *
 * @param {string[]} operationIds
 * @param {object}   [meta]
 * @param {string}   [meta.actor]
 * @returns {Promise<{ results: Array<{ operationId, replayed, durationMs, reason? }>, total: number, replayed: number, skipped: number }>}
 */
async function replayBatch(operationIds, { actor = 'operator' } = {}) {
  if (!Array.isArray(operationIds) || operationIds.length === 0) {
    throw Object.assign(new Error('operationIds must be a non-empty array'), { code: 'INVALID_INPUT' });
  }
  if (operationIds.length > MAX_BATCH_SIZE) {
    throw Object.assign(
      new Error(`Batch size ${operationIds.length} exceeds maximum of ${MAX_BATCH_SIZE}`),
      { code: 'BATCH_TOO_LARGE' },
    );
  }

  if (!queue._isReady()) {
    throw Object.assign(new Error('PostgreSQL not ready — cannot replay DLQ batch'), { code: 'PG_UNAVAILABLE' });
  }

  const batchStartMs = Date.now();
  const results      = [];
  let replayedCount  = 0;
  let skippedCount   = 0;

  for (const operationId of operationIds) {
    try {
      _validateOperationId(operationId);
      const result = await replayItem(operationId, { actor });
      results.push({ operationId, ...result });
      if (result.replayed) replayedCount++;
      else                  skippedCount++;
    } catch (err) {
      results.push({ operationId, replayed: false, durationMs: 0, reason: err.message });
      skippedCount++;
    }
  }

  const totalDurationMs = Date.now() - batchStartMs;

  emit('INFO', 'DLQ_BATCH_REPLAYED', {
    source:        SOURCE,
    actor,
    total:         operationIds.length,
    replayed:      replayedCount,
    skipped:       skippedCount,
    durationMs:    totalDurationMs,
    outcome:       replayedCount > 0 ? 'SUCCESS' : 'NO_OP',
    auditCategory: 'LIFECYCLE',
    auditOutcome:  replayedCount > 0 ? 'SUCCESS' : 'WARNING',
  });

  return {
    results,
    total:    operationIds.length,
    replayed: replayedCount,
    skipped:  skippedCount,
  };
}

// ── Archive ───────────────────────────────────────────────────────────────────

/**
 * Soft-archive a DLQ item — removes it from the active DLQ and stores it in
 * the archived set. The operation hash is preserved for audit purposes.
 *
 * Items are never physically destroyed via this operation.
 *
 * Prometheus metrics updated:
 *   qodiqa_prq_dlq_archive_total +1
 *   qodiqa_prq_dlq_depth -1
 *   qodiqa_prq_archived_depth +1
 *
 * @param {string} operationId
 * @param {object} [meta]
 * @param {string} [meta.actor]   Operator username for audit
 * @param {string} [meta.reason]  Human-readable reason for archival
 * @returns {Promise<{ archived: boolean, durationMs: number, reason?: string }>}
 */
async function archiveItem(operationId, { actor = 'operator', reason } = {}) {
  _validateOperationId(operationId);

  if (!queue._isReady()) {
    throw Object.assign(new Error('PostgreSQL not ready — cannot archive DLQ item'), { code: 'PG_UNAVAILABLE' });
  }

  const startMs  = Date.now();
  const archived = await queue.archiveDlqItem(operationId);
  const durationMs = Date.now() - startMs;

  if (!archived) {
    emit('WARN', 'DLQ_ARCHIVE_NOT_FOUND', {
      source:    SOURCE,
      operationId,
      actor,
      durationMs,
      outcome:   'NOT_IN_DLQ',
      reason:    'item not in DLQ (may have been processed, replayed, or already archived)',
    });
    return { archived: false, durationMs, reason: 'NOT_IN_DLQ' };
  }

  obsMetrics.prqDlqArchiveTotal.inc({});
  obsMetrics.prqDlqDepth.dec({});
  obsMetrics.prqArchivedDepth.inc({});
  metrics.inc('dlq_archive_total');

  emit('INFO', 'DLQ_ITEM_ARCHIVED', {
    source:        SOURCE,
    operationId,
    actor,
    durationMs,
    archiveReason: reason ?? null,
    outcome:       'SUCCESS',
    auditCategory: 'LIFECYCLE',
    auditOutcome:  'SUCCESS',
  });

  return { archived: true, durationMs };
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/**
 * Return combined queue stats and update Prometheus gauges.
 *
 * Updates the following Prometheus gauges on every call:
 *   qodiqa_prq_dlq_depth
 *   qodiqa_prq_archived_depth
 *   qodiqa_prq_dlq_oldest_item_age_seconds
 *   qodiqa_prq_dlq_average_retry_count
 *
 * @returns {Promise<{
 *   queueDepth: number,
 *   dlqDepth: number,
 *   archivedDepth: number,
 *   oldestItemAgeSeconds: number,
 *   averageRetryCount: number,
 *   journalDepth: number,
 *   journalOldestEntryAgeSeconds: number,
 *   journalBytes: number,
 *   metricsSnapshot: object,
 *   pgReady: boolean
 * }>}
 */
async function getStats() {
  // The filesystem journal (FAILOVER-1) is independent of PostgreSQL
  // readiness by construction — it exists precisely for when PostgreSQL is
  // NOT ready, so its stats are always read, even in the early-return branch
  // below.
  const journalStats = await journal.getStats();
  obsMetrics.prqJournalDepth.set({}, journalStats.depth);
  obsMetrics.prqJournalOldestEntryAgeSeconds.set({}, Math.floor(journalStats.oldestEntryAgeMs / 1000));
  obsMetrics.prqJournalBytes.set({}, journalStats.totalBytes);

  if (!queue._isReady()) {
    obsMetrics.prqDlqDepth.set({}, 0);
    obsMetrics.prqArchivedDepth.set({}, 0);
    obsMetrics.prqDlqOldestItemAgeSeconds.set({}, 0);
    obsMetrics.prqDlqAverageRetryCount.set({}, 0);
    return {
      queueDepth:           0,
      dlqDepth:             0,
      archivedDepth:        0,
      oldestItemAgeSeconds: 0,
      averageRetryCount:    0,
      journalDepth:                 journalStats.depth,
      journalOldestEntryAgeSeconds: Math.floor(journalStats.oldestEntryAgeMs / 1000),
      journalBytes:                 journalStats.totalBytes,
      metricsSnapshot:      metrics.snapshot(),
      pgReady:              false,
    };
  }

  const [queueStats, archivedResult, dlqStats] = await Promise.all([
    queue.getStats(),
    queue.listArchivedItems({ limit: 1 }),
    queue.getDlqStats(),
  ]);

  const { queueDepth, dlqDepth }         = queueStats;
  const { total: archivedDepth }         = archivedResult;
  const { oldestItemAgeMs, averageRetryCount } = dlqStats;
  const oldestItemAgeSeconds             = Math.floor(oldestItemAgeMs / 1000);

  // Update Prometheus gauges so /metrics endpoint reflects current queue state
  obsMetrics.prqDlqDepth.set({}, dlqDepth);
  obsMetrics.prqArchivedDepth.set({}, archivedDepth);
  obsMetrics.prqDlqOldestItemAgeSeconds.set({}, oldestItemAgeSeconds);
  obsMetrics.prqDlqAverageRetryCount.set({}, averageRetryCount);

  return {
    queueDepth,
    dlqDepth,
    archivedDepth,
    oldestItemAgeSeconds,
    averageRetryCount,
    journalDepth:                 journalStats.depth,
    journalOldestEntryAgeSeconds: Math.floor(journalStats.oldestEntryAgeMs / 1000),
    journalBytes:                 journalStats.totalBytes,
    metricsSnapshot: metrics.snapshot(),
    pgReady:         true,
  };
}

// ── Archived listing ──────────────────────────────────────────────────────────

/**
 * List soft-archived DLQ items (newest archived first).
 *
 * @param {object} [opts]
 * @param {number} [opts.offset=0]
 * @param {number} [opts.limit=50]
 * @returns {Promise<{ items: object[], total: number }>}
 */
async function listArchivedItems(opts = {}) {
  if (!queue._isReady()) return { items: [], total: 0 };
  return queue.listArchivedItems(opts);
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  listItems,
  getItem,
  replayItem,
  replayBatch,
  archiveItem,
  getStats,
  listArchivedItems,
  MAX_BATCH_SIZE,
};
