'use strict';

/**
 * Persistence Recovery DLQ Management Router — Component #32
 *
 * Factory: createPrqDlqRouter({ requirePermission })
 *
 * Mounted at /v1/prq in server.js, behind the full ops middleware stack.
 *
 * Routes:
 *   GET    /v1/prq/stats                      — queue + DLQ stats        [READ_RECOVERY_QUEUE]
 *   GET    /v1/prq/dlq                        — list DLQ items            [READ_RECOVERY_QUEUE]
 *   GET    /v1/prq/dlq/:operationId           — single item with payload  [READ_RECOVERY_QUEUE]
 *   POST   /v1/prq/dlq/replay                 — replay one or more items  [MANAGE_RECOVERY_QUEUE]
 *   DELETE /v1/prq/dlq/:operationId           — soft-archive item         [MANAGE_RECOVERY_QUEUE]
 *   GET    /v1/prq/archived                   — list archived items       [READ_RECOVERY_QUEUE]
 *
 * Filtering (GET /v1/prq/dlq query params):
 *   ?offset=0&limit=50        — pagination
 *   ?operationType=...        — filter by operation type
 *   ?service=...              — filter by service name
 *   ?minRetryCount=3          — items with retryCount >= N
 *   ?after=<ISO>&before=<ISO> — time range on dlqAt
 *   ?sort=asc|desc            — sort order (oldest first / newest first)
 *
 * Replay body (POST /v1/prq/dlq/replay):
 *   { operationId: string }          — single item
 *   { operationIds: string[] }       — batch (max 100)
 *
 * Security:
 *   READ_RECOVERY_QUEUE  — admin + auditor
 *   MANAGE_RECOVERY_QUEUE — admin only
 *   All routes are protected by the ops IP allowlist + ops auth middleware
 *   applied at the server.js mount point.
 */

const { Router } = require('express');
const { emit }   = require('../../../services/logger');
const dlqManager = require('../../core/persistenceRecovery/dlqManager');
const { OPERATION_TYPES } = require('../../core/persistenceRecovery/persistenceOperation');
const { success, failure } = require('../response');
const { parsePagination, parseSortOrder, withPaginationMeta } = require('../../utils/pagination');

// ── Helpers ───────────────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, req, data, status = 200) {
  return success(res, data, status);
}

function _err(res, req, status, code, detail) {
  emit('WARN', `PRQ_DLQ_${code}`, { requestId: req.requestId, detail });
  return failure(res, code, detail, status);
}

function _actor(req) {
  const u = req.rbacUser?.username;
  return typeof u === 'string' && u.trim() ? u.trim().slice(0, 64) : 'operator';
}

// Parse a non-negative integer query param; returns undefined if absent/invalid.
function _parseNonNegInt(raw) {
  if (raw == null) return undefined;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
}

// ── Router factory ────────────────────────────────────────────────────────────

function createPrqDlqRouter({ requirePermission }) {
  const router = Router();

  const _canRead   = requirePermission('READ_RECOVERY_QUEUE');
  const _canManage = requirePermission('MANAGE_RECOVERY_QUEUE');

  // ── GET /stats ───────────────────────────────────────────────────────────────
  // Combined view: main queue depth, DLQ depth, archived depth, metrics snapshot.
  router.get('/stats', _canRead, async (req, res) => {
    try {
      const stats = await dlqManager.getStats();
      emit('INFO', 'PRQ_DLQ_STATS_READ', {
        requestId: req.requestId,
        actor:     _actor(req),
        ...stats,
      });
      _ok(res, req, stats);
    } catch (err) {
      emit('ERROR', 'PRQ_DLQ_STATS_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to retrieve queue stats');
    }
  });

  // ── GET /dlq ─────────────────────────────────────────────────────────────────
  // List DLQ items with pagination and optional filtering.
  router.get('/dlq', _canRead, async (req, res) => {
    const {
      after,
      before,
      operationType,
      service,
      minRetryCount:   rawMinRetry,
    } = req.query;

    // Canonical page/pageSize (API-4 remediation) accepted as aliases
    // alongside this endpoint's original offset/limit; either still works.
    const { page, pageSize, limit, offset } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 200 });
    const minRetryCount = _parseNonNegInt(rawMinRetry);

    // Validate operationType if provided
    if (operationType && !Object.values(OPERATION_TYPES).includes(operationType)) {
      return _err(res, req, 400, 'INVALID_OPERATION_TYPE',
        `Unknown operationType "${operationType}". Valid values: ${Object.values(OPERATION_TYPES).join(', ')}`);
    }

    // `sort` here is oldest-first by default (opposite of every other file's
    // `sortOrder`, which defaults desc) — canonical `sortOrder` is now also
    // accepted as an alias via the shared parser, same default preserved.
    const sortVal = parseSortOrder(req.query, { default: 'asc' });

    // Validate date params
    if (after && isNaN(new Date(after).getTime())) {
      return _err(res, req, 400, 'INVALID_DATE', 'after must be a valid ISO 8601 date');
    }
    if (before && isNaN(new Date(before).getTime())) {
      return _err(res, req, 400, 'INVALID_DATE', 'before must be a valid ISO 8601 date');
    }

    try {
      const result = await dlqManager.listItems({
        offset,
        limit,
        after:         after   || undefined,
        before:        before  || undefined,
        operationType: operationType || undefined,
        service:       service || undefined,
        minRetryCount,
        sort:          sortVal,
      });

      emit('INFO', 'PRQ_DLQ_LISTED', {
        requestId: req.requestId,
        actor:     _actor(req),
        returned:  result.items.length,
        total:     result.total,
        dlqTotal:  result.dlqTotal,
      });

      _ok(res, req, { ...result, ...withPaginationMeta({ page, pageSize, total: result.total }) });
    } catch (err) {
      emit('ERROR', 'PRQ_DLQ_LIST_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to list DLQ items');
    }
  });

  // ── GET /dlq/replay — guard: this path must not be shadowed by /:operationId ─
  // Explicit route so /dlq/replay is not matched by /dlq/:operationId below.
  // (Express matches routes in registration order; this comes first.)
  router.get('/dlq/replay', _canRead, (_req, res) => {
    return failure(res, 'METHOD_NOT_ALLOWED', 'Use POST /v1/prq/dlq/replay to replay DLQ items', 405);
  });

  // ── GET /dlq/:operationId ────────────────────────────────────────────────────
  // Fetch a single DLQ item with full payload for inspection.
  router.get('/dlq/:operationId', _canRead, async (req, res) => {
    const { operationId } = req.params;

    try {
      const item = await dlqManager.getItem(operationId);
      if (!item) {
        return _err(res, req, 404, 'NOT_FOUND', `DLQ item "${operationId}" not found`);
      }

      emit('INFO', 'PRQ_DLQ_ITEM_READ', {
        requestId:     req.requestId,
        actor:         _actor(req),
        operationId,
        operationType: item.operationType,
      });

      _ok(res, req, { item });
    } catch (err) {
      if (err.code === 'INVALID_OPERATION_ID') {
        return _err(res, req, 400, 'INVALID_OPERATION_ID', err.message);
      }
      emit('ERROR', 'PRQ_DLQ_ITEM_READ_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to retrieve DLQ item');
    }
  });

  // ── POST /dlq/replay ─────────────────────────────────────────────────────────
  // Replay one or more DLQ items through the standard persistence pipeline.
  //
  // Body forms:
  //   { "operationId": "att:uuid" }              — single item
  //   { "operationIds": ["att:uuid", "cert:uuid"] } — batch
  router.post('/dlq/replay', _canManage, async (req, res) => {
    const { operationId, operationIds } = req.body ?? {};
    const actor = _actor(req);

    // Single-item form: { operationId } → returns single-item response shape.
    // Batch form: { operationIds } → always returns batch response shape,
    //   even for a one-element array, so callers can use a consistent shape.
    const isBatch = Array.isArray(operationIds);

    try {
      if (!isBatch) {
        if (typeof operationId !== 'string') {
          return _err(res, req, 400, 'MISSING_FIELDS',
            'Request body must include "operationId" (string) or "operationIds" (array)');
        }
        const result = await dlqManager.replayItem(operationId, { actor });
        return _ok(res, req, {
          operationId,
          replayed: result.replayed,
          reason:   result.reason ?? null,
        });
      }

      if (operationIds.length === 0) {
        return _err(res, req, 400, 'EMPTY_BATCH', 'operationIds array must not be empty');
      }

      const batchResult = await dlqManager.replayBatch(operationIds, { actor });
      return _ok(res, req, batchResult);
    } catch (err) {
      if (err.code === 'BATCH_TOO_LARGE') {
        return _err(res, req, 400, 'BATCH_TOO_LARGE', err.message);
      }
      if (err.code === 'PG_UNAVAILABLE') {
        return _err(res, req, 503, 'SERVICE_UNAVAILABLE', 'PostgreSQL is unavailable — cannot replay DLQ items');
      }
      if (err.code === 'INVALID_OPERATION_ID') {
        return _err(res, req, 400, 'INVALID_OPERATION_ID', err.message);
      }
      emit('ERROR', 'PRQ_DLQ_REPLAY_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to replay DLQ item(s)');
    }
  });

  // ── DELETE /dlq/:operationId ─────────────────────────────────────────────────
  // Soft-archive a DLQ item. The item is moved to the archived set and
  // never physically destroyed.
  router.delete('/dlq/:operationId', _canManage, async (req, res) => {
    const { operationId } = req.params;
    const { reason }      = req.body ?? {};
    const actor           = _actor(req);

    try {
      const result = await dlqManager.archiveItem(operationId, { actor, reason });
      if (!result.archived) {
        return _err(res, req, 404, 'NOT_FOUND', `DLQ item "${operationId}" not found or already archived`);
      }
      _ok(res, req, { archived: true, operationId });
    } catch (err) {
      if (err.code === 'INVALID_OPERATION_ID') {
        return _err(res, req, 400, 'INVALID_OPERATION_ID', err.message);
      }
      if (err.code === 'PG_UNAVAILABLE') {
        return _err(res, req, 503, 'SERVICE_UNAVAILABLE', 'PostgreSQL is unavailable — cannot archive DLQ item');
      }
      emit('ERROR', 'PRQ_DLQ_ARCHIVE_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to archive DLQ item');
    }
  });

  // ── GET /archived ────────────────────────────────────────────────────────────
  // List soft-archived DLQ items (admin audit trail).
  router.get('/archived', _canRead, async (req, res) => {
    // Canonical page/pageSize (API-4 remediation) accepted as aliases
    // alongside this endpoint's original offset/limit; either still works.
    const { page, pageSize, limit, offset } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 200 });

    try {
      const result = await dlqManager.listArchivedItems({ offset, limit });
      emit('INFO', 'PRQ_DLQ_ARCHIVED_LISTED', {
        requestId: req.requestId,
        actor:     _actor(req),
        returned:  result.items.length,
        total:     result.total,
      });
      _ok(res, req, { ...result, ...withPaginationMeta({ page, pageSize, total: result.total }) });
    } catch (err) {
      emit('ERROR', 'PRQ_DLQ_ARCHIVED_LIST_ERROR', { requestId: req.requestId, error: err.message });
      _err(res, req, 500, 'INTERNAL_ERROR', 'Failed to list archived items');
    }
  });

  return router;
}

module.exports = { createPrqDlqRouter };
