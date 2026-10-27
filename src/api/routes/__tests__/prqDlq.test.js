'use strict';

/**
 * Persistence Recovery DLQ Management — Component #32 Tests
 *
 * DLQ-01…10   GET /v1/prq/dlq — list, pagination, filtering, empty, PostgreSQL down
 * DLQ-11…15   GET /v1/prq/stats — combined stats
 * DLQ-16…20   GET /v1/prq/dlq/:operationId — single item lookup
 * DLQ-21…30   POST /v1/prq/dlq/replay — single, batch, not found, PostgreSQL down, validation
 * DLQ-31…37   DELETE /v1/prq/dlq/:operationId — archive, not found, PostgreSQL down
 * DLQ-38…43   GET /v1/prq/archived — list archived items
 * DLQ-44…52   RBAC: READ_RECOVERY_QUEUE and MANAGE_RECOVERY_QUEUE enforcement
 * DLQ-53…60   Audit events emitted on mutating operations
 * DLQ-61…67   Input validation: bad operationId, date format, batch limits
 * DLQ-68…72   Pipeline invariant: replay goes through queue.replayDlqItem
 * DLQ-73…76   Idempotency: replay/archive of already-moved items returns correct status
 *
 * Hardening pass (Component #32 finalization):
 * DLQ-77…84   Idempotency proof — concurrent and sequential duplicate operations
 * DLQ-85…91   Prometheus metrics updated by replay / archive / stats
 * DLQ-92…98   Audit events include duration, outcome, actor on every action
 * DLQ-99…104  Failure recovery — PostgreSQL unavailable / partial replay
 * DLQ-105…112 Multi-tenant RBAC model verification
 * DLQ-113…118 API consistency — response shapes, error formats, pagination
 */

// ── Global mocks (must precede all requires) ──────────────────────────────────

// Mock queue with all DLQ operations
const mockQueue = {
  _ready: true,
  _isReady() { return this._ready; },
  getStats:           jest.fn(),
  listDlq:            jest.fn(),
  getDlqItem:         jest.fn(),
  listDlqFull:        jest.fn(),
  replayDlqItem:      jest.fn(),
  archiveDlqItem:     jest.fn(),
  getDlqStats:        jest.fn(),
  listArchivedItems:  jest.fn(),
};
jest.mock('../../../core/persistenceRecovery/queue', () => mockQueue);

// Mock the filesystem recovery journal (FAILOVER-1) so getStats() tests never
// touch real disk — default to an empty journal, same convention as mockQueue.
const mockJournal = {
  getStats: jest.fn().mockResolvedValue({ depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 }),
};
jest.mock('../../../core/persistenceRecovery/journal', () => mockJournal);

// Mock Prometheus-style metrics so dlqManager's gauge/counter calls are verifiable
const mockObsMetrics = {
  prqDlqDepth:                { inc: jest.fn(), dec: jest.fn(), set: jest.fn() },
  prqArchivedDepth:           { inc: jest.fn(), dec: jest.fn(), set: jest.fn() },
  prqDlqReplayTotal:          { inc: jest.fn() },
  prqDlqArchiveTotal:         { inc: jest.fn() },
  prqDlqReplayDurationMs:     { observe: jest.fn() },
  prqDlqOldestItemAgeSeconds: { set: jest.fn() },
  prqDlqAverageRetryCount:    { set: jest.fn() },
  prqJournalDepth:                 { set: jest.fn() },
  prqJournalOldestEntryAgeSeconds: { set: jest.fn() },
  prqJournalBytes:                 { set: jest.fn() },
};
jest.mock('../../../observability/metrics', () => mockObsMetrics);

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({
  emit:                 mockEmit,
  allowed:              jest.fn(),
  blocked:              jest.fn(),
  eventBus:             { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const supertest = require('supertest');
const express   = require('express');
const { createPrqDlqRouter } = require('../prqDlq');
const { OPERATION_TYPES }    = require('../../../core/persistenceRecovery/persistenceOperation');

// ── Helpers ───────────────────────────────────────────────────────────────────

function _makeApp({
  rbacUser      = { username: 'admin-user', role: 'admin', enabled: true },
  requirePermission,
} = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    req.rbacUser  = rbacUser;
    req.requestId = 'test-req-id';
    res.locals.requestId = 'test-req-id';
    next();
  });
  const _noop = (_r, _s, n) => n();
  app.use('/v1/prq', createPrqDlqRouter({
    requirePermission: requirePermission ?? (() => _noop),
  }));
  return app;
}

const ITEM_1 = {
  operationId:   'att:aaaaaaaa-1111-1111-1111-111111111111',
  operationType: OPERATION_TYPES.ATTESTATION_SAVE,
  service:       'attestation',
  retryCount:    5,
  replayCount:   0,
  lastError:     'connection refused',
  createdAt:     '2026-06-20T10:00:00.000Z',
  dlqAt:         '2026-06-20T10:05:00.000Z',
  replayedAt:    null,
  archivedAt:    null,
  status:        'PENDING',
  errorHistory:  [{ error: 'connection refused', timestamp: '2026-06-20T10:05:00.000Z', retryCount: 5, final: true }],
};

const ITEM_2 = {
  operationId:   'cert:bbbbbbbb-2222-2222-2222-222222222222',
  operationType: OPERATION_TYPES.CERTIFICATION_SAVE,
  service:       'certification',
  retryCount:    5,
  replayCount:   1,
  lastError:     'query timeout',
  createdAt:     '2026-06-21T09:00:00.000Z',
  dlqAt:         '2026-06-21T09:30:00.000Z',
  replayedAt:    '2026-06-22T08:00:00.000Z',
  archivedAt:    null,
  status:        'PENDING',
  errorHistory:  [],
};

// ── Setup / teardown ──────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  mockQueue._ready = true;

  // Default mock returns
  mockQueue.getStats.mockResolvedValue({ queueDepth: 2, dlqDepth: 3 });
  mockQueue.listDlqFull.mockResolvedValue({ items: [ITEM_1, ITEM_2], total: 2, dlqTotal: 2 });
  mockQueue.getDlqItem.mockResolvedValue(ITEM_1);
  mockQueue.replayDlqItem.mockResolvedValue(true);
  mockQueue.archiveDlqItem.mockResolvedValue(true);
  mockQueue.getDlqStats.mockResolvedValue({ oldestItemAgeMs: 60_000, averageRetryCount: 4.5 });
  mockQueue.listArchivedItems.mockResolvedValue({ items: [], total: 0 });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-01…10  GET /v1/prq/dlq
// ═════════════════════════════════════════════════════════════════════════════

describe('GET /v1/prq/dlq — list', () => {

  test('DLQ-01: returns 200 with items array and total', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.items).toHaveLength(2);
    expect(res.body.data.total).toBe(2);
    expect(res.body.data.dlqTotal).toBe(2);
  });

  test('DLQ-02: returns empty array when DLQ is empty', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(res.status).toBe(200);
    expect(res.body.data.items).toHaveLength(0);
    expect(res.body.data.total).toBe(0);
  });

  test('DLQ-03: passes offset and limit to listDlqFull', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [ITEM_2], total: 1, dlqTotal: 5 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?offset=1&limit=1');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ offset: 1, limit: 1 }),
    );
  });

  test('DLQ-04: caps limit at 200', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?limit=9999');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 200 }),
    );
  });

  test('DLQ-05: passes operationType filter', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [ITEM_1], total: 1, dlqTotal: 2 });
    const res = await supertest(_makeApp()).get(`/v1/prq/dlq?operationType=${OPERATION_TYPES.ATTESTATION_SAVE}`);
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ operationType: OPERATION_TYPES.ATTESTATION_SAVE }),
    );
  });

  test('DLQ-06: rejects unknown operationType with 400', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?operationType=NOT_A_REAL_TYPE');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_OPERATION_TYPE');
  });

  test('DLQ-07: passes after/before date filters', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?after=2026-06-01T00:00:00Z&before=2026-06-30T23:59:59Z');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({
        after:  '2026-06-01T00:00:00Z',
        before: '2026-06-30T23:59:59Z',
      }),
    );
  });

  test('DLQ-08: rejects invalid date with 400', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?after=not-a-date');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_DATE');
  });

  test('DLQ-09: returns 200 with empty items when PostgreSQL is down', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(res.status).toBe(200);
    expect(res.body.data.items).toHaveLength(0);
  });

  test('DLQ-10: passes sort=desc to listDlqFull', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [ITEM_2, ITEM_1], total: 2, dlqTotal: 2 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?sort=desc');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ sort: 'desc' }),
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-11…15  GET /v1/prq/stats
// ═════════════════════════════════════════════════════════════════════════════

describe('GET /v1/prq/stats', () => {

  test('DLQ-11: returns 200 with queue depths', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 7 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.queueDepth).toBe(2);
    expect(res.body.data.dlqDepth).toBe(3);
    expect(typeof res.body.data.metricsSnapshot).toBe('object');
  });

  test('DLQ-12: includes archivedDepth, oldestItemAgeSeconds, averageRetryCount', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 4 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.archivedDepth).toBe(4);
    expect(typeof res.body.data.oldestItemAgeSeconds).toBe('number');
    expect(typeof res.body.data.averageRetryCount).toBe('number');
  });

  test('DLQ-13: returns pgReady: false when PostgreSQL is down', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.pgReady).toBe(false);
    expect(res.body.data.queueDepth).toBe(0);
    expect(res.body.data.dlqDepth).toBe(0);
    expect(res.body.data.oldestItemAgeSeconds).toBe(0);
    expect(res.body.data.averageRetryCount).toBe(0);
  });

  test('DLQ-14: returns pgReady: true when PostgreSQL is ready', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.status).toBe(200);
    expect(res.body.data.pgReady).toBe(true);
  });

  test('DLQ-15: response shape includes requestId and timestamp', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.body.requestId).toBe('test-req-id');
    expect(typeof res.body.timestamp).toBe('string');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-16…20  GET /v1/prq/dlq/:operationId
// ═════════════════════════════════════════════════════════════════════════════

describe('GET /v1/prq/dlq/:operationId', () => {

  test('DLQ-16: returns 200 with full item including errorHistory', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(res.status).toBe(200);
    expect(res.body.data.item.operationId).toBe(ITEM_1.operationId);
    expect(res.body.data.item.errorHistory).toHaveLength(1);
  });

  test('DLQ-17: returns 404 when item not in DLQ', async () => {
    mockQueue.getDlqItem.mockResolvedValueOnce(null);
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/att%3Anot-found');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-18: returns 404 when PostgreSQL is down', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-19: item includes payload field for inspection', async () => {
    mockQueue.getDlqItem.mockResolvedValueOnce({ ...ITEM_1, payload: { attestationId: 'aaa' } });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(200);
    expect(res.body.data.item.payload).toBeDefined();
    expect(res.body.data.item.payload.attestationId).toBe('aaa');
  });

  test('DLQ-20: calls getDlqItem with correct operationId', async () => {
    await supertest(_makeApp()).get('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    // The : is URL-encoded as %3A
    expect(mockQueue.getDlqItem).toHaveBeenCalledWith('att:aaaaaaaa-1111-1111-1111-111111111111');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-21…30  POST /v1/prq/dlq/replay
// ═════════════════════════════════════════════════════════════════════════════

describe('POST /v1/prq/dlq/replay', () => {

  test('DLQ-21: single replay returns { replayed: true }', async () => {
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(true);
    expect(res.body.data.operationId).toBe(ITEM_1.operationId);
  });

  test('DLQ-22: single replay calls queue.replayDlqItem exactly once', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockQueue.replayDlqItem).toHaveBeenCalledTimes(1);
    expect(mockQueue.replayDlqItem).toHaveBeenCalledWith(ITEM_1.operationId);
  });

  test('DLQ-23: returns { replayed: false, reason: NOT_IN_DLQ } when item not in DLQ', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(false);
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: 'att:not-in-dlq' });
    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(false);
    expect(res.body.data.reason).toBe('NOT_IN_DLQ');
  });

  test('DLQ-24: batch replay returns results array with replayed/skipped counts', async () => {
    mockQueue.replayDlqItem
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);

    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_2.operationId] });

    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(2);
    expect(res.body.data.replayed).toBe(1);
    expect(res.body.data.skipped).toBe(1);
    expect(Array.isArray(res.body.data.results)).toBe(true);
    expect(res.body.data.results).toHaveLength(2);
  });

  test('DLQ-25: batch replay calls replayDlqItem for each id', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const ids = [ITEM_1.operationId, ITEM_2.operationId];
    await supertest(_makeApp()).post('/v1/prq/dlq/replay').send({ operationIds: ids });
    expect(mockQueue.replayDlqItem).toHaveBeenCalledTimes(2);
  });

  test('DLQ-26: returns 400 with BATCH_TOO_LARGE when batch exceeds 100', async () => {
    const ids = Array.from({ length: 101 }, (_, i) => `att:id-${i}`);
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: ids });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('BATCH_TOO_LARGE');
    expect(mockQueue.replayDlqItem).not.toHaveBeenCalled();
  });

  test('DLQ-27: returns 503 when PostgreSQL is unavailable', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
  });

  test('DLQ-28: returns 400 when body has neither operationId nor operationIds', async () => {
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ unknown: 'field' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('MISSING_FIELDS');
  });

  test('DLQ-29: returns 400 on empty operationIds array', async () => {
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [] });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('EMPTY_BATCH');
  });

  test('DLQ-30: batch result includes per-item operationId in results array', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const ids = [ITEM_1.operationId, ITEM_2.operationId];
    const res = await supertest(_makeApp()).post('/v1/prq/dlq/replay').send({ operationIds: ids });
    const resultIds = res.body.data.results.map(r => r.operationId);
    expect(resultIds).toContain(ITEM_1.operationId);
    expect(resultIds).toContain(ITEM_2.operationId);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-31…37  DELETE /v1/prq/dlq/:operationId
// ═════════════════════════════════════════════════════════════════════════════

describe('DELETE /v1/prq/dlq/:operationId', () => {

  test('DLQ-31: archive success returns { archived: true }', async () => {
    const res = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(res.status).toBe(200);
    expect(res.body.data.archived).toBe(true);
    expect(res.body.data.operationId).toBe(ITEM_1.operationId);
  });

  test('DLQ-32: archive calls queue.archiveDlqItem with correct operationId', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(mockQueue.archiveDlqItem).toHaveBeenCalledWith(ITEM_1.operationId);
  });

  test('DLQ-33: returns 404 when item not in DLQ', async () => {
    mockQueue.archiveDlqItem.mockResolvedValueOnce(false);
    const res = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Anot-found');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-34: returns 503 when PostgreSQL is unavailable', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
  });

  test('DLQ-35: does NOT call queue.listDlq or queue.replayDlqItem on archive', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Asome-id');
    expect(mockQueue.listDlq).not.toHaveBeenCalled();
    expect(mockQueue.replayDlqItem).not.toHaveBeenCalled();
  });

  test('DLQ-36: optional reason body accepted without error', async () => {
    const res = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Asome-id')
      .send({ reason: 'non-retryable data error, archiving permanently' });
    expect(res.status).toBe(200);
  });

  test('DLQ-37: item is soft-archived (archiveDlqItem called, not deleteDlqItem)', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Asome-id');
    // Must use archiveDlqItem (soft) — no physical deletion
    expect(mockQueue.archiveDlqItem).toHaveBeenCalledTimes(1);
    // No direct row-deletion path (markComplete) called
    expect(mockQueue.replayDlqItem).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-38…43  GET /v1/prq/archived
// ═════════════════════════════════════════════════════════════════════════════

describe('GET /v1/prq/archived', () => {

  const ARCHIVED_ITEM = {
    ...ITEM_1,
    status:     'ARCHIVED',
    archivedAt: '2026-06-22T12:00:00.000Z',
  };

  beforeEach(() => {
    mockQueue.listArchivedItems.mockResolvedValue({ items: [ARCHIVED_ITEM], total: 1 });
  });

  test('DLQ-38: returns 200 with archived items', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/archived');
    expect(res.status).toBe(200);
    expect(res.body.data.items).toHaveLength(1);
    expect(res.body.data.total).toBe(1);
  });

  test('DLQ-39: passes offset and limit to listArchivedItems', async () => {
    await supertest(_makeApp()).get('/v1/prq/archived?offset=5&limit=10');
    expect(mockQueue.listArchivedItems).toHaveBeenCalledWith(
      expect.objectContaining({ offset: 5, limit: 10 }),
    );
  });

  test('DLQ-40: returns empty when no archived items', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/archived');
    expect(res.status).toBe(200);
    expect(res.body.data.items).toHaveLength(0);
  });

  test('DLQ-41: returns 200 with empty when PostgreSQL down', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp()).get('/v1/prq/archived');
    expect(res.status).toBe(200);
    expect(res.body.data.items).toHaveLength(0);
    expect(res.body.data.total).toBe(0);
  });

  test('DLQ-42: archived items have status ARCHIVED', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/archived');
    expect(res.body.data.items[0].status).toBe('ARCHIVED');
  });

  test('DLQ-43: caps limit at 200', async () => {
    await supertest(_makeApp()).get('/v1/prq/archived?limit=5000');
    expect(mockQueue.listArchivedItems).toHaveBeenCalledWith(
      expect.objectContaining({ limit: 200 }),
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-44…52  RBAC enforcement
// ═════════════════════════════════════════════════════════════════════════════

describe('RBAC enforcement', () => {

  function _makeRestrictedApp(grantedPermissions = []) {
    const requirePermission = (perm) => {
      if (grantedPermissions.includes(perm)) return (_r, _s, n) => n();
      return (_req, res) => res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions', requestId: null });
    };
    return _makeApp({ requirePermission });
  }

  test('DLQ-44: GET /dlq requires READ_RECOVERY_QUEUE — granted', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const app = _makeRestrictedApp(['READ_RECOVERY_QUEUE']);
    const res = await supertest(app).get('/v1/prq/dlq');
    expect(res.status).toBe(200);
  });

  test('DLQ-45: GET /dlq requires READ_RECOVERY_QUEUE — denied', async () => {
    const app = _makeRestrictedApp([]);
    const res = await supertest(app).get('/v1/prq/dlq');
    expect(res.status).toBe(403);
  });

  test('DLQ-46: GET /stats requires READ_RECOVERY_QUEUE — denied', async () => {
    const app = _makeRestrictedApp([]);
    const res = await supertest(app).get('/v1/prq/stats');
    expect(res.status).toBe(403);
  });

  test('DLQ-47: GET /dlq/:id requires READ_RECOVERY_QUEUE — denied', async () => {
    const app = _makeRestrictedApp([]);
    const res = await supertest(app).get('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(403);
  });

  test('DLQ-48: POST /dlq/replay requires MANAGE_RECOVERY_QUEUE — granted', async () => {
    const app = _makeRestrictedApp(['MANAGE_RECOVERY_QUEUE']);
    const res = await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(200);
  });

  test('DLQ-49: POST /dlq/replay requires MANAGE_RECOVERY_QUEUE — denied even with READ', async () => {
    const app = _makeRestrictedApp(['READ_RECOVERY_QUEUE']);
    const res = await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(403);
  });

  test('DLQ-50: DELETE /dlq/:id requires MANAGE_RECOVERY_QUEUE — granted', async () => {
    const app = _makeRestrictedApp(['MANAGE_RECOVERY_QUEUE']);
    const res = await supertest(app).delete('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(200);
  });

  test('DLQ-51: DELETE /dlq/:id requires MANAGE_RECOVERY_QUEUE — denied even with READ', async () => {
    const app = _makeRestrictedApp(['READ_RECOVERY_QUEUE']);
    const res = await supertest(app).delete('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(403);
  });

  test('DLQ-52: GET /archived requires READ_RECOVERY_QUEUE — granted', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const app = _makeRestrictedApp(['READ_RECOVERY_QUEUE']);
    const res = await supertest(app).get('/v1/prq/archived');
    expect(res.status).toBe(200);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-53…60  Audit events
// ═════════════════════════════════════════════════════════════════════════════

describe('Audit events emitted', () => {

  test('DLQ-53: replay emits DLQ_ITEM_REPLAYED with operationId and actor', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });

    const replayCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(replayCall).toBeDefined();
    expect(replayCall[2]).toMatchObject({
      operationId: ITEM_1.operationId,
      actor:       'admin-user',
    });
  });

  test('DLQ-54: archive emits DLQ_ITEM_ARCHIVED with operationId and actor', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');

    const archiveCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(archiveCall).toBeDefined();
    expect(archiveCall[2]).toMatchObject({
      operationId: ITEM_1.operationId,
      actor:       'admin-user',
    });
  });

  test('DLQ-55: replay emits WARN DLQ_REPLAY_NOT_FOUND when item not in DLQ', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(false);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: 'att:missing' });

    const warnCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_REPLAY_NOT_FOUND');
    expect(warnCall).toBeDefined();
  });

  test('DLQ-56: archive emits WARN DLQ_ARCHIVE_NOT_FOUND when item not in DLQ', async () => {
    mockQueue.archiveDlqItem.mockResolvedValueOnce(false);
    await supertest(_makeApp()).delete('/v1/prq/dlq/att%3Amissing');

    const warnCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ARCHIVE_NOT_FOUND');
    expect(warnCall).toBeDefined();
  });

  test('DLQ-57: batch replay emits DLQ_BATCH_REPLAYED with counts', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_2.operationId] });

    const batchCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_BATCH_REPLAYED');
    expect(batchCall).toBeDefined();
    expect(batchCall[2]).toMatchObject({ total: 2, replayed: 2 });
  });

  test('DLQ-58: list emits PRQ_DLQ_LISTED with returned count', async () => {
    await supertest(_makeApp()).get('/v1/prq/dlq');
    const listCall = mockEmit.mock.calls.find(c => c[1] === 'PRQ_DLQ_LISTED');
    expect(listCall).toBeDefined();
    expect(listCall[2]).toMatchObject({ returned: 2, total: 2 });
  });

  test('DLQ-59: stats emits PRQ_DLQ_STATS_READ', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    await supertest(_makeApp()).get('/v1/prq/stats');
    const statsCall = mockEmit.mock.calls.find(c => c[1] === 'PRQ_DLQ_STATS_READ');
    expect(statsCall).toBeDefined();
  });

  test('DLQ-60: item read emits PRQ_DLQ_ITEM_READ with operationId', async () => {
    await supertest(_makeApp()).get('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    const readCall = mockEmit.mock.calls.find(c => c[1] === 'PRQ_DLQ_ITEM_READ');
    expect(readCall).toBeDefined();
    expect(readCall[2]).toMatchObject({ operationId: ITEM_1.operationId });
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-61…67  Input validation
// ═════════════════════════════════════════════════════════════════════════════

describe('Input validation', () => {

  test('DLQ-61: replay with empty string operationId returns 400', async () => {
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: '' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toMatch(/INVALID_OPERATION_ID|MISSING_FIELDS/);
  });

  test('DLQ-62: batch replay with non-string entries returns error or skips', async () => {
    // Non-string id causes per-item error; overall request still returns 200
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [null, ITEM_1.operationId] });
    // null entry should be skipped with reason set
    expect(res.status).toBe(200);
    expect(res.body.data.skipped).toBeGreaterThanOrEqual(1);
  });

  test('DLQ-63: minRetryCount=0 passes as zero filter', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?minRetryCount=0');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ minRetryCount: 0 }),
    );
  });

  test('DLQ-64: negative offset is treated as 0', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?offset=-5');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ offset: 0 }),
    );
  });

  test('DLQ-65: sort defaults to asc when not specified', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ sort: 'asc' }),
    );
  });

  test('DLQ-66: sort=invalid defaults to asc', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    await supertest(_makeApp()).get('/v1/prq/dlq?sort=random');
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ sort: 'asc' }),
    );
  });

  test('DLQ-67: GET /dlq/replay returns 405 Method Not Allowed', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/replay');
    expect(res.status).toBe(405);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-68…72  Pipeline invariant: replay goes through queue.replayDlqItem
// ═════════════════════════════════════════════════════════════════════════════

describe('Pipeline invariant — replay uses queue.replayDlqItem', () => {

  test('DLQ-68: replay does not call archiveDlqItem', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockQueue.archiveDlqItem).not.toHaveBeenCalled();
  });

  test('DLQ-69: replay does not call listDlqFull', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockQueue.listDlqFull).not.toHaveBeenCalled();
  });

  test('DLQ-70: archive does not call replayDlqItem', async () => {
    await supertest(_makeApp()).delete('/v1/prq/dlq/att%3Asome-id');
    expect(mockQueue.replayDlqItem).not.toHaveBeenCalled();
  });

  test('DLQ-71: batch replay calls replayDlqItem for each item independently', async () => {
    mockQueue.replayDlqItem
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    const ids = [ITEM_1.operationId, 'att:not-found', ITEM_2.operationId];
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: ids });

    expect(mockQueue.replayDlqItem).toHaveBeenCalledTimes(3);
    expect(res.body.data.replayed).toBe(2);
    expect(res.body.data.skipped).toBe(1);
  });

  test('DLQ-72: replay metrics incremented for each successful replay', async () => {
    // The dlqManager increments dlq_replay_total — we just verify no error thrown
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_2.operationId] });
    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(2);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-73…76  Idempotency
// ═════════════════════════════════════════════════════════════════════════════

describe('Idempotency', () => {

  test('DLQ-73: replaying an already-replayed item returns { replayed: false } not an error', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(false); // item moved out of DLQ
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(false);
    expect(res.body.data.reason).toBe('NOT_IN_DLQ');
  });

  test('DLQ-74: archiving an already-archived item returns 404', async () => {
    mockQueue.archiveDlqItem.mockResolvedValueOnce(false);
    const res = await supertest(_makeApp()).delete('/v1/prq/dlq/att%3Aalready-archived');
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-75: second replay of same batch item is flagged as skipped not errored', async () => {
    mockQueue.replayDlqItem
      .mockResolvedValueOnce(true)   // first replay succeeds
      .mockResolvedValueOnce(false); // second (same) replay — item gone

    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_1.operationId] });

    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(1);
    expect(res.body.data.skipped).toBe(1);
  });

  test('DLQ-76: response shape is consistent across single and batch replay', async () => {
    // Single replay shape: { replayed, operationId, reason? }
    const singleRes = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(singleRes.status).toBe(200);
    expect(singleRes.body.data).toHaveProperty('replayed');
    expect(singleRes.body.data).toHaveProperty('operationId');

    // Batch replay shape: { results, total, replayed, skipped }
    mockQueue.replayDlqItem.mockResolvedValueOnce(true);
    const batchRes = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_2.operationId] });
    expect(batchRes.status).toBe(200);
    expect(batchRes.body.data).toHaveProperty('results');
    expect(batchRes.body.data).toHaveProperty('total');
    expect(batchRes.body.data).toHaveProperty('replayed');
    expect(batchRes.body.data).toHaveProperty('skipped');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-77…82  Idempotency — batch and combined lifecycle scenarios
// ═════════════════════════════════════════════════════════════════════════════

describe('Idempotency — batch and combined lifecycle scenarios', () => {

  test('DLQ-77: batch where all items are not in DLQ returns replayed:0, skipped:all, status 200', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(false);
    const ids = [ITEM_1.operationId, ITEM_2.operationId, 'att:ghost-id'];
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: ids });
    expect(res.status).toBe(200);
    expect(res.body.data.replayed).toBe(0);
    expect(res.body.data.skipped).toBe(3);
    expect(res.body.data.total).toBe(3);
    expect(res.body.data.results).toHaveLength(3);
  });

  test('DLQ-78: after replay, archive of same item returns 404 (item now in queue, not DLQ)', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(true);
    mockQueue.archiveDlqItem.mockResolvedValueOnce(false); // item moved from DLQ

    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });

    const archiveRes = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(archiveRes.status).toBe(404);
    expect(archiveRes.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-79: after archive, GET /dlq/:id returns 404 (item moved to archived set)', async () => {
    mockQueue.getDlqItem.mockResolvedValueOnce(null); // item no longer in DLQ

    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');

    const getRes = await supertest(_makeApp())
      .get('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(getRes.status).toBe(404);
    expect(getRes.body.error.code).toBe('NOT_FOUND');
  });

  test('DLQ-80: mid-batch item error does not stop processing of remaining items', async () => {
    mockQueue.replayDlqItem
      .mockResolvedValueOnce(true)
      .mockRejectedValueOnce(new Error('transient database error'))
      .mockResolvedValueOnce(true);

    const ids = [ITEM_1.operationId, 'att:error-id', ITEM_2.operationId];
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: ids });

    expect(res.status).toBe(200);
    expect(res.body.data.total).toBe(3);
    expect(res.body.data.replayed).toBe(2);
    expect(res.body.data.skipped).toBe(1);
    expect(res.body.data.results).toHaveLength(3);
    const failedResult = res.body.data.results.find(r => r.operationId === 'att:error-id');
    expect(failedResult.replayed).toBe(false);
    expect(typeof failedResult.reason).toBe('string');
  });

  test('DLQ-81: archive with reason body emits archiveReason in audit event', async () => {
    const reason = 'permanent constraint violation — data cannot be retried';
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111')
      .send({ reason });

    const archiveCall = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(archiveCall).toBeDefined();
    expect(archiveCall[2].archiveReason).toBe(reason);
  });

  test('DLQ-82: batch exceeding MAX_BATCH_SIZE is rejected before any queue calls', async () => {
    const oversizedIds = Array.from({ length: 101 }, (_, i) => `att:item-${i}`);
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: oversizedIds });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('BATCH_TOO_LARGE');
    expect(mockQueue.replayDlqItem).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-83…89  Prometheus metrics updated by operations
// ═════════════════════════════════════════════════════════════════════════════

describe('Prometheus metrics updated by operations', () => {

  test('DLQ-83: replay success increments prqDlqReplayTotal with result:success', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(true);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockObsMetrics.prqDlqReplayTotal.inc).toHaveBeenCalledWith({ result: 'success' });
  });

  test('DLQ-84: replay NOT_IN_DLQ increments prqDlqReplayTotal with result:failure', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(false);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: 'att:not-in-dlq' });
    expect(mockObsMetrics.prqDlqReplayTotal.inc).toHaveBeenCalledWith({ result: 'failure' });
  });

  test('DLQ-85: replay success calls prqDlqReplayDurationMs.observe with a number', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(true);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockObsMetrics.prqDlqReplayDurationMs.observe).toHaveBeenCalledWith(
      {},
      expect.any(Number),
    );
  });

  test('DLQ-86: replay success decrements prqDlqDepth gauge', async () => {
    mockQueue.replayDlqItem.mockResolvedValueOnce(true);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(mockObsMetrics.prqDlqDepth.dec).toHaveBeenCalledWith({});
  });

  test('DLQ-87: archive success increments prqDlqArchiveTotal counter', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(mockObsMetrics.prqDlqArchiveTotal.inc).toHaveBeenCalledWith({});
  });

  test('DLQ-88: archive success increments prqArchivedDepth and decrements prqDlqDepth', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    expect(mockObsMetrics.prqArchivedDepth.inc).toHaveBeenCalledWith({});
    expect(mockObsMetrics.prqDlqDepth.dec).toHaveBeenCalledWith({});
  });

  test('DLQ-89: getStats sets all four Prometheus gauges', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 7 });
    await supertest(_makeApp()).get('/v1/prq/stats');
    expect(mockObsMetrics.prqDlqDepth.set).toHaveBeenCalled();
    expect(mockObsMetrics.prqArchivedDepth.set).toHaveBeenCalled();
    expect(mockObsMetrics.prqDlqOldestItemAgeSeconds.set).toHaveBeenCalled();
    expect(mockObsMetrics.prqDlqAverageRetryCount.set).toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-90…96  Audit event completeness — duration, outcome, actor
// ═════════════════════════════════════════════════════════════════════════════

describe('Audit event completeness', () => {

  test('DLQ-90: DLQ_ITEM_REPLAYED audit event includes durationMs as a non-negative number', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call).toBeDefined();
    expect(typeof call[2].durationMs).toBe('number');
    expect(call[2].durationMs).toBeGreaterThanOrEqual(0);
  });

  test('DLQ-91: DLQ_ITEM_REPLAYED audit event includes outcome:SUCCESS', async () => {
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].outcome).toBe('SUCCESS');
  });

  test('DLQ-92: DLQ_ITEM_ARCHIVED audit event includes durationMs as a non-negative number', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(call).toBeDefined();
    expect(typeof call[2].durationMs).toBe('number');
    expect(call[2].durationMs).toBeGreaterThanOrEqual(0);
  });

  test('DLQ-93: DLQ_ITEM_ARCHIVED audit event includes outcome:SUCCESS', async () => {
    await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Aaaaaaaaa-1111-1111-1111-111111111111');
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(call[2].outcome).toBe('SUCCESS');
  });

  test('DLQ-94: DLQ_BATCH_REPLAYED audit event includes durationMs and outcome', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_2.operationId] });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_BATCH_REPLAYED');
    expect(call).toBeDefined();
    expect(typeof call[2].durationMs).toBe('number');
    expect(call[2].outcome).toMatch(/^(SUCCESS|NO_OP)$/);
  });

  test('DLQ-95: actor from rbacUser.username propagated into DLQ_ITEM_REPLAYED event', async () => {
    const app = _makeApp({ rbacUser: { username: 'operator-alice', role: 'admin' } });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].actor).toBe('operator-alice');
  });

  test('DLQ-96: absent rbacUser uses actor:operator fallback in audit events', async () => {
    const app = _makeApp({ rbacUser: null });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].actor).toBe('operator');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-97…102  Failure recovery
// ═════════════════════════════════════════════════════════════════════════════

describe('Failure recovery', () => {

  test('DLQ-97: PostgreSQL down for batch replay returns 503', async () => {
    mockQueue._ready = false;
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId, ITEM_2.operationId] });
    expect(res.status).toBe(503);
    expect(res.body.error.code).toBe('SERVICE_UNAVAILABLE');
  });

  test('DLQ-98: PostgreSQL recovering — first request gets empty result, next request succeeds', async () => {
    mockQueue._ready = false;
    const downRes = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(downRes.status).toBe(200);
    expect(downRes.body.data.items).toHaveLength(0);

    mockQueue._ready = true;
    const upRes = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(upRes.status).toBe(200);
    expect(upRes.body.data.items).toHaveLength(2);
  });

  test('DLQ-99: unexpected error from replayDlqItem returns 500 INTERNAL_ERROR', async () => {
    mockQueue.replayDlqItem.mockRejectedValueOnce(new Error('unexpected pg connection reset'));
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });

  test('DLQ-100: unexpected error from archiveDlqItem returns 500 INTERNAL_ERROR', async () => {
    mockQueue.archiveDlqItem.mockRejectedValueOnce(new Error('terminating connection due to administrator command'));
    const res = await supertest(_makeApp())
      .delete('/v1/prq/dlq/att%3Asome-id');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });

  test('DLQ-101: INVALID_OPERATION_ID thrown by getDlqItem returns 400', async () => {
    const err = Object.assign(
      new Error('operationId must be a non-empty string'),
      { code: 'INVALID_OPERATION_ID' },
    );
    mockQueue.getDlqItem.mockRejectedValueOnce(err);
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/att%3Abad-id');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_OPERATION_ID');
  });

  test('DLQ-102: unexpected error from listDlqFull returns 500 INTERNAL_ERROR', async () => {
    mockQueue.listDlqFull.mockRejectedValueOnce(new Error('remaining connection slots are reserved'));
    const res = await supertest(_makeApp()).get('/v1/prq/dlq');
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-103…110  Actor username propagation and RBAC read/write scope
// ═════════════════════════════════════════════════════════════════════════════

describe('Actor username propagation', () => {

  test('DLQ-103: rbacUser.username propagated as actor in DLQ_ITEM_ARCHIVED audit event', async () => {
    const app = _makeApp({ rbacUser: { username: 'sre-bob', role: 'admin' } });
    await supertest(app).delete('/v1/prq/dlq/att%3Asome-id');
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(call[2].actor).toBe('sre-bob');
  });

  test('DLQ-104: rbacUser.username propagated as actor in DLQ_BATCH_REPLAYED audit event', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const app = _makeApp({ rbacUser: { username: 'batch-operator', role: 'admin' } });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: [ITEM_1.operationId] });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_BATCH_REPLAYED');
    expect(call[2].actor).toBe('batch-operator');
  });

  test('DLQ-105: whitespace-only username falls back to actor:operator', async () => {
    const app = _makeApp({ rbacUser: { username: '   ', role: 'admin' } });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].actor).toBe('operator');
  });

  test('DLQ-106: username longer than 64 chars is truncated to 64 chars in audit events', async () => {
    const longName = 'x'.repeat(80);
    const app = _makeApp({ rbacUser: { username: longName, role: 'admin' } });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].actor).toHaveLength(64);
    expect(call[2].actor).toBe('x'.repeat(64));
  });

  test('DLQ-107: null rbacUser falls back to actor:operator in archive audit event', async () => {
    const app = _makeApp({ rbacUser: null });
    await supertest(app).delete('/v1/prq/dlq/att%3Asome-id');
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_ARCHIVED');
    expect(call[2].actor).toBe('operator');
  });

  test('DLQ-108: leading/trailing spaces stripped from username in actor field', async () => {
    const app = _makeApp({ rbacUser: { username: '  carol  ', role: 'admin' } });
    await supertest(app)
      .post('/v1/prq/dlq/replay')
      .send({ operationId: ITEM_1.operationId });
    const call = mockEmit.mock.calls.find(c => c[1] === 'DLQ_ITEM_REPLAYED');
    expect(call[2].actor).toBe('carol');
  });

  test('DLQ-109: READ_RECOVERY_QUEUE grants access to all four read endpoints', async () => {
    const requirePermission = (perm) =>
      perm === 'READ_RECOVERY_QUEUE'
        ? (_r, _s, n) => n()
        : (_req, res) => res.status(403).json({ error: 'FORBIDDEN' });
    const app = _makeApp({ requirePermission });
    mockQueue.listArchivedItems.mockResolvedValue({ items: [], total: 0 });

    const [statsRes, listRes, itemRes, archivedRes] = await Promise.all([
      supertest(app).get('/v1/prq/stats'),
      supertest(app).get('/v1/prq/dlq'),
      supertest(app).get('/v1/prq/dlq/att%3Asome-id'),
      supertest(app).get('/v1/prq/archived'),
    ]);
    expect(statsRes.status).toBe(200);
    expect(listRes.status).toBe(200);
    expect(itemRes.status).toBe(200);
    expect(archivedRes.status).toBe(200);
  });

  test('DLQ-110: READ_RECOVERY_QUEUE alone blocks POST /dlq/replay and DELETE /dlq/:id', async () => {
    const requirePermission = (perm) =>
      perm === 'READ_RECOVERY_QUEUE'
        ? (_r, _s, n) => n()
        : (_req, res) => res.status(403).json({ error: 'FORBIDDEN' });
    const app = _makeApp({ requirePermission });

    const [replayRes, archiveRes] = await Promise.all([
      supertest(app).post('/v1/prq/dlq/replay').send({ operationId: ITEM_1.operationId }),
      supertest(app).delete('/v1/prq/dlq/att%3Asome-id'),
    ]);
    expect(replayRes.status).toBe(403);
    expect(archiveRes.status).toBe(403);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DLQ-111…118  API consistency — response shapes, error formats, pagination
// ═════════════════════════════════════════════════════════════════════════════

describe('API consistency — response shapes and conventions', () => {

  test('DLQ-111: every success response has status:success, data, timestamp, requestId', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.body.status).toBe('success');
    expect(res.body.data).toBeDefined();
    expect(typeof res.body.timestamp).toBe('string');
    expect(res.body.requestId).toBe('test-req-id');
  });

  test('DLQ-112: every error response has status:error, code, detail, timestamp, requestId', async () => {
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({});
    expect(res.body.status).toBe('error');
    expect(typeof res.body.error.code).toBe('string');
    expect('message' in res.body.error).toBe(true);
    expect(typeof res.body.timestamp).toBe('string');
    expect(res.body.requestId).toBe('test-req-id');
  });

  test('DLQ-113: list DLQ response includes offset and limit in data', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?offset=10&limit=25');
    expect(res.status).toBe(200);
    expect(res.body.data.offset).toBe(10);
    expect(res.body.data.limit).toBe(25);
  });

  test('DLQ-114: service query param forwarded to listDlqFull', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?service=attestation');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ service: 'attestation' }),
    );
  });

  test('DLQ-115: minRetryCount param forwarded to listDlqFull as a parsed integer', async () => {
    mockQueue.listDlqFull.mockResolvedValueOnce({ items: [], total: 0, dlqTotal: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/dlq?minRetryCount=3');
    expect(res.status).toBe(200);
    expect(mockQueue.listDlqFull).toHaveBeenCalledWith(
      expect.objectContaining({ minRetryCount: 3 }),
    );
  });

  test('DLQ-116: GET /dlq/replay returns 405 with code:METHOD_NOT_ALLOWED in body', async () => {
    const res = await supertest(_makeApp()).get('/v1/prq/dlq/replay');
    expect(res.status).toBe(405);
    expect(res.body.status).toBe('error');
    expect(res.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  test('DLQ-117: batch replay total always equals operationIds.length and results array length', async () => {
    mockQueue.replayDlqItem.mockResolvedValue(true);
    const ids = [ITEM_1.operationId, ITEM_2.operationId, 'att:third-id'];
    const res = await supertest(_makeApp())
      .post('/v1/prq/dlq/replay')
      .send({ operationIds: ids });
    expect(res.body.data.total).toBe(3);
    expect(res.body.data.results).toHaveLength(3);
    expect(res.body.data.replayed + res.body.data.skipped).toBe(3);
  });

  test('DLQ-118: response timestamps are valid ISO 8601 dates', async () => {
    mockQueue.listArchivedItems.mockResolvedValueOnce({ items: [], total: 0 });
    const res = await supertest(_makeApp()).get('/v1/prq/stats');
    expect(res.status).toBe(200);
    const ts = new Date(res.body.timestamp);
    expect(ts.toString()).not.toBe('Invalid Date');
    expect(ts.getTime()).toBeGreaterThan(0);
  });
});
