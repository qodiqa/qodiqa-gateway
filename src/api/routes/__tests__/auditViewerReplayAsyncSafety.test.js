'use strict';

/**
 * — regression tests.
 *   1. GET /audit-viewer/replay/:artifactId used to call `.filter` on the Promise returned by the async
 *      getRequestHashEntries() -> TypeError inside an async handler -> unhandledRejection -> process.exit(1).
 *   2. Any async route rejection must reach the error middleware (500) and must NOT surface as an unhandledRejection.
 *   3. GET /compliance/report/:id/download?format[]=x used to throw (`format.toLowerCase`) outside any try/catch.
 */

const express = require('express');
const request = require('supertest');

jest.mock('../../../core/rateLimit', () => ({ createRateLimitMiddleware: () => (_req, _res, next) => next() }));

const ARTIFACT_ID = '11111111-2222-4333-8444-555555555555';
const OTHER_ID    = '11111111-2222-4333-8444-666666666666';

jest.mock('../../../core/audit/audit-log.js', () => ({
  getAuditChain: jest.fn(), getModernChain: jest.fn(), verifyAuditChainDetailed: jest.fn(),
  validateChainIntegrity: jest.fn(), getArtifactNeighbors: jest.fn(), getChainStats: jest.fn(),
  getArtifactById: jest.fn(async () => ({ artifactId: '11111111-2222-4333-8444-555555555555', timestamp: '2026-10-20T10:00:00.000Z', decision: 'ALLOW', requestHash: 'abc123', nonce: 'n1' })),
  getReplayLineage: jest.fn(async () => []),
  getRequestHashEntries: jest.fn(async () => ([
    { artifactId: '11111111-2222-4333-8444-555555555555', timestamp: '2026-10-20T10:00:00.000Z', decision: 'ALLOW', requestHash: 'abc123' },
    { artifactId: '11111111-2222-4333-8444-666666666666', timestamp: '2026-10-20T10:00:05.000Z', decision: 'BLOCK', requestHash: 'abc123' },
  ])),
}));

const auditLog = require('../../../core/audit/audit-log.js');
const createAuditViewerRouter = require('../auditViewer');
const { install } = require('../../../runtime/expressAsyncSafety');

function app(router, mount) {
  const a = express();
  a.use(mount, router);
  // same shape as the real final error middleware in src/app.js
  a.use((err, _req, res, _next) => { res.status(500).json({ status: 'error', error: { code: 'INTERNAL_ERROR' } }); });
  return a;
}

describe('item 3.1 — async route safety', () => {
  let unhandled;
  const onUnhandled = (r) => { unhandled.push(r); };
  beforeEach(() => { unhandled = []; process.on('unhandledRejection', onUnhandled); install(); });
  afterEach(() => { process.removeListener('unhandledRejection', onUnhandled); });

  test('AS-01 replay route returns 200 with relatedRequests (the awaited array is filtered, not the Promise)', async () => {
    const { createAuditViewerRouter: factory } = require('../auditViewer');
    const router = (factory || createAuditViewerRouter)({});
    const res = await request(app(router, '/audit-viewer')).get(`/audit-viewer/replay/${ARTIFACT_ID}`);
    expect(res.status).toBe(200);
    const data = res.body.data || res.body;
    const related = data.relatedRequests || (data.replay && data.replay.relatedRequests);
    expect(Array.isArray(related)).toBe(true);
    expect(related.map((r) => r.artifactId)).toEqual([OTHER_ID]); // the queried artifact itself is filtered out
    await new Promise((r) => setImmediate(r));
    expect(unhandled).toEqual([]);
  });

  test('AS-02 an async handler that rejects is answered 500 through the error middleware, with NO unhandledRejection', async () => {
    const router = express.Router();
    router.get('/boom', async () => { throw new Error('AUDIT_HISTORY_UNAVAILABLE'); });
    router.get('/sync', () => { throw new Error('sync boom'); });
    router.get('/ok', async (_req, res) => { res.json({ ok: true }); });
    const a = app(router, '/t');
    expect((await request(a).get('/t/boom')).status).toBe(500);
    expect((await request(a).get('/t/sync')).status).toBe(500);
    expect((await request(a).get('/t/ok')).status).toBe(200);
    await new Promise((r) => setImmediate(r));
    expect(unhandled).toEqual([]);
  });

  test('AS-03 audit-viewer: a store failure inside any async route is a 500, not a process-level rejection', async () => {
    auditLog.getArtifactById.mockRejectedValueOnce(Object.assign(new Error('history unreadable'), { code: 'AUDIT_HISTORY_UNAVAILABLE' }));
    const { createAuditViewerRouter: factory } = require('../auditViewer');
    const router = (factory || createAuditViewerRouter)({});
    const res = await request(app(router, '/audit-viewer')).get(`/audit-viewer/replay/${ARTIFACT_ID}`);
    expect(res.status).toBe(500);
    await new Promise((r) => setImmediate(r));
    expect(unhandled).toEqual([]);
  });
});
