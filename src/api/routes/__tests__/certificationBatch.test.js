'use strict';

// ── Mocks ─────────────────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
  registerCentralStore: jest.fn(),
}));

jest.mock('../../../core/rateLimit', () => ({
  createRateLimitMiddleware: () => (_req, _res, next) => next(),
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const request = require('supertest');
const express = require('express');
const { createBatchStore, buildBatch } = require('../../../certification/batch/store');
const { createBatchService }           = require('../../../certification/batch/index');
const { createCertificationBatchRouter } = require('../certificationBatch');
const { drainPendingWrites }             = require('../../../core/audit/audit-log');

// batch processing appends audit entries that can still be in
// flight when the last test returns; without this the append's checksum-anchor
// write ran after teardown ("require after the Jest environment has been torn
// down", checksumAnchor.saveChecksumPg). Same drain processor.test.js uses.
afterAll(() => drainPendingWrites());

// ── Test app factory ──────────────────────────────────────────────────────────

function makeApp({ store, evaluationEngine, requirePermission } = {}) {
  const batchService = createBatchService({
    store:            store || createBatchStore(),
    evaluationEngine: evaluationEngine || makeSuccessEngine(),
  });

  const router = createCertificationBatchRouter({
    requirePermission,
    batchService,
  });

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    req.rbacUser  = { username: 'testuser', tenantId: 'tenant-001' };
    req.clientIp  = '127.0.0.1';
    next();
  });
  app.use('/v1/certifications', router);
  return { app, batchService };
}

function makeSuccessEngine() {
  return {
    evaluate: jest.fn().mockResolvedValue({
      certification_id:       'cert-abc-001',
      certification_decision: 'CERTIFIED',
      certification_level:    'CERTIFIED',
      score:                  75,
      generated_at:           '2024-01-01T00:00:00.000Z',
    }),
  };
}

function makeFailEngine() {
  return { evaluate: jest.fn().mockRejectedValue(new Error('engine failure')) };
}

const VALID_BODY = {
  frameworkId: 'SOC2',
  items: [
    { subjectId: 'subject-1', artifacts: [], evidencePackages: [] },
    { subjectId: 'subject-2', artifacts: [], evidencePackages: [] },
  ],
};

// ── POST /batch ───────────────────────────────────────────────────────────────

describe('POST /v1/certifications/batch', () => {
  it('returns 202 with batchId and pending status', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    expect(res.status).toBe(202);
    expect(res.body.status).toBe('success');
    expect(res.body.data.batchId).toMatch(/^batch_[0-9a-f]{32}$/);
    expect(res.body.data.status).toBe('pending');
  });

  it('includes itemCount in response', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    expect(res.body.data.itemCount).toBe(2);
  });

  it('returns 400 for missing frameworkId', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send({ items: [{ subjectId: 's1' }] });
    expect(res.status).toBe(400);
  });

  it('returns 400 for empty items array', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send({ frameworkId: 'SOC2', items: [] });
    expect(res.status).toBe(400);
  });

  it('returns 400 for item missing subjectId', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send({
      frameworkId: 'SOC2',
      items: [{}],
    });
    expect(res.status).toBe(400);
  });

  it('includes apiVersion in response', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    expect(res.body.data.apiVersion).toBe('v1');
  });
});

// ── GET /batch/:batchId ───────────────────────────────────────────────────────

describe('GET /v1/certifications/batch/:batchId', () => {
  it('returns batch status and counts', async () => {
    const store = createBatchStore();
    const { app } = makeApp({ store });
    const created = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    const { batchId } = created.body.data;

    const res = await request(app).get(`/v1/certifications/batch/${batchId}`);
    expect(res.status).toBe(200);
    expect(res.body.data.batchId).toBe(batchId);
    expect(typeof res.body.data.itemCount).toBe('number');
    expect(res.body.data.itemCounts).toBeDefined();
  });

  it('returns 404 for unknown batchId', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/v1/certifications/batch/batch_' + '0'.repeat(32));
    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid batchId format', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/v1/certifications/batch/not-a-valid-id');
    expect(res.status).toBe(400);
  });

  it('returns 403 when tenantId does not match', async () => {
    const store = createBatchStore();
    const batch = buildBatch({
      frameworkId: 'SOC2',
      tenantId:    'tenant-OTHER',
      requestedBy: 'other',
      requestId:   null,
      items:       [{ subjectId: 's1' }],
    });
    await store.save(batch);

    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.requestId = 'test-req-id';
      req.rbacUser  = { username: 'testuser', tenantId: 'tenant-001' };
      next();
    });
    const batchService = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    app.use('/v1/certifications', createCertificationBatchRouter({ batchService }));

    const res = await request(app).get(`/v1/certifications/batch/${batch.batchId}`);
    expect(res.status).toBe(403);
  });
});

// ── GET /batch/:batchId/results ───────────────────────────────────────────────

describe('GET /v1/certifications/batch/:batchId/results', () => {
  it('returns items array with status fields', async () => {
    const store = createBatchStore();
    const { app } = makeApp({ store });
    const created = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    const { batchId } = created.body.data;

    const res = await request(app).get(`/v1/certifications/batch/${batchId}/results`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data.items)).toBe(true);
    expect(res.body.data.totalItems).toBe(2);
  });

  it('includes per-item subjectId', async () => {
    const store = createBatchStore();
    const { app } = makeApp({ store });
    const created = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    const { batchId } = created.body.data;
    const res = await request(app).get(`/v1/certifications/batch/${batchId}/results`);
    const subjects = res.body.data.items.map(i => i.subjectId);
    expect(subjects).toContain('subject-1');
    expect(subjects).toContain('subject-2');
  });

  it('returns 404 for unknown batchId', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/v1/certifications/batch/batch_' + '0'.repeat(32) + '/results');
    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid batchId format', async () => {
    const { app } = makeApp();
    const res = await request(app).get('/v1/certifications/batch/bad-id/results');
    expect(res.status).toBe(400);
  });
});

// ── POST /batch/:batchId/cancel ───────────────────────────────────────────────

describe('POST /v1/certifications/batch/:batchId/cancel', () => {
  it('cancels a pending batch and returns 200', async () => {
    // Create batch directly in store to avoid background processing race
    const store = createBatchStore();
    const batch = buildBatch({
      frameworkId: 'SOC2', tenantId: 'tenant-001',
      requestedBy: 'testuser', requestId: null,
      items: [{ subjectId: 's1' }],
    });
    await store.save(batch);

    const batchService = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const router = createCertificationBatchRouter({ batchService });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test-req-id'; req.rbacUser = { username: 'testuser', tenantId: 'tenant-001' }; next(); });
    app.use('/v1/certifications', router);

    const res = await request(app).post(`/v1/certifications/batch/${batch.batchId}/cancel`);
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('cancelled');
    expect(res.body.data.cancelledAt).toBeTruthy();
  });

  it('returns 409 for already-completed batch', async () => {
    const store = createBatchStore();
    const batch = buildBatch({
      frameworkId: 'SOC2', tenantId: 'tenant-001',
      requestedBy: 'u', requestId: null,
      items: [{ subjectId: 's1' }],
    });
    await store.save(batch);
    await store.update(batch.batchId, { status: 'running' });
    await store.update(batch.batchId, { status: 'completed' });

    const { app } = makeApp({ store });
    const res = await request(app).post(`/v1/certifications/batch/${batch.batchId}/cancel`);
    expect(res.status).toBe(409);
  });

  it('returns 409 for already-cancelled batch', async () => {
    const store = createBatchStore();
    const batch = buildBatch({
      frameworkId: 'SOC2', tenantId: 'tenant-001',
      requestedBy: 'u', requestId: null,
      items: [{ subjectId: 's1' }],
    });
    await store.save(batch);
    await store.update(batch.batchId, { status: 'cancelled' });

    const { app } = makeApp({ store });
    const res = await request(app).post(`/v1/certifications/batch/${batch.batchId}/cancel`);
    expect(res.status).toBe(409);
  });

  it('returns 404 for unknown batchId', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch/batch_' + '0'.repeat(32) + '/cancel');
    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid batchId format', async () => {
    const { app } = makeApp();
    const res = await request(app).post('/v1/certifications/batch/not-valid/cancel');
    expect(res.status).toBe(400);
  });
});

// ── RBAC gating ───────────────────────────────────────────────────────────────

describe('certificationBatch — RBAC enforcement', () => {
  it('calls requirePermission for SUBMIT_BATCH_CERTIFICATION on POST /batch', async () => {
    const requirePermission = jest.fn().mockReturnValue((_req, res) => res.status(403).json({ reason: 'FORBIDDEN' }));
    const batchService = createBatchService({ evaluationEngine: makeSuccessEngine() });
    const router = createCertificationBatchRouter({ requirePermission, batchService });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'x'; req.rbacUser = { username: 'u', tenantId: 't1' }; next(); });
    app.use('/v1/certifications', router);

    const res = await request(app).post('/v1/certifications/batch').send(VALID_BODY);
    expect(requirePermission).toHaveBeenCalledWith('SUBMIT_BATCH_CERTIFICATION');
    expect(res.status).toBe(403);
  });
});
