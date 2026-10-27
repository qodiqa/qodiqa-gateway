'use strict';

const { createBatchProcessor }             = require('../processor');
const { createBatchStore, buildBatch }     = require('../store');
const { drainPendingWrites }               = require('../../../core/audit/audit-log');

// _appendBatchAuditEvent() (processor.js) is fire-and-forget by design — audit
// failure must never corrupt batch processing. Its write is now queued/async
// (PERF-10), so without draining here a write can still be in flight when
// Jest tears down this file's module environment, surfacing as a spurious
// "require after environment torn down" error from the queued task.
afterEach(async () => {
  await drainPendingWrites();
});

function makeBatch(itemCount = 2) {
  return buildBatch({
    frameworkId: 'SOC2',
    tenantId:    'tenant-001',
    requestedBy: 'user@example.com',
    requestId:   'req_abc',
    items: Array.from({ length: itemCount }, (_, i) => ({
      subjectId: `subject-${i + 1}`,
      artifacts: [],
      evidencePackages: [],
    })),
  });
}

function makeSuccessEngine() {
  return {
    // the REAL evaluationEngine.evaluate() returns camelCase; this mock used snake_case and so hid
    // the processor reading the wrong field names (certificationId null in production).
    evaluate: jest.fn().mockResolvedValue({
      certificationId:       'cert-uuid-001',
      certificationDecision: 'CERTIFIED',
      certificationLevel:    'CERTIFIED',
      score:                 75,
      generatedAt:           '2024-01-01T00:00:00.000Z',
    }),
  };
}

function makeFailEngine(message = 'evaluation failed') {
  return {
    evaluate: jest.fn().mockRejectedValue(new Error(message)),
  };
}

// ── Happy path ────────────────────────────────────────────────────────────────

describe('createBatchProcessor — success', () => {
  it('processes all items and returns completed batch', async () => {
    const store     = createBatchStore();
    const engine    = makeSuccessEngine();
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(3);
    await store.save(batch);

    const result = await processor.processBatch(batch.batchId);

    expect(result.status).toBe('completed');
    const saved = await store.get(batch.batchId);
    expect(saved.items.every(i => i.status === 'completed')).toBe(true);
  });

  it('sets batch status to running before processing', async () => {
    let capturedMid;
    const store = createBatchStore();
    const originalUpdate = store.update.bind(store);
    store.update = async (id, patch) => {
      if (patch.status === 'running' && !capturedMid) capturedMid = patch.status;
      return originalUpdate(id, patch);
    };
    const engine    = makeSuccessEngine();
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(1);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    expect(capturedMid).toBe('running');
  });

  it('sets certificationId on each completed item', async () => {
    const store     = createBatchStore();
    const engine    = makeSuccessEngine();
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(2);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    const saved = await store.get(batch.batchId);
    expect(saved.items.every(i => i.certificationId === 'cert-uuid-001')).toBe(true);
  });

  it('calls engine once per item', async () => {
    const store     = createBatchStore();
    const engine    = makeSuccessEngine();
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(4);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    expect(engine.evaluate).toHaveBeenCalledTimes(4);
  });
});

// ── Partial failures ──────────────────────────────────────────────────────────

describe('createBatchProcessor — partial failures', () => {
  it('marks failed items without failing whole batch prematurely', async () => {
    const store = createBatchStore();
    let callCount = 0;
    const engine = {
      evaluate: jest.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 2) return Promise.reject(new Error('item 2 failed'));
        return Promise.resolve({
          certification_id: 'cert-001', certification_decision: 'CERTIFIED',
          certification_level: 'CERTIFIED', score: 70, generated_at: '2024-01-01T00:00:00.000Z',
        });
      }),
    };
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(3);
    await store.save(batch);
    const result = await processor.processBatch(batch.batchId);

    expect(result.status).toBe('failed');
    const saved = await store.get(batch.batchId);
    const failed   = saved.items.filter(i => i.status === 'failed');
    const completed = saved.items.filter(i => i.status === 'completed');
    expect(failed.length).toBe(1);
    expect(completed.length).toBe(2);
  });

  it('stores error message on failed item', async () => {
    const store     = createBatchStore();
    const engine    = makeFailEngine('pg connection refused');
    const processor = createBatchProcessor({ store, evaluationEngine: engine });
    const batch     = makeBatch(1);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    const saved = await store.get(batch.batchId);
    expect(saved.items[0].error).toBe('pg connection refused');
  });

  it('batch status is failed when any item fails', async () => {
    const store  = createBatchStore();
    const engine = makeFailEngine();
    const proc   = createBatchProcessor({ store, evaluationEngine: engine });
    const batch  = makeBatch(2);
    await store.save(batch);
    const result = await proc.processBatch(batch.batchId);
    expect(result.status).toBe('failed');
  });
});

// ── Cancellation ──────────────────────────────────────────────────────────────

describe('createBatchProcessor — cancellation', () => {
  it('throws NOT_FOUND for unknown batchId', async () => {
    const store = createBatchStore();
    const proc  = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    await expect(proc.processBatch('batch_' + '0'.repeat(32)))
      .rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('skips items when batch is cancelled mid-flight', async () => {
    const store = createBatchStore();
    const batch = makeBatch(3);
    await store.save(batch);

    let firstCall = true;
    const engine = {
      evaluate: jest.fn().mockImplementation(async () => {
        if (firstCall) {
          firstCall = false;
          // Cancel the batch after first item starts
          await store.update(batch.batchId, { status: 'cancelled', cancelledAt: new Date().toISOString() });
        }
        return {
          certification_id: 'cert-001', certification_decision: 'CERTIFIED',
          certification_level: 'CERTIFIED', score: 70, generated_at: '2024-01-01T00:00:00.000Z',
        };
      }),
    };

    const proc = createBatchProcessor({ store, evaluationEngine: engine, concurrency: 1 });
    await proc.processBatch(batch.batchId);

    // With concurrency=1, subsequent items see cancelled status
    const saved    = await store.get(batch.batchId);
    const cancelled = saved.items.filter(i => i.status === 'cancelled');
    expect(cancelled.length).toBeGreaterThan(0);
  });
});

// ── Concurrency ───────────────────────────────────────────────────────────────

describe('createBatchProcessor — concurrency', () => {
  it('never exceeds configured concurrency', async () => {
    const CONCURRENCY = 2;
    let active = 0;
    let maxActive = 0;

    const store  = createBatchStore();
    const engine = {
      evaluate: jest.fn().mockImplementation(() => {
        active++;
        maxActive = Math.max(maxActive, active);
        return new Promise(resolve => {
          setImmediate(() => {
            active--;
            resolve({
              certification_id: 'cert-001', certification_decision: 'CERTIFIED',
              certification_level: 'CERTIFIED', score: 70, generated_at: '2024-01-01T00:00:00.000Z',
            });
          });
        });
      }),
    };

    const proc  = createBatchProcessor({ store, evaluationEngine: engine, concurrency: CONCURRENCY });
    const batch = makeBatch(6);
    await store.save(batch);
    await proc.processBatch(batch.batchId);

    expect(maxActive).toBeLessThanOrEqual(CONCURRENCY);
    expect(engine.evaluate).toHaveBeenCalledTimes(6);
  });
});


// ── shape contract with the REAL engine ──────────────────────────────────────────────────

describe('createBatchProcessor — real evaluationEngine field names', () => {
  it('records certificationId, decision, level and generatedAt from the real engine output', async () => {
    const real = require('../../../core/certification/evaluationEngine');
    const store = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: real });
    const batch = makeBatch(1);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    const saved = await store.get(batch.batchId);
    const item = saved.items[0];
    expect(item.status).toBe('completed');
    expect(item.certificationId).toMatch(/^[0-9a-f-]{36}$/);   // was null
    expect(typeof item.result.certificationDecision).toBe('string');
    expect(typeof item.result.certificationLevel).toBe('string');
    expect(typeof item.result.generatedAt).toBe('string');
  });

  it('still accepts the legacy snake_case shape', async () => {
    const store = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: { evaluate: jest.fn().mockResolvedValue({
      certification_id: 'legacy-1', certification_decision: 'CERTIFIED', certification_level: 'CERTIFIED', score: 1, generated_at: 'x' }) } });
    const batch = makeBatch(1);
    await store.save(batch);
    await processor.processBatch(batch.batchId);
    expect((await store.get(batch.batchId)).items[0].certificationId).toBe('legacy-1');
  });
});
