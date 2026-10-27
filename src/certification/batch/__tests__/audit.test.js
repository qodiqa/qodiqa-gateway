'use strict';

// ── Mocks (must precede all requires) ─────────────────────────────────────────

const mockAppend = jest.fn();
jest.mock('../../../core/audit/audit-log', () => ({
  append: mockAppend,
}));

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({
  emit: mockEmit,
  registerCentralStore: jest.fn(),
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const { createBatchStore, buildBatch }   = require('../store');
const { createBatchProcessor }           = require('../processor');
const { createBatchService }             = require('../index');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeBatch(overrides = {}) {
  return buildBatch({
    frameworkId: 'SOC2',
    tenantId:    'tenant-001',
    requestedBy: 'user@example.com',
    requestId:   'req-001',
    items: [{ subjectId: 'subject-1', artifacts: [], evidencePackages: [] }],
    ...overrides,
  });
}

function makeSuccessEngine() {
  return {
    evaluate: jest.fn().mockResolvedValue({
      certification_id:       'cert-001',
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

beforeEach(() => {
  jest.clearAllMocks();
  mockAppend.mockImplementation(() => ({ hash: 'mock-hash' }));
});

// ── BATCH_CREATED ─────────────────────────────────────────────────────────────

describe('audit — BATCH_CREATED', () => {
  it('calls append() once when a batch is created', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });

    await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    const createdCalls = mockAppend.mock.calls.filter(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    expect(createdCalls.length).toBe(1);
  });

  it('BATCH_CREATED record uses ALLOW decision', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    expect(call[0].decision).toBe('ALLOW');
    expect(call[0].verificationResult).toBe(true);
  });

  it('BATCH_CREATED artifactId is batchId:BATCH_CREATED', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    expect(call[0].artifactId).toBe(`${batch.batchId}:BATCH_CREATED`);
  });

  it('BATCH_CREATED record includes tenantId', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-abc', requestedBy: 'user', requestId: null,
    });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    expect(call[0].tenantId).toBe('tenant-abc');
  });

  it('BATCH_CREATED record has all required crypto fields', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    const record = call[0];
    expect(typeof record.inputHash).toBe('string');
    expect(typeof record.requestHash).toBe('string');
    expect(typeof record.policyHash).toBe('string');
    expect(typeof record.signature).toBe('string');
    expect(record.inputHash.length).toBe(64);
  });

  it('BATCH_CREATED executionContext includes stage=BATCH_LIFECYCLE', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CREATED');
    expect(call[0].executionContext.stage).toBe('BATCH_LIFECYCLE');
    expect(call[0].executionContext.frameworkId).toBe('SOC2');
    expect(call[0].executionContext.itemCount).toBe(1);
  });
});

// ── BATCH_STARTED ─────────────────────────────────────────────────────────────

describe('audit — BATCH_STARTED', () => {
  it('calls append() with BATCH_STARTED when processing begins', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const startedCalls = mockAppend.mock.calls.filter(([a]) => a.executionContext?.event === 'BATCH_STARTED');
    expect(startedCalls.length).toBe(1);
  });

  it('BATCH_STARTED uses ALLOW decision', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_STARTED');
    expect(call[0].decision).toBe('ALLOW');
    expect(call[0].verificationResult).toBe(true);
  });

  it('BATCH_STARTED artifactId is batchId:BATCH_STARTED', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_STARTED');
    expect(call[0].artifactId).toBe(`${batch.batchId}:BATCH_STARTED`);
  });
});

// ── BATCH_COMPLETED ───────────────────────────────────────────────────────────

describe('audit — BATCH_COMPLETED', () => {
  it('calls append() with BATCH_COMPLETED when all items succeed', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const completedCalls = mockAppend.mock.calls.filter(([a]) => a.executionContext?.event === 'BATCH_COMPLETED');
    expect(completedCalls.length).toBe(1);
  });

  it('BATCH_COMPLETED uses ALLOW decision', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_COMPLETED');
    expect(call[0].decision).toBe('ALLOW');
    expect(call[0].verificationResult).toBe(true);
  });

  it('BATCH_COMPLETED executionContext includes succeeded count', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_COMPLETED');
    expect(typeof call[0].executionContext.succeeded).toBe('number');
    expect(call[0].executionContext.succeeded).toBe(1);
    expect(call[0].executionContext.failed).toBe(0);
  });

  it('BATCH_COMPLETED artifactId is batchId:BATCH_COMPLETED', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_COMPLETED');
    expect(call[0].artifactId).toBe(`${batch.batchId}:BATCH_COMPLETED`);
  });
});

// ── BATCH_FAILED ──────────────────────────────────────────────────────────────

describe('audit — BATCH_FAILED', () => {
  it('calls append() with BATCH_FAILED when items fail', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeFailEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const failedCalls = mockAppend.mock.calls.filter(([a]) => a.executionContext?.event === 'BATCH_FAILED');
    expect(failedCalls.length).toBe(1);
  });

  it('BATCH_FAILED uses BLOCK decision', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeFailEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_FAILED');
    expect(call[0].decision).toBe('BLOCK');
    expect(call[0].verificationResult).toBe(false);
  });

  it('BATCH_FAILED executionContext includes failed count', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeFailEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_FAILED');
    expect(call[0].executionContext.failed).toBe(1);
    expect(call[0].executionContext.succeeded).toBe(0);
  });

  it('BATCH_FAILED artifactId is batchId:BATCH_FAILED', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeFailEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_FAILED');
    expect(call[0].artifactId).toBe(`${batch.batchId}:BATCH_FAILED`);
  });
});

// ── BATCH_CANCELLED ───────────────────────────────────────────────────────────

describe('audit — BATCH_CANCELLED', () => {
  it('calls append() with BATCH_CANCELLED when batch is cancelled', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = makeBatch();
    await store.save(batch);

    await service.cancelBatch(batch.batchId, { requestedBy: 'admin' });

    const cancelledCalls = mockAppend.mock.calls.filter(([a]) => a.executionContext?.event === 'BATCH_CANCELLED');
    expect(cancelledCalls.length).toBe(1);
  });

  it('BATCH_CANCELLED uses BLOCK decision', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = makeBatch();
    await store.save(batch);

    await service.cancelBatch(batch.batchId, { requestedBy: 'admin' });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CANCELLED');
    expect(call[0].decision).toBe('BLOCK');
    expect(call[0].verificationResult).toBe(false);
  });

  it('BATCH_CANCELLED artifactId is batchId:BATCH_CANCELLED', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = makeBatch();
    await store.save(batch);

    await service.cancelBatch(batch.batchId, { requestedBy: 'admin' });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CANCELLED');
    expect(call[0].artifactId).toBe(`${batch.batchId}:BATCH_CANCELLED`);
  });

  it('BATCH_CANCELLED executionContext includes stage=BATCH_LIFECYCLE', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = makeBatch();
    await store.save(batch);

    await service.cancelBatch(batch.batchId, { requestedBy: 'admin' });

    const call = mockAppend.mock.calls.find(([a]) => a.executionContext?.event === 'BATCH_CANCELLED');
    expect(call[0].executionContext.stage).toBe('BATCH_LIFECYCLE');
    expect(call[0].executionContext.batchId).toBe(batch.batchId);
  });
});

// ── append() invocation verification ─────────────────────────────────────────

describe('audit — append() invocation verification', () => {
  it('full lifecycle generates 3 append() calls: CREATED, STARTED, COMPLETED', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });

    const batch = await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });
    // Wait for background processing to complete
    await new Promise(r => setImmediate(r));
    await new Promise(r => setImmediate(r));

    const events = mockAppend.mock.calls.map(([a]) => a.executionContext?.event);
    expect(events).toContain('BATCH_CREATED');
    expect(events).toContain('BATCH_STARTED');
    expect(events).toContain('BATCH_COMPLETED');
  });

  it('each audit event has a unique artifactId', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const artifactIds = mockAppend.mock.calls.map(([a]) => a.artifactId);
    const unique      = new Set(artifactIds);
    expect(unique.size).toBe(artifactIds.length);
  });

  it('all audit records include a 64-char hex policyHash', async () => {
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    for (const [record] of mockAppend.mock.calls) {
      expect(record.policyHash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('all audit records have inputHash !== requestHash only if distinct', async () => {
    // inputHash and requestHash are both derived from the payload — they should be equal
    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    for (const [record] of mockAppend.mock.calls) {
      expect(record.inputHash).toBe(record.requestHash);
    }
  });
});

// ── Audit failure isolation ───────────────────────────────────────────────────

describe('audit — failure isolation', () => {
  it('batch processing completes even when append() throws on BATCH_STARTED', async () => {
    mockAppend.mockImplementation(({ artifactId }) => {
      if (artifactId && artifactId.includes('BATCH_STARTED')) throw new Error('audit unavailable');
      return { hash: 'mock-hash' };
    });

    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    const result = await processor.processBatch(batch.batchId);
    expect(result.status).toBe('completed');
  });

  it('batch processing completes even when append() throws on BATCH_COMPLETED', async () => {
    mockAppend.mockImplementation(({ artifactId }) => {
      if (artifactId && artifactId.includes('BATCH_COMPLETED')) throw new Error('audit unavailable');
      return { hash: 'mock-hash' };
    });

    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    const result = await processor.processBatch(batch.batchId);
    expect(result.status).toBe('completed');
  });

  it('BATCH_AUDIT_APPEND_FAILED is emitted when append() throws', async () => {
    mockAppend.mockImplementation(() => { throw new Error('disk full'); });

    const store     = createBatchStore();
    const processor = createBatchProcessor({ store, evaluationEngine: makeSuccessEngine() });
    const batch     = makeBatch();
    await store.save(batch);

    await processor.processBatch(batch.batchId);

    const failEvents = mockEmit.mock.calls.filter(([, type]) => type === 'BATCH_AUDIT_APPEND_FAILED');
    expect(failEvents.length).toBeGreaterThan(0);
  });

  it('batch creation completes even when append() throws on BATCH_CREATED', async () => {
    mockAppend.mockImplementation(() => { throw new Error('audit system down'); });

    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });

    // createBatch must not throw even though append() throws
    const batch = await service.createBatch({
      frameworkId: 'SOC2', items: [{ subjectId: 's1' }],
      tenantId: 'tenant-001', requestedBy: 'user', requestId: null,
    });

    // Batch was still persisted despite audit failure
    const saved = await store.get(batch.batchId);
    expect(saved).not.toBeNull();
  });

  it('batch cancellation completes even when append() throws on BATCH_CANCELLED', async () => {
    const store   = createBatchStore();
    const service = createBatchService({ store, evaluationEngine: makeSuccessEngine() });
    const batch   = makeBatch();
    await store.save(batch);

    mockAppend.mockImplementation(() => { throw new Error('audit system down'); });

    const result = await service.cancelBatch(batch.batchId, { requestedBy: 'admin' });
    expect(result.status).toBe('cancelled');
  });
});
