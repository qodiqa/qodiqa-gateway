'use strict';

const os   = require('os');
const path = require('path');
const fs   = require('fs');
const { createBatchStore, buildBatch, VALID_TRANSITIONS } = require('../store');

function makeBatch(overrides = {}) {
  return buildBatch({
    frameworkId: 'SOC2',
    tenantId:    'tenant-001',
    requestedBy: 'user@example.com',
    requestId:   'req_abc',
    items: [
      { subjectId: 'subject-1', artifacts: [], evidencePackages: [] },
      { subjectId: 'subject-2', artifacts: [], evidencePackages: [] },
    ],
    ...overrides,
  });
}

// ── In-memory store ───────────────────────────────────────────────────────────

describe('createBatchStore — memory', () => {
  let store;
  beforeEach(() => { store = createBatchStore(); });

  it('save and get round-trips', async () => {
    const batch = makeBatch();
    await store.save(batch);
    const got = await store.get(batch.batchId);
    expect(got).not.toBeNull();
    expect(got.batchId).toBe(batch.batchId);
    expect(got.frameworkId).toBe('SOC2');
  });

  it('get returns null for unknown id', async () => {
    expect(await store.get('batch_' + '0'.repeat(32))).toBeNull();
  });

  it('update merges patch onto batch', async () => {
    const batch = makeBatch();
    await store.save(batch);
    const updated = await store.update(batch.batchId, { status: 'running', startedAt: '2024-01-01T00:00:00.000Z' });
    expect(updated.status).toBe('running');
    expect(updated.startedAt).toBe('2024-01-01T00:00:00.000Z');
  });

  it('update throws NOT_FOUND for unknown batchId', async () => {
    await expect(store.update('batch_' + '0'.repeat(32), { status: 'running' }))
      .rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('updateItem updates a single item', async () => {
    const batch = makeBatch();
    await store.save(batch);
    const itemId = batch.items[0].itemId;
    const updated = await store.updateItem(batch.batchId, itemId, { status: 'running' });
    expect(updated.status).toBe('running');
  });

  it('updateItem throws NOT_FOUND for unknown item', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await expect(store.updateItem(batch.batchId, 'item_bad', { status: 'running' }))
      .rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('listByTenant filters by tenantId', async () => {
    const b1 = makeBatch({ tenantId: 'tenant-A' });
    const b2 = makeBatch({ tenantId: 'tenant-B' });
    await store.save(buildBatch({ ...b1 }));
    await store.save(buildBatch({ ...b2 }));
    await store.save(b1);
    await store.save(b2);
    const list = await store.listByTenant('tenant-A');
    expect(list.every(b => b.tenantId === 'tenant-A')).toBe(true);
  });

  it('remove deletes the batch', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await store.remove(batch.batchId);
    expect(await store.get(batch.batchId)).toBeNull();
  });

  it('returns cloned objects (mutations do not affect store)', async () => {
    const batch = makeBatch();
    await store.save(batch);
    const got = await store.get(batch.batchId);
    got.status = 'MUTATED';
    const got2 = await store.get(batch.batchId);
    expect(got2.status).toBe('pending');
  });
});

// ── State machine ─────────────────────────────────────────────────────────────

describe('createBatchStore — state transitions', () => {
  let store;
  beforeEach(() => { store = createBatchStore(); });

  it('allows pending → running', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await expect(store.update(batch.batchId, { status: 'running' })).resolves.toBeTruthy();
  });

  it('allows running → completed', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await store.update(batch.batchId, { status: 'running' });
    await expect(store.update(batch.batchId, { status: 'completed' })).resolves.toBeTruthy();
  });

  it('allows running → failed', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await store.update(batch.batchId, { status: 'running' });
    await expect(store.update(batch.batchId, { status: 'failed' })).resolves.toBeTruthy();
  });

  it('allows pending → cancelled', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await expect(store.update(batch.batchId, { status: 'cancelled' })).resolves.toBeTruthy();
  });

  it('rejects pending → completed (invalid)', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await expect(store.update(batch.batchId, { status: 'completed' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
  });

  it('rejects running → pending (invalid)', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await store.update(batch.batchId, { status: 'running' });
    await expect(store.update(batch.batchId, { status: 'pending' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
  });

  it('rejects completed → running (terminal)', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await store.update(batch.batchId, { status: 'running' });
    await store.update(batch.batchId, { status: 'completed' });
    await expect(store.update(batch.batchId, { status: 'running' }))
      .rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
  });

  it('no-ops same-status update', async () => {
    const batch = makeBatch();
    await store.save(batch);
    await expect(store.update(batch.batchId, { status: 'pending' })).resolves.toBeTruthy();
  });
});

// ── File-backed store ─────────────────────────────────────────────────────────

describe('createBatchStore — file-backed', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = path.join(os.tmpdir(), 'batch-store-test-' + Date.now());
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  it('persists batch to disk and survives store re-creation', async () => {
    const store1 = createBatchStore({ dir: tmpDir });
    const batch  = makeBatch();
    await store1.save(batch);

    const store2 = createBatchStore({ dir: tmpDir });
    const got    = await store2.get(batch.batchId);
    expect(got).not.toBeNull();
    expect(got.batchId).toBe(batch.batchId);
  });

  it('persists updated status to disk', async () => {
    const store1 = createBatchStore({ dir: tmpDir });
    const batch  = makeBatch();
    await store1.save(batch);
    await store1.update(batch.batchId, { status: 'running' });

    const store2 = createBatchStore({ dir: tmpDir });
    const got    = await store2.get(batch.batchId);
    expect(got.status).toBe('running');
  });

  it('remove deletes the file', async () => {
    const store1 = createBatchStore({ dir: tmpDir });
    const batch  = makeBatch();
    await store1.save(batch);
    await store1.remove(batch.batchId);

    const store2 = createBatchStore({ dir: tmpDir });
    expect(await store2.get(batch.batchId)).toBeNull();
  });

  it('creates data directory if it does not exist', () => {
    const nested = path.join(tmpDir, 'sub', 'dir');
    expect(() => createBatchStore({ dir: nested })).not.toThrow();
    expect(fs.existsSync(nested)).toBe(true);
  });
});

// ── buildBatch ─────────────────────────────────────────────────────────────────

describe('buildBatch', () => {
  it('generates unique batchId for each call', () => {
    const a = buildBatch({ frameworkId: 'X', items: [{ subjectId: 's1' }] });
    const b = buildBatch({ frameworkId: 'X', items: [{ subjectId: 's1' }] });
    expect(a.batchId).not.toBe(b.batchId);
  });

  it('batchId has batch_ prefix', () => {
    const batch = buildBatch({ frameworkId: 'X', items: [{ subjectId: 's1' }] });
    expect(batch.batchId).toMatch(/^batch_[0-9a-f]{32}$/);
  });

  it('each item gets unique itemId', () => {
    const batch = buildBatch({
      frameworkId: 'X',
      items: [{ subjectId: 's1' }, { subjectId: 's2' }],
    });
    expect(batch.items[0].itemId).not.toBe(batch.items[1].itemId);
  });

  it('initial status is pending', () => {
    const batch = buildBatch({ frameworkId: 'X', items: [{ subjectId: 's1' }] });
    expect(batch.status).toBe('pending');
    expect(batch.items[0].status).toBe('pending');
  });

  it('defaults missing item fields to empty arrays/null', () => {
    const batch = buildBatch({ frameworkId: 'X', items: [{ subjectId: 's1' }] });
    const item  = batch.items[0];
    expect(item.artifacts).toEqual([]);
    expect(item.evidencePackages).toEqual([]);
    expect(item.controls).toEqual({});
    expect(item.certificationId).toBeNull();
    expect(item.result).toBeNull();
    expect(item.error).toBeNull();
  });
});

// ── VALID_TRANSITIONS export ───────────────────────────────────────────────────

describe('VALID_TRANSITIONS', () => {
  it('is frozen', () => {
    expect(Object.isFrozen(VALID_TRANSITIONS)).toBe(true);
  });

  it('terminal states have empty transition lists', () => {
    for (const state of ['completed', 'failed', 'cancelled']) {
      expect(VALID_TRANSITIONS[state]).toEqual([]);
    }
  });
});
