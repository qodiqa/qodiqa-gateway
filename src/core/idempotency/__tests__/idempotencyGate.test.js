'use strict';

// Small, deterministic wait/poll bounds so concurrency tests run fast.
// Must be set before idempotencyGate.js is first required — its constants
// are read from process.env once at module load time.
process.env.IDEMPOTENCY_WAIT_TIMEOUT_MS = '400';
process.env.IDEMPOTENCY_POLL_INTERVAL_MS = '40';
process.env.IDEMPOTENCY_RETENTION_TTL_MS = '86400000';

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const idempotencyGate = require('../idempotencyGate');
const { makeIdempotencyStore } = require('../../../testing/stores');

const BASE_PARAMS = {
  idempotencyKey:   'idem-key-1',
  tenantId:         'acme',
  organizationId:   'org-1',
  publicKeyId:      'acme:key_v1',
  callerId:         'user-1',
  provider:         'openai',
  requestHash:      'a'.repeat(64),
  reservationTtlMs: 60_000,
};

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

describe('idempotencyGate.gate', () => {
  test('fresh key: outcome is "proceed" with a populated ctx', async () => {
    const store = makeIdempotencyStore();
    const result = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    expect(result.outcome).toBe('proceed');
    expect(result.ctx).toMatchObject({
      tenantId: 'acme',
      idempotencyKey: 'idem-key-1',
      retentionTtlMs: 86_400_000,
    });
    expect(typeof result.ctx.fingerprint).toBe('string');
  });

  test('same key + same fingerprint, already completed: outcome is "replay" with the stored record', async () => {
    const store = makeIdempotencyStore();
    const first = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    await idempotencyGate.complete(first.ctx, { httpStatus: 200, body: { response: 'hello' } });

    const second = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    expect(second.outcome).toBe('replay');
    expect(second.record).toMatchObject({ status: 'completed', httpStatus: 200, body: { response: 'hello' } });
  });

  test('same key, different fingerprint (different requestHash), already completed: outcome is "conflict"', async () => {
    const store = makeIdempotencyStore();
    const first = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    await idempotencyGate.complete(first.ctx, { httpStatus: 200, body: {} });

    const second = await idempotencyGate.gate({ ...BASE_PARAMS, requestHash: 'b'.repeat(64), _store: store });
    expect(second.outcome).toBe('conflict');
    expect(second.reason).toBe('IDEMPOTENCY_KEY_CONFLICT');
  });

  test('same key, different fingerprint, still pending: outcome is "conflict" immediately (no wait)', async () => {
    const store = makeIdempotencyStore();
    await idempotencyGate.gate({ ...BASE_PARAMS, _store: store }); // leaves it pending — never completed

    const start = Date.now();
    const second = await idempotencyGate.gate({ ...BASE_PARAMS, requestHash: 'c'.repeat(64), _store: store });
    expect(second.outcome).toBe('conflict');
    expect(Date.now() - start).toBeLessThan(100); // did not wait out the poll budget
  });

  test('different idempotencyKey: independent reservation, both proceed', async () => {
    const store = makeIdempotencyStore();
    const a = await idempotencyGate.gate({ ...BASE_PARAMS, idempotencyKey: 'key-a', _store: store });
    const b = await idempotencyGate.gate({ ...BASE_PARAMS, idempotencyKey: 'key-b', _store: store });
    expect(a.outcome).toBe('proceed');
    expect(b.outcome).toBe('proceed');
  });

  test('tenant isolation: identical key + identical fingerprint under a different tenant is an independent reservation', async () => {
    const store = makeIdempotencyStore();
    const a = await idempotencyGate.gate({ ...BASE_PARAMS, tenantId: 'tenant-a', _store: store });
    await idempotencyGate.complete(a.ctx, { httpStatus: 200, body: { from: 'a' } });

    const b = await idempotencyGate.gate({ ...BASE_PARAMS, tenantId: 'tenant-b', _store: store });
    expect(b.outcome).toBe('proceed'); // NOT a replay of tenant-a's completed record
  });

  test('concurrent duplicate requests: only one proceeds, the other replays once the first completes — provider-equivalent work runs exactly once', async () => {
    const store = makeIdempotencyStore();
    let executionCount = 0;

    async function simulateRequest() {
      const result = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
      if (result.outcome === 'proceed') {
        executionCount += 1;
        await sleep(80); // simulate provider latency
        await idempotencyGate.complete(result.ctx, { httpStatus: 200, body: { response: 'hi' } });
        return { outcome: 'proceed' };
      }
      return result;
    }

    const [r1, r2] = await Promise.all([simulateRequest(), simulateRequest()]);
    const outcomes = [r1.outcome, r2.outcome].sort();

    expect(executionCount).toBe(1); // the "provider" ran exactly once
    expect(outcomes).toEqual(['proceed', 'replay']);
  });

  test('pending duplicate that never completes within the wait budget: outcome is "in_progress"', async () => {
    const store = makeIdempotencyStore();
    await idempotencyGate.gate({ ...BASE_PARAMS, _store: store }); // never completed — simulates a stuck/slow first attempt

    const second = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    expect(second.outcome).toBe('in_progress');
    expect(second.reason).toBe('IDEMPOTENCY_REQUEST_IN_PROGRESS');
  });

  test('a released reservation is immediately available for a fresh attempt', async () => {
    const store = makeIdempotencyStore();
    const first = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    await idempotencyGate.release(first.ctx);

    const second = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    expect(second.outcome).toBe('proceed');
  });

  test('store unavailable: outcome is "store_unavailable", never throws', async () => {
    const deadStore = {
      reserve: async () => { throw new Error('ECONNREFUSED'); },
    };
    const result = await idempotencyGate.gate({ ...BASE_PARAMS, _store: deadStore });
    expect(result.outcome).toBe('store_unavailable');
    expect(result.reason).toBe('IDEMPOTENCY_STORE_UNAVAILABLE');
  });
});

describe('idempotencyGate.complete / release', () => {
  test('complete() and release() are safe no-ops when ctx is null (no Idempotency-Key supplied)', async () => {
    await expect(idempotencyGate.complete(null, { httpStatus: 200, body: {} })).resolves.toBeUndefined();
    await expect(idempotencyGate.release(null)).resolves.toBeUndefined();
  });

  test('complete() failure is swallowed (best-effort) — never throws back into the request path', async () => {
    const store = makeIdempotencyStore();
    const { ctx } = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    ctx.store = { complete: async () => { throw new Error('store down'); } };
    await expect(idempotencyGate.complete(ctx, { httpStatus: 200, body: {} })).resolves.toBeUndefined();
  });

  test('release() failure is swallowed (best-effort) — never throws back into the request path', async () => {
    const store = makeIdempotencyStore();
    const { ctx } = await idempotencyGate.gate({ ...BASE_PARAMS, _store: store });
    ctx.store = { release: async () => { throw new Error('store down'); } };
    await expect(idempotencyGate.release(ctx)).resolves.toBeUndefined();
  });
});
