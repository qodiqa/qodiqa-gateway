'use strict';

/**
 * recovery-queue additions.
 *
 * TS-01…07  TRANSPARENCY_SAVE handler (D3): idempotent on transparencyId,
 *           replays through registrar.register(), classifies failures
 * EO-01…05  enqueueWithOutcome(): reports where the operation became durable
 * WK-01…03 worker: "non-retryable:" results go to the DLQ at once;
 *           retryable ones keep the backoff schedule
 */

jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn(() => true), query: jest.fn(), withTransaction: jest.fn() }));
jest.mock('../../transparency/logStore', () => ({ getByTransparencyId: jest.fn() }));
jest.mock('../../transparency/registrar', () => ({ register: jest.fn() }));
jest.mock('../queue', () => ({
  _isReady: jest.fn(() => true), _connect: jest.fn(), _disconnect: jest.fn(),
  enqueue: jest.fn(), markComplete: jest.fn(), markRetry: jest.fn(), moveToDlq: jest.fn(),
  getStats: jest.fn(), listDlq: jest.fn(),
}));
jest.mock('../journal', () => ({ appendEntry: jest.fn(), getStats: jest.fn() }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const pgPool          = require('../../../infra/postgres/pool');
const logStore        = require('../../transparency/logStore');
const registrar       = require('../../transparency/registrar');
const queue           = require('../queue');
const journal         = require('../journal');
const recoveryManager = require('../recoveryManager');
const worker          = require('../worker');

const { TRANSPARENCY_SAVE } = recoveryManager.OPERATION_TYPES;
const handler = recoveryManager._builtinHandlers[TRANSPARENCY_SAVE];
const TID = '6f1c1a52-3d0e-4d55-9a3c-0d7b5e0b3f11';
const REG = { transparencyId: TID, entryType: 'AUDIT', artifactId: 'req-1', payload: { decision: 'ALLOW' }, registeredBy: 'ai-chat-enforcement', tenantId: null };
const op = (registration = REG) => ({ operationId: `tlog:${TID}`, operationType: TRANSPARENCY_SAVE, retryCount: 0, payload: { registration } });
const connErr = () => Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });

beforeEach(() => {
  jest.clearAllMocks();
  pgPool.isEnabled.mockReturnValue(true);
  queue._isReady.mockReturnValue(true);
});

describe('TRANSPARENCY_SAVE handler', () => {
  test('TS-01 entry already present (original INSERT committed) → success, no second leaf', async () => {
    logStore.getByTransparencyId.mockResolvedValue({ id: 7, transparency_id: TID });
    await expect(handler(op())).resolves.toEqual({ success: true });
    expect(registrar.register).not.toHaveBeenCalled();
  });

  test('TS-02 absent → registrar.register(registration) with the SAME transparencyId and payload', async () => {
    logStore.getByTransparencyId.mockResolvedValue(null);
    registrar.register.mockResolvedValue({ transparencyId: TID, persisted: true });
    await expect(handler(op())).resolves.toEqual({ success: true });
    expect(registrar.register).toHaveBeenCalledWith(REG);
  });

  test('TS-03 register returns persisted:false → failure (not reported as recovered)', async () => {
    logStore.getByTransparencyId.mockResolvedValue(null);
    registrar.register.mockResolvedValue({ transparencyId: TID, persisted: false });
    expect((await handler(op())).success).toBe(false);
  });

  test('TS-04 PG still down → retryable failure', async () => {
    logStore.getByTransparencyId.mockRejectedValue(connErr());
    const r = await handler(op());
    expect(r.success).toBe(false);
    expect(r.error).not.toMatch(/^non-retryable:/);
  });

  test('TS-05 unique violation raced by a concurrent writer that committed the id → success', async () => {
    logStore.getByTransparencyId.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: 9 });
    registrar.register.mockRejectedValue(Object.assign(new Error('duplicate key'), { code: '23505' }));
    await expect(handler(op())).resolves.toEqual({ success: true });
  });

  test('TS-06 deterministic failure (data) → non-retryable', async () => {
    logStore.getByTransparencyId.mockResolvedValue(null);
    registrar.register.mockRejectedValue(Object.assign(new Error('invalid input'), { code: '22P02' }));
    expect((await handler(op())).error).toMatch(/^non-retryable:/);
  });

  test('TS-07 malformed payload → non-retryable', async () => {
    expect((await handler({ ...op(), payload: {} })).error).toMatch(/^non-retryable:/);
  });

  test('TS-08 PG disabled → failure without touching the log', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    expect((await handler(op())).success).toBe(false);
    expect(logStore.getByTransparencyId).not.toHaveBeenCalled();
  });
});

describe('enqueueWithOutcome', () => {
  test('EO-01 PG queue accepts → durable "queue", operation id tlog:<transparencyId>', async () => {
    queue.enqueue.mockResolvedValue();
    const r = await recoveryManager.enqueueWithOutcome(TRANSPARENCY_SAVE, { registration: REG }, connErr());
    expect(r).toEqual({ phantom: null, durable: 'queue' });
    expect(queue.enqueue).toHaveBeenCalledWith(expect.objectContaining({ operationId: `tlog:${TID}`, operationType: TRANSPARENCY_SAVE, service: 'transparency' }));
  });

  test('EO-02 PG enqueue fails → journal → durable "journal"', async () => {
    queue.enqueue.mockRejectedValue(connErr());
    journal.appendEntry.mockResolvedValue();
    const r = await recoveryManager.enqueueWithOutcome(TRANSPARENCY_SAVE, { registration: REG }, connErr());
    expect(r.durable).toBe('journal');
    expect(journal.appendEntry).toHaveBeenCalledWith(expect.objectContaining({ operationId: `tlog:${TID}`, operationType: TRANSPARENCY_SAVE, payload: { registration: REG } }));
  });

  test('EO-03 PG and journal both fail → durable false', async () => {
    queue.enqueue.mockRejectedValue(connErr());
    journal.appendEntry.mockRejectedValue(new Error('ENOSPC'));
    expect((await recoveryManager.enqueueWithOutcome(TRANSPARENCY_SAVE, { registration: REG }, connErr())).durable).toBe(false);
  });

  test('EO-04 queue not ready (PG disabled) → durable false', async () => {
    pgPool.isEnabled.mockReturnValue(false);
    queue._isReady.mockReturnValue(false);
    expect((await recoveryManager.enqueueWithOutcome(TRANSPARENCY_SAVE, { registration: REG }, connErr())).durable).toBe(false);
  });

  test('EO-05 enqueue() keeps its contract: returns only the phantom', async () => {
    queue.enqueue.mockResolvedValue();
    await expect(recoveryManager.enqueue(TRANSPARENCY_SAVE, { registration: REG }, connErr())).resolves.toBeNull();
  });
});

describe('worker — non-retryable results', () => {
  beforeEach(() => {
    worker.registerHandler('W3_TEST_OP', async () => ({ success: false, error: 'non-retryable: value too long' }));
    worker.registerHandler('W3_TEST_RETRY', async () => ({ success: false, error: 'connect ECONNREFUSED' }));
  });

  test('WK-01 "non-retryable:" on the first attempt → DLQ immediately', async () => {
    await worker._processOne({ operationId: 'x1', operationType: 'W3_TEST_OP', retryCount: 0 });
    expect(queue.moveToDlq).toHaveBeenCalledWith('x1', 'non-retryable: value too long', 1);
    expect(queue.markRetry).not.toHaveBeenCalled();
  });

  test('WK-02 retryable failure → rescheduled with the first backoff delay', async () => {
    const t0 = Date.now();
    await worker._processOne({ operationId: 'x2', operationType: 'W3_TEST_RETRY', retryCount: 0 });
    expect(queue.moveToDlq).not.toHaveBeenCalled();
    const [id, err, n, at] = queue.markRetry.mock.calls[0];
    expect([id, err, n]).toEqual(['x2', 'connect ECONNREFUSED', 1]);
    expect(at).toBeGreaterThanOrEqual(t0 + worker.RETRY_DELAYS_MS[0]);
  });

  test('WK-03 retryable failure after MAX_RETRIES → DLQ (unchanged)', async () => {
    await worker._processOne({ operationId: 'x3', operationType: 'W3_TEST_RETRY', retryCount: worker.MAX_RETRIES });
    expect(queue.moveToDlq).toHaveBeenCalledWith('x3', 'connect ECONNREFUSED', worker.MAX_RETRIES + 1);
  });
});
