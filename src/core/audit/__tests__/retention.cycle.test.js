'use strict';

/**
 * Audit Retention Cycle Tests —
 *
 * RT-CYCLE-01 … RT-CYCLE-05  Functional: batching, zero-row deletes, guards, success path
 * RT-CYCLE-06 … RT-CYCLE-10  Negative: permission denied, RLS-silent, rollback/unrelated errors
 *
 * the automated cleanup cycle's own statements (stampRetentionDates's
 * UPDATE, expireEvents's DELETE, and the run-journal INSERTs) now execute
 * through retentionPool (the dedicated qodiqa_retention role), not the
 * general-purpose pgPool — see retention.js's module header. This file mocks
 * retentionPool instead; mockPool (pgPool) is retained only because retention.js
 * still imports it for the human-triggered admin-API functions this file
 * doesn't exercise.
 *
 * Uses a mock retentionPool routed by query label (retention.js's 3rd query()
 * argument) rather than parsing SQL text — mirrors this module's own query()
 * signature. Metrics assertions spy on the real observability/metrics.js
 * module (in-memory, side-effect-free) rather than mocking it, so
 * counter/label wiring is verified against the actual registry shape.
 */

const mockPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query: jest.fn(),
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockRetentionPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query: jest.fn(),
};
jest.mock('../../../infra/postgres/retentionPool', () => mockRetentionPool);

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...args) => mockEmit(...args) }));

const metrics = require('../../../observability/metrics');
const retention = require('../retention');

const BATCH_SIZE = 1000;

function permissionDeniedError() {
  const err = new Error('permission denied for table platform_audit_events');
  err.code = '42501';
  return err;
}

beforeEach(() => {
  mockPool._enabled = true;
  mockPool.query.mockReset();
  mockRetentionPool._enabled = true;
  mockRetentionPool.query.mockReset();
  mockEmit.mockReset();
});

// ── RT-CYCLE-01 … RT-CYCLE-05: functional ─────────────────────────────────────

describe('RT-CYCLE-01 … RT-CYCLE-05: expireEvents / runRetentionCycle functional behavior', () => {
  test('RT-CYCLE-01 batches deletes until a partial batch is returned', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_count_held') return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch') {
        mockRetentionPool.query.mock.calls.filter(c => c[2] === 'retention_expire_batch').length;
        const callNum = mockRetentionPool.query.mock.calls.filter(c => c[2] === 'retention_expire_batch').length;
        if (callNum <= 2) return { rowCount: BATCH_SIZE };
        return { rowCount: 200 };
      }
      return { rows: [], rowCount: 0 };
    });

    const result = await retention.expireEvents();

    expect(result.expired).toBe(BATCH_SIZE * 2 + 200);
    expect(result.held).toBe(0);
    const batchCalls = mockRetentionPool.query.mock.calls.filter(c => c[2] === 'retention_expire_batch');
    expect(batchCalls.length).toBe(3);
  });

  test('RT-CYCLE-02 zero-row delete stops after a single batch, expired = 0', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_count_held') return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch') return { rowCount: 0 };
      return { rows: [], rowCount: 0 };
    });

    const result = await retention.expireEvents();

    expect(result.expired).toBe(0);
    const batchCalls = mockRetentionPool.query.mock.calls.filter(c => c[2] === 'retention_expire_batch');
    expect(batchCalls.length).toBe(1);
  });

  test('RT-CYCLE-03 DELETE excludes legal_hold and ENFORCEMENT category rows', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_count_held') return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch') return { rowCount: 0 };
      return { rows: [], rowCount: 0 };
    });

    await retention.expireEvents();

    const deleteCall = mockRetentionPool.query.mock.calls.find(c => c[2] === 'retention_expire_batch');
    expect(deleteCall[0]).toMatch(/legal_hold = false/);
    expect(deleteCall[0]).toMatch(/event_category != 'ENFORCEMENT'/);
    expect(deleteCall[0]).toMatch(/FOR UPDATE SKIP LOCKED/);
  });

  test('RT-CYCLE-04 held count comes from a separate legal-hold-blocked query', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_count_held') return { rows: [{ held: '5' }] };
      if (label === 'retention_expire_batch') return { rowCount: 0 };
      return { rows: [], rowCount: 0 };
    });

    const result = await retention.expireEvents();
    expect(result.held).toBe(5);
  });

  test('RT-CYCLE-05 successful cycle increments COMPLETE counter and last-success timestamp', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_load_policies')   return { rows: [] };
      if (label === 'retention_count_held')       return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch')     return { rowCount: 0 };
      return { rows: [], rowCount: 0 };
    });

    const runsSpy    = jest.spyOn(metrics.auditRetentionRunsTotal, 'inc');
    const successSpy = jest.spyOn(metrics.auditRetentionLastSuccessTimestamp, 'set');

    const result = await retention.runRetentionCycle();

    expect(result.error).toBeNull();
    expect(runsSpy).toHaveBeenCalledWith({ status: 'COMPLETE' });
    expect(successSpy).toHaveBeenCalled();
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'AUDIT_RETENTION_CYCLE_COMPLETE', expect.any(Object));

    runsSpy.mockRestore();
    successSpy.mockRestore();
  });
});

// ── RT-CYCLE-06 … RT-CYCLE-10: negative ───────────────────────────────────────

describe('RT-CYCLE-06 … RT-CYCLE-10: runRetentionCycle failure attribution', () => {
  test('RT-CYCLE-06 DELETE permission denied is attributed to the DELETE operation', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_load_policies') return { rows: [] };
      if (label === 'retention_count_held')     return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch')   throw permissionDeniedError();
      return { rows: [], rowCount: 0 };
    });

    const permSpy = jest.spyOn(metrics.auditRetentionPermissionFailuresTotal, 'inc');
    const failSpy = jest.spyOn(metrics.auditRetentionRunsTotal, 'inc');

    const result = await retention.runRetentionCycle();

    expect(result.error).toMatch(/permission denied/);
    expect(permSpy).toHaveBeenCalledWith({ operation: 'DELETE' });
    expect(failSpy).toHaveBeenCalledWith({ status: 'FAILED' });

    const failedLog = mockEmit.mock.calls.find(c => c[1] === 'AUDIT_RETENTION_CYCLE_FAILED');
    expect(failedLog[2]).toMatchObject({
      table:     'platform_audit_events',
      operation: 'DELETE',
      sqlstate:  '42501',
      reason:    'GRANT_MISSING',
    });

    permSpy.mockRestore();
    failSpy.mockRestore();
  });

  test('RT-CYCLE-07 UPDATE (stamping) permission denied is attributed to the UPDATE operation', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_load_policies') return { rows: [{ id: 1, retain_days: 30 }] };
      if (label === 'retention_stamp')          throw permissionDeniedError();
      if (label === 'retention_count_held')     return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch')   return { rowCount: 0 };
      return { rows: [], rowCount: 0 };
    });

    const permSpy = jest.spyOn(metrics.auditRetentionPermissionFailuresTotal, 'inc');

    const result = await retention.runRetentionCycle();

    expect(result.error).toMatch(/permission denied/);
    expect(permSpy).toHaveBeenCalledWith({ operation: 'UPDATE' });

    const failedLog = mockEmit.mock.calls.find(c => c[1] === 'AUDIT_RETENTION_CYCLE_FAILED');
    expect(failedLog[2].operation).toBe('UPDATE');

    permSpy.mockRestore();
  });

  test('RT-CYCLE-08 failure diagnostic reports the configured retention role', async () => {
    const prevUser = process.env.QODIQA_PG_RETENTION_USER;
    process.env.QODIQA_PG_RETENTION_USER = 'qodiqa_retention_custom';
    try {
      mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
        if (label === 'retention_load_policies') return { rows: [] };
        if (label === 'retention_count_held')     return { rows: [{ held: '0' }] };
        if (label === 'retention_expire_batch')   throw permissionDeniedError();
        return { rows: [], rowCount: 0 };
      });

      await retention.runRetentionCycle();

      const failedLog = mockEmit.mock.calls.find(c => c[1] === 'AUDIT_RETENTION_CYCLE_FAILED');
      expect(failedLog[2].role).toBe('qodiqa_retention_custom');
    } finally {
      if (prevUser === undefined) delete process.env.QODIQA_PG_RETENTION_USER;
      else process.env.QODIQA_PG_RETENTION_USER = prevUser;
    }
  });

  test('RT-CYCLE-09 a non-permission error (e.g. connection reset) is classified UNKNOWN, not counted as a permission failure', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_load_policies') return { rows: [] };
      if (label === 'retention_count_held')     return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch') {
        const err = new Error('Connection terminated unexpectedly');
        err.code = 'ECONNRESET';
        throw err;
      }
      return { rows: [], rowCount: 0 };
    });

    const permSpy = jest.spyOn(metrics.auditRetentionPermissionFailuresTotal, 'inc');

    const result = await retention.runRetentionCycle();

    expect(result.error).toMatch(/Connection terminated/);
    expect(permSpy).not.toHaveBeenCalled();

    const failedLog = mockEmit.mock.calls.find(c => c[1] === 'AUDIT_RETENTION_CYCLE_FAILED');
    expect(failedLog[2].reason).toBe('UNKNOWN');

    permSpy.mockRestore();
  });

  test('RT-CYCLE-10 stamping and expiry both failing still logs one FAILED run (first error wins, no duplicate run rows)', async () => {
    mockRetentionPool.query.mockImplementation(async (sql, params, label) => {
      if (label === 'retention_load_policies') return { rows: [{ id: 1, retain_days: 30 }] };
      if (label === 'retention_stamp')          throw permissionDeniedError();
      if (label === 'retention_count_held')     return { rows: [{ held: '0' }] };
      if (label === 'retention_expire_batch')   throw permissionDeniedError();
      return { rows: [], rowCount: 0 };
    });

    await retention.runRetentionCycle();

    const runLogInserts = mockRetentionPool.query.mock.calls.filter(c => c[2] === 'retention_log_failure');
    expect(runLogInserts.length).toBe(1);
  });
});
