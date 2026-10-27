'use strict';

/**
 * Pool Transaction Isolation Tests — Component #18
 *
 * PI-01 … PI-04  withTransaction: isolation level in BEGIN, COMMIT on success,
 *                ROLLBACK on throw, caller-supplied isolation level
 * PI-05 … PI-08  withSerializableTransaction: retry on SQLSTATE 40001,
 *                no retry on other errors, maxAttempts exhaustion, emit on retry
 *
 * Strategy: pool.js is a singleton with module-level state (_pool, _enabled).
 * Each test uses jest.resetModules() + jest.doMock() to load a fresh pool
 * instance backed by a fake pg.Pool, so no real database connection is needed.
 */

// ── PI-01 … PI-04: withTransaction ───────────────────────────────────────────

describe('PI-01 … PI-04: pool.withTransaction isolation and lifecycle', () => {
  let mockClientQuery;
  let mockClientRelease;

  function loadPool() {
    process.env.QODIQA_PG_ENABLED = 'true';
    const pool = require('../pool');
    pool.initialize();
    return pool;
  }

  beforeEach(() => {
    jest.resetModules();

    mockClientQuery   = jest.fn().mockResolvedValue({ rows: [], rowCount: 0 });
    mockClientRelease = jest.fn();

    const client = { query: mockClientQuery, release: mockClientRelease };
    jest.doMock('pg', () => ({
      Pool: jest.fn().mockImplementation(() => ({
        connect:      jest.fn().mockResolvedValue(client),
        on:           jest.fn(),
        end:          jest.fn().mockResolvedValue(),
        waitingCount: 0,
        options:      { max: 10 },
      })),
    }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
  });

  test('PI-01 opens with REPEATABLE READ by default', async () => {
    const pool = loadPool();

    await pool.withTransaction(async () => {});

    const sqls = mockClientQuery.mock.calls.map(c => c[0]);
    expect(sqls[0]).toBe('BEGIN ISOLATION LEVEL REPEATABLE READ');
  });

  test('PI-02 commits and releases the client on success', async () => {
    const pool   = loadPool();
    const result = await pool.withTransaction(async () => 'value');

    const sqls = mockClientQuery.mock.calls.map(c => c[0]);
    expect(sqls).toContain('COMMIT');
    expect(sqls).not.toContain('ROLLBACK');
    expect(mockClientRelease).toHaveBeenCalledTimes(1);
    expect(result).toBe('value');
  });

  test('PI-03 rolls back and releases the client when fn throws', async () => {
    const pool = loadPool();

    await expect(
      pool.withTransaction(async () => { throw new Error('work failed'); })
    ).rejects.toThrow('work failed');

    const sqls = mockClientQuery.mock.calls.map(c => c[0]);
    expect(sqls).toContain('ROLLBACK');
    expect(sqls).not.toContain('COMMIT');
    expect(mockClientRelease).toHaveBeenCalledTimes(1);
  });

  test('PI-04 uses a caller-supplied isolation level', async () => {
    const pool = loadPool();

    await pool.withTransaction(async () => {}, { isolationLevel: 'SERIALIZABLE' });

    const sqls = mockClientQuery.mock.calls.map(c => c[0]);
    expect(sqls[0]).toBe('BEGIN ISOLATION LEVEL SERIALIZABLE');
  });
});

// ── PI-05 … PI-08: withSerializableTransaction ────────────────────────────────

describe('PI-05 … PI-08: pool.withSerializableTransaction retry logic', () => {
  let mockClientQuery;
  let mockClientRelease;
  let mockEmit;

  function loadPool() {
    process.env.QODIQA_PG_ENABLED = 'true';
    const pool = require('../pool');
    pool.initialize();
    return pool;
  }

  function serializationError() {
    const e = new Error('could not serialize access');
    e.code  = '40001';
    return e;
  }

  beforeEach(() => {
    jest.resetModules();

    mockClientRelease = jest.fn();
    mockClientQuery   = jest.fn();
    mockEmit          = jest.fn();

    const client = { query: mockClientQuery, release: mockClientRelease };
    jest.doMock('pg', () => ({
      Pool: jest.fn().mockImplementation(() => ({
        connect:      jest.fn().mockResolvedValue(client),
        on:           jest.fn(),
        end:          jest.fn().mockResolvedValue(),
        waitingCount: 0,
        options:      { max: 10 },
      })),
    }));
    jest.doMock('../../../../services/logger', () => ({ emit: mockEmit }));
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
  });

  test('PI-05 retries on SQLSTATE 40001 and succeeds on second attempt', async () => {
    let commitCount = 0;
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql === 'COMMIT' && ++commitCount === 1) throw serializationError();
      return { rows: [], rowCount: 0 };
    });

    const pool   = loadPool();
    const result = await pool.withSerializableTransaction(async () => 'ok');

    expect(result).toBe('ok');
    expect(commitCount).toBe(2);
  });

  test('PI-06 does not retry on non-serialization errors', async () => {
    let commitCount = 0;
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql === 'COMMIT') {
        commitCount++;
        const e = new Error('disk full'); e.code = '53100'; throw e;
      }
      return { rows: [], rowCount: 0 };
    });

    const pool = loadPool();
    await expect(
      pool.withSerializableTransaction(async () => 'ok')
    ).rejects.toThrow('disk full');
    expect(commitCount).toBe(1);
  });

  test('PI-07 exhausts maxAttempts and rethrows the last 40001 error', async () => {
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql === 'COMMIT') throw serializationError();
      return { rows: [], rowCount: 0 };
    });

    const pool = loadPool();
    await expect(
      pool.withSerializableTransaction(async () => 'ok', { maxAttempts: 3, label: 'test-label' })
    ).rejects.toThrow('could not serialize access');

    const commits = mockClientQuery.mock.calls.filter(c => c[0] === 'COMMIT');
    expect(commits).toHaveLength(3);
  });

  test('PI-08 emits PG_SERIALIZATION_RETRY for each retry before success', async () => {
    let commitCount = 0;
    mockClientQuery.mockImplementation(async (sql) => {
      if (sql === 'COMMIT' && ++commitCount < 3) throw serializationError();
      return { rows: [], rowCount: 0 };
    });

    const pool = loadPool();
    await pool.withSerializableTransaction(async () => 'ok', { label: 'op-label' });

    const retries = mockEmit.mock.calls.filter(c => c[1] === 'PG_SERIALIZATION_RETRY');
    expect(retries).toHaveLength(2);
    expect(retries[0][2]).toMatchObject({ label: 'op-label', attempt: 1 });
    expect(retries[1][2]).toMatchObject({ label: 'op-label', attempt: 2 });
  });
});
