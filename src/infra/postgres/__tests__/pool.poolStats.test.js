'use strict';

/**
 * PostgreSQL pool telemetry tests —.
 *
 * Covers poolStats() (the lightweight, synchronous, zero-query pool
 * telemetry used by /diagnostics — see pool.js's poolStats() header) and
 * acquisition-failure tracking (withTransaction()'s pool.connect() path).
 *
 * Mirrors pool.readiness.test.js's pattern: fresh module instance per test
 * via jest.resetModules() + jest.doMock('pg', ...), no real database.
 */

function loadPool() {
  process.env.QODIQA_PG_ENABLED = 'true';
  const pool = require('../pool');
  pool.initialize();
  return pool;
}

describe('pool.poolStats()', () => {
  let mockPoolObj;
  let mockMetrics;

  beforeEach(() => {
    jest.resetModules();
    mockPoolObj = {
      query:        jest.fn().mockResolvedValue({ rows: [{ ping: 1 }], rowCount: 1 }),
      connect:      jest.fn(),
      on:           jest.fn(),
      end:          jest.fn().mockResolvedValue(),
      totalCount:   0,
      idleCount:    0,
      waitingCount: 0,
      options:      { max: 10 },
    };
    jest.doMock('pg', () => ({ Pool: jest.fn().mockImplementation(() => mockPoolObj) }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    mockMetrics = {
      pgPoolSize:                 { set: jest.fn() },
      pgPoolActive:               { set: jest.fn() },
      pgPoolIdle:                 { set: jest.fn() },
      pgPoolWaiting:              { set: jest.fn() },
      pgPoolMax:                  { set: jest.fn() },
      pgPoolAcquireFailuresTotal: { inc: jest.fn() },
    };
    jest.doMock('../../../observability/metrics', () => mockMetrics);
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
  });

  test('returns { enabled: false } when the pool has never been initialized', () => {
    process.env.QODIQA_PG_ENABLED = 'false';
    const pool = require('../pool');
    pool.initialize(); // no-op — QODIQA_PG_ENABLED !== 'true'
    expect(pool.poolStats()).toEqual({ enabled: false });
  });

  test('reflects live totalCount/idleCount/waitingCount with no query issued', () => {
    mockPoolObj.totalCount   = 5;
    mockPoolObj.idleCount    = 2;
    mockPoolObj.waitingCount = 0;
    const pool = loadPool();

    const s = pool.poolStats();
    expect(s).toMatchObject({
      enabled: true, size: 5, idle: 2, active: 3, waiting: 0, max: 10,
    });
    expect(mockPoolObj.query).not.toHaveBeenCalled();
  });

  test('active is clamped to zero rather than going negative', () => {
    mockPoolObj.totalCount = 0;
    mockPoolObj.idleCount  = 0;
    const pool = loadPool();
    expect(pool.poolStats().active).toBe(0);
  });

  test('marks saturated when callers are queued (waiting > 0)', () => {
    mockPoolObj.totalCount   = 10;
    mockPoolObj.idleCount    = 0;
    mockPoolObj.waitingCount = 3;
    const pool = loadPool();
    expect(pool.poolStats().saturated).toBe(true);
  });

  test('marks saturated when pool is at max with no idle connections, even with nobody queued yet', () => {
    mockPoolObj.totalCount   = 10;
    mockPoolObj.idleCount    = 0;
    mockPoolObj.waitingCount = 0;
    const pool = loadPool();
    expect(pool.poolStats().saturated).toBe(true);
  });

  test('not saturated when idle connections are available', () => {
    mockPoolObj.totalCount   = 4;
    mockPoolObj.idleCount    = 2;
    mockPoolObj.waitingCount = 0;
    const pool = loadPool();
    expect(pool.poolStats().saturated).toBe(false);
  });

  test('reflects the current _healthy flag alongside pool counters', async () => {
    const pool = loadPool();
    expect(pool.poolStats().healthy).toBe(false); // no probe has completed yet
    await pool.healthCheck();
    expect(pool.poolStats().healthy).toBe(true);
  });

  test('starts with acquireFailures at 0', () => {
    const pool = loadPool();
    expect(pool.poolStats().acquireFailures).toBe(0);
  });
});

describe('pool acquisition-failure tracking', () => {
  let mockPoolObj;
  let mockEmit;
  let mockMetrics;

  beforeEach(() => {
    jest.resetModules();
    mockEmit = jest.fn();
    mockPoolObj = {
      query:        jest.fn().mockResolvedValue({ rows: [{ ping: 1 }], rowCount: 1 }),
      connect:      jest.fn(),
      on:           jest.fn(),
      end:          jest.fn().mockResolvedValue(),
      totalCount:   0,
      idleCount:    0,
      waitingCount: 0,
      options:      { max: 10 },
    };
    jest.doMock('pg', () => ({ Pool: jest.fn().mockImplementation(() => mockPoolObj) }));
    jest.doMock('../../../../services/logger', () => ({ emit: mockEmit }));

    mockMetrics = { pgPoolAcquireFailuresTotal: { inc: jest.fn() } };
    jest.doMock('../../../observability/metrics', () => mockMetrics);
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
  });

  test('withTransaction() increments acquireFailures and rethrows when pool.connect() rejects', async () => {
    mockPoolObj.connect.mockRejectedValue(Object.assign(new Error('timeout exceeded when trying to connect'), { code: 'ETIMEDOUT' }));
    const pool = loadPool();

    await expect(pool.withTransaction(async () => 'unreached')).rejects.toThrow('timeout exceeded');
    expect(pool.poolStats().acquireFailures).toBe(1);
    expect(mockMetrics.pgPoolAcquireFailuresTotal.inc).toHaveBeenCalledWith({});
    expect(mockEmit).toHaveBeenCalledWith('ERROR', 'PG_POOL_ACQUIRE_FAILED', expect.objectContaining({ error: expect.any(String) }));
  });

  test('a successful acquisition does not increment acquireFailures', async () => {
    const mockClient = {
      query:   jest.fn().mockResolvedValue({ rows: [] }),
      release: jest.fn(),
    };
    mockPoolObj.connect.mockResolvedValue(mockClient);
    const pool = loadPool();

    await pool.withTransaction(async () => 'ok');
    expect(pool.poolStats().acquireFailures).toBe(0);
  });

  test('shutdown() resets acquireFailures back to 0', async () => {
    mockPoolObj.connect.mockRejectedValue(new Error('pool exhausted'));
    const pool = loadPool();

    await expect(pool.withTransaction(async () => {})).rejects.toThrow();
    expect(pool.poolStats().acquireFailures).toBe(1);

    await pool.shutdown();
    // Pool is torn down after shutdown; re-initialize to inspect state.
    process.env.QODIQA_PG_ENABLED = 'true';
    pool.initialize();
    expect(pool.poolStats().acquireFailures).toBe(0);
  });
});
