'use strict';

/**
 * PostgreSQL Query Circuit Breaker — Tests (FAILOVER-2 remediation).
 *
 * pool.js is a singleton with module-level state; each test loads a fresh
 * instance (jest.resetModules() + jest.doMock('pg', ...)) backed by a fake
 * pg.Pool so no real database connection is required — same pattern as the
 * existing pool.readiness.test.js / pool.isolation.test.js suites.
 */

function loadPool(cbEnv = {}) {
  process.env.QODIQA_PG_ENABLED = 'true';
  for (const [k, v] of Object.entries(cbEnv)) process.env[k] = String(v);
  const pool = require('../pool');
  pool.initialize();
  return pool;
}

const CONNECTION_REFUSED = Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' });
const SYNTAX_ERROR       = Object.assign(new Error('syntax error at or near "SELCT"'), { code: '42601' });
// Exact shape pg-pool itself throws on pool exhaustion — no .code at all
// (node_modules/pg-pool/index.js). #114/5.9 regression: this must
// trip the breaker like any other connection-class failure.
const POOL_EXHAUSTED     = new Error('timeout exceeded when trying to connect');

describe('PostgreSQL query circuit breaker (FAILOVER-2)', () => {
  let mockPoolQuery;
  let mockConnect;
  let mockClient;

  beforeEach(() => {
    jest.resetModules();
    mockPoolQuery = jest.fn();
    mockClient = { query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }), release: jest.fn() };
    mockConnect = jest.fn().mockResolvedValue(mockClient);

    jest.doMock('pg', () => ({
      Pool: jest.fn().mockImplementation(() => ({
        query:        mockPoolQuery,
        connect:      mockConnect,
        on:           jest.fn(),
        end:          jest.fn().mockResolvedValue(),
        waitingCount: 0,
        options:      { max: 10 },
      })),
    }));
  });

  afterEach(() => {
    delete process.env.QODIQA_PG_ENABLED;
    delete process.env.QODIQA_PG_CB_FAILURE_THRESHOLD;
    delete process.env.QODIQA_PG_CB_WINDOW_MS;
    delete process.env.QODIQA_PG_CB_RECOVERY_MS;
    delete process.env.QODIQA_PG_CB_SUCCESS_THRESHOLD;
  });

  test('stays CLOSED and passes queries through under normal operation', async () => {
    mockPoolQuery.mockResolvedValue({ rows: [{ x: 1 }], rowCount: 1 });
    const pool = loadPool();
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 10; i++) await pool.query('SELECT 1');

    expect(breaker.state).toBe('CLOSED');
    expect(mockPoolQuery).toHaveBeenCalledTimes(10);
  });

  test('opens after cbFailureThreshold consecutive connection failures, then fast-fails without touching the pool', async () => {
    mockPoolQuery.mockRejectedValue(CONNECTION_REFUSED);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 3 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 3; i++) {
      await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    }
    expect(breaker.state).toBe('OPEN');
    expect(mockPoolQuery).toHaveBeenCalledTimes(3);

    // Circuit is OPEN — the next call must fast-fail with PG_CIRCUIT_OPEN
    // WITHOUT calling the underlying pool at all (avoid cascading stalls).
    mockPoolQuery.mockClear();
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });
    expect(mockPoolQuery).not.toHaveBeenCalled();
  });

  test('a query error that is NOT connection/timeout-shaped (e.g. bad SQL) never trips the breaker', async () => {
    mockPoolQuery.mockRejectedValue(SYNTAX_ERROR);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 3 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 10; i++) {
      await expect(pool.query('SELCT 1')).rejects.toMatchObject({ code: '42601' });
    }
    expect(breaker.state).toBe('CLOSED');
    expect(mockPoolQuery).toHaveBeenCalledTimes(10); // every call really reached the pool
  });

  test('automatic recovery: after cbRecoveryMs elapses, one probe is allowed through (HALF_OPEN), and success threshold closes the circuit', async () => {
    mockPoolQuery.mockRejectedValue(CONNECTION_REFUSED);
    const pool = loadPool({
      QODIQA_PG_CB_FAILURE_THRESHOLD: 2,
      QODIQA_PG_CB_RECOVERY_MS: 20,
      QODIQA_PG_CB_SUCCESS_THRESHOLD: 2,
    });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 2; i++) await expect(pool.query('SELECT 1')).rejects.toBeTruthy();
    expect(breaker.state).toBe('OPEN');

    // Fast-fails while still within the recovery window.
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });

    // Recovery window elapses — PostgreSQL is healthy again.
    await new Promise((resolve) => setTimeout(resolve, 25));
    mockPoolQuery.mockResolvedValue({ rows: [], rowCount: 0 });

    await pool.query('SELECT 1'); // HALF_OPEN probe #1 — succeeds
    expect(breaker.state).toBe('HALF_OPEN');
    await pool.query('SELECT 1'); // HALF_OPEN probe #2 — success threshold reached
    expect(breaker.state).toBe('CLOSED');
  });

  test('a failure during the HALF_OPEN probe reopens the circuit immediately', async () => {
    mockPoolQuery.mockRejectedValue(CONNECTION_REFUSED);
    const pool = loadPool({
      QODIQA_PG_CB_FAILURE_THRESHOLD: 1,
      QODIQA_PG_CB_RECOVERY_MS: 15,
    });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    await expect(pool.query('SELECT 1')).rejects.toBeTruthy();
    expect(breaker.state).toBe('OPEN');

    await new Promise((resolve) => setTimeout(resolve, 20));
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'ECONNREFUSED' }); // HALF_OPEN probe fails
    expect(breaker.state).toBe('OPEN');
  });

  test('pool-exhaustion timeouts (no .code, pg-pool\'s own shape) trip the breaker and fast-fail subsequent callers', async () => {
    mockPoolQuery.mockRejectedValue(POOL_EXHAUSTED);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 3 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 3; i++) {
      await expect(pool.query('SELECT 1')).rejects.toMatchObject({ message: 'timeout exceeded when trying to connect' });
    }
    expect(breaker.state).toBe('OPEN');
    expect(mockPoolQuery).toHaveBeenCalledTimes(3);

    // Once OPEN, exhaustion no longer piles every caller up against the
    // pool's connectionTimeoutMillis — they fast-fail immediately instead.
    mockPoolQuery.mockClear();
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });
    expect(mockPoolQuery).not.toHaveBeenCalled();
  });

  // PH16-D1: the HALF_OPEN probe must never wedge the breaker. Before the fix each of these left
  // _halfOpenProbeInFlight set forever: every later call fast-failed PG_CIRCUIT_OPEN until restart
  //.
  describe.each([
    ['T1 unclassified driver error', () => Promise.reject(new Error('Connection terminated unexpectedly')), 'OPEN'],
    ['T2 caller-class SQLSTATE (23505)', () => Promise.reject(Object.assign(new Error('duplicate key'), { code: '23505' })), 'CLOSED'],
  ])('PH16-D1 %s as the HALF_OPEN probe', (_n, probe, expectedAfterProbe) => {
    test('does not wedge: the breaker leaves HALF_OPEN and healthy queries succeed again', async () => {
      mockPoolQuery.mockRejectedValue(CONNECTION_REFUSED);
      const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 1, QODIQA_PG_CB_RECOVERY_MS: 15, QODIQA_PG_CB_SUCCESS_THRESHOLD: 1 });
      const breaker = require('../pgCircuitBreaker').getCircuitBreaker();
      await expect(pool.query('SELECT 1')).rejects.toBeTruthy();
      expect(breaker.state).toBe('OPEN');
      await new Promise((r) => setTimeout(r, 20));
      mockPoolQuery.mockImplementationOnce(probe).mockResolvedValue({ rows: [], rowCount: 0 });
      await expect(pool.query('INSERT x')).rejects.toBeTruthy();          // the probe settles with that error
      expect(breaker.state).toBe(expectedAfterProbe);                     // SQLSTATE = server up; unclassified = failed probe
      await new Promise((r) => setTimeout(r, 20));
      await pool.query('SELECT 1'); await pool.query('SELECT 1');
      expect(breaker.state).toBe('CLOSED');
    });
  });

  test('PH16-D1 T3 a probe that never settles expires after cbRecoveryMs and a fresh probe is admitted', async () => {
    mockPoolQuery.mockRejectedValue(CONNECTION_REFUSED);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 1, QODIQA_PG_CB_RECOVERY_MS: 15, QODIQA_PG_CB_SUCCESS_THRESHOLD: 1 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();
    await expect(pool.query('SELECT 1')).rejects.toBeTruthy();
    await new Promise((r) => setTimeout(r, 20));
    mockPoolQuery.mockImplementationOnce(() => new Promise(() => {})).mockResolvedValue({ rows: [], rowCount: 0 });
    pool.query('SELECT pg_sleep(1e9)').catch(() => {});                  // the probe hangs (silent partition)
    expect(breaker.state).toBe('HALF_OPEN');
    await new Promise((r) => setTimeout(r, 20));                          // lease expires
    await expect(pool.query('SELECT 1')).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' }); // expiry → OPEN, re-armed
    expect(breaker.state).toBe('OPEN');
    await new Promise((r) => setTimeout(r, 20));
    await pool.query('SELECT 1');                                         // fresh probe succeeds
    expect(breaker.state).toBe('CLOSED');
  });

  test('withTransaction() connection-acquisition exhaustion also trips the breaker', async () => {
    mockConnect.mockRejectedValue(POOL_EXHAUSTED);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 2 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 2; i++) {
      await expect(pool.withTransaction(async () => {})).rejects.toMatchObject({ message: 'timeout exceeded when trying to connect' });
    }
    expect(breaker.state).toBe('OPEN');
  });

  test('withTransaction() is gated by the same breaker on connection acquisition', async () => {
    mockConnect.mockRejectedValue(CONNECTION_REFUSED);
    const pool = loadPool({ QODIQA_PG_CB_FAILURE_THRESHOLD: 2 });
    const breaker = require('../pgCircuitBreaker').getCircuitBreaker();

    for (let i = 0; i < 2; i++) {
      await expect(pool.withTransaction(async () => {})).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    }
    expect(breaker.state).toBe('OPEN');

    mockConnect.mockClear();
    await expect(pool.withTransaction(async () => {})).rejects.toMatchObject({ code: 'PG_CIRCUIT_OPEN' });
    expect(mockConnect).not.toHaveBeenCalled();
  });
});
