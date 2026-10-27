'use strict';

/**
 * PostgreSQL readiness monitor tests — READY-50.
 *
 * pool.js is a singleton with module-level state; each test loads a fresh
 * instance (jest.resetModules() + jest.doMock('pg', ...)) backed by a fake
 * pg.Pool so no real database connection is required. Timing-sensitive
 * behavior (bounded timeout, overlap guard, periodic refresh) uses real
 * timers with short env-configured intervals rather than fake timers, since
 * the monitor races a real Promise against a real setTimeout internally.
 */

function loadPool({ intervalMs = 20, timeoutMs = 30 } = {}) {
  process.env.QODIQA_PG_ENABLED = 'true';
  process.env.QODIQA_PG_READY_CHECK_INTERVAL_MS = String(intervalMs);
  process.env.QODIQA_PG_READY_TIMEOUT_MS = String(timeoutMs);
  const pool = require('../pool');
  pool.initialize();
  return pool;
}

function flushMicrotasks() {
  return new Promise((resolve) => setImmediate(resolve));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('PostgreSQL readiness monitor (READY-50)', () => {
  let mockPoolQuery;
  let mockEmit;

  beforeEach(() => {
    jest.resetModules();
    mockPoolQuery = jest.fn().mockResolvedValue({ rows: [{ ping: 1 }], rowCount: 1 });
    mockEmit = jest.fn();

    jest.doMock('pg', () => ({
      Pool: jest.fn().mockImplementation(() => ({
        query:        mockPoolQuery,
        connect:      jest.fn(),
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
    delete process.env.QODIQA_PG_READY_CHECK_INTERVAL_MS;
    delete process.env.QODIQA_PG_READY_TIMEOUT_MS;
  });

  test('isHealthy() starts false before any probe completes', () => {
    const pool = loadPool();
    expect(pool.isHealthy()).toBe(false);
  });

  test('startReadinessMonitor() is a no-op when PostgreSQL is disabled', async () => {
    process.env.QODIQA_PG_ENABLED = 'false';
    const pool = require('../pool');
    pool.initialize(); // no pool created — QODIQA_PG_ENABLED !== 'true'
    pool.startReadinessMonitor();
    await sleep(50);
    expect(mockPoolQuery).not.toHaveBeenCalled();
    expect(pool.isHealthy()).toBe(false);
    pool.stopReadinessMonitor();
  });

  test('seeds an immediate probe on start rather than waiting for the first interval tick', async () => {
    const pool = loadPool({ intervalMs: 10_000 }); // long interval — only the seed probe should fire
    pool.startReadinessMonitor();
    await flushMicrotasks();
    await flushMicrotasks();
    expect(mockPoolQuery).toHaveBeenCalledTimes(1);
    expect(pool.isHealthy()).toBe(true);
    pool.stopReadinessMonitor();
  });

  test('keeps isHealthy() fresh via periodic bounded checks without per-request queries', async () => {
    // 2026-10-14 (launch plan, flake root cause): this used a real 80 ms sleep against a 15 ms interval. Windows timer
    // granularity (~15.6 ms) plus event-loop delay under in-band coverage instrumentation let only ONE tick land
    // (2 calls < 3). The interval is now driven by fake timers: same property (seed probe + periodic ticks, no
    // per-request queries), same lower bound, deterministic.
    jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick', 'queueMicrotask'] }); // flushMicrotasks uses setImmediate
    try {
      const pool = loadPool({ intervalMs: 15 });
      pool.startReadinessMonitor();
      await flushMicrotasks();
      for (let i = 0; i < 4; i++) { jest.advanceTimersByTime(15); await flushMicrotasks(); await flushMicrotasks(); }
      pool.stopReadinessMonitor();
      expect(mockPoolQuery.mock.calls.length).toBeGreaterThanOrEqual(3);
      expect(pool.isHealthy()).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  test('marks the pool unhealthy when the probe query fails', async () => {
    mockPoolQuery.mockRejectedValue(Object.assign(new Error('connection terminated'), { code: 'ECONNRESET' }));
    const pool = loadPool({ intervalMs: 10_000 });
    pool.startReadinessMonitor();
    await flushMicrotasks();
    await flushMicrotasks();
    expect(pool.isHealthy()).toBe(false);
    pool.stopReadinessMonitor();
  });

  test('recovers to healthy once the probe query succeeds again', async () => {
    mockPoolQuery.mockRejectedValueOnce(new Error('transient'));
    const pool = loadPool({ intervalMs: 15 });
    pool.startReadinessMonitor();
    await sleep(60);
    expect(pool.isHealthy()).toBe(true);
    pool.stopReadinessMonitor();
  });

  test('bounded timeout: marks unhealthy without waiting indefinitely for a hung query', async () => {
    let releaseHang;
    const hang = new Promise((resolve) => { releaseHang = resolve; });
    mockPoolQuery.mockReturnValue(hang.then(() => ({ rows: [{ ping: 1 }], rowCount: 1 })));

    const pool = loadPool({ intervalMs: 10_000, timeoutMs: 25 });
    pool.startReadinessMonitor();

    await sleep(60); // well past the 25ms bounded timeout, query still unresolved
    expect(pool.isHealthy()).toBe(false);

    releaseHang(); // let the hung query resolve so it doesn't leak into the next test
    await flushMicrotasks();
    pool.stopReadinessMonitor();
  });

  // regression: the test above starts from isHealthy()'s default-false
  // state, so it would pass even if the bounded timeout never actually wrote
  // to _healthy (it would just stay at its untouched default). This test
  // starts from a genuinely HEALTHY state via a real successful probe first,
  // so only an actual _healthy=false assignment on timeout can pass it.
  test('bounded timeout: flips a PREVIOUSLY HEALTHY pool back to unhealthy on a hang', async () => {
    const pool = loadPool({ intervalMs: 10_000, timeoutMs: 25 });

    await pool.healthCheck(); // establishes a genuine healthy baseline
    expect(pool.isHealthy()).toBe(true);

    let releaseHang;
    mockPoolQuery.mockReturnValue(new Promise((resolve) => { releaseHang = resolve; }));

    pool.startReadinessMonitor(); // seeds an immediate bounded probe, which now hangs
    await sleep(80); // well past the 25ms bound

    expect(pool.isHealthy()).toBe(false);

    releaseHang({ rows: [{ ping: 1 }], rowCount: 1 });
    await flushMicrotasks();
    pool.stopReadinessMonitor();
  });

  test('overlap guard: does not start a second probe while one is still in flight', async () => {
    let resolveFirst;
    let callCount = 0;
    mockPoolQuery.mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return new Promise((resolve) => {
          resolveFirst = () => resolve({ rows: [{ ping: 1 }], rowCount: 1 });
        });
      }
      return Promise.resolve({ rows: [{ ping: 1 }], rowCount: 1 });
    });

    const pool = loadPool({ intervalMs: 10, timeoutMs: 10_000 }); // interval far shorter than the hang
    pool.startReadinessMonitor();

    await sleep(60); // several interval ticks would have fired if the guard were absent
    expect(callCount).toBe(1); // only the seed probe — still in flight, no overlapping tick started one more

    resolveFirst();
    await flushMicrotasks();
    expect(pool.isHealthy()).toBe(true);

    await sleep(40); // guard released — ticks resume
    expect(callCount).toBeGreaterThan(1);

    pool.stopReadinessMonitor();
  });

  test('stopReadinessMonitor() halts further probes', async () => {
    const pool = loadPool({ intervalMs: 15 });
    pool.startReadinessMonitor();
    await sleep(40);
    const callsBeforeStop = mockPoolQuery.mock.calls.length;
    expect(callsBeforeStop).toBeGreaterThan(0);

    pool.stopReadinessMonitor();
    await sleep(60);
    expect(mockPoolQuery.mock.calls.length).toBe(callsBeforeStop);
  });

  test('shutdown() stops the readiness monitor', async () => {
    const pool = loadPool({ intervalMs: 15 });
    pool.startReadinessMonitor();
    await sleep(40);
    await pool.shutdown();
    const callsAfterShutdown = mockPoolQuery.mock.calls.length;

    await sleep(60);
    expect(mockPoolQuery.mock.calls.length).toBe(callsAfterShutdown);
  });

  test('startReadinessMonitor() is idempotent — calling it twice does not double the probe rate', async () => {
    const pool = loadPool({ intervalMs: 15 });
    pool.startReadinessMonitor();
    pool.startReadinessMonitor();
    await sleep(50);
    pool.stopReadinessMonitor();
    // Roughly 3-4 ticks expected over 50ms at a 15ms interval, not double that.
    expect(mockPoolQuery.mock.calls.length).toBeLessThan(8);
  });
});
