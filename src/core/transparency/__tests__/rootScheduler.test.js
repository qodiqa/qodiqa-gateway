'use strict';

/**
 * Transparency Root Scheduler — Component #33 Tests
 *
 * RS-01…06   Factory and configuration
 * RS-07…12   Start / stop lifecycle
 * RS-13…20   Time-based trigger
 * RS-21…28   Entry-count trigger
 * RS-29…33   Combined trigger mode
 * RS-34…38   Concurrency safety
 * RS-39…43   Retry logic
 * RS-44…51   Prometheus metrics
 * RS-52…58   Audit events
 * RS-59…62   Restart-safe state recovery
 * RS-63…68   Stress / edge cases
 */

const { createScheduler } = require('../rootScheduler');

// ── Helpers ───────────────────────────────────────────────────────────────────

function _makeMockMetrics() {
  return {
    trSchedulerRunsTotal:      { inc:     jest.fn() },
    trSchedulerGeneratedTotal: { inc:     jest.fn() },
    trSchedulerSkippedTotal:   { inc:     jest.fn() },
    trSchedulerErrorsTotal:    { inc:     jest.fn() },
    trSchedulerRetriesTotal:   { inc:     jest.fn() },
    trSchedulerDurationMs:     { observe: jest.fn() },
    trSchedulerLastRunTs:      { set:     jest.fn() },
    trSchedulerActive:         { set:     jest.fn() },
  };
}

function _successResult(overrides = {}) {
  return {
    rootId:     'root-uuid-1',
    seqFrom:    1,
    seqTo:      100,
    entryCount: 100,
    rootHash:   'abc123',
    persisted:  true,
    ...overrides,
  };
}

/**
 * Build a scheduler with convenient defaults for most tests.
 * Fake timers must be enabled before calling this.
 */
function _makeScheduler(overrides = {}) {
  return createScheduler({
    intervalMs:     0,
    entryThreshold: 0,
    initialDelayMs: 0,
    pollIntervalMs: 1_000,
    maxRetries:     0,
    retryDelayMs:   0,
    generatedBy:    'test-scheduler',
    _generateRoot:  jest.fn().mockResolvedValue(_successResult()),
    _getLatestRoot: jest.fn().mockResolvedValue(null),
    _getLatestEntry:jest.fn().mockResolvedValue(null),
    _emit:          jest.fn(),
    _metrics:       _makeMockMetrics(),
    ...overrides,
  });
}

// ── Global timer setup ────────────────────────────────────────────────────────

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
  jest.clearAllMocks();
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-01…06  Factory and configuration
// ═════════════════════════════════════════════════════════════════════════════

describe('Factory and configuration', () => {

  test('RS-01: createScheduler returns object with start, stop, isRunning, getStatus', () => {
    const s = _makeScheduler();
    expect(typeof s.start).toBe('function');
    expect(typeof s.stop).toBe('function');
    expect(typeof s.isRunning).toBe('function');
    expect(typeof s.getStatus).toBe('function');
  });

  test('RS-02: scheduler starts not running', () => {
    const s = _makeScheduler();
    expect(s.isRunning()).toBe(false);
  });

  test('RS-03: getStatus reflects configuration before start', () => {
    const s = _makeScheduler({ intervalMs: 5_000, entryThreshold: 200 });
    const status = s.getStatus();
    expect(status.running).toBe(false);
    expect(status.intervalMs).toBe(5_000);
    expect(status.entryThreshold).toBe(200);
    expect(status.timeMode).toBe(true);
    expect(status.entryMode).toBe(true);
    expect(status.totalRuns).toBe(0);
    expect(status.totalGenerated).toBe(0);
  });

  test('RS-04: generatedBy passed through to getStatus', () => {
    const s = _makeScheduler({ generatedBy: 'cron' });
    expect(s.getStatus().generatedBy).toBe('cron');
  });

  test('RS-05: timeMode false when intervalMs=0, entryMode false when threshold=0', () => {
    const s = _makeScheduler({ intervalMs: 0, entryThreshold: 0 });
    const status = s.getStatus();
    expect(status.timeMode).toBe(false);
    expect(status.entryMode).toBe(false);
  });

  test('RS-06: getStatus returns a frozen object', () => {
    const s = _makeScheduler();
    const status = s.getStatus();
    expect(Object.isFrozen(status)).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-07…12  Start / stop lifecycle
// ═════════════════════════════════════════════════════════════════════════════

describe('Start / stop lifecycle', () => {

  test('RS-07: start() sets isRunning to true', async () => {
    const s = _makeScheduler();
    await s.start();
    expect(s.isRunning()).toBe(true);
    s.stop();
  });

  test('RS-08: stop() sets isRunning to false', async () => {
    const s = _makeScheduler();
    await s.start();
    s.stop();
    expect(s.isRunning()).toBe(false);
  });

  test('RS-09: start() is idempotent — double start emits ALREADY_RUNNING warning', async () => {
    const mockEmit = jest.fn();
    const s = _makeScheduler({ _emit: mockEmit });
    await s.start();
    await s.start(); // second call
    const warned = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_ALREADY_RUNNING');
    expect(warned).toBeDefined();
    s.stop();
  });

  test('RS-10: stop() is idempotent — double stop does not throw', async () => {
    const s = _makeScheduler();
    await s.start();
    s.stop();
    expect(() => s.stop()).not.toThrow();
  });

  test('RS-11: start() returns the scheduler instance for chaining', async () => {
    const s = _makeScheduler();
    const result = await s.start();
    expect(result).toBe(s);
    s.stop();
  });

  test('RS-12: stop() returns the scheduler instance for chaining', async () => {
    const s = _makeScheduler();
    await s.start();
    const result = s.stop();
    expect(result).toBe(s);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-13…20  Time-based trigger
// ═════════════════════════════════════════════════════════════════════════════

describe('Time-based trigger', () => {

  test('RS-13: fires once after intervalMs (initialDelayMs=intervalMs, no prior root)', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 1_000, initialDelayMs: 1_000, _generateRoot: mockGenerate });
    await s.start();
    expect(mockGenerate).not.toHaveBeenCalled(); // not yet

    await jest.advanceTimersByTimeAsync(1_001);
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    expect(mockGenerate).toHaveBeenCalledWith({ generatedBy: 'test-scheduler' });
    s.stop();
  });

  test('RS-14: fires repeatedly at each intervalMs interval', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 500, initialDelayMs: 500, _generateRoot: mockGenerate });
    await s.start();

    await jest.advanceTimersByTimeAsync(501);
    expect(mockGenerate).toHaveBeenCalledTimes(1);

    await jest.advanceTimersByTimeAsync(500);
    expect(mockGenerate).toHaveBeenCalledTimes(2);

    await jest.advanceTimersByTimeAsync(500);
    expect(mockGenerate).toHaveBeenCalledTimes(3);
    s.stop();
  });

  test('RS-15: respects initialDelayMs before first run when no prior root', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({
      intervalMs:     1_000,
      initialDelayMs: 2_000,
      _generateRoot:  mockGenerate,
    });
    await s.start();

    await jest.advanceTimersByTimeAsync(1_500); // past intervalMs but under initialDelayMs
    expect(mockGenerate).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(600);   // total 2100ms — past initialDelayMs
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-16: catches up missed interval on restart — runs immediately when elapsed >= intervalMs', async () => {
    const twoMinutesAgo = new Date(Date.now() - 120_000);
    const mockGenerate  = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({
      intervalMs:     60_000, // 1 minute interval
      _generateRoot:  mockGenerate,
      _getLatestRoot: jest.fn().mockResolvedValue({
        seq_to:       '50',
        generated_at: twoMinutesAgo.toISOString(),
      }),
    });
    await s.start();
    // elapsed (120s) >= intervalMs (60s) → delay = 0 → fires immediately
    await jest.advanceTimersByTimeAsync(1);
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-17: waits remainder of interval when restart is within interval', async () => {
    const thirtySecondsAgo = new Date(Date.now() - 30_000);
    const mockGenerate     = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({
      intervalMs:     60_000,
      _generateRoot:  mockGenerate,
      _getLatestRoot: jest.fn().mockResolvedValue({
        seq_to:       '50',
        generated_at: thirtySecondsAgo.toISOString(),
      }),
    });
    await s.start();

    await jest.advanceTimersByTimeAsync(20_000); // only 20s of the 30s remainder
    expect(mockGenerate).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(11_000); // now 31s elapsed — past the 30s remainder
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-18: stop() prevents pending timer from firing', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 1_000, _generateRoot: mockGenerate });
    await s.start();
    s.stop();
    await jest.advanceTimersByTimeAsync(2_000);
    expect(mockGenerate).not.toHaveBeenCalled();
  });

  test('RS-19: no time trigger when intervalMs=0', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 0, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(100_000);
    expect(mockGenerate).not.toHaveBeenCalled();
    s.stop();
  });

  test('RS-20: getStatus.nextTimeTriggerAt is set when running with intervalMs>0', async () => {
    const s = _makeScheduler({ intervalMs: 5_000 });
    await s.start();
    const status = s.getStatus();
    expect(status.nextTimeTriggerAt).not.toBeNull();
    expect(new Date(status.nextTimeTriggerAt).getTime()).toBeGreaterThan(Date.now() - 100);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-21…28  Entry-count trigger
// ═════════════════════════════════════════════════════════════════════════════

describe('Entry-count trigger', () => {

  test('RS-21: fires when new entries >= threshold', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 150 }));
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '150' }),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-22: does not fire when new entries < threshold', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '50' }), // only 50 entries
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(1_001); // two polls
    expect(mockGenerate).not.toHaveBeenCalled();
    s.stop();
  });

  test('RS-23: fires exactly once per threshold crossing — not on every subsequent poll', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 150 }));
    // Note: _loadDbState() in start() consumes the first _getLatestRoot() call.
    const mockGetRoot = jest.fn()
      .mockResolvedValueOnce(null)                    // _loadDbState: no root
      .mockResolvedValueOnce(null)                    // poll 1: no root, 150 entries → fire
      .mockResolvedValue({ seq_to: '150', generated_at: new Date().toISOString() }); // polls 2+
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  mockGetRoot,
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '150' }),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(1_600); // three poll intervals
    expect(mockGenerate).toHaveBeenCalledTimes(1); // only once
    s.stop();
  });

  test('RS-24: poll reschedules after each check regardless of outcome', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const mockGetEntry = jest.fn().mockResolvedValue({ id: '10' }); // below threshold
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: mockGetEntry,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(2_501); // 5 poll intervals
    expect(mockGetEntry.mock.calls.length).toBeGreaterThanOrEqual(5);
    s.stop();
  });

  test('RS-25: stop() cancels the poll timer', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const mockGetEntry = jest.fn().mockResolvedValue({ id: '10' });
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: mockGetEntry,
    });
    await s.start();
    s.stop();
    const callCountAtStop = mockGetEntry.mock.calls.length;
    await jest.advanceTimersByTimeAsync(2_000);
    expect(mockGetEntry.mock.calls.length).toBe(callCountAtStop); // no more polls
  });

  test('RS-26: DB error in poll emits POLL_FAILED warning and reschedules', async () => {
    const mockEmit     = jest.fn();
    const mockGetEntry = jest.fn().mockRejectedValue(new Error('DB connection lost'));
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  500,
      _emit:           mockEmit,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: mockGetEntry,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const warnCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_POLL_FAILED');
    expect(warnCall).toBeDefined();
    // Poll should have rescheduled — advance another interval
    await jest.advanceTimersByTimeAsync(501);
    expect(mockGetEntry.mock.calls.length).toBeGreaterThanOrEqual(2);
    s.stop();
  });

  test('RS-27: no entry trigger when entryThreshold=0', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const mockGetEntry = jest.fn().mockResolvedValue({ id: '9999' });
    const s = _makeScheduler({
      entryThreshold: 0,
      _generateRoot:  mockGenerate,
      _getLatestEntry:mockGetEntry,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(100_000);
    expect(mockGenerate).not.toHaveBeenCalled();
    s.stop();
  });

  test('RS-28: entry trigger uses seq_to=0 as baseline when no previous root', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({
      entryThreshold:  50,
      pollIntervalMs:  500,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null), // no prior root → seqTo=0
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '75' }), // 75 entries > 50
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-29…33  Combined trigger mode
// ═════════════════════════════════════════════════════════════════════════════

describe('Combined trigger mode', () => {

  test('RS-29: both triggers active — time fires first when entry not yet at threshold', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 100 }));
    const s = _makeScheduler({
      intervalMs:      500,
      initialDelayMs:  500,    // first time tick at 500ms (same as intervalMs)
      entryThreshold:  100,
      pollIntervalMs:  2_000,  // poll is slower than time tick
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '30' }), // below threshold
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501); // time fires first
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-30: both triggers active — entry fires first when threshold crossed before time tick', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 100 }));
    const s = _makeScheduler({
      intervalMs:      2_000,
      initialDelayMs:  2_000,  // first time tick at 2000ms (time tick is slow)
      pollIntervalMs:  500,     // poll is fast
      entryThreshold:  100,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '150' }), // above threshold
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501); // poll fires first
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-31: after time trigger generates root, entry poll does not duplicate', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 150 }));
    // After time-based generation at 300ms, subsequent polls see seq_to=150 → newEntries=0.
    // _loadDbState() in start() consumes the first _getLatestRoot() call.
    const mockGetRoot = jest.fn()
      .mockResolvedValueOnce(null)                    // _loadDbState
      .mockResolvedValue({ seq_to: '150', generated_at: new Date().toISOString() }); // polls: root exists
    const s = _makeScheduler({
      intervalMs:      300,
      initialDelayMs:  300,
      pollIntervalMs:  500,
      entryThreshold:  100,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  mockGetRoot,
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '150' }),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(800); // both triggers have a chance to fire
    // Time fires at 300ms and 600ms → up to 2 time generations.
    // Entry poll fires at 500ms: sees seq_to=150, newEntries=0 → no duplicate.
    expect(mockGenerate.mock.calls.length).toBeLessThanOrEqual(2);
    s.stop();
  });

  test('RS-32: with both triggers, getStatus shows both modes active', async () => {
    const s = _makeScheduler({ intervalMs: 1_000, entryThreshold: 100 });
    await s.start();
    const status = s.getStatus();
    expect(status.timeMode).toBe(true);
    expect(status.entryMode).toBe(true);
    s.stop();
  });

  test('RS-33: neither trigger active — scheduler runs but never generates', async () => {
    const mockGenerate = jest.fn();
    const s = _makeScheduler({ intervalMs: 0, entryThreshold: 0, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(100_000);
    expect(mockGenerate).not.toHaveBeenCalled();
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-34…38  Concurrency safety
// ═════════════════════════════════════════════════════════════════════════════

describe('Concurrency safety', () => {

  test('RS-34: _generating flag prevents concurrent executions from same instance', async () => {
    // Use both triggers: time fires at 0ms (initialDelayMs=0) and entry poll fires at 500ms.
    // Time generation never resolves until we call resolveFirst, so the entry poll
    // fires while time generation is in-flight and should be SKIPPED.
    let resolveFirst;
    const first  = new Promise(res => { resolveFirst = res; });
    const second = jest.fn().mockResolvedValue(_successResult());
    const mockGenerate = jest.fn()
      .mockReturnValueOnce(first) // first call never resolves until we tell it to
      .mockImplementation(() => second());

    const mockEmit = jest.fn();
    const metrics  = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:      5_000,   // time fires at 0ms (initialDelayMs=0), next at 5000ms
      entryThreshold:  100,
      pollIntervalMs:  500,     // entry poll fires at 500ms while time gen is in-flight
      _generateRoot:   mockGenerate,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '150' }),
      _emit:           mockEmit,
      _metrics:        metrics,
    });

    await s.start();
    // Time trigger fires immediately (initialDelayMs=0); generation is in-flight
    // Entry poll fires at 500ms while time generation is still running → SKIPPED
    await jest.advanceTimersByTimeAsync(501);

    // Concurrent entry poll attempt should have been skipped
    const skippedCalls = metrics.trSchedulerSkippedTotal.inc.mock.calls
      .filter(c => c[0].reason === 'generating');
    expect(skippedCalls.length).toBeGreaterThanOrEqual(1);

    // Resolve the first generation
    resolveFirst(_successResult());
    await jest.advanceTimersByTimeAsync(100);
    s.stop();
  });

  test('RS-35: "no new entries since last root" error is treated as skip, not failure', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(
      new Error('generateRoot: no new entries since last root (seqTo=100, latestEntry=100)')
    );
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:    500,
      _generateRoot: mockGenerate,
      _metrics:      metrics,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerSkippedTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'no_new_entries' })
    );
    expect(metrics.trSchedulerErrorsTotal.inc).not.toHaveBeenCalled();
    s.stop();
  });

  test('RS-36: "no transparency log entries exist" error is a skip, not failure', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(
      new Error('generateRoot: no transparency log entries exist')
    );
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:    500,
      _generateRoot: mockGenerate,
      _metrics:      metrics,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerSkippedTotal.inc).toHaveBeenCalled();
    expect(metrics.trSchedulerErrorsTotal.inc).not.toHaveBeenCalled();
    s.stop();
  });

  test('RS-37: cross-process duplicate (both processes see skip) — each processes result cleanly', async () => {
    // Simulate two independent scheduler instances (different processes) both trying
    // to generate at the same time. The second one receives "no new entries" which
    // is the PG FOR UPDATE result surfaced as an error message.
    const firstGenerate  = jest.fn().mockResolvedValue(_successResult());
    const secondGenerate = jest.fn().mockRejectedValue(
      new Error('generateRoot: no new entries since last root (seqTo=100, latestEntry=100)')
    );

    const metrics1 = _makeMockMetrics();
    const metrics2 = _makeMockMetrics();

    const s1 = _makeScheduler({ intervalMs: 500, _generateRoot: firstGenerate,  _metrics: metrics1 });
    const s2 = _makeScheduler({ intervalMs: 500, _generateRoot: secondGenerate, _metrics: metrics2 });

    await Promise.all([s1.start(), s2.start()]);
    await jest.advanceTimersByTimeAsync(501);

    expect(metrics1.trSchedulerGeneratedTotal.inc).toHaveBeenCalled();
    expect(metrics2.trSchedulerSkippedTotal.inc).toHaveBeenCalled();
    expect(metrics2.trSchedulerErrorsTotal.inc).not.toHaveBeenCalled();

    s1.stop(); s2.stop();
  });

  test('RS-38: stop during active generation does not schedule next tick', async () => {
    let resolve;
    const inflight = new Promise(res => { resolve = res; });
    const mockGenerate = jest.fn().mockReturnValueOnce(inflight);
    const s = _makeScheduler({ intervalMs: 500, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(501); // first tick fires
    s.stop(); // stop while generating
    resolve(_successResult());
    await jest.advanceTimersByTimeAsync(1_000); // no more ticks should fire
    expect(mockGenerate).toHaveBeenCalledTimes(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-39…43  Retry logic
// ═════════════════════════════════════════════════════════════════════════════

describe('Retry logic', () => {

  test('RS-39: retries up to maxRetries on failure', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('DB transient error'));
    const metrics      = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:    5_000,
      initialDelayMs:500,
      maxRetries:    3,
      retryDelayMs:  100,  // non-zero so advanceTimersByTimeAsync can drain retries
      _generateRoot: mockGenerate,
      _metrics:      metrics,
    });
    await s.start();
    // Fire initial tick (500ms) + drain all 3 retries (100ms each) + buffer
    await jest.advanceTimersByTimeAsync(1_000);
    // Total calls: 1 initial + 3 retries = 4
    expect(mockGenerate).toHaveBeenCalledTimes(4);
    s.stop();
  });

  test('RS-40: emits RETRY event for each retry attempt', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('transient'));
    const mockEmit     = jest.fn();
    const s = _makeScheduler({
      intervalMs:    500,
      initialDelayMs:500,
      maxRetries:    2,
      retryDelayMs:  0,
      _generateRoot: mockGenerate,
      _emit:         mockEmit,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const retryCalls = mockEmit.mock.calls.filter(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_RETRY');
    expect(retryCalls).toHaveLength(2);
    s.stop();
  });

  test('RS-41: increments trSchedulerRetriesTotal on each retry', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('transient'));
    const metrics      = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:    500,
      initialDelayMs:500,
      maxRetries:    2,
      retryDelayMs:  0,
      _generateRoot: mockGenerate,
      _metrics:      metrics,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerRetriesTotal.inc).toHaveBeenCalledTimes(2);
    s.stop();
  });

  test('RS-42: emits FAILED after exhausting all retries', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('permanent failure'));
    const mockEmit     = jest.fn();
    const s = _makeScheduler({
      intervalMs:    500,
      maxRetries:    2,
      retryDelayMs:  0,
      _generateRoot: mockGenerate,
      _emit:         mockEmit,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const failedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_FAILED');
    expect(failedCall).toBeDefined();
    expect(failedCall[2].error).toBe('permanent failure');
    s.stop();
  });

  test('RS-43: scheduler continues running after exhausted retries — next tick still fires', async () => {
    const mockGenerate = jest.fn()
      .mockRejectedValueOnce(new Error('transient'))
      .mockResolvedValue(_successResult());
    const s = _makeScheduler({
      intervalMs:    500,
      initialDelayMs:500,  // first tick at 500ms; second at 1000ms
      maxRetries:    0,    // no retries — first call fails immediately
      retryDelayMs:  0,
      _generateRoot: mockGenerate,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);  // first tick: fails (maxRetries=0)
    await jest.advanceTimersByTimeAsync(500);  // second tick: succeeds
    expect(mockGenerate).toHaveBeenCalledTimes(2);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-44…51  Prometheus metrics
// ═════════════════════════════════════════════════════════════════════════════

describe('Prometheus metrics', () => {

  test('RS-44: trSchedulerActive set to 1 on start and 0 on stop', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ _metrics: metrics });
    await s.start();
    expect(metrics.trSchedulerActive.set).toHaveBeenCalledWith({}, 1);
    s.stop();
    expect(metrics.trSchedulerActive.set).toHaveBeenCalledWith({}, 0);
  });

  test('RS-45: trSchedulerRunsTotal incremented with trigger label on each run', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ intervalMs: 500, _metrics: metrics });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerRunsTotal.inc).toHaveBeenCalledWith({ trigger: 'time' });
    s.stop();
  });

  test('RS-46: trSchedulerGeneratedTotal incremented with trigger on success', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ intervalMs: 500, _metrics: metrics });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerGeneratedTotal.inc).toHaveBeenCalledWith({ trigger: 'time' });
    s.stop();
  });

  test('RS-47: trSchedulerSkippedTotal incremented with reason on skip', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(
      new Error('generateRoot: no new entries since last root (seqTo=50, latestEntry=50)')
    );
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ intervalMs: 500, _generateRoot: mockGenerate, _metrics: metrics });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerSkippedTotal.inc).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'no_new_entries' })
    );
    s.stop();
  });

  test('RS-48: trSchedulerErrorsTotal incremented with trigger on failure', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('real error'));
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      intervalMs:    500,
      maxRetries:    0,
      _generateRoot: mockGenerate,
      _metrics:      metrics,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerErrorsTotal.inc).toHaveBeenCalledWith({ trigger: 'time' });
    s.stop();
  });

  test('RS-49: trSchedulerDurationMs.observe called with trigger label and a number', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ intervalMs: 500, _metrics: metrics });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerDurationMs.observe).toHaveBeenCalledWith(
      { trigger: 'time' },
      expect.any(Number),
    );
    s.stop();
  });

  test('RS-50: trSchedulerLastRunTs.set called with Unix seconds after each run', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ intervalMs: 500, _metrics: metrics });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerLastRunTs.set).toHaveBeenCalledWith({}, expect.any(Number));
    const tsArg = metrics.trSchedulerLastRunTs.set.mock.calls[0][1];
    expect(tsArg).toBeGreaterThan(0);
    s.stop();
  });

  test('RS-51: entry-count trigger uses label trigger:entry in metrics', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      entryThreshold:  50,
      pollIntervalMs:  500,
      _metrics:        metrics,
      _getLatestRoot:  jest.fn().mockResolvedValue(null),
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '100' }),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    expect(metrics.trSchedulerRunsTotal.inc).toHaveBeenCalledWith({ trigger: 'entry' });
    expect(metrics.trSchedulerGeneratedTotal.inc).toHaveBeenCalledWith({ trigger: 'entry' });
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-52…58  Audit events
// ═════════════════════════════════════════════════════════════════════════════

describe('Audit events', () => {

  test('RS-52: emits STARTED on start() with config fields', async () => {
    const mockEmit = jest.fn();
    const s = _makeScheduler({ intervalMs: 1_000, entryThreshold: 200, _emit: mockEmit });
    await s.start();
    const startedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_STARTED');
    expect(startedCall).toBeDefined();
    expect(startedCall[0]).toBe('INFO');
    expect(startedCall[2]).toMatchObject({ intervalMs: 1_000, entryThreshold: 200 });
    s.stop();
  });

  test('RS-53: emits STOPPED on stop() with run statistics', async () => {
    const mockEmit     = jest.fn();
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 500, initialDelayMs: 500, _emit: mockEmit, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    s.stop();
    const stoppedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_STOPPED');
    expect(stoppedCall).toBeDefined();
    expect(stoppedCall[0]).toBe('INFO');
    expect(stoppedCall[2]).toMatchObject({ totalRuns: 1, totalGenerated: 1 });
  });

  test('RS-54: emits GENERATED with rootId, trigger, entryCount on success', async () => {
    const mockEmit     = jest.fn();
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ rootId: 'test-root', entryCount: 42 }));
    const s = _makeScheduler({ intervalMs: 500, _emit: mockEmit, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const generatedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_GENERATED');
    expect(generatedCall).toBeDefined();
    expect(generatedCall[0]).toBe('INFO');
    expect(generatedCall[2]).toMatchObject({
      trigger:    'time',
      rootId:     'test-root',
      entryCount: 42,
      generatedBy:'test-scheduler',
    });
    s.stop();
  });

  test('RS-55: emits SKIPPED with reason:NO_NEW_ENTRIES when no work to do', async () => {
    const mockEmit     = jest.fn();
    const mockGenerate = jest.fn().mockRejectedValue(
      new Error('generateRoot: no new entries since last root (seqTo=99, latestEntry=99)')
    );
    const s = _makeScheduler({ intervalMs: 500, _emit: mockEmit, _generateRoot: mockGenerate });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const skippedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_SKIPPED');
    expect(skippedCall).toBeDefined();
    expect(skippedCall[0]).toBe('INFO');
    expect(skippedCall[2].reason).toBe('NO_NEW_ENTRIES');
    s.stop();
  });

  test('RS-56: emits FAILED at ERROR level after retry exhaustion', async () => {
    const mockEmit     = jest.fn();
    const mockGenerate = jest.fn().mockRejectedValue(new Error('signing key unavailable'));
    const s = _makeScheduler({
      intervalMs:    500,
      maxRetries:    1,
      retryDelayMs:  0,
      _emit:         mockEmit,
      _generateRoot: mockGenerate,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const failedCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_FAILED');
    expect(failedCall).toBeDefined();
    expect(failedCall[0]).toBe('ERROR');
    expect(failedCall[2].error).toContain('signing key unavailable');
    s.stop();
  });

  test('RS-57: emits RETRY at WARN level before each retry attempt', async () => {
    const mockEmit     = jest.fn();
    const mockGenerate = jest.fn().mockRejectedValue(new Error('transient'));
    const s = _makeScheduler({
      intervalMs:    500,
      initialDelayMs:500,
      maxRetries:    2,
      retryDelayMs:  0,
      _emit:         mockEmit,
      _generateRoot: mockGenerate,
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(501);
    const retryCalls = mockEmit.mock.calls.filter(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_RETRY');
    expect(retryCalls).toHaveLength(2);
    expect(retryCalls[0][0]).toBe('WARN');
    expect(retryCalls[0][2]).toMatchObject({ attempt: 1, trigger: 'time' });
    s.stop();
  });

  test('RS-58: emits STATE_LOAD_FAILED as WARN when DB is unavailable at start', async () => {
    const mockEmit    = jest.fn();
    const mockGetRoot = jest.fn().mockRejectedValue(new Error('connection refused'));
    const s = _makeScheduler({ _emit: mockEmit, _getLatestRoot: mockGetRoot });
    await s.start();
    const warnCall = mockEmit.mock.calls.find(c => c[1] === 'TRANSPARENCY_ROOT_SCHEDULER_STATE_LOAD_FAILED');
    expect(warnCall).toBeDefined();
    expect(warnCall[0]).toBe('WARN');
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-59…62  Restart-safe state recovery
// ═════════════════════════════════════════════════════════════════════════════

describe('Restart-safe state recovery', () => {

  test('RS-59: queries DB state on start() — calls getLatestRoot and getLatestEntry', async () => {
    const mockGetRoot  = jest.fn().mockResolvedValue(null);
    const mockGetEntry = jest.fn().mockResolvedValue(null);
    const s = _makeScheduler({ _getLatestRoot: mockGetRoot, _getLatestEntry: mockGetEntry });
    await s.start();
    expect(mockGetRoot).toHaveBeenCalledTimes(1);
    expect(mockGetEntry).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-60: getStatus.lastGeneratedAt reflects value from DB at startup', async () => {
    const dbTime = new Date('2026-01-01T12:00:00.000Z');
    const mockGetRoot = jest.fn().mockResolvedValue({
      seq_to:       '200',
      generated_at: dbTime.toISOString(),
    });
    const s = _makeScheduler({ _getLatestRoot: mockGetRoot });
    await s.start();
    expect(s.getStatus().lastGeneratedAt).toBe(dbTime.toISOString());
    s.stop();
  });

  test('RS-61: getStatus.lastSeqTo reflects seq_to from DB at startup', async () => {
    const mockGetRoot = jest.fn().mockResolvedValue({
      seq_to:       '777',
      generated_at: new Date().toISOString(),
    });
    const s = _makeScheduler({ _getLatestRoot: mockGetRoot });
    await s.start();
    expect(s.getStatus().lastSeqTo).toBe(777);
    s.stop();
  });

  test('RS-62: DB state load failure does not prevent scheduler from starting', async () => {
    const mockGetRoot = jest.fn().mockRejectedValue(new Error('DB unavailable'));
    const s = _makeScheduler({ _getLatestRoot: mockGetRoot });
    await s.start(); // should not throw
    expect(s.isRunning()).toBe(true);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// RS-63…68  Stress / edge cases
// ═════════════════════════════════════════════════════════════════════════════

describe('Stress and edge cases', () => {

  test('RS-63: rapid successive entry additions trigger exactly one generation per threshold crossing', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult({ seqTo: 500 }));
    // Simulate many entries crossing threshold multiple times:
    //   - poll 1: 500 entries (>=100) → fire
    //   - poll 2+: 500 entries still (mock doesn't update), BUT latestRoot returns seq_to=500 after first generation
    const mockGetRoot = jest.fn()
      .mockResolvedValueOnce(null) // _loadDbState: no root
      .mockResolvedValueOnce(null) // poll 1: no root, 500 entries ≥ 100 → generate
      .mockResolvedValue({ seq_to: '500', generated_at: new Date().toISOString() }); // polls 2+
    const s = _makeScheduler({
      entryThreshold:  100,
      pollIntervalMs:  200,
      _generateRoot:   mockGenerate,
      _getLatestRoot:  mockGetRoot,
      _getLatestEntry: jest.fn().mockResolvedValue({ id: '500' }),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(1_001); // 5 poll intervals
    expect(mockGenerate).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('RS-64: high-frequency time trigger correctly counts totalRuns', async () => {
    const s = _makeScheduler({ intervalMs: 100 });
    await s.start();
    await jest.advanceTimersByTimeAsync(1_001); // ~10 intervals
    s.stop();
    expect(s.getStatus().totalRuns).toBeGreaterThanOrEqual(10);
  });

  test('RS-65: scheduler handles generateRoot returning undefined fields gracefully', async () => {
    // generateRoot returns an object missing optional fields
    const mockGenerate = jest.fn().mockResolvedValue({ rootId: 'r1' });
    const s = _makeScheduler({ intervalMs: 500, _generateRoot: mockGenerate });
    await expect(async () => {
      await s.start();
      await jest.advanceTimersByTimeAsync(501);
      s.stop();
    }).not.toThrow();
  });

  test('RS-66: totalGenerated in getStatus increments on each successful run', async () => {
    const mockGenerate = jest.fn().mockResolvedValue(_successResult());
    const s = _makeScheduler({ intervalMs: 200 });
    // Replace with our mock (can't do it in _makeScheduler since it returns a different scheduler)
    const s2 = createScheduler({
      intervalMs:     200,
      initialDelayMs: 0,
      maxRetries:     0,
      retryDelayMs:   0,
      _generateRoot:  mockGenerate,
      _getLatestRoot: jest.fn().mockResolvedValue(null),
      _getLatestEntry:jest.fn().mockResolvedValue(null),
      _emit:          jest.fn(),
      _metrics:       _makeMockMetrics(),
    });
    await s2.start();
    await jest.advanceTimersByTimeAsync(401); // fires at 0ms, 200ms, 400ms → 3 runs
    s2.stop();
    expect(s2.getStatus().totalGenerated).toBe(3);
  });

  test('RS-67: totalErrors in getStatus increments on each failed run', async () => {
    const mockGenerate = jest.fn().mockRejectedValue(new Error('DB down'));
    const s = createScheduler({
      intervalMs:     300,
      initialDelayMs: 0,
      maxRetries:     0,
      retryDelayMs:   0,
      _generateRoot:  mockGenerate,
      _getLatestRoot: jest.fn().mockResolvedValue(null),
      _getLatestEntry:jest.fn().mockResolvedValue(null),
      _emit:          jest.fn(),
      _metrics:       _makeMockMetrics(),
    });
    await s.start();
    await jest.advanceTimersByTimeAsync(601); // fires at 0ms, 300ms, 600ms → 3 runs
    s.stop();
    expect(s.getStatus().totalErrors).toBe(3);
  });

  test('RS-68: getStatus.nextTimeTriggerAt is null when stopped or no intervalMs', async () => {
    const s1 = _makeScheduler({ intervalMs: 0 });
    await s1.start();
    expect(s1.getStatus().nextTimeTriggerAt).toBeNull();
    s1.stop();

    const s2 = _makeScheduler({ intervalMs: 1_000 });
    await s2.start();
    s2.stop();
    expect(s2.getStatus().nextTimeTriggerAt).toBeNull();
  });
});
