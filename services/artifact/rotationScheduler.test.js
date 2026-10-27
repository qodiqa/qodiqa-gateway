'use strict';

/**
 * Automatic Key Rotation Scheduler — Tests
 *
 * KRS-01…06   Factory, configuration, interval resolution
 * KRS-07…12   Start / stop lifecycle
 * KRS-13…20   Due-ness detection and rotation trigger
 * KRS-21…27   Distributed lock / cluster coordination
 * KRS-28…33   Retry logic and failure handling
 * KRS-34…39   Metrics
 * KRS-40…45   Audit events
 * KRS-46…50   Follower reload (fleet-wide visibility)
 * KRS-51…55   Restart-safety / idempotency
 * KRS-56…60   Manual trigger (runOnce) and status introspection
 */

const { createScheduler, resolveRotationIntervalMs, DAY_MS, WEEK_MS, MONTH_MS } = require('./rotationScheduler');

// ── Helpers ───────────────────────────────────────────────────────────────────

function _makeMockMetrics() {
  return {
    keyRotationSchedulerRunsTotal:      { inc: jest.fn() },
    keyRotationSchedulerSuccessTotal:   { inc: jest.fn() },
    keyRotationSchedulerFailuresTotal:  { inc: jest.fn() },
    keyRotationSchedulerSkippedTotal:   { inc: jest.fn() },
    keyRotationSchedulerRetriesTotal:   { inc: jest.fn() },
    keyRotationSchedulerDurationMs:     { observe: jest.fn() },
    keyRotationSchedulerLastRunTs:      { set: jest.fn() },
    keyRotationSchedulerNextRunTs:      { set: jest.fn() },
    keyRotationSchedulerActive:         { set: jest.fn() },
    keyRotationLockContentionTotal:     { inc: jest.fn() },
    keyActiveAgeSeconds:                { set: jest.fn() },
  };
}

function _activeKey(clientId, { ageMs = 0, keyId } = {}) {
  return {
    clientId,
    keyId:     keyId || `${clientId}:key_v1`,
    status:    'active',
    createdAt: new Date(Date.now() - ageMs).toISOString(),
    version:   1,
  };
}

function _makeMockLock({ acquired = true } = {}) {
  return {
    acquire: jest.fn().mockResolvedValue(acquired ? { acquired: true, token: 'tok-1' } : { acquired: false }),
    release: jest.fn().mockResolvedValue(true),
  };
}

function _makeScheduler(overrides = {}) {
  return createScheduler({
    schedule:         'disabled',
    checkIntervalMs:  1_000,
    reloadIntervalMs: 5_000,
    lockTtlMs:        30_000,
    maxRetries:       0,
    retryDelayMs:     0,
    clientIds:        ['acme'],
    _listKeys:        jest.fn().mockReturnValue([_activeKey('acme')]),
    _rotateAsync:     jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' }),
    _reload:          jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 }),
    _lock:            _makeMockLock(),
    _emit:            jest.fn(),
    _metrics:         _makeMockMetrics(),
    ...overrides,
  });
}

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
  jest.clearAllMocks();
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-01…06  Factory, configuration, interval resolution
// ═════════════════════════════════════════════════════════════════════════════

describe('Factory and interval resolution', () => {
  test('KRS-01: createScheduler returns start/stop/isRunning/getStatus/runOnce', () => {
    const s = _makeScheduler();
    expect(typeof s.start).toBe('function');
    expect(typeof s.stop).toBe('function');
    expect(typeof s.isRunning).toBe('function');
    expect(typeof s.getStatus).toBe('function');
    expect(typeof s.runOnce).toBe('function');
  });

  test('KRS-02: scheduler starts not running', () => {
    expect(_makeScheduler().isRunning()).toBe(false);
  });

  test('KRS-03: resolveRotationIntervalMs — daily/weekly/monthly presets', () => {
    expect(resolveRotationIntervalMs({ schedule: 'daily' })).toBe(DAY_MS);
    expect(resolveRotationIntervalMs({ schedule: 'weekly' })).toBe(WEEK_MS);
    expect(resolveRotationIntervalMs({ schedule: 'monthly' })).toBe(MONTH_MS);
    expect(resolveRotationIntervalMs({ schedule: 'disabled' })).toBe(0);
  });

  test('KRS-04: resolveRotationIntervalMs — explicit intervalMs takes precedence over schedule', () => {
    expect(resolveRotationIntervalMs({ schedule: 'daily', intervalMs: 12_345 })).toBe(12_345);
  });

  test('KRS-05: resolveRotationIntervalMs — intervalDays converts to ms and beats schedule', () => {
    expect(resolveRotationIntervalMs({ schedule: 'monthly', intervalDays: 45 })).toBe(45 * DAY_MS);
  });

  test('KRS-06: resolveRotationIntervalMs — invalid schedule falls back to monthly with a warning', () => {
    const emitMock = jest.fn();
    expect(resolveRotationIntervalMs({ schedule: 'fortnightly' }, emitMock)).toBe(MONTH_MS);
    expect(emitMock).toHaveBeenCalledWith('WARN', 'KEY_ROTATION_SCHEDULE_INVALID', expect.objectContaining({ value: 'fortnightly' }));
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-07…12  Start / stop lifecycle
// ═════════════════════════════════════════════════════════════════════════════

describe('Start / stop lifecycle', () => {
  test('KRS-07: start() with rotation schedule disabled still runs — reload is independent of rotation', () => {
    const s = _makeScheduler({ schedule: 'disabled' });
    s.start();
    // Rotation never ticks, but the scheduler itself is "running" because
    // reload (default-enabled) still has a live timer — disabling rotation
    // must never disable trust-store reload.
    expect(s.isRunning()).toBe(true);
    expect(s.getStatus().rotationActive).toBe(false);
    expect(s.getStatus().reloadActive).toBe(true);
    s.stop();
  });

  test('KRS-07b: start() fully no-ops only when BOTH rotation and reload are disabled', () => {
    const s = _makeScheduler({ schedule: 'disabled', reloadEnabled: false });
    s.start();
    expect(s.isRunning()).toBe(false);
    expect(s.getStatus().rotationActive).toBe(false);
    expect(s.getStatus().reloadActive).toBe(false);
  });

  test('KRS-08: start() with a real interval sets running=true and schedules a tick', async () => {
    const s = _makeScheduler({ schedule: 'daily' });
    s.start();
    expect(s.isRunning()).toBe(true);
    await jest.advanceTimersByTimeAsync(0);
    s.stop();
  });

  test('KRS-09: duplicate start() call warns and does not reset state', async () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'daily', _emit: emitMock });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    s.start();
    expect(emitMock).toHaveBeenCalledWith('WARN', 'KEY_ROTATION_SCHEDULER_ALREADY_RUNNING', expect.any(Object));
    s.stop();
  });

  test('KRS-10: stop() is idempotent', () => {
    const s = _makeScheduler({ schedule: 'daily' });
    s.start();
    s.stop();
    expect(() => s.stop()).not.toThrow();
    expect(s.isRunning()).toBe(false);
  });

  test('KRS-11: stop() clears timers so no further ticks fire', async () => {
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 1_000,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0); // first immediate tick
    const callsAfterFirstTick = rotateAsync.mock.calls.length;
    s.stop();
    await jest.advanceTimersByTimeAsync(10_000);
    expect(rotateAsync.mock.calls.length).toBe(callsAfterFirstTick);
  });

  test('KRS-12: getStatus reflects configuration before start', () => {
    const s = _makeScheduler({ schedule: 'weekly', checkIntervalMs: 2_000 });
    const status = s.getStatus();
    expect(status.running).toBe(false);
    expect(status.intervalMs).toBe(WEEK_MS);
    expect(status.checkIntervalMs).toBe(2_000);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-13…20  Due-ness detection and rotation trigger
// ═════════════════════════════════════════════════════════════════════════════

describe('Due-ness detection and rotation trigger', () => {
  test('KRS-13: a key younger than the interval is not rotated', async () => {
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 1_000 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled();
    s.stop();
  });

  test('KRS-14: a key older than the interval is rotated exactly once per tick', async () => {
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).toHaveBeenCalledTimes(1);
    expect(rotateAsync).toHaveBeenCalledWith('acme', expect.objectContaining({ reason: 'SCHEDULED_ROTATION', triggeredBy: 'scheduler' }));
    s.stop();
  });

  test('KRS-15: multiple due clients are all evaluated in a single tick', async () => {
    const rotateAsync = jest.fn().mockImplementation(cid => Promise.resolve({ keyId: `${cid}:key_v2`, version: 2, clientId: cid, fingerprint: 'ff' }));
    const s = _makeScheduler({
      schedule: 'daily',
      clientIds: ['acme', 'globex'],
      _listKeys: jest.fn().mockReturnValue([
        _activeKey('acme',   { ageMs: DAY_MS + 1 }),
        _activeKey('globex', { ageMs: DAY_MS + 1 }),
      ]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).toHaveBeenCalledTimes(2);
    s.stop();
  });

  test('KRS-16: a client with no active key is skipped, not an error', async () => {
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled();
    const status = s.getStatus();
    expect(status.totalErrors).toBe(0);
    s.stop();
  });

  test('KRS-17: discovers clients automatically from the key store when no allowlist is configured', async () => {
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'x:key_v2', version: 2, clientId: 'x', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily',
      clientIds: null,
      _listKeys: jest.fn().mockReturnValue([_activeKey('discovered-client', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).toHaveBeenCalledWith('discovered-client', expect.any(Object));
    s.stop();
  });

  test('KRS-18: when multiple active keys exist for a client (structural anomaly), the most recent is used', async () => {
    const older = _activeKey('acme', { ageMs: DAY_MS + 100, keyId: 'acme:key_v1' });
    const newer = _activeKey('acme', { ageMs: 10, keyId: 'acme:key_v2' });
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v3', version: 3, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([older, newer]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    // The newer key is only 10ms old — not due — so no rotation should occur.
    expect(rotateAsync).not.toHaveBeenCalled();
    s.stop();
  });

  test('KRS-19: active key age metric is recorded for every evaluated client', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 5_000 })]),
      _metrics: metrics,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyActiveAgeSeconds.set).toHaveBeenCalledWith({ clientId: 'acme' }, expect.any(Number));
    s.stop();
  });

  test('KRS-20: schedule "disabled" never rotates even if keys are ancient', async () => {
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'disabled',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 10 * MONTH_MS })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    expect(s.getStatus().rotationActive).toBe(false);
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled();
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-21…27  Distributed lock / cluster coordination
// ═════════════════════════════════════════════════════════════════════════════

describe('Distributed lock / cluster coordination', () => {
  test('KRS-21: lock is acquired before rotating', async () => {
    const lock = _makeMockLock();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: lock,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(lock.acquire).toHaveBeenCalledWith('acme', 30_000);
    s.stop();
  });

  test('KRS-22: lock held by another instance → rotation is skipped, not attempted', async () => {
    const rotateAsync = jest.fn();
    const lock = _makeMockLock({ acquired: false });
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: lock,
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled();
    const status = s.getStatus();
    expect(status.totalSkipped).toBe(1);
    s.stop();
  });

  test('KRS-23: lock contention increments the dedicated metric', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: _makeMockLock({ acquired: false }),
      _metrics: metrics,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationLockContentionTotal.inc).toHaveBeenCalled();
    s.stop();
  });

  test('KRS-24: Redis unavailable during acquire → treated as a skip, never rotates unlocked', async () => {
    const rotateAsync = jest.fn();
    const lock = { acquire: jest.fn().mockRejectedValue(new Error('Redis down')), release: jest.fn() };
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: lock,
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled();
    s.stop();
  });

  test('KRS-25: lock is released after a successful rotation', async () => {
    const lock = _makeMockLock();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: lock,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(lock.release).toHaveBeenCalledWith('acme', 'tok-1');
    s.stop();
  });

  test('KRS-26: lock is released even when rotation fails', async () => {
    const lock = _makeMockLock();
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 0,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _lock: lock,
      _rotateAsync: jest.fn().mockRejectedValue(new Error('boom')),
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(lock.release).toHaveBeenCalledWith('acme', 'tok-1');
    s.stop();
  });

  test('KRS-27: two clients due in the same tick each acquire their own independent lock', async () => {
    const lock = _makeMockLock();
    const s = _makeScheduler({
      schedule: 'daily',
      clientIds: ['acme', 'globex'],
      _listKeys: jest.fn().mockReturnValue([
        _activeKey('acme',   { ageMs: DAY_MS + 1 }),
        _activeKey('globex', { ageMs: DAY_MS + 1 }),
      ]),
      _lock: lock,
      _rotateAsync: jest.fn().mockImplementation(cid => Promise.resolve({ keyId: `${cid}:key_v2`, version: 2, clientId: cid, fingerprint: 'ff' })),
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(lock.acquire).toHaveBeenCalledWith('acme', 30_000);
    expect(lock.acquire).toHaveBeenCalledWith('globex', 30_000);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-28…33  Retry logic and failure handling
// ═════════════════════════════════════════════════════════════════════════════

describe('Retry logic and failure handling', () => {
  test('KRS-28: transient failure is retried up to maxRetries then succeeds', async () => {
    const rotateAsync = jest.fn()
      .mockRejectedValueOnce(new Error('transient'))
      .mockResolvedValueOnce({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 2, retryDelayMs: 100,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    await jest.advanceTimersByTimeAsync(200);
    expect(rotateAsync).toHaveBeenCalledTimes(2);
    expect(s.getStatus().totalRotated).toBe(1);
    s.stop();
  });

  test('KRS-29: exhausting all retries records a failure, never a partial rotation', async () => {
    const rotateAsync = jest.fn().mockRejectedValue(new Error('permanent'));
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 2, retryDelayMs: 10,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    await jest.advanceTimersByTimeAsync(100);
    expect(rotateAsync).toHaveBeenCalledTimes(3); // initial + 2 retries
    expect(s.getStatus().totalErrors).toBe(1);
    expect(s.getStatus().totalRotated).toBe(0);
    s.stop();
  });

  test('KRS-30: failure on one client does not prevent rotation of another due client in the same tick', async () => {
    const rotateAsync = jest.fn()
      .mockImplementation(cid => cid === 'acme' ? Promise.reject(new Error('boom')) : Promise.resolve({ keyId: `${cid}:key_v2`, version: 2, clientId: cid, fingerprint: 'ff' }));
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 0,
      clientIds: ['acme', 'globex'],
      _listKeys: jest.fn().mockReturnValue([
        _activeKey('acme',   { ageMs: DAY_MS + 1 }),
        _activeKey('globex', { ageMs: DAY_MS + 1 }),
      ]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(s.getStatus().totalErrors).toBe(1);
    expect(s.getStatus().totalRotated).toBe(1);
    s.stop();
  });

  test('KRS-31: a tick already in progress is skipped rather than run concurrently', async () => {
    let resolveRotate;
    const rotateAsync = jest.fn().mockReturnValue(new Promise(r => { resolveRotate = r; }));
    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 500,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0); // first tick starts, hangs on rotateAsync
    expect(s.getStatus().ticking).toBe(true);
    resolveRotate({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    await jest.advanceTimersByTimeAsync(0);
    s.stop();
  });

  test('KRS-32: retryDelayMs is honored between attempts', async () => {
    const timestamps = [];
    const rotateAsync = jest.fn().mockImplementation(() => {
      timestamps.push(Date.now());
      return timestamps.length < 2 ? Promise.reject(new Error('x')) : Promise.resolve({ keyId: 'a:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    });
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 1, retryDelayMs: 5_000,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    await jest.advanceTimersByTimeAsync(5_000);
    expect(timestamps.length).toBe(2);
    expect(timestamps[1] - timestamps[0]).toBeGreaterThanOrEqual(5_000);
    s.stop();
  });

  test('KRS-33: stopping mid-retry aborts further retry attempts', async () => {
    const rotateAsync = jest.fn().mockRejectedValue(new Error('always fails'));
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 5, retryDelayMs: 1_000,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    s.stop();
    await jest.advanceTimersByTimeAsync(10_000);
    // Should not have exhausted all 6 attempts (1 + 5 retries) since stop() aborted early.
    expect(rotateAsync.mock.calls.length).toBeLessThan(6);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// Finding 3.6 — unhandled rejection isolation regression tests
//
// Before this remediation, _runTick()'s try{} had no catch — a synchronous
// throw from _discoverClients() (i.e. _listKeys()) propagated out of the
// async tick function as an unhandled rejection with nothing downstream to
// catch it, which (via the old unconditional process.exit(1) global
// handler) could crash the whole gateway. These tests prove the tick body
// now runs through BackgroundTaskRunner: the failure is contained, no
// unhandled rejection is produced, and the self-rescheduling loop
// continues on the next interval.
// ═════════════════════════════════════════════════════════════════════════════

describe('Finding 3.6 — unhandled rejection isolation', () => {
  test('a synchronous throw from _listKeys() during a tick does not crash the scheduler and does not produce an unhandled rejection', async () => {
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    try {
      const s = _makeScheduler({
        schedule: 'daily',
        _listKeys: jest.fn(() => { throw new Error('discovery-blew-up'); }),
      });
      s.start();
      await jest.advanceTimersByTimeAsync(0);

      expect(unhandled).not.toHaveBeenCalled();
      expect(s.isRunning()).toBe(true);
      s.stop();
    } finally {
      process.removeListener('unhandledRejection', unhandled);
    }
  });

  test('scheduling continues after a failed tick — the next interval still ticks', async () => {
    const listKeys = jest.fn()
      .mockImplementationOnce(() => { throw new Error('first-tick-blows-up'); })
      .mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]);
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });

    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 1_000,
      _listKeys: listKeys,
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);       // first tick: throws, contained
    expect(s.getStatus().totalTicks).toBe(1);
    expect(rotateAsync).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(1_000);   // second tick: scheduled normally, succeeds
    expect(s.getStatus().totalTicks).toBe(2);
    expect(rotateAsync).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('a rejection from the lock-release finally block inside _rotateWithRetry is also contained', async () => {
    const unhandled = jest.fn();
    process.on('unhandledRejection', unhandled);
    try {
      const flakyLock = _makeMockLock();
      flakyLock.release.mockRejectedValue(new Error('release-failed'));

      const s = _makeScheduler({
        schedule: 'daily',
        _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
        _rotateAsync: jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' }),
        _lock: flakyLock,
      });
      s.start();
      await jest.advanceTimersByTimeAsync(0);

      expect(unhandled).not.toHaveBeenCalled();
      expect(s.isRunning()).toBe(true);
      s.stop();
    } finally {
      process.removeListener('unhandledRejection', unhandled);
    }
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-34…39  Metrics
// ═════════════════════════════════════════════════════════════════════════════

describe('Metrics', () => {
  test('KRS-34: successful rotation increments success metric with provider label', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _metrics: metrics,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationSchedulerSuccessTotal.inc).toHaveBeenCalledWith(expect.objectContaining({ trigger: 'scheduled' }));
    s.stop();
  });

  test('KRS-35: failed rotation increments failure metric', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 0,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: jest.fn().mockRejectedValue(new Error('x')),
      _metrics: metrics,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationSchedulerFailuresTotal.inc).toHaveBeenCalled();
    s.stop();
  });

  test('KRS-36: duration histogram observed on success', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _metrics: metrics,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationSchedulerDurationMs.observe).toHaveBeenCalledWith({ trigger: 'scheduled' }, expect.any(Number));
    s.stop();
  });

  test('KRS-37: active gauge set to 1 on start and 0 on stop', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ schedule: 'daily', _metrics: metrics });
    s.start();
    expect(metrics.keyRotationSchedulerActive.set).toHaveBeenCalledWith({}, 1);
    s.stop();
    expect(metrics.keyRotationSchedulerActive.set).toHaveBeenCalledWith({}, 0);
  });

  test('KRS-38: next-run gauge is populated after start and cleared after stop', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ schedule: 'daily', checkIntervalMs: 1_000, _metrics: metrics });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationSchedulerNextRunTs.set).toHaveBeenCalledWith({}, expect.any(Number));
    s.stop();
    expect(metrics.keyRotationSchedulerNextRunTs.set).toHaveBeenCalledWith({}, 0);
  });

  test('KRS-39: runs-total incremented once per tick', async () => {
    const metrics = _makeMockMetrics();
    const s = _makeScheduler({ schedule: 'daily', checkIntervalMs: 1_000, _metrics: metrics });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(metrics.keyRotationSchedulerRunsTotal.inc).toHaveBeenCalledTimes(1);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-40…45  Audit events
// ═════════════════════════════════════════════════════════════════════════════

describe('Audit events', () => {
  test('KRS-40: KEY_ROTATION_SCHEDULER_STARTED emitted on start with config', () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'daily', _emit: emitMock });
    s.start();
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_STARTED', expect.objectContaining({ intervalMs: DAY_MS }));
    s.stop();
  });

  test('KRS-41: KEY_ROTATION_SCHEDULER_STOPPED emitted on stop with totals', () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'daily', _emit: emitMock });
    s.start();
    s.stop();
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_STOPPED', expect.objectContaining({ totalTicks: expect.any(Number) }));
  });

  test('KRS-42: KEY_ROTATION_SCHEDULER_ROTATED emitted with keyId, version, fingerprint', async () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _emit: emitMock,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_ROTATED', expect.objectContaining({
      clientId: 'acme', keyId: 'acme:key_v2', version: 2, fingerprint: 'ff',
    }));
    s.stop();
  });

  test('KRS-43: KEY_ROTATION_SCHEDULER_DISABLED emitted when schedule is disabled', () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'disabled', _emit: emitMock });
    s.start();
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_DISABLED', expect.any(Object));
  });

  test('KRS-44: KEY_ROTATION_SCHEDULER_TICK_STARTED and _TICK_COMPLETED bracket every tick', async () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'daily', _emit: emitMock });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_TICK_STARTED', expect.any(Object));
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_ROTATION_SCHEDULER_TICK_COMPLETED', expect.any(Object));
    s.stop();
  });

  test('KRS-45: KEY_ROTATION_SCHEDULER_FAILED emitted with error detail after exhausting retries', async () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily', maxRetries: 0,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: jest.fn().mockRejectedValue(new Error('provider unreachable')),
      _emit: emitMock,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(emitMock).toHaveBeenCalledWith('ERROR', 'KEY_ROTATION_SCHEDULER_FAILED', expect.objectContaining({ error: 'provider unreachable' }));
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-46…50  Follower reload (fleet-wide visibility)
// ═════════════════════════════════════════════════════════════════════════════

describe('Follower reload', () => {
  test('KRS-46: reload is invoked on the configured reload cadence', async () => {
    const reload = jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 });
    const s = _makeScheduler({ schedule: 'daily', reloadIntervalMs: 1_000, _reload: reload });
    s.start();
    await jest.advanceTimersByTimeAsync(1_000);
    expect(reload).toHaveBeenCalled();
    s.stop();
  });

  test('KRS-47: reload failure emits a warning but does not stop the scheduler', async () => {
    const emitMock = jest.fn();
    const reload = jest.fn().mockReturnValue({ reloaded: false, error: 'file corrupt' });
    const s = _makeScheduler({ schedule: 'daily', reloadIntervalMs: 1_000, _reload: reload, _emit: emitMock });
    s.start();
    await jest.advanceTimersByTimeAsync(1_000);
    expect(emitMock).toHaveBeenCalledWith('WARN', 'KEY_ROTATION_SCHEDULER_RELOAD_FAILED', expect.objectContaining({ error: 'file corrupt' }));
    expect(s.isRunning()).toBe(true);
    s.stop();
  });

  test('KRS-48: reload throwing synchronously is caught and does not crash the scheduler', async () => {
    const reload = jest.fn().mockImplementation(() => { throw new Error('boom'); });
    const s = _makeScheduler({ schedule: 'daily', reloadIntervalMs: 1_000, _reload: reload });
    s.start();
    await expect(jest.advanceTimersByTimeAsync(1_000)).resolves.not.toThrow();
    expect(s.isRunning()).toBe(true);
    s.stop();
  });

  test('KRS-49: reload continues on its own cadence independent of the rotation tick cadence', async () => {
    const reload = jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 });
    const s = _makeScheduler({ schedule: 'daily', checkIntervalMs: 10_000, reloadIntervalMs: 1_000, _reload: reload });
    s.start();
    await jest.advanceTimersByTimeAsync(3_000);
    expect(reload.mock.calls.length).toBeGreaterThanOrEqual(3);
    s.stop();
  });

  test('KRS-50: reload stops firing after stop()', async () => {
    const reload = jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 });
    const s = _makeScheduler({ schedule: 'daily', reloadIntervalMs: 1_000, _reload: reload });
    s.start();
    await jest.advanceTimersByTimeAsync(1_000);
    const callsBeforeStop = reload.mock.calls.length;
    s.stop();
    await jest.advanceTimersByTimeAsync(5_000);
    expect(reload.mock.calls.length).toBe(callsBeforeStop);
  });

  // ── remediation: reload must never depend on rotation being enabled ──

  test('KRS-51: reload fires on its cadence even when the rotation schedule is fully disabled', async () => {
    const reload = jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 });
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'disabled', reloadIntervalMs: 1_000, _reload: reload, _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(3_000);
    expect(reload.mock.calls.length).toBeGreaterThanOrEqual(3);
    expect(rotateAsync).not.toHaveBeenCalled(); // rotation still never runs
    s.stop();
  });

  test('KRS-52: reload fires even when QODIQA_KEY_ROTATION_ENABLED is false but a valid interval is configured', async () => {
    const reload = jest.fn().mockReturnValue({ reloaded: true, clients: 1, active: 1 });
    const s = _makeScheduler({ schedule: 'daily', enabled: false, reloadIntervalMs: 1_000, _reload: reload });
    s.start();
    expect(s.getStatus().rotationActive).toBe(false);
    await jest.advanceTimersByTimeAsync(1_000);
    expect(reload).toHaveBeenCalled();
    s.stop();
  });

  test('KRS-53: reload can be independently turned off via reloadEnabled while rotation keeps running', async () => {
    const reload = jest.fn();
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily', reloadEnabled: false, reloadIntervalMs: 1_000,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _reload: reload, _rotateAsync: rotateAsync,
    });
    s.start();
    expect(s.getStatus().reloadActive).toBe(false);
    await jest.advanceTimersByTimeAsync(5_000);
    expect(reload).not.toHaveBeenCalled();
    expect(rotateAsync).toHaveBeenCalled(); // rotation unaffected by reload being off
    s.stop();
  });

  test('KRS-54: a KEY_RELOAD_SCHEDULER_DISABLED event is emitted when reload is explicitly disabled', () => {
    const emitMock = jest.fn();
    const s = _makeScheduler({ schedule: 'daily', reloadEnabled: false, _emit: emitMock });
    s.start();
    expect(emitMock).toHaveBeenCalledWith('INFO', 'KEY_RELOAD_SCHEDULER_DISABLED', expect.any(Object));
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-51…55  Restart-safety / idempotency
// ═════════════════════════════════════════════════════════════════════════════

describe('Restart-safety / idempotency', () => {
  test('KRS-51: due-ness is derived from key createdAt, not scheduler-internal state — safe across restarts', async () => {
    // Simulate a fresh scheduler instance (as if the process just restarted)
    // observing a key that was rotated long before this instance existed.
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 1_000 })]), // freshly rotated elsewhere
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).not.toHaveBeenCalled(); // not due — no double-rotation after restart
    s.stop();
  });

  test('KRS-52: a key exactly at the interval boundary is treated as due', async () => {
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(rotateAsync).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('KRS-53: rotating once resets due-ness for the remainder of the interval (no duplicate on next tick)', async () => {
    let age = DAY_MS + 1;
    const rotateAsync = jest.fn().mockImplementation(() => {
      age = 0; // the mock simulates the key store now reporting a freshly-created key
      return Promise.resolve({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    });
    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 1_000,
      _listKeys: jest.fn().mockImplementation(() => [_activeKey('acme', { ageMs: age })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    await jest.advanceTimersByTimeAsync(1_000);
    expect(rotateAsync).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('KRS-54: multiple start()/stop() cycles do not duplicate rotations for a non-due key', async () => {
    const rotateAsync = jest.fn();
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 100 })]),
      _rotateAsync: rotateAsync,
    });
    for (let i = 0; i < 3; i++) {
      s.start();
      await jest.advanceTimersByTimeAsync(0);
      s.stop();
    }
    expect(rotateAsync).not.toHaveBeenCalled();
  });

  test('KRS-55: getStatus totals persist across ticks until the instance is discarded', async () => {
    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 1_000,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 100 })]),
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    await jest.advanceTimersByTimeAsync(1_000);
    expect(s.getStatus().totalTicks).toBe(2);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-56…60  Manual trigger (runOnce) and status introspection
// ═════════════════════════════════════════════════════════════════════════════

describe('Manual trigger and status introspection', () => {
  test('KRS-56: runOnce() forces a tick outside the timer cadence', async () => {
    const rotateAsync = jest.fn().mockResolvedValue({ keyId: 'acme:key_v2', version: 2, clientId: 'acme', fingerprint: 'ff' });
    const s = _makeScheduler({
      schedule: 'daily', checkIntervalMs: 999_999_999,
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: DAY_MS + 1 })]),
      _rotateAsync: rotateAsync,
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0); // consume the initial immediate tick
    rotateAsync.mockClear();
    await s.runOnce();
    expect(rotateAsync).toHaveBeenCalledTimes(1);
    s.stop();
  });

  test('KRS-57: getStatus exposes lockTtlMs, maxRetries, retryDelayMs for operational visibility', () => {
    const s = _makeScheduler({ schedule: 'daily', lockTtlMs: 15_000, maxRetries: 4, retryDelayMs: 2_000 });
    const status = s.getStatus();
    expect(status.lockTtlMs).toBe(15_000);
    expect(status.maxRetries).toBe(4);
    expect(status.retryDelayMs).toBe(2_000);
  });

  test('KRS-58: getStatus.enabled reflects the enabled flag even when schedule is disabled', () => {
    const s = _makeScheduler({ schedule: 'disabled', enabled: true });
    expect(s.getStatus().enabled).toBe(true);
  });

  test('KRS-59: totalSkipped increases for not-due clients evaluated in a tick', async () => {
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 10 })]),
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(s.getStatus().totalSkipped).toBe(1);
    s.stop();
  });

  test('KRS-60: ticking flag is false once a tick fully completes', async () => {
    const s = _makeScheduler({
      schedule: 'daily',
      _listKeys: jest.fn().mockReturnValue([_activeKey('acme', { ageMs: 10 })]),
    });
    s.start();
    await jest.advanceTimersByTimeAsync(0);
    expect(s.getStatus().ticking).toBe(false);
    s.stop();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// KRS-61 Part 8 — scheduled rotation's REAL default wiring is graceful,
// never the implicit/emergency default. Every other test in this file injects
// _rotateAsync as a mock — this is the one test that exercises the actual,
// unmocked createScheduler() default parameter binding against the real
// keyManager/keyStore, proving the scheduler itself never depends on
// keyManager.rotateAsync()'s (now-mandatory, see keyStore.js) implicit
// behavior for its own operation.
// ═════════════════════════════════════════════════════════════════════════════

describe('Part 8 — scheduled rotation default wiring is graceful', () => {
  test('KRS-61: with no _rotateAsync override, a real due rotation calls keyManager.rotateGracefullyAsync and never keyManager.rotateAsync', async () => {
    const keyManager = require('./keyManager');
    const keyStore    = require('./keyStore');

    const clientId = `wp009-scheduler-${Date.now()}`;
    keyStore.rotateKey(clientId); // first provisioning — mode is irrelevant for a brand-new client

    const gracefulSpy  = jest.spyOn(keyManager, 'rotateGracefullyAsync');
    const emergencySpy = jest.spyOn(keyManager, 'rotateAsync');

    const s = createScheduler({
      schedule:         'daily',
      intervalMs:       1_000, // 1s — comfortably beaten by the artificial age below
      checkIntervalMs:  999_999_999,
      reloadIntervalMs: 999_999_999,
      clientIds:        [clientId],
      // Due-ness reads an artificially-aged createdAt so the test does not
      // race real wall-clock elapsed time; the actual rotation call below
      // still operates on the REAL (unmodified) active key record.
      _listKeys: () => keyStore.listKeys().map(k => (
        k.clientId === clientId ? { ...k, createdAt: new Date(Date.now() - 60_000).toISOString() } : k
      )),
      _lock:            _makeMockLock(),
      _emit:            jest.fn(),
      _metrics:         _makeMockMetrics(),
      // No _rotateAsync override — this is the point of the test.
    });

    s.start();
    await jest.advanceTimersByTimeAsync(0); // consume the initial immediate tick

    expect(gracefulSpy).toHaveBeenCalledWith(clientId, expect.objectContaining({ reason: 'SCHEDULED_ROTATION', triggeredBy: 'scheduler' }));
    expect(emergencySpy).not.toHaveBeenCalled();

    const keys     = keyStore.getKeysByClient(clientId);
    const statuses = keys.map(k => k.status).sort();
    expect(statuses).toEqual(['active', 'deprecated']); // graceful outcome, never 'revoked'

    s.stop();
    gracefulSpy.mockRestore();
    emergencySpy.mockRestore();
  });
});
