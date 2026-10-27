'use strict';

// persistenceMonitor reads its interval/enabled flag from process.env at
// require() time, so every test that needs non-default config must set env
// vars and jest.resetModules() before requiring the module fresh — same
// pattern as src/runtime/__tests__/eventLoopMonitor.test.js, which this
// module is modeled on.

const _ENV_KEYS = [
  'QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED',
  'QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS',
];

let logger;
let metrics;
let nonceStore;

function makeGauge() { return { set: jest.fn() }; }
function makeCounter() { return { inc: jest.fn() }; }
function makeHistogram() { return { observe: jest.fn() }; }

function safeDiag(overrides = {}) {
  return {
    safe: true, aofEnabled: true, appendfsync: 'everysec',
    lastSave: null, aofCurrentSize: null, warnings: [],
    ...overrides,
  };
}

function unsafeDiag(overrides = {}) {
  return {
    safe: false, aofEnabled: false, appendfsync: 'unknown',
    lastSave: null, aofCurrentSize: null, warnings: ['AOF_DISABLED: ...'],
    ...overrides,
  };
}

function unknownDiag(overrides = {}) {
  return {
    safe: false, aofEnabled: null, appendfsync: null,
    lastSave: null, aofCurrentSize: null, warnings: [],
    error: 'NONCE_STORE_NOT_CONNECTED',
    ...overrides,
  };
}

/** (Re)requires the module with the given env vars applied. */
function loadModule(env = {}) {
  jest.resetModules();
  for (const key of _ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;

  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../../observability/metrics', () => ({
    redisPersistenceSafe:               makeGauge(),
    redisPersistenceAofEnabled:         makeGauge(),
    redisPersistenceLastCheckTimestamp: makeGauge(),
    redisPersistenceDriftTotal:         makeCounter(),
    redisPersistenceCheckDurationMs:    makeHistogram(),
  }));
  jest.doMock('../../../validation/nonceStore', () => ({
    checkPersistence: jest.fn().mockResolvedValue(safeDiag()),
  }));

  logger     = require('../../../../services/logger');
  metrics    = require('../../../observability/metrics');
  nonceStore = require('../../../validation/nonceStore');

  return require('../persistenceMonitor');
}

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
  for (const key of _ENV_KEYS) delete process.env[key];
  jest.dontMock('../../../../services/logger');
  jest.dontMock('../../../observability/metrics');
  jest.dontMock('../../../validation/nonceStore');
});

describe('persistenceMonitor', () => {
  test('before initialize(): disabled, unknown state, empty stats', () => {
    const mod = loadModule();
    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toBe('unknown');
    expect(mod.getStats()).toEqual({
      state: 'unknown', lastCheckedAt: null, consecutiveUnsafeChecks: 0, diagnostics: null,
    });
  });

  test('initialize() starts the background timer and logs once', () => {
    const mod = loadModule();
    mod.initialize();

    expect(mod.isEnabled()).toBe(true);
    expect(logger.emit).toHaveBeenCalledWith('INFO', 'REDIS_PERSISTENCE_MONITOR_STARTED', expect.any(Object));
  });

  test('initialize() is idempotent — a second call does not create a second timer', () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    mod.initialize();

    expect(jest.getTimerCount()).toBe(1);
  });

  test('QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED=false skips initialization entirely', () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_MONITOR_ENABLED: 'false' });
    mod.initialize();

    expect(mod.isEnabled()).toBe(false);
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'REDIS_PERSISTENCE_MONITOR_DISABLED', expect.any(Object));
  });

  test('shutdown() stops the timer and resets to unknown/empty stats', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    await jest.advanceTimersByTimeAsync(1000);
    mod.shutdown();

    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toBe('unknown');
    expect(mod.getStats()).toEqual({
      state: 'unknown', lastCheckedAt: null, consecutiveUnsafeChecks: 0, diagnostics: null,
    });
  });

  test('shutdown() is safe to call before initialize() or more than once', () => {
    const mod = loadModule();
    expect(() => mod.shutdown()).not.toThrow();
    mod.initialize();
    mod.shutdown();
    expect(() => mod.shutdown()).not.toThrow();
  });

  test('a tick calls nonceStore.checkPersistence() (the same live connection the startup check uses), not a separate diagnostic client', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    await jest.advanceTimersByTimeAsync(1000);

    expect(nonceStore.checkPersistence).toHaveBeenCalledTimes(1);
  });

  test('a safe tick pushes gauges/histogram and does not log (no transition from initial unknown -> safe is a WARN-worthy drift)', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    logger.emit.mockClear(); // drop the STARTED log

    await jest.advanceTimersByTimeAsync(1000);

    expect(mod.getState()).toBe('safe');
    expect(metrics.redisPersistenceSafe.set).toHaveBeenCalledWith({}, 1);
    expect(metrics.redisPersistenceAofEnabled.set).toHaveBeenCalledWith({}, 1);
    expect(metrics.redisPersistenceCheckDurationMs.observe).toHaveBeenCalledTimes(1);
    expect(metrics.redisPersistenceDriftTotal.inc).not.toHaveBeenCalled();
  });

  test('safe -> unsafe drift: exactly one WARN, drift counter incremented once', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();

    nonceStore.checkPersistence.mockResolvedValue(safeDiag());
    await jest.advanceTimersByTimeAsync(1000);
    expect(mod.getState()).toBe('safe');
    logger.emit.mockClear();

    nonceStore.checkPersistence.mockResolvedValue(unsafeDiag());
    await jest.advanceTimersByTimeAsync(1000);

    expect(mod.getState()).toBe('unsafe');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'WARN', 'REDIS_PERSISTENCE_DRIFT_DETECTED',
      expect.objectContaining({ fromState: 'safe', toState: 'unsafe' }),
    );
    expect(metrics.redisPersistenceDriftTotal.inc).toHaveBeenCalledTimes(1);

    // Sustained unsafe — repeated ticks at the same state log nothing more.
    logger.emit.mockClear();
    await jest.advanceTimersByTimeAsync(3000);
    expect(logger.emit).not.toHaveBeenCalled();
    expect(metrics.redisPersistenceDriftTotal.inc).toHaveBeenCalledTimes(1);
  });

  test('unsafe -> safe recovery: exactly one INFO', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();

    nonceStore.checkPersistence.mockResolvedValue(unsafeDiag());
    await jest.advanceTimersByTimeAsync(1000);
    expect(mod.getState()).toBe('unsafe');
    logger.emit.mockClear();

    nonceStore.checkPersistence.mockResolvedValue(safeDiag());
    await jest.advanceTimersByTimeAsync(1000);

    expect(mod.getState()).toBe('safe');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'INFO', 'REDIS_PERSISTENCE_RECOVERED',
      expect.objectContaining({ fromState: 'unsafe', toState: 'safe' }),
    );
  });

  test('a connection-not-ready result is classified "unknown", distinct from "unsafe" — no drift counter increment', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();

    nonceStore.checkPersistence.mockResolvedValue(unknownDiag());
    await jest.advanceTimersByTimeAsync(1000);

    expect(mod.getState()).toBe('unknown');
    expect(metrics.redisPersistenceDriftTotal.inc).not.toHaveBeenCalled();
    expect(metrics.redisPersistenceSafe.set).toHaveBeenCalledWith({}, -1);
  });

  test('consecutiveUnsafeChecks increments across sustained-unsafe ticks and resets on recovery', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    nonceStore.checkPersistence.mockResolvedValue(unsafeDiag());

    await jest.advanceTimersByTimeAsync(1000);
    expect(mod.getStats().consecutiveUnsafeChecks).toBe(1);
    await jest.advanceTimersByTimeAsync(1000);
    expect(mod.getStats().consecutiveUnsafeChecks).toBe(2);

    nonceStore.checkPersistence.mockResolvedValue(safeDiag());
    await jest.advanceTimersByTimeAsync(1000);
    expect(mod.getStats().consecutiveUnsafeChecks).toBe(0);
  });

  test('a rejected checkPersistence() promise (contract violation) is treated as unknown, never throws out of the timer', async () => {
    const mod = loadModule({ QODIQA_REDIS_PERSISTENCE_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    nonceStore.checkPersistence.mockRejectedValue(new Error('unexpected'));

    await expect(jest.advanceTimersByTimeAsync(1000)).resolves.not.toThrow();
    expect(mod.getState()).toBe('unknown');
  });
});
