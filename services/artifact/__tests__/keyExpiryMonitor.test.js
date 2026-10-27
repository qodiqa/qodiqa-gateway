'use strict';

// keyExpiryMonitor reads its interval/enabled flag from process.env at
// require() time — same jest.resetModules() + env-reset + jest.doMock()
// pattern as src/runtime/__tests__/eventLoopMonitor.test.js.

const _ENV_KEYS = [
  'QODIQA_KEY_EXPIRY_MONITOR_ENABLED',
  'QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS',
];

let logger;
let metrics;
let keyStore;

function makeGauge() { return { set: jest.fn() }; }
function makeCounter() { return { inc: jest.fn() }; }

function loadModule(env = {}) {
  jest.resetModules();
  for (const key of _ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;

  jest.doMock('../../logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../../src/observability/metrics', () => ({
    keyExpiryMonitorRunsTotal: makeCounter(),
    keyExpiryApproachingCount: makeGauge(),
    keyRotationOverdueCount:   makeGauge(),
  }));
  jest.doMock('../keyStore', () => ({
    validateKeyStore: jest.fn(() => ({ expiringKeys: [], overdueKeys: [] })),
  }));
  // the monitor also checks the transparency/checkpoint stores — modelled here as not in use
  // (no key file), so this suite keeps testing the artifact path only; keyExpiryMonitorEd25519.test.js covers them.
  jest.doMock('../../../src/core/transparency/transparencyKeyStore', () => ({ DATA_PATH: null, validateKeyStore: jest.fn() }));
  jest.doMock('../../../src/core/audit/checkpoint/checkpointKeyStore', () => ({ DATA_PATH: null, validateKeyStore: jest.fn() }));

  logger   = require('../../logger');
  metrics  = require('../../../src/observability/metrics');
  keyStore = require('../keyStore');

  return require('../keyExpiryMonitor');
}

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
  for (const key of _ENV_KEYS) delete process.env[key];
  jest.dontMock('../../logger');
  jest.dontMock('../../../src/observability/metrics');
  jest.dontMock('../keyStore');
  jest.dontMock('../../../src/core/transparency/transparencyKeyStore');
  jest.dontMock('../../../src/core/audit/checkpoint/checkpointKeyStore');
});

describe('keyExpiryMonitor', () => {
  test('before initialize(): disabled', () => {
    const mod = loadModule();
    expect(mod.isEnabled()).toBe(false);
  });

  test('initialize() starts the background timer and logs once', () => {
    const mod = loadModule();
    mod.initialize();

    expect(mod.isEnabled()).toBe(true);
    expect(logger.emit).toHaveBeenCalledWith('INFO', 'KEY_EXPIRY_MONITOR_STARTED', expect.any(Object));
  });

  test('initialize() is idempotent', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    mod.initialize();
    expect(jest.getTimerCount()).toBe(1);
  });

  test('QODIQA_KEY_EXPIRY_MONITOR_ENABLED=false skips initialization entirely', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_MONITOR_ENABLED: 'false' });
    mod.initialize();

    expect(mod.isEnabled()).toBe(false);
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'KEY_EXPIRY_MONITOR_DISABLED', expect.any(Object));
  });

  test('shutdown() stops the timer', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    mod.shutdown();
    expect(mod.isEnabled()).toBe(false);
  });

  test('shutdown() is safe before initialize() or called twice', () => {
    const mod = loadModule();
    expect(() => mod.shutdown()).not.toThrow();
    mod.initialize();
    mod.shutdown();
    expect(() => mod.shutdown()).not.toThrow();
  });

  test('a tick with no expiring/overdue keys emits nothing and records zero counts', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    logger.emit.mockClear();

    jest.advanceTimersByTime(1000);

    expect(logger.emit).not.toHaveBeenCalled();
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenCalledWith({}, 0);
    expect(metrics.keyRotationOverdueCount.set).toHaveBeenCalledWith({}, 0);
    expect(metrics.keyExpiryMonitorRunsTotal.inc).toHaveBeenCalledTimes(1);
  });

  test('a tick with expiring keys re-emits KEY_EXPIRING_SOON for each one, tagged source=PERIODIC_MONITOR', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    keyStore.validateKeyStore.mockReturnValue({
      expiringKeys: [{ clientId: 'acme', keyId: 'acme:key_v1', daysRemaining: 5 }],
      overdueKeys:  [],
    });
    mod.initialize();
    logger.emit.mockClear();

    jest.advanceTimersByTime(1000);

    expect(logger.emit).toHaveBeenCalledWith('WARN', 'KEY_EXPIRING_SOON', {
      clientId: 'acme', keyId: 'acme:key_v1', daysRemaining: 5, source: 'PERIODIC_MONITOR',
    });
    expect(metrics.keyExpiryApproachingCount.set).toHaveBeenCalledWith({}, 1);
  });

  test('a tick with overdue keys re-emits KEY_ROTATION_OVERDUE for each one', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    keyStore.validateKeyStore.mockReturnValue({
      expiringKeys: [],
      overdueKeys:  [{ clientId: 'acme', keyId: 'acme:key_v1', daysOverdue: 3 }],
    });
    mod.initialize();
    logger.emit.mockClear();

    jest.advanceTimersByTime(1000);

    expect(logger.emit).toHaveBeenCalledWith('WARN', 'KEY_ROTATION_OVERDUE', {
      clientId: 'acme', keyId: 'acme:key_v1', daysOverdue: 3, source: 'PERIODIC_MONITOR',
    });
    expect(metrics.keyRotationOverdueCount.set).toHaveBeenCalledWith({}, 1);
  });

  test('every tick re-checks and re-emits — repeated ticks with the same expiring key log it again each time (not state-transition-only)', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    keyStore.validateKeyStore.mockReturnValue({
      expiringKeys: [{ clientId: 'acme', keyId: 'acme:key_v1', daysRemaining: 5 }],
      overdueKeys:  [],
    });
    mod.initialize();
    logger.emit.mockClear();

    jest.advanceTimersByTime(1000);
    jest.advanceTimersByTime(1000);

    const warnCalls = logger.emit.mock.calls.filter(c => c[1] === 'KEY_EXPIRING_SOON');
    expect(warnCalls).toHaveLength(2);
  });

  test('a thrown error from validateKeyStore() is caught and logged, never escapes the timer', () => {
    const mod = loadModule({ QODIQA_KEY_EXPIRY_CHECK_INTERVAL_MS: '1000' });
    keyStore.validateKeyStore.mockImplementation(() => { throw new Error('key store unreadable'); });
    mod.initialize();
    logger.emit.mockClear();

    expect(() => jest.advanceTimersByTime(1000)).not.toThrow();
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'KEY_EXPIRY_MONITOR_CHECK_FAILED', expect.any(Object));
  });
});
