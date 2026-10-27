'use strict';

// latencySlaMonitor reads its thresholds/interval from process.env at
// require() time — same jest.resetModules() + env-reset + jest.doMock()
// pattern as src/runtime/__tests__/eventLoopMonitor.test.js.

const _ENV_KEYS = [
  'QODIQA_LATENCY_SLA_MONITOR_ENABLED',
  'QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS',
  'QODIQA_SLA_LATENCY_MS',
  'QODIQA_P99_LATENCY_MS',
];

let logger;
let metrics;

function makeHistogram({ meanMs = 0, p99Ms = 0 } = {}) {
  return {
    getMean:            jest.fn(() => meanMs),
    estimatePercentile: jest.fn(() => p99Ms),
  };
}

function loadModule(env = {}) {
  jest.resetModules();
  for (const key of _ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;

  jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));
  jest.doMock('../metrics', () => ({
    requestDurationMs: makeHistogram(),
  }));

  logger  = require('../../../services/logger');
  metrics = require('../metrics');

  return require('../latencySlaMonitor');
}

function setLatency(meanMs, p99Ms) {
  metrics.requestDurationMs.getMean.mockReturnValue(meanMs);
  metrics.requestDurationMs.estimatePercentile.mockReturnValue(p99Ms);
}

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
  for (const key of _ENV_KEYS) delete process.env[key];
  jest.dontMock('../../../services/logger');
  jest.dontMock('../metrics');
});

describe('latencySlaMonitor', () => {
  test('before initialize(): disabled, both healthy', () => {
    const mod = loadModule();
    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toEqual({ sla: 'healthy', p99: 'healthy' });
  });

  test('initialize() starts the background timer and logs once', () => {
    const mod = loadModule();
    mod.initialize();

    expect(mod.isEnabled()).toBe(true);
    expect(logger.emit).toHaveBeenCalledWith('INFO', 'LATENCY_SLA_MONITOR_STARTED', expect.any(Object));
  });

  test('initialize() is idempotent', () => {
    const mod = loadModule({ QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    mod.initialize();
    expect(jest.getTimerCount()).toBe(1);
  });

  test('QODIQA_LATENCY_SLA_MONITOR_ENABLED=false skips initialization entirely', () => {
    const mod = loadModule({ QODIQA_LATENCY_SLA_MONITOR_ENABLED: 'false' });
    mod.initialize();

    expect(mod.isEnabled()).toBe(false);
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'LATENCY_SLA_MONITOR_DISABLED', expect.any(Object));
  });

  test('shutdown() stops the timer and resets to healthy', () => {
    const mod = loadModule({ QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();
    mod.shutdown();

    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toEqual({ sla: 'healthy', p99: 'healthy' });
  });

  test('shutdown() is safe before initialize() or called twice', () => {
    const mod = loadModule();
    expect(() => mod.shutdown()).not.toThrow();
    mod.initialize();
    mod.shutdown();
    expect(() => mod.shutdown()).not.toThrow();
  });

  test('mean latency below threshold: no breach, no log', () => {
    const mod = loadModule({
      QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000', QODIQA_SLA_LATENCY_MS: '2000',
    });
    mod.initialize();
    logger.emit.mockClear();

    setLatency(500, 0);
    jest.advanceTimersByTime(1000);

    expect(mod.getState().sla).toBe('healthy');
    expect(logger.emit).not.toHaveBeenCalled();
  });

  test('mean latency crossing the SLA threshold: exactly one WARN, then recovery emits exactly one INFO', () => {
    const mod = loadModule({
      QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000', QODIQA_SLA_LATENCY_MS: '2000',
    });
    mod.initialize();
    logger.emit.mockClear();

    setLatency(2500, 0);
    jest.advanceTimersByTime(1000);
    expect(mod.getState().sla).toBe('breached');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'WARN', 'REQUEST_LATENCY_SLA_BREACH',
      expect.objectContaining({ fromState: 'healthy', toState: 'breached', meanMs: 2500, slaThresholdMs: 2000 }),
    );

    // Sustained breach — no further logs.
    logger.emit.mockClear();
    jest.advanceTimersByTime(3000);
    expect(logger.emit).not.toHaveBeenCalled();

    // Recovery.
    logger.emit.mockClear();
    setLatency(500, 0);
    jest.advanceTimersByTime(1000);
    expect(mod.getState().sla).toBe('healthy');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'INFO', 'REQUEST_LATENCY_SLA_RECOVERED',
      expect.objectContaining({ fromState: 'breached', toState: 'healthy' }),
    );
  });

  test('p99 breach is tracked independently of the SLA (mean) state', () => {
    const mod = loadModule({
      QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000',
      QODIQA_SLA_LATENCY_MS: '2000', QODIQA_P99_LATENCY_MS: '5000',
    });
    mod.initialize();
    logger.emit.mockClear();

    // Mean healthy, but p99 breached — the long tail.
    setLatency(500, 6000);
    jest.advanceTimersByTime(1000);

    expect(mod.getState()).toEqual({ sla: 'healthy', p99: 'breached' });
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'WARN', 'REQUEST_LATENCY_P99_BREACH',
      expect.objectContaining({ p99Ms: 6000, p99ThresholdMs: 5000 }),
    );
  });

  test('background tick reads requestDurationMs with the EXECUTE label', () => {
    const mod = loadModule({ QODIQA_LATENCY_SLA_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();

    jest.advanceTimersByTime(1000);

    expect(metrics.requestDurationMs.getMean).toHaveBeenCalledWith({ decision: 'EXECUTE' });
    expect(metrics.requestDurationMs.estimatePercentile).toHaveBeenCalledWith({ decision: 'EXECUTE' }, 99);
  });
});
