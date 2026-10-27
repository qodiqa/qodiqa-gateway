'use strict';

// eventLoopMonitor reads its thresholds/intervals from process.env at
// require() time, so every test that needs non-default config must set env
// vars and jest.resetModules() before requiring the module fresh.

const _ENV_KEYS = [
  'QODIQA_EVENT_LOOP_MONITOR_ENABLED',
  'QODIQA_EVENT_LOOP_RESOLUTION_MS',
  'QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS',
  'QODIQA_EVENT_LOOP_WARN_MS',
  'QODIQA_EVENT_LOOP_CRITICAL_MS',
];

let fakeHistogram;   // the lifetime histogram (first created)
let windowHistogram; // RT-08: the interval histogram (second created), reset on every tick
let monitorEventLoopDelaySpy;
let logger;
let metrics;

function freshHistogram() {
  return {
    enable:  jest.fn(),
    disable: jest.fn(),
    mean:    0,
    max:     0,
    min:     0,
    stddev:  0,
    percentile: jest.fn(() => 0),
    reset:   jest.fn(),
  };
}

function makeGauge() { return { set: jest.fn() }; }

/** (Re)requires the module with the given env vars applied. */
function loadModule(env = {}) {
  jest.resetModules();
  let created = 0; fakeHistogram = null; windowHistogram = null;
  for (const key of _ENV_KEYS) delete process.env[key];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;

  jest.doMock('perf_hooks', () => ({
    monitorEventLoopDelay: jest.fn((opts) => {
      const h = freshHistogram();
      if (created++ % 2 === 0) fakeHistogram = h; else windowHistogram = h; // initialize() creates lifetime, then window
      monitorEventLoopDelaySpy.lastOptions = opts;
      return h;
    }),
  }));
  jest.doMock('../../../services/logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../observability/metrics', () => ({
    eventLoopDelayMeanMs:    makeGauge(),
    eventLoopDelayMaxMs:     makeGauge(),
    eventLoopDelayMinMs:     makeGauge(),
    eventLoopDelayStddevMs:  makeGauge(),
    eventLoopDelayP50Ms:     makeGauge(),
    eventLoopDelayP95Ms:     makeGauge(),
    eventLoopDelayP99Ms:     makeGauge(),
    eventLoopDelayStateCode: makeGauge(),
    eventLoopDelayWindowMaxMs: makeGauge(),
    eventLoopDelayWindowP99Ms: makeGauge(),
  }));

  logger = require('../../../services/logger');
  metrics = require('../../observability/metrics');
  monitorEventLoopDelaySpy = require('perf_hooks').monitorEventLoopDelay;

  return require('../eventLoopMonitor');
}

beforeEach(() => {
  jest.useFakeTimers();
  monitorEventLoopDelaySpy = jest.fn();
});

afterEach(() => {
  jest.useRealTimers();
  for (const key of _ENV_KEYS) delete process.env[key];
  jest.dontMock('perf_hooks');
  jest.dontMock('../../../services/logger');
  jest.dontMock('../../observability/metrics');
});

describe('eventLoopMonitor', () => {
  test('before initialize(): disabled, healthy, zeroed stats', () => {
    const mod = loadModule();
    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toBe('healthy');
    expect(mod.getStats()).toEqual({
      meanMs: 0, maxMs: 0, minMs: 0, stddevMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0,
    });
  });

  test('initialize() enables the histogram, starts the background timer, and logs once', () => {
    const mod = loadModule();
    mod.initialize();

    expect(mod.isEnabled()).toBe(true);
    expect(fakeHistogram.enable).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith('INFO', 'EVENT_LOOP_MONITOR_STARTED', expect.any(Object));
  });

  test('initialize() is idempotent — a second call does not recreate the histogram', () => {
    const mod = loadModule();
    mod.initialize();
    mod.initialize();
    expect(monitorEventLoopDelaySpy).toHaveBeenCalledTimes(2); // lifetime + RT-08 interval histogram
  });

  test('QODIQA_EVENT_LOOP_MONITOR_ENABLED=false skips initialization entirely', () => {
    const mod = loadModule({ QODIQA_EVENT_LOOP_MONITOR_ENABLED: 'false' });
    mod.initialize();

    expect(mod.isEnabled()).toBe(false);
    expect(monitorEventLoopDelaySpy).not.toHaveBeenCalled();
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'EVENT_LOOP_MONITOR_DISABLED', expect.any(Object));
  });

  test('shutdown() disables the histogram, stops the timer, and resets to healthy/zeroed', () => {
    const mod = loadModule();
    mod.initialize();
    mod.shutdown();

    expect(fakeHistogram.disable).toHaveBeenCalledTimes(1);
    expect(mod.isEnabled()).toBe(false);
    expect(mod.getState()).toBe('healthy');
    expect(mod.getStats()).toEqual({
      meanMs: 0, maxMs: 0, minMs: 0, stddevMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0,
    });
  });

  test('shutdown() is safe to call before initialize() or more than once', () => {
    const mod = loadModule();
    expect(() => mod.shutdown()).not.toThrow();
    mod.initialize();
    mod.shutdown();
    expect(() => mod.shutdown()).not.toThrow();
  });

  test('getStats() converts nanosecond histogram values to milliseconds', () => {
    const mod = loadModule();
    mod.initialize();

    fakeHistogram.mean   = 12 * 1e6;
    fakeHistogram.max    = 20 * 1e6;
    fakeHistogram.min    = 1  * 1e6;
    fakeHistogram.stddev = 3  * 1e6;
    fakeHistogram.percentile.mockImplementation((p) => {
      if (p === 50) return 10 * 1e6;
      if (p === 95) return 18 * 1e6;
      if (p === 99) return 19 * 1e6;
      return 0;
    });

    expect(mod.getStats()).toEqual({
      meanMs: 12, maxMs: 20, minMs: 1, stddevMs: 3, p50Ms: 10, p95Ms: 18, p99Ms: 19,
    });
  });

  test('background tick pushes current stats into the Prometheus gauges without resetting the histogram', () => {
    const mod = loadModule({ QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS: '1000' });
    mod.initialize();

    fakeHistogram.mean = 12 * 1e6;
    fakeHistogram.max  = 20 * 1e6;
    fakeHistogram.min  = 1  * 1e6;
    jest.advanceTimersByTime(1000);

    expect(metrics.eventLoopDelayMeanMs.set).toHaveBeenCalledWith({}, 12);
    expect(metrics.eventLoopDelayMaxMs.set).toHaveBeenCalledWith({}, 20);
    expect(metrics.eventLoopDelayMinMs.set).toHaveBeenCalledWith({}, 1);
    expect(metrics.eventLoopDelayStateCode.set).toHaveBeenCalledWith({}, 0);
  });

  test('state transitions are logged exactly once each — healthy -> degraded -> unhealthy -> healthy', () => {
    const mod = loadModule({
      QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS: '1000',
      QODIQA_EVENT_LOOP_WARN_MS:           '100',
      QODIQA_EVENT_LOOP_CRITICAL_MS:       '500',
    });
    mod.initialize();
    logger.emit.mockClear(); // drop the STARTED log

    // Still healthy — no log.
    fakeHistogram.mean = 50 * 1e6;
    jest.advanceTimersByTime(1000);
    expect(mod.getState()).toBe('healthy');
    expect(logger.emit).not.toHaveBeenCalled();

    // Crosses into degraded — exactly one WARN.
    fakeHistogram.mean = 150 * 1e6;
    jest.advanceTimersByTime(1000);
    expect(mod.getState()).toBe('degraded');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'WARN', 'EVENT_LOOP_DELAY_WARNING',
      expect.objectContaining({ fromState: 'healthy', toState: 'degraded' }),
    );

    // Sustained degraded — repeated ticks at the same state log nothing more.
    logger.emit.mockClear();
    jest.advanceTimersByTime(3000);
    expect(logger.emit).not.toHaveBeenCalled();

    // Crosses into unhealthy — exactly one ERROR.
    fakeHistogram.mean = 600 * 1e6;
    jest.advanceTimersByTime(1000);
    expect(mod.getState()).toBe('unhealthy');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'ERROR', 'EVENT_LOOP_DELAY_CRITICAL',
      expect.objectContaining({ fromState: 'degraded', toState: 'unhealthy' }),
    );

    // Recovery — exactly one INFO.
    logger.emit.mockClear();
    fakeHistogram.mean = 5 * 1e6;
    jest.advanceTimersByTime(1000);
    expect(mod.getState()).toBe('healthy');
    expect(logger.emit).toHaveBeenCalledTimes(1);
    expect(logger.emit).toHaveBeenCalledWith(
      'INFO', 'EVENT_LOOP_DELAY_RECOVERED',
      expect.objectContaining({ fromState: 'unhealthy', toState: 'healthy' }),
    );
  });
});

// RT-08: an interval histogram feeds window gauges and is reset every tick, so a
// boot-time spike no longer pins the only max signal forever.
test('RT-08 window gauges report the last interval and the interval histogram is reset each tick', () => {
  const mod = loadModule({ QODIQA_EVENT_LOOP_CHECK_INTERVAL_MS: '1000' });
  mod.initialize();
  fakeHistogram.max = 180 * 1e6;           // the boot-time spike stays in the lifetime histogram
  windowHistogram.max = 7 * 1e6;
  windowHistogram.percentile.mockImplementation(() => 5 * 1e6);
  jest.advanceTimersByTime(1000);
  expect(metrics.eventLoopDelayMaxMs.set).toHaveBeenLastCalledWith({}, 180);
  expect(metrics.eventLoopDelayWindowMaxMs.set).toHaveBeenLastCalledWith({}, 7);
  expect(metrics.eventLoopDelayWindowP99Ms.set).toHaveBeenLastCalledWith({}, 5);
  expect(windowHistogram.reset).toHaveBeenCalledTimes(1);
  expect(fakeHistogram.reset).not.toHaveBeenCalled(); // the lifetime histogram (and readiness) are unchanged
  mod.shutdown();
});
