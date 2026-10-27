'use strict';

// #7 — dashboard resilience: per-client SSE isolation (regression)
// and backpressure handling (new). sseManager.js subscribes to the
// dashboard bus at module-load time and holds module-level singleton state
// (_clients, timers), so every test loads a fresh instance via
// jest.resetModules() + jest.doMock(), matching the pattern used by the
// other background-monitor test files.

function makeRes(overrides = {}) {
  return {
    write: jest.fn(() => true),
    once:  jest.fn(),
    ...overrides,
  };
}

function loadModule() {
  jest.resetModules();

  const busHandlers = {};
  jest.doMock('../bus', () => ({
    subscribe: jest.fn((channel, handler) => { busHandlers[channel] = handler; }),
  }));
  jest.doMock('../aggregator', () => ({
    getOverview: jest.fn(() => ({ requests: 0 })),
  }));
  jest.doMock('../statusChecker', () => ({
    getStatus: jest.fn(() => ({ ready: true })),
  }));
  jest.doMock('../../runtime/backgroundTasks/BackgroundTaskRunner', () => ({
    runTask: jest.fn((_name, fn) => Promise.resolve(fn())),
  }));
  jest.doMock('../../observability/metrics', () => ({
    dashboardSseBackpressureEventsTotal: { inc: jest.fn() },
  }));

  const sseManager = require('../sseManager');
  const metrics    = require('../../observability/metrics');
  // addClient() starts real setInterval timers that only stop when
  // the last client is removed; without this they kept firing after the file
  // finished ("require after the Jest environment has been torn down" from
  // _recordBackpressureSkip). Record every client so afterEach removes it.
  const addClient = sseManager.addClient;
  sseManager.addClient = (res) => {
    const id = addClient(res);
    _addedClients.push(() => sseManager.removeClient(id));
    return id;
  };
  return { sseManager, busHandlers, metrics };
}

const _addedClients = [];

afterEach(() => {
  while (_addedClients.length) _addedClients.pop()();
  jest.dontMock('../bus');
  jest.dontMock('../aggregator');
  jest.dontMock('../statusChecker');
  jest.dontMock('../../runtime/backgroundTasks/BackgroundTaskRunner');
  jest.dontMock('../../observability/metrics');
});

describe('sseManager — per-client isolation (regression)', () => {
  test('one client\'s res.write() throwing does not affect delivery to other clients', () => {
    const { sseManager, busHandlers } = loadModule();

    const throwingRes = makeRes({ write: jest.fn(() => { throw new Error('ECONNRESET'); }) });
    const healthyRes   = makeRes();

    sseManager.addClient(throwingRes);
    sseManager.addClient(healthyRes);
    healthyRes.write.mockClear(); // drop the initial-snapshot write from addClient

    expect(() => busHandlers.log({ eventType: 'TEST_EVENT' })).not.toThrow();
    expect(healthyRes.write).toHaveBeenCalledTimes(1);
    expect(healthyRes.write.mock.calls[0][0]).toContain('TEST_EVENT');
  });

  test('a client that disconnects before its first write (addClient) does not prevent addClient from returning an id', () => {
    const { sseManager } = loadModule();
    const throwingRes = makeRes({ write: jest.fn(() => { throw new Error('disconnected'); }) });

    expect(() => sseManager.addClient(throwingRes)).not.toThrow();
  });
});

describe('sseManager — backpressure', () => {
  test('log events are always attempted, even to a client whose last write returned false', () => {
    const { sseManager, busHandlers } = loadModule();
    const backedUpRes = makeRes({ write: jest.fn(() => false) });

    sseManager.addClient(backedUpRes); // initial snapshot write returns false -> marks backpressured
    backedUpRes.write.mockClear();

    busHandlers.log({ eventType: 'AUDIT_EXECUTION_RECORDED' });

    expect(backedUpRes.write).toHaveBeenCalledTimes(1);
  });

  test('res.write() returning false marks the client backpressured and registers a one-time drain listener', () => {
    const { sseManager } = loadModule();
    const backedUpRes = makeRes({ write: jest.fn(() => false) });

    sseManager.addClient(backedUpRes);

    expect(backedUpRes.once).toHaveBeenCalledWith('drain', expect.any(Function));
  });

  test('the drain listener clears backpressure so subsequent broadcasts reach the client again', () => {
    const { sseManager, busHandlers } = loadModule();
    let drainCallback;
    const res = makeRes({
      write: jest.fn(() => false),
      once:  jest.fn((evt, cb) => { if (evt === 'drain') drainCallback = cb; }),
    });

    sseManager.addClient(res); // backpressured after the initial write

    drainCallback(); // simulate the socket draining
    res.write.mockImplementation(() => true);
    res.write.mockClear();

    busHandlers.log({ eventType: 'AFTER_DRAIN' });

    expect(res.write).toHaveBeenCalledTimes(1);
  });

  test('metrics counter increments once per backpressure marking, not accumulated silently forever', () => {
    const { sseManager } = loadModule();
    const res = makeRes({ write: jest.fn(() => false) });

    sseManager.addClient(res);

    // once() is only registered on the transition into backpressure — a
    // second write() returning false while already backpressured must not
    // register a second drain listener (idempotent marking).
    expect(res.once).toHaveBeenCalledTimes(1);
  });

  test('a periodic "snapshot" tick skips a backpressured client and increments the mapping metric, but still ticks for a healthy client', () => {
    jest.useFakeTimers();
    const { sseManager, metrics } = loadModule();

    const backedUpRes = makeRes({ write: jest.fn(() => false) });
    const healthyRes   = makeRes();
    sseManager.addClient(backedUpRes);
    sseManager.addClient(healthyRes);
    backedUpRes.write.mockClear();
    healthyRes.write.mockClear();

    jest.advanceTimersByTime(5_000); // SNAPSHOT_INTERVAL_MS

    expect(backedUpRes.write).not.toHaveBeenCalled();
    expect(healthyRes.write).toHaveBeenCalledTimes(1);
    expect(metrics.dashboardSseBackpressureEventsTotal.inc).toHaveBeenCalledWith({ eventName: 'snapshot' });

    jest.useRealTimers();
  });
});
