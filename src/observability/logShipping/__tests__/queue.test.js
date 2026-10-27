'use strict';

const { createQueue, _isRetryable } = require('../queue');

// ── _isRetryable ──────────────────────────────────────────────────────────────

describe('_isRetryable', () => {
  it('returns true for err.retryable === true', () => {
    expect(_isRetryable(Object.assign(new Error(), { retryable: true }))).toBe(true);
  });

  it('returns false for err.retryable === false', () => {
    expect(_isRetryable(Object.assign(new Error(), { retryable: false }))).toBe(false);
  });

  it('returns true for ECONNREFUSED code', () => {
    expect(_isRetryable(Object.assign(new Error(), { code: 'ECONNREFUSED' }))).toBe(true);
  });

  it('returns true for ETIMEDOUT code', () => {
    expect(_isRetryable(Object.assign(new Error(), { code: 'ETIMEDOUT' }))).toBe(true);
  });

  it('returns true for ENOTFOUND code', () => {
    expect(_isRetryable(Object.assign(new Error(), { code: 'ENOTFOUND' }))).toBe(true);
  });

  it('returns false for generic error with no classification', () => {
    expect(_isRetryable(new Error('something bad'))).toBe(false);
  });

  it('returns false for null', () => {
    expect(_isRetryable(null)).toBe(false);
  });
});

// ── createQueue — failure isolation ──────────────────────────────────────────

describe('createQueue — failure isolation', () => {
  const CONFIG = { maxRetries: 0 };

  it('ship() does not throw when destination.send() throws', () => {
    const dest = {
      name: 'test',
      send: jest.fn().mockRejectedValue(new Error('destination down')),
    };
    const q = createQueue([dest], CONFIG);
    expect(() => q.ship({ eventType: 'X' })).not.toThrow();
  });

  it('ship() returns undefined synchronously (non-blocking)', () => {
    const dest = { name: 'test', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], CONFIG);
    const result = q.ship({ eventType: 'X' });
    expect(result).toBeUndefined();
  });

  it('one destination failing does not prevent others from being called', async () => {
    const failDest  = { name: 'fail',    send: jest.fn().mockRejectedValue(new Error('fail')) };
    const goodDest  = { name: 'good',    send: jest.fn().mockResolvedValue() };
    const q = createQueue([failDest, goodDest], CONFIG);

    q.ship({ eventType: 'X' });
    await new Promise(r => setImmediate(r)); // flush microtasks

    expect(goodDest.send).toHaveBeenCalledTimes(1);
  });
});

// ── createQueue — retry logic ─────────────────────────────────────────────────

describe('createQueue — retry logic', () => {
  // Only fake setTimeout/setInterval — leave setImmediate and nextTick real so
  // promise-flush helpers (await new Promise(r => setImmediate(r))) still work.
  beforeEach(() => jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] }));
  afterEach(() => jest.useRealTimers());

  it('retries on retryable error up to maxRetries times', async () => {
    const transientErr = Object.assign(new Error('transient'), { retryable: true });
    const send = jest.fn()
      .mockRejectedValueOnce(transientErr)
      .mockRejectedValueOnce(transientErr)
      .mockResolvedValueOnce();

    const dest = { name: 'test', send };
    const q = createQueue([dest], { maxRetries: 3 });

    q.ship({ eventType: 'X' });

    // First attempt fires and rejects; _sleep(1000) is now scheduled.
    await new Promise(r => setImmediate(r));

    jest.advanceTimersByTime(1000);
    // Second attempt fires and rejects; _sleep(2000) is now scheduled.
    await new Promise(r => setImmediate(r));

    jest.advanceTimersByTime(2000);
    // Third attempt fires and resolves.
    await new Promise(r => setImmediate(r));

    expect(send).toHaveBeenCalledTimes(3);
  });

  it('does not retry non-retryable errors', async () => {
    const nonRetryable = Object.assign(new Error('auth failure'), { retryable: false });
    const send = jest.fn().mockRejectedValue(nonRetryable);
    const dest = { name: 'test', send };
    const q = createQueue([dest], { maxRetries: 3 });

    q.ship({ eventType: 'X' });
    await new Promise(r => setImmediate(r));

    expect(send).toHaveBeenCalledTimes(1);
  });
});

// ── createQueue — health monitoring ───────────────────────────────────────────

describe('createQueue — health monitoring', () => {
  it('getHealth returns unknown status before any traffic', () => {
    const dest = { name: 'elk', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], { maxRetries: 0 });
    const health = q.getHealth();
    expect(health.elk).toMatchObject({ destination: 'elk', status: 'unknown' });
  });

  it('getHealth shows healthy after successful send', async () => {
    const dest = { name: 'elk', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship({ eventType: 'X' });
    await new Promise(r => setImmediate(r));

    expect(q.getHealth().elk.status).toBe('healthy');
    expect(q.getHealth().elk.lastSuccess).not.toBeNull();
  });

  it('getHealth shows degraded after failed send', async () => {
    const dest = {
      name: 'splunk',
      send: jest.fn().mockRejectedValue(Object.assign(new Error('fail'), { retryable: false })),
    };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship({ eventType: 'X' });
    await new Promise(r => setImmediate(r));

    expect(q.getHealth().splunk.status).toBe('degraded');
    expect(q.getHealth().splunk.lastFailure).not.toBeNull();
  });

  it('getHealth includes queuedEvents count', () => {
    const dest = { name: 'dd', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], { maxRetries: 0 });
    expect(q.getHealth().dd.queuedEvents).toBe(0);
  });
});

// ── createQueue — metrics ─────────────────────────────────────────────────────

describe('createQueue — metrics', () => {
  it('tracks logs_exported_total after successful send', async () => {
    const dest = { name: 'elk', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship([{ eventType: 'X' }, { eventType: 'Y' }]);
    await new Promise(r => setImmediate(r));

    expect(q.getMetrics().elk.logs_exported_total).toBe(2);
  });

  it('tracks logs_failed_total after non-retryable failure', async () => {
    const dest = {
      name: 'elk',
      send: jest.fn().mockRejectedValue(Object.assign(new Error(), { retryable: false })),
    };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship([{ eventType: 'X' }]);
    await new Promise(r => setImmediate(r));

    expect(q.getMetrics().elk.logs_failed_total).toBe(1);
  });

  it('tracks queue_depth', () => {
    const dest = { name: 'elk', send: jest.fn().mockResolvedValue() };
    const q = createQueue([dest], { maxRetries: 0 });
    expect(q.getMetrics().elk.queue_depth).toBe(0);
  });
});

// ── createQueue — backpressure / dropped events ───────────────────────────────

describe('createQueue — backpressure', () => {
  it('drops events beyond maxQueueDepth and counts them', async () => {
    let resolveSend;
    const send = jest.fn(() => new Promise(r => { resolveSend = r; }));
    const dest = { name: 'slow', send };
    const q = createQueue([dest], { maxRetries: 0, maxQueueDepth: 1 });

    q.ship({ eventType: 'A' }); // occupies the single slot (queueDepth increments synchronously)
    q.ship({ eventType: 'B' }); // should be dropped — depth check is synchronous too

    // dest.send() itself is invoked on a later microtask (BackgroundTaskRunner
    // defers via Promise.resolve().then(fn)); the depth bookkeeping above is
    // synchronous and already reflects the drop, but wait a tick before
    // asserting on the mock so the first dispatch has actually started.
    await new Promise(r => setImmediate(r));

    expect(send).toHaveBeenCalledTimes(1);
    expect(q.getMetrics().slow.logs_dropped_total).toBe(1);

    resolveSend();
    await new Promise(r => setImmediate(r));
  });

  it('does not drop once in-flight count falls back under the cap', async () => {
    const send = jest.fn().mockResolvedValue();
    const dest = { name: 'fast', send };
    const q = createQueue([dest], { maxRetries: 0, maxQueueDepth: 1 });

    q.ship({ eventType: 'A' });
    await new Promise(r => setImmediate(r));
    q.ship({ eventType: 'B' });
    await new Promise(r => setImmediate(r));

    expect(send).toHaveBeenCalledTimes(2);
    expect(q.getMetrics().fast.logs_dropped_total).toBe(0);
  });
});

// ── createQueue — graceful shutdown drain ─────────────────────────────────────

describe('createQueue — drain', () => {
  it('resolves immediately when nothing is in flight', async () => {
    const q = createQueue([{ name: 'x', send: jest.fn().mockResolvedValue() }], { maxRetries: 0 });
    await expect(q.drain(1000)).resolves.toBeUndefined();
  });

  it('waits for an in-flight dispatch to settle', async () => {
    let resolveSend;
    const send = jest.fn(() => new Promise(r => { resolveSend = r; }));
    const dest = { name: 'x', send };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship({ eventType: 'A' });
    const drainPromise = q.drain(5000);

    // Not yet settled — resolve the underlying send after a tick.
    setImmediate(() => resolveSend());

    await drainPromise;
    expect(q.getMetrics().x.logs_exported_total).toBe(1);
  });

  it('does not hang indefinitely — bounded by timeoutMs', async () => {
    const send = jest.fn(() => new Promise(() => {})); // never resolves
    const dest = { name: 'stuck', send };
    const q = createQueue([dest], { maxRetries: 0 });

    q.ship({ eventType: 'A' });
    const start = Date.now();
    await q.drain(100);
    expect(Date.now() - start).toBeLessThan(2000);
  });
});

// ── createQueue — ship() with no destinations ─────────────────────────────────

describe('createQueue — empty destinations', () => {
  it('ship() does not throw with empty destinations array', () => {
    const q = createQueue([], { maxRetries: 0 });
    expect(() => q.ship({ eventType: 'X' })).not.toThrow();
  });
});

// ── createLogShipper — failure isolation from shipper API ────────────────────

describe('createLogShipper — failure isolation', () => {
  it('ship() on no-op shipper never throws', () => {
    const { createLogShipper } = require('../index');
    const config = {
      elk:     { enabled: false, valid: false },
      datadog: { enabled: false, valid: false },
      splunk:  { enabled: false, valid: false },
      maxRetries: 0, batchSize: 50,
      service: 'qodiqa', environment: 'test',
    };
    const shipper = createLogShipper(config);
    expect(() => shipper.ship({ eventType: 'CERT_COMPLETE' })).not.toThrow();
    expect(shipper.getHealth()).toEqual({});
    expect(shipper.getMetrics()).toEqual({});
  });

  it('shipper ship() does not throw even when all destinations fail', async () => {
    const { createLogShipper } = require('../index');
    const config = {
      elk:     { enabled: true, valid: true, url: 'https://elk.test' },
      datadog: { enabled: false, valid: false },
      splunk:  { enabled: false, valid: false },
      maxRetries: 0, batchSize: 50,
      service: 'qodiqa', environment: 'test',
    };
    const failPost = jest.fn().mockRejectedValue(new Error('connection refused'));
    const shipper = createLogShipper(config, { elkHttpsPost: failPost });

    expect(() => shipper.ship({ eventType: 'X', level: 'INFO' })).not.toThrow();
    await new Promise(r => setImmediate(r));
    // After the async failure, ship is still callable
    expect(() => shipper.ship({ eventType: 'Y' })).not.toThrow();
  });
});
