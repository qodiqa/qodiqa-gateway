'use strict';

const drain = require('../requestDrain');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeRes(opts = {}) {
  const handlers = {};
  return {
    _handlers: handlers,
    on: jest.fn((event, fn) => { handlers[event] = fn; }),
    status: jest.fn().mockReturnThis(),
    json:   jest.fn(),
    ...opts,
  };
}

function runMiddleware(res, next) {
  drain.middleware({}, res, next || jest.fn());
}

// ── Test lifecycle ────────────────────────────────────────────────────────────

beforeEach(() => {
  drain._reset();
});

// ── Active request counter ────────────────────────────────────────────────────

describe('active request counter', () => {
  it('starts at zero', () => {
    expect(drain.activeCount()).toBe(0);
  });

  it('increments by 1 when a request enters the pipeline', () => {
    const res  = makeRes();
    const next = jest.fn();
    runMiddleware(res, next);

    expect(drain.activeCount()).toBe(1);
    expect(next).toHaveBeenCalled();
  });

  it('decrements to 0 when the response emits finish', () => {
    const res = makeRes();
    runMiddleware(res);
    expect(drain.activeCount()).toBe(1);

    res._handlers.finish();
    expect(drain.activeCount()).toBe(0);
  });

  it('decrements to 0 when the response emits close', () => {
    const res = makeRes();
    runMiddleware(res);
    expect(drain.activeCount()).toBe(1);

    res._handlers.close();
    expect(drain.activeCount()).toBe(0);
  });

  it('decrements exactly once even when both finish and close fire', () => {
    const res = makeRes();
    runMiddleware(res);
    expect(drain.activeCount()).toBe(1);

    res._handlers.finish();
    res._handlers.close(); // second event — must not go below 0
    expect(drain.activeCount()).toBe(0);
  });

  it('tracks multiple concurrent requests correctly', () => {
    const r1 = makeRes();
    const r2 = makeRes();
    const r3 = makeRes();

    runMiddleware(r1);
    runMiddleware(r2);
    runMiddleware(r3);
    expect(drain.activeCount()).toBe(3);

    r1._handlers.finish();
    expect(drain.activeCount()).toBe(2);

    r2._handlers.finish();
    r3._handlers.close();
    expect(drain.activeCount()).toBe(0);
  });
});

// ── Shutdown rejection ────────────────────────────────────────────────────────

describe('shutdown rejection', () => {
  it('returns HTTP 503 for new requests after beginShutdown()', () => {
    drain.beginShutdown();

    const res  = makeRes();
    const next = jest.fn();
    runMiddleware(res, next);

    expect(res.status).toHaveBeenCalledWith(503);
    expect(next).not.toHaveBeenCalled();
  });

  it('503 body matches SERVICE_SHUTTING_DOWN canonical shape', () => {
    drain.beginShutdown();

    const res = makeRes();
    runMiddleware(res);

    expect(res.json).toHaveBeenCalledWith({
      success: false,
      error: {
        code:    'SERVICE_SHUTTING_DOWN',
        message: 'Service unavailable',
      },
    });
  });

  it('does not increment the counter for rejected requests', () => {
    drain.beginShutdown();

    runMiddleware(makeRes());
    runMiddleware(makeRes());

    expect(drain.activeCount()).toBe(0);
  });

  it('does not call next() for rejected requests', () => {
    drain.beginShutdown();

    const next = jest.fn();
    drain.middleware({}, makeRes(), next);

    expect(next).not.toHaveBeenCalled();
  });
});

// ── In-flight completion after shutdown begins ────────────────────────────────

describe('in-flight request completion after beginShutdown()', () => {
  it('allows a request that entered before shutdown to decrement correctly', () => {
    const res = makeRes();
    runMiddleware(res); // enters before shutdown
    expect(drain.activeCount()).toBe(1);

    drain.beginShutdown();
    expect(drain.activeCount()).toBe(1); // still in-flight

    res._handlers.finish();
    expect(drain.activeCount()).toBe(0);
  });

  it('new requests are rejected while the earlier request is still in-flight', () => {
    const res1 = makeRes();
    runMiddleware(res1);

    drain.beginShutdown();

    const res2 = makeRes();
    const next = jest.fn();
    runMiddleware(res2, next);

    expect(res2.status).toHaveBeenCalledWith(503);
    expect(drain.activeCount()).toBe(1); // only the original request counted
  });
});

// ── Drain ─────────────────────────────────────────────────────────────────────

describe('drain()', () => {
  it('resolves immediately when active count is already zero', async () => {
    await expect(drain.drain()).resolves.toBeUndefined();
  });

  it('resolves after an in-flight request completes', async () => {
    const res = makeRes();
    runMiddleware(res);
    expect(drain.activeCount()).toBe(1);

    const drainPromise = drain.drain();

    res._handlers.finish(); // triggers decrement → 0

    await drainPromise;
    expect(drain.activeCount()).toBe(0);
  });
});

// ── State reset ───────────────────────────────────────────────────────────────

describe('_reset()', () => {
  it('clears active count to zero', () => {
    const res = makeRes();
    runMiddleware(res);
    expect(drain.activeCount()).toBe(1);

    drain._reset();
    expect(drain.activeCount()).toBe(0);
  });

  it('clears shutting-down flag so middleware accepts new requests again', () => {
    drain.beginShutdown();
    expect(drain.isShuttingDown()).toBe(true);

    drain._reset();
    expect(drain.isShuttingDown()).toBe(false);

    const res  = makeRes();
    const next = jest.fn();
    runMiddleware(res, next);
    expect(next).toHaveBeenCalled();
    expect(drain.activeCount()).toBe(1);
  });
});
