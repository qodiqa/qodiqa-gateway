'use strict';

const { executeShutdown, registerHandlers, _reset } = require('../shutdown');
// THROUGHPUT-12: services/logger.js batches INFO/WARN/ERROR stdout writes and
// flushes asynchronously. executeShutdown() already awaits flush() internally
// before exiting (see src/runtime/shutdown.js Step 6), so most `await
// executeShutdown(...)` tests below need no change. The exceptions are: (a)
// tests that trigger a signal handler without awaiting executeShutdown to
// completion, and (b) the forced-exit timeout path, which exits before
// reaching Step 6 — both call flush() explicitly. events() also now splits on
// '\n' since a single write() call may batch multiple JSON records.
const { flush } = require('../../../services/logger');

// ── Shared helpers ────────────────────────────────────────────────────────────

function makeServer(opts = {}) {
  const { syncClose = true } = opts;
  return {
    close: syncClose
      ? jest.fn(cb => cb())       // resolves immediately
      : jest.fn(() => {}),         // never resolves — simulates stall
  };
}

function makeDrain() {
  return {
    beginShutdown: jest.fn(),
    activeCount:   jest.fn(() => 0),
    drain:         jest.fn().mockResolvedValue(undefined),
  };
}

// ── Test lifecycle ────────────────────────────────────────────────────────────

let written;
let writeSpy;
let exitMock;

beforeEach(() => {
  _reset();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');

  written  = [];
  writeSpy = jest.spyOn(process.stdout, 'write').mockImplementation(data => {
    if (typeof data === 'string') written.push(data);
    return true;
  });
  exitMock = jest.fn();
});

afterEach(() => {
  writeSpy.mockRestore();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
});

function events() {
  // A single write() call may contain multiple '\n'-joined records (batched
  // stdout flush — see services/logger.js) — split before parsing.
  return written
    .join('')
    .split('\n')
    .filter(line => line.trim())
    .map(line => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);
}

// ── Signal handler registration ───────────────────────────────────────────────

describe('signal handler registration', () => {
  it('registers exactly one SIGTERM listener', () => {
    registerHandlers({}, [], { _exit: exitMock });
    expect(process.listenerCount('SIGTERM')).toBe(1);
  });

  it('registers exactly one SIGINT listener', () => {
    registerHandlers({}, [], { _exit: exitMock });
    expect(process.listenerCount('SIGINT')).toBe(1);
  });

  it('SIGTERM emits SHUTDOWN_SIGNAL_RECEIVED before the shutdown sequence stalls', async () => {
    // stalled server → async chain never completes → no exit, no Step-6 flush.
    // SHUTDOWN_SIGNAL_RECEIVED is still queued synchronously by _doShutdown()
    // before executeShutdown() is even invoked — flush() here just forces
    // that already-queued record out (see services/logger.js batching).
    registerHandlers(makeServer({ syncClose: false }), [], { _exit: exitMock });
    process.emit('SIGTERM');
    await flush();
    expect(events().some(e => e.eventType === 'SHUTDOWN_SIGNAL_RECEIVED' && e.signal === 'SIGTERM'))
      .toBe(true);
  });

  it('SIGINT emits SHUTDOWN_SIGNAL_RECEIVED before the shutdown sequence stalls', async () => {
    registerHandlers(makeServer({ syncClose: false }), [], { _exit: exitMock });
    process.emit('SIGINT');
    await flush();
    expect(events().some(e => e.eventType === 'SHUTDOWN_SIGNAL_RECEIVED' && e.signal === 'SIGINT'))
      .toBe(true);
  });
});

// ── Single-execution guarantee ────────────────────────────────────────────────

describe('single-execution guarantee', () => {
  it('SHUTDOWN_STARTED appears exactly once when called concurrently', async () => {
    const drain = makeDrain();
    await Promise.all([
      executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: drain }),
      executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: drain }),
    ]);

    expect(events().filter(e => e.eventType === 'SHUTDOWN_STARTED')).toHaveLength(1);
    expect(exitMock).toHaveBeenCalledTimes(1);
    expect(exitMock).toHaveBeenCalledWith(0);
  });

  it('second call after first completes emits no events and does not call exit', async () => {
    await executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: makeDrain() });

    exitMock.mockClear();
    written = [];

    await executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: makeDrain() });

    expect(exitMock).not.toHaveBeenCalled();
    expect(events()).toHaveLength(0);
  });
});

// ── Shutdown timeout ──────────────────────────────────────────────────────────

describe('shutdown timeout', () => {
  it('emits SHUTDOWN_TIMEOUT and calls exit(1) when sequence stalls past timeoutMs', async () => {
    jest.useFakeTimers();

    // Never-closing server causes the chain to stall at step 2.
    executeShutdown(makeServer({ syncClose: false }), [], {
      timeoutMs: 100,
      _exit:     exitMock,
    });

    jest.advanceTimersByTime(200);
    await Promise.resolve();
    // The forced-exit timeout path exits before reaching Step 6's flush —
    // drain explicitly (flush() is synchronous under the hood, so it is
    // unaffected by fake timers).
    await flush();

    expect(exitMock).toHaveBeenCalledWith(1);
    expect(events().some(e => e.eventType === 'SHUTDOWN_TIMEOUT')).toBe(true);

    jest.useRealTimers();
  });
});

// ── Shutdown sequence ordering ────────────────────────────────────────────────

describe('shutdown sequence ordering', () => {
  it('beginShutdown() is called before httpServer.close() (step 1 before step 2)', async () => {
    const callOrder = [];
    const drain = {
      beginShutdown: jest.fn(() => callOrder.push('beginShutdown')),
      activeCount:   jest.fn(() => 0),
      drain:         jest.fn().mockResolvedValue(undefined),
    };
    const server = { close: jest.fn(cb => { callOrder.push('httpClose'); cb(); }) };

    await executeShutdown(server, [], { _exit: exitMock, _requestDrain: drain });

    expect(callOrder.indexOf('beginShutdown')).toBeLessThan(callOrder.indexOf('httpClose'));
  });

  it('SHUTDOWN_READY_FALSE appears before SHUTDOWN_HTTP_CLOSE_STARTED', async () => {
    await executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: makeDrain() });

    const ev  = events();
    const rdy = ev.findIndex(e => e.eventType === 'SHUTDOWN_READY_FALSE');
    const htp = ev.findIndex(e => e.eventType === 'SHUTDOWN_HTTP_CLOSE_STARTED');
    expect(rdy).toBeGreaterThanOrEqual(0);
    expect(htp).toBeGreaterThanOrEqual(0);
    expect(rdy).toBeLessThan(htp);
  });

  it('all required lifecycle events appear in correct order', async () => {
    await executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: makeDrain() });

    const names = events().map(e => e.eventType);
    const required = [
      'SHUTDOWN_STARTED',
      'SHUTDOWN_READY_FALSE',
      'SHUTDOWN_HTTP_CLOSE_STARTED',
      'SHUTDOWN_HTTP_CLOSED',
      'SHUTDOWN_DRAIN_STARTED',
      'SHUTDOWN_DRAIN_COMPLETE',
      'REDIS_SHUTDOWN_STARTED',
      'SHUTDOWN_AUDIT_FLUSH_STARTED',
      'SHUTDOWN_AUDIT_FLUSH_COMPLETE',
      'SHUTDOWN_COMPLETE',
    ];

    for (let i = 0; i < required.length - 1; i++) {
      const a = names.indexOf(required[i]);
      const b = names.indexOf(required[i + 1]);
      expect(a).toBeGreaterThanOrEqual(0);
      expect(b).toBeGreaterThanOrEqual(0);
      expect(a).toBeLessThan(b);
    }
  });

  it('calls exit(0) on successful shutdown', async () => {
    await executeShutdown(makeServer(), [], { _exit: exitMock, _requestDrain: makeDrain() });
    expect(exitMock).toHaveBeenCalledWith(0);
  });
});

// ── Redis shutdown ────────────────────────────────────────────────────────────

describe('Redis shutdown', () => {
  it('emits REDIS_SHUTDOWN_STARTED then REDIS_SHUTDOWN_COMPLETED for a successful disconnect', async () => {
    const store = { disconnect: jest.fn().mockResolvedValue(undefined) };

    await executeShutdown(makeServer(), [{ name: 'NONCE_STORE', store }], {
      _exit: exitMock, _requestDrain: makeDrain(),
    });

    const ev = events();
    expect(ev.some(e => e.eventType === 'REDIS_SHUTDOWN_STARTED')).toBe(true);
    const completed = ev.filter(e => e.eventType === 'REDIS_SHUTDOWN_COMPLETED');
    expect(completed).toHaveLength(1);
    expect(completed[0].source).toBe('NONCE_STORE');
    expect(store.disconnect).toHaveBeenCalledTimes(1);
  });

  it('emits REDIS_SHUTDOWN_FAILED on disconnect error and shutdown still completes with exit(0)', async () => {
    const store = { disconnect: jest.fn().mockRejectedValue(new Error('connection lost')) };

    await executeShutdown(makeServer(), [{ name: 'NONCE_STORE', store }], {
      _exit: exitMock, _requestDrain: makeDrain(),
    });

    const ev = events();
    expect(ev.some(e => e.eventType === 'REDIS_SHUTDOWN_FAILED' && e.source === 'NONCE_STORE')).toBe(true);
    expect(exitMock).toHaveBeenCalledWith(0);
  });

  it('disconnects all three stores independently via Promise.allSettled', async () => {
    const stores = [
      { name: 'NONCE_STORE',      store: { disconnect: jest.fn().mockResolvedValue(undefined) } },
      { name: 'ANOMALY_STORE',    store: { disconnect: jest.fn().mockResolvedValue(undefined) } },
      { name: 'RATE_LIMIT_STORE', store: { disconnect: jest.fn().mockResolvedValue(undefined) } },
    ];

    await executeShutdown(makeServer(), stores, { _exit: exitMock, _requestDrain: makeDrain() });

    for (const { store } of stores) {
      expect(store.disconnect).toHaveBeenCalledTimes(1);
    }
    expect(events().filter(e => e.eventType === 'REDIS_SHUTDOWN_COMPLETED')).toHaveLength(3);
  });

  it('continues shutdown when one store fails and another succeeds', async () => {
    const stores = [
      { name: 'NONCE_STORE',   store: { disconnect: jest.fn().mockRejectedValue(new Error('err')) } },
      { name: 'ANOMALY_STORE', store: { disconnect: jest.fn().mockResolvedValue(undefined) } },
    ];

    await executeShutdown(makeServer(), stores, { _exit: exitMock, _requestDrain: makeDrain() });

    const ev = events();
    expect(ev.some(e => e.eventType === 'REDIS_SHUTDOWN_FAILED'    && e.source === 'NONCE_STORE')).toBe(true);
    expect(ev.some(e => e.eventType === 'REDIS_SHUTDOWN_COMPLETED' && e.source === 'ANOMALY_STORE')).toBe(true);
    expect(exitMock).toHaveBeenCalledWith(0);
  });
});

// GA-CKPT-RATE: the final signed audit checkpoint runs as a pre-store hook — after the
// request drain, before any store (PostgreSQL included) is disconnected, and a failing hook never aborts shutdown.
describe('pre-store hooks (final audit checkpoint)', () => {
  it('runs after the request drain and before the first store disconnect', async () => {
    const order = [];
    const drain = makeDrain(); drain.drain.mockImplementation(async () => { order.push('drain'); });
    const stores = [{ name: 'PG_POOL', store: { disconnect: jest.fn(async () => { order.push('disconnect'); }) } }];
    const hook = { name: 'AUDIT_FINAL_CHECKPOINT', run: jest.fn(async () => { order.push('checkpoint'); }) };
    await executeShutdown(makeServer(), stores, { _exit: exitMock, _requestDrain: drain, preStoreHooks: [hook] });
    expect(order).toEqual(['drain', 'checkpoint', 'disconnect']);
    expect(exitMock).toHaveBeenCalledWith(0);
  });

  it('a failing hook is reported and shutdown still completes with exit(0)', async () => {
    const stores = [{ name: 'PG_POOL', store: { disconnect: jest.fn().mockResolvedValue(undefined) } }];
    const hook = { name: 'AUDIT_FINAL_CHECKPOINT', run: jest.fn().mockRejectedValue(new Error('sign failed')) };
    await executeShutdown(makeServer(), stores, { _exit: exitMock, _requestDrain: makeDrain(), preStoreHooks: [hook] });
    expect(events().some(e => e.eventType === 'SHUTDOWN_HOOK_FAILED' && e.hook === 'AUDIT_FINAL_CHECKPOINT')).toBe(true);
    expect(stores[0].store.disconnect).toHaveBeenCalled();
    expect(exitMock).toHaveBeenCalledWith(0);
  });

  it('registerHandlers forwards preStoreHooks to the shutdown sequence', async () => {
    const hook = { name: 'AUDIT_FINAL_CHECKPOINT', run: jest.fn().mockResolvedValue(undefined) };
    registerHandlers(makeServer(), [], { _exit: exitMock, requestDrain: makeDrain(), preStoreHooks: [hook] });
    process.emit('SIGTERM');
    for (let i = 0; i < 50 && !exitMock.mock.calls.length; i++) await new Promise((r) => setTimeout(r, 10));
    expect(hook.run).toHaveBeenCalledTimes(1);
  });
});
