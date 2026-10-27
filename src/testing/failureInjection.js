'use strict';

/**
 * Failure Injection Framework —
 *
 * Provides injectable faults for integration testing of QODIQA's fail-closed
 * enforcement pipeline.  All faults are implemented as in-process interceptors
 * that wrap existing store/pool interfaces — no real infrastructure is required.
 *
 * Fault types:
 *   REDIS_DOWN           — all store operations reject immediately (ECONNREFUSED)
 *   REDIS_LATENCY        — all store operations are delayed by N ms before resolving
 *   REDIS_TIMEOUT        — all store operations hang until a timeout fires
 *   PG_DOWN              — all pool.query() calls reject immediately
 *   PG_LATENCY           — all pool.query() calls are delayed by N ms
 *   PG_SATURATION        — pool.connect() hangs (simulates pool exhaustion)
 *   NETWORK_PARTITION    — both Redis and PG stores fail simultaneously
 *   MEMORY_PRESSURE      — allocates a configurable block of heap before each call
 *   DISK_FULL            — fs.writeFile/writeFileSync calls throw ENOSPC
 *   CLOCK_SKEW           — Date.now() returns a value offset by N ms
 *
 * Usage:
 *   const faults = new FaultInjector();
 *   const brokenStore = faults.redisDown(realStore);
 *   // ... run test against brokenStore ...
 *   faults.restore(); // remove all fault interceptors
 */

// ── Error factories ───────────────────────────────────────────────────────────

function _econnrefused(msg = 'connect ECONNREFUSED 127.0.0.1:6379') {
  return Object.assign(new Error(msg), { code: 'ECONNREFUSED' });
}

function _etimedout(msg = 'connect ETIMEDOUT') {
  return Object.assign(new Error(msg), { code: 'ETIMEDOUT' });
}

function _enospc(msg = 'ENOSPC: no space left on device') {
  return Object.assign(new Error(msg), { code: 'ENOSPC' });
}

// ── Nonce store faults ────────────────────────────────────────────────────────

/**
 * Wrap a nonce store so all operations reject immediately (simulates Redis down).
 *
 * @param {object} [_store] — original store (unused; all calls fail)
 * @returns {object}        — store-shaped object whose methods always reject
 */
function redisDownNonceStore(_store) {
  const fail = () => Promise.reject(_econnrefused());
  return { register: fail, isRegistered: fail };
}

/**
 * Wrap a nonce store so all operations are delayed by `latencyMs`.
 *
 * @param {object} store
 * @param {number} latencyMs
 * @returns {object}
 */
function redisLatencyNonceStore(store, latencyMs) {
  // the wrapper used to call fn() with NO arguments, silently dropping every argument of the wrapped
  // store call (register(nonce, ttl) became register()). Arguments are now forwarded.
  const _delay = (fn) => (...args) => new Promise((res, rej) => {
    setTimeout(() => fn(...args).then(res, rej), latencyMs);
  });
  return {
    register:     _delay((...a) => store.register(...a)),
    isRegistered: _delay((...a) => store.isRegistered(...a)),
  };
}

/**
 * Wrap a nonce store so all operations hang indefinitely (until aborted by the
 * caller's own timeout, simulating a network partition with no RST).
 *
 * @param {object} _store
 * @param {number} [hangMs=30000]  — how long to hang before rejecting
 * @returns {object}
 */
function redisTimeoutNonceStore(_store, hangMs = 30_000) {
  const hang = () => new Promise((_, rej) => setTimeout(() => rej(_etimedout()), hangMs));
  return { register: hang, isRegistered: hang };
}

// ── Anomaly store faults ──────────────────────────────────────────────────────

function redisDownAnomalyStore() {
  const fail = () => Promise.reject(_econnrefused());
  return { record: fail, peek: fail };
}

function redisLatencyAnomalyStore(store, latencyMs) {
  // the wrapper used to call fn() with NO arguments, silently dropping every argument of the wrapped
  // store call (register(nonce, ttl) became register()). Arguments are now forwarded.
  const _delay = (fn) => (...args) => new Promise((res, rej) => {
    setTimeout(() => fn(...args).then(res, rej), latencyMs);
  });
  return {
    record: _delay((...a) => store.record(...a)),
    peek:   _delay((...a) => store.peek(...a)),
  };
}

function redisTimeoutAnomalyStore(_store, hangMs = 30_000) {
  const hang = () => new Promise((_, rej) => setTimeout(() => rej(_etimedout()), hangMs));
  return { record: hang, peek: hang };
}

// ── PG pool faults ────────────────────────────────────────────────────────────

/**
 * Wrap a pg.Pool-compatible object so all query() calls reject immediately.
 *
 * @param {object} [_pool]
 * @returns {object}
 */
function pgDownPool(_pool) {
  const fail = () => Promise.reject(
    Object.assign(new Error('connection refused'), { code: 'ECONNREFUSED' })
  );
  return { query: fail, connect: fail, end: () => Promise.resolve() };
}

/**
 * Wrap a pg.Pool so all query() calls are delayed by `latencyMs`.
 *
 * @param {object} pool
 * @param {number} latencyMs
 * @returns {object}
 */
function pgLatencyPool(pool, latencyMs) {
  return {
    async query(...args) {
      await new Promise(r => setTimeout(r, latencyMs));
      return pool.query(...args);
    },
    async connect() {
      await new Promise(r => setTimeout(r, latencyMs));
      return pool.connect();
    },
    end: () => pool.end(),
  };
}

/**
 * Wrap a pg.Pool so all connect() calls hang (simulates pool exhaustion).
 *
 * @param {object} _pool
 * @param {number} [hangMs=30000]
 * @returns {object}
 */
function pgSaturationPool(_pool, hangMs = 30_000) {
  const hang = () => new Promise((_, rej) => setTimeout(() => rej(_etimedout()), hangMs));
  return {
    connect: hang,
    query:   hang,
    end:     () => Promise.resolve(),
  };
}

// ── Disk fault ────────────────────────────────────────────────────────────────

/**
 * Intercept `fs.writeFile` and `fs.writeFileSync` to throw ENOSPC.
 * Returns a restore function; call it when the test is complete.
 *
 * WARNING: this patches the `fs` module in-process.  Always call restore()
 * in an afterEach/finally block.
 *
 * @returns {{ restore: Function }}
 */
function injectDiskFull() {
  const fs = require('fs');
  const origWriteFile     = fs.writeFile.bind(fs);
  const origWriteFileSync = fs.writeFileSync.bind(fs);
  const origRenameSync    = fs.renameSync.bind(fs);
  const origAppendFile    = fs.appendFile.bind(fs);

  fs.writeFile = (_p, _d, _o, cb) => {
    const callback = typeof _o === 'function' ? _o : cb;
    if (typeof callback === 'function') callback(_enospc());
    else return Promise.reject(_enospc());
  };
  fs.writeFileSync = () => { throw _enospc(); };
  fs.renameSync    = () => { throw _enospc(); };
  fs.appendFile    = (_p, _d, _o, cb) => {
    const callback = typeof _o === 'function' ? _o : cb;
    if (typeof callback === 'function') callback(_enospc());
    else return Promise.reject(_enospc());
  };

  return {
    restore() {
      fs.writeFile     = origWriteFile;
      fs.writeFileSync = origWriteFileSync;
      fs.renameSync    = origRenameSync;
      fs.appendFile    = origAppendFile;
    },
  };
}

// ── Clock skew ────────────────────────────────────────────────────────────────

/**
 * Offset `Date.now()` by `skewMs` milliseconds (positive = future, negative = past).
 * Returns a restore function.
 *
 * @param {number} skewMs
 * @returns {{ restore: Function }}
 */
function injectClockSkew(skewMs) {
  const origNow = Date.now.bind(Date);
  Date.now = () => origNow() + skewMs;
  return {
    restore() { Date.now = origNow; },
  };
}

// ── Memory pressure ───────────────────────────────────────────────────────────

/**
 * Allocate `sizeBytes` of heap before each call to `fn`, to simulate
 * memory pressure.  The buffer is held for the duration of `fn` then released.
 *
 * Returns a wrapped version of `fn`.
 *
 * @param {Function} fn
 * @param {number}   sizeBytes
 * @returns {Function}
 */
function withMemoryPressure(fn, sizeBytes) {
  return async (...args) => {
    const buf = Buffer.alloc(sizeBytes);
    void buf; // held in scope for GC lifetime
    try {
      return await fn(...args);
    } finally {
      // buf goes out of scope here
    }
  };
}

// ── Network partition ─────────────────────────────────────────────────────────

/**
 * Simulate a full network partition: returns both a broken nonce store and a
 * broken anomaly store that reject all operations.
 *
 * @returns {{ nonceStore: object, anomalyStore: object }}
 */
function networkPartition() {
  return {
    nonceStore:  redisDownNonceStore(),
    anomalyStore: redisDownAnomalyStore(),
    pgPool:      pgDownPool(),
  };
}

// ── FaultInjector class ───────────────────────────────────────────────────────

/**
 * Stateful injector that tracks active faults and can restore all of them
 * with a single restore() call.
 */
class FaultInjector {
  constructor() {
    this._restores = [];
  }

  /**
   * Apply disk-full fault.
   * @returns {this}
   */
  diskFull() {
    const handle = injectDiskFull();
    this._restores.push(() => handle.restore());
    return this;
  }

  /**
   * Apply clock skew fault.
   * @param {number} skewMs
   * @returns {this}
   */
  clockSkew(skewMs) {
    const handle = injectClockSkew(skewMs);
    this._restores.push(() => handle.restore());
    return this;
  }

  /** Restore all active faults. */
  restore() {
    for (const fn of this._restores) { try { fn(); } catch { /* ignore */ } }
    this._restores.length = 0;
  }
}

module.exports = {
  // Nonce store faults
  redisDownNonceStore,
  redisLatencyNonceStore,
  redisTimeoutNonceStore,
  // Anomaly store faults
  redisDownAnomalyStore,
  redisLatencyAnomalyStore,
  redisTimeoutAnomalyStore,
  // PG pool faults
  pgDownPool,
  pgLatencyPool,
  pgSaturationPool,
  // System-level faults
  injectDiskFull,
  injectClockSkew,
  withMemoryPressure,
  networkPartition,
  // Class
  FaultInjector,
};
