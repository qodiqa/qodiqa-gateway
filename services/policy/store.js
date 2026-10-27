'use strict';

/**
 * Policy rate limit stores.
 *
 * createStore()       — in-memory tumbling window, sync interface.
 *                       Used for test injection; no Redis dependency.
 *
 * createRedisStore()  — Redis-backed distributed rate limit store, async interface.
 *                       Backed by module-level singleton client managed by
 *                       initialize() / isReady() / disconnect().
 *
 * Both satisfy the engine's store contract:
 *   checkAndIncrement(key, windowSeconds, maxRequests) → { allowed, count }  (sync or async)
 *     Atomically reads the counter, decides admission against maxRequests,
 *     increments only when admitted, and (re)sets the TTL on first write —
 *     all as one indivisible operation. This is what the policy engine uses
 *     to make real admission decisions; there is no separate read-then-write
 *     step, so concurrent callers cannot race each other.
 *
 * Also exposed, unchanged, for read-only callers (e.g. the /verify dry-run
 * policy store, which must observe the same counter without mutating it):
 *   getCount(key, windowSeconds)  → number  (sync or async) — pure read
 *   increment(key, windowSeconds) → void    (sync or async) — pure write
 *
 * Redis store key prefix: ratelimit:v1:
 *
 * Auth/TLS env: see src/infra/redis/clientConfig.js
 */

const EventEmitter = require('events');
const {
  getConfigSummary,
  isAuthError,
  isTlsError,
} = require('../../src/infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../src/infra/redis/managedClient');
const { resolveHaConfig } = require('../../src/infra/redis/haConfig');
const { emit } = require('../logger');

// resolved once, at module load — REDIS_MODE doesn't change at
// runtime, and resolveHaConfig() is a pure env-var read, so caching costs
// nothing (same rationale/precedent as validateBoundRequest.js's own
// _cachedHaMode, item 17). CHECK_AND_INCR_BATCH_SCRIPT below runs in
// 'single' and 'sentinel' modes (one logical dataset, no cross-key slot
// risk) and falls back to a sequential per-key path only in 'cluster' mode,
// where the batch script's own multiple keys (one per consecutive
// RATE_LIMIT policy) are not guaranteed to share a hash slot — see
// checkAndIncrementBatch() below for the CROSSSLOT reasoning.
const _cachedHaMode = resolveHaConfig().mode;

// ── In-memory store (sync, for test injection) ────────────────────────────────

function createStore() {
  // Map<key, { count: number, windowStart: number }>
  const _buckets = new Map();

  function _nowSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  // gate A-02: budget keys carry the period index, so every period adds a bucket; an expired bucket is dropped by a sweep every 512 writes
  let _writes = 0;
  function _put(key, count, windowStart, windowSeconds) {
    _buckets.set(key, { count, windowStart, windowSeconds });
    if (++_writes % 512 === 0) {
      const now = _nowSeconds();
      for (const [k, b] of _buckets) if (b.windowSeconds && now >= b.windowStart + b.windowSeconds) _buckets.delete(k);
    }
  }

  function getCount(key, windowSeconds) {
    const bucket = _buckets.get(key);
    if (!bucket) return 0;
    if (_nowSeconds() >= bucket.windowStart + windowSeconds) return 0;
    return bucket.count;
  }

  function increment(key, windowSeconds) {
    const now    = _nowSeconds();
    const bucket = _buckets.get(key);
    if (!bucket || now >= bucket.windowStart + windowSeconds) {
      _put(key, 1, now, windowSeconds);
    } else {
      bucket.count += 1;
    }
  }

  // Atomic (single synchronous call, no interleaving possible in-process):
  // reads the counter, decides admission, and increments only when admitted —
  // read, decision, and write happen as one indivisible step.
  function checkAndIncrement(key, windowSeconds, maxRequests) {
    const now     = _nowSeconds();
    const bucket  = _buckets.get(key);
    const expired = !bucket || now >= bucket.windowStart + windowSeconds;
    const current = expired ? 0 : bucket.count;

    if (current >= maxRequests) {
      return { allowed: false, count: current };
    }

    if (expired) {
      _put(key, 1, now, windowSeconds);
      return { allowed: true, count: 1 };
    }

    bucket.count += 1;
    return { allowed: true, count: bucket.count };
  }

  // In-memory counterpart to CHECK_AND_INCR_BATCH_SCRIPT (item 16): each
  // checkAndIncrement() call is itself already a single, uninterleaved
  // synchronous step, so running them in order with an early exit on the
  // first denial reproduces the batched Lua script's semantics exactly —
  // no Redis round trip exists here to actually collapse, but the shape
  // (checks in, {allowed,count}[] out, stops at first denial) matches so
  // engine.js can use one capability check for both stores.
  function checkAndIncrementBatch(checks) {
    const results = [];
    for (const { key, windowSeconds, maxRequests } of checks) {
      const r = checkAndIncrement(key, windowSeconds, maxRequests);
      results.push(r);
      if (!r.allowed) break;
    }
    return results;
  }

  // weighted charge. Admits only when current + amount <= max (an all-or-nothing charge, e.g. tokens), and never leaves a half charge behind.
  function chargeBy(key, windowSeconds, amount, max) {
    const now     = _nowSeconds();
    const bucket  = _buckets.get(key);
    const expired = !bucket || now >= bucket.windowStart + windowSeconds;
    const current = expired ? 0 : bucket.count;
    if (current + amount > max) return { allowed: false, count: current };
    if (expired) { _put(key, amount, now, windowSeconds); return { allowed: true, count: amount }; }
    bucket.count += amount;
    return { allowed: true, count: bucket.count };
  }

  // correct a charge after the fact (a refund, or the difference between an estimate and the real usage). The counter never goes below zero.
  function adjust(key, windowSeconds, delta) {
    const now     = _nowSeconds();
    const bucket  = _buckets.get(key);
    const expired = !bucket || now >= bucket.windowStart + windowSeconds;
    if (expired) { const c = Math.max(0, delta); _put(key, c, now, windowSeconds); return c; }
    bucket.count = Math.max(0, bucket.count + delta);
    return bucket.count;
  }

  function _reset(key) { _buckets.delete(key); }
  function _clear()    { _buckets.clear(); }
  function _size()     { return _buckets.size; }

  return { getCount, increment, checkAndIncrement, checkAndIncrementBatch, chargeBy, adjust, _reset, _clear, _size };
}

// ── Redis-backed distributed store ────────────────────────────────────────────

const KEY_PREFIX      = 'ratelimit:v1:';
const MAX_RECONNECTS  = 5;
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const FLAP_WINDOW_MS  = 60_000;
const FLAP_THRESHOLD  = 3;

const _rlEmitter = new EventEmitter();
_rlEmitter.setMaxListeners(20);

// Atomic INCR + EXPIRE on first write: implements a tumbling window via Redis TTL.
const INCR_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return count
`;

// Atomic check-and-increment: read the counter, decide admission against
// maxRequests, and increment only when admitted — all inside one Lua script.
// Redis executes scripts single-threaded to completion, so no other client
// command (including another concurrent caller's own check-and-increment)
// can interleave between the GET and the INCR/EXPIRE here. This is what
// closes the read/decide/write race that a separate GET + INCR pair has.
//
// KEYS[1] = counter key
// ARGV[1] = windowSeconds (TTL applied on first write of a tumbling window)
// ARGV[2] = maxRequests   (admission threshold)
// Returns {admitted (0/1), resultingCount}. On denial, resultingCount is the
// pre-existing (unincremented) count — the request that would push it over
// the limit is never counted, exactly as the old getCount()+increment() split
// only incremented on the allow path.
const CHECK_AND_INCR_SCRIPT = `
local current = tonumber(redis.call('GET', KEYS[1])) or 0
local max_req = tonumber(ARGV[2])

if current >= max_req then
  return {0, current}
end

local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end

return {1, count}
`;

// weighted atomic charge. KEYS[1] counter; ARGV[1] window seconds (TTL on first write); ARGV[2] amount; ARGV[3] maximum. Returns {admitted, resultingCount}.
const CHARGE_BY_SCRIPT = `
local current = tonumber(redis.call('GET', KEYS[1])) or 0
local amount = tonumber(ARGV[2])
local max_amount = tonumber(ARGV[3])
if current + amount > max_amount then
  return {0, current}
end
local count = redis.call('INCRBY', KEYS[1], amount)
if count == amount then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return {1, count}
`;

// signed correction of a counter (a refund or the difference between an estimate and the real usage); never below zero; keeps a TTL on a key that has none.
const ADJUST_SCRIPT = `
local count = redis.call('INCRBY', KEYS[1], tonumber(ARGV[2]))
if count < 0 then
  redis.call('SET', KEYS[1], 0, 'KEEPTTL')
  count = 0
end
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return count
`;

// Batched, order-preserving version of CHECK_AND_INCR_SCRIPT (item 16):
// evaluates each KEYS[i]/ARGV[2i-1,2i] triple in order inside ONE Lua
// invocation — a single round trip — and stops the moment a key is over
// its limit, WITHOUT reading, incrementing, or emitting a result for any
// key after that point. This reproduces exactly what a caller running
// CHECK_AND_INCR_SCRIPT once per key, sequentially, and breaking on the
// first denial would do — no key after the stopping point is touched, so
// there is no side effect for policies that would never have run.
//
// KEYS[i]     = counter key i, 1..N (already namespaced by the caller)
// ARGV[2i-1]  = windowSeconds for key i
// ARGV[2i]    = maxRequests   for key i
// Returns a flat array of {allowed, count} pairs, one pair per key that
// was actually evaluated. A result shorter than 2*#KEYS means the batch
// stopped early — the caller maps the returned length back to "how many
// checks ran" the same way it already does for a partial evaluationPath.
const CHECK_AND_INCR_BATCH_SCRIPT = `
local results = {}
for i = 1, #KEYS do
  local key     = KEYS[i]
  local window  = tonumber(ARGV[2 * i - 1])
  local max_req = tonumber(ARGV[2 * i])
  local current = tonumber(redis.call('GET', key)) or 0

  if current >= max_req then
    results[#results + 1] = 0
    results[#results + 1] = current
    break
  end

  local count = redis.call('INCR', key)
  if count == 1 then
    redis.call('EXPIRE', key, window)
  end
  results[#results + 1] = 1
  results[#results + 1] = count
end
return results
`;

let _rlClient             = null;
let _rlConnectPromise     = null;
let _rlHadFirstReady      = false;
let _rlWasReady           = false;
let _rlHadAuthError       = false;
let _rlHadTlsError        = false;
let _rlConfigSummary      = null;
let _rlReconnectCount     = 0;
let _rlDisconnectCount    = 0;
let _rlReconnectTimestamps  = [];
let _rlReadinessTransitions = [];

function _checkRlReconnectFlapping() {
  const now = Date.now();
  _rlReconnectTimestamps.push(now);
  _rlReconnectTimestamps = _rlReconnectTimestamps.filter(t => now - t < FLAP_WINDOW_MS);
  if (_rlReconnectTimestamps.length > FLAP_THRESHOLD) {
    emit('WARN', 'REDIS_RECONNECT_FLAPPING', {
      source:         'RATE_LIMIT_STORE',
      reconnectCount: _rlReconnectTimestamps.length,
      windowMs:       FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:         'RATE_LIMIT_STORE',
      reason:         'reconnect rate exceeds threshold',
      reconnectCount: _rlReconnectTimestamps.length,
      windowMs:       FLAP_WINDOW_MS,
    });
  }
}

function _checkRlReadinessFlapping(newState) {
  const now = Date.now();
  _rlReadinessTransitions.push({ time: now, state: newState });
  _rlReadinessTransitions = _rlReadinessTransitions.filter(t => now - t.time < FLAP_WINDOW_MS);
  if (_rlReadinessTransitions.length > FLAP_THRESHOLD) {
    emit('WARN', 'REDIS_READINESS_FLAPPING', {
      source:          'RATE_LIMIT_STORE',
      transitionCount: _rlReadinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:          'RATE_LIMIT_STORE',
      reason:          'readiness flapping detected',
      transitionCount: _rlReadinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
  }
}

function _rlReconnectStrategy(retries) {
  if (retries >= MAX_RECONNECTS) {
    emit('ERROR', 'REDIS_RECONNECT_FAILED', {
      source:          'RATE_LIMIT_STORE',
      retries,
      maxRetries:      MAX_RECONNECTS,
      totalReconnects: _rlReconnectCount,
    });
    emit('ERROR', 'REDIS_RUNTIME_DEGRADED', {
      source:          'RATE_LIMIT_STORE',
      message:         'max reconnect attempts exhausted — rate limit protection fail-closed until server restarts',
      reconnectCount:  _rlReconnectCount,
      disconnectCount: _rlDisconnectCount,
    });
    return false;
  }
  _rlReconnectCount++;
  _checkRlReconnectFlapping();
  const delay = Math.min(100 * Math.pow(2, retries), 2_000);
  emit('WARN', 'REDIS_RECONNECTING', {
    source:          'RATE_LIMIT_STORE',
    retries,
    nextDelayMs:     delay,
    totalReconnects: _rlReconnectCount,
    disconnectCount: _rlDisconnectCount,
  });
  return delay;
}

function _getRlClient() {
  if (_rlClient) return _rlClient;

  _rlConfigSummary = getConfigSummary();

  if (_rlConfigSummary.tlsEnabled) {
    emit('INFO', 'REDIS_TLS_ENABLED', {
      source:      'RATE_LIMIT_STORE',
      tlsVerified: _rlConfigSummary.tlsVerified,
      url:         _rlConfigSummary.urlRedacted,
    });
  }

  _rlClient = createManagedRedisClient({
    purpose:           'rateLimitPolicy',
    reconnectStrategy: _rlReconnectStrategy,
    connectTimeout:    CONNECT_TIMEOUT,
  });

  _rlClient.on('connect', () => {
    emit('INFO', 'REDIS_CONNECTED', {
      source: 'RATE_LIMIT_STORE',
      url:    _rlConfigSummary.urlRedacted,
    });
  });

  _rlClient.on('error', err => {
    emit('ERROR', 'RATE_LIMIT_STORE_ERROR', { error: err.message });

    if (!_rlHadAuthError && isAuthError(err)) {
      _rlHadAuthError = true;
      emit('ERROR', 'REDIS_AUTH_REJECTED', {
        source: 'RATE_LIMIT_STORE',
        error:  err.message,
      });
    }

    if (!_rlHadTlsError && isTlsError(err)) {
      _rlHadTlsError = true;
      emit('ERROR', 'REDIS_TLS_FAILED', {
        source: 'RATE_LIMIT_STORE',
        error:  err.message,
      });
    }

    if (_rlWasReady) {
      _rlDisconnectCount++;
      _rlWasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:          'RATE_LIMIT_STORE',
        error:           err.message,
        disconnectCount: _rlDisconnectCount,
      });
      emit('WARN', 'REDIS_READINESS_FALSE', {
        source:                    'RATE_LIMIT_STORE',
        reason:                    err.message,
        reconnectCount:            _rlReconnectCount,
        disconnectCount:           _rlDisconnectCount,
        executionBlocked:          true,
        policyRateLimitStoreReady: false,
      });
      _checkRlReadinessFlapping(false);
      _rlEmitter.emit('degraded', { source: 'RATE_LIMIT_STORE', reason: err.message });
    }
  });

  _rlClient.on('ready', () => {
    const isReconnect = _rlHadFirstReady;
    _rlHadFirstReady  = true;
    _rlWasReady       = true;
    _rlHadAuthError   = false;
    _rlHadTlsError    = false;

    emit('INFO', 'REDIS_READY', {
      source:          'RATE_LIMIT_STORE',
      url:             _rlConfigSummary?.urlRedacted,
      isReconnect,
      reconnectCount:  _rlReconnectCount,
      disconnectCount: _rlDisconnectCount,
    });

    if (isReconnect) {
      emit('INFO', 'REDIS_RECONNECTED', {
        source:          'RATE_LIMIT_STORE',
        url:             _rlConfigSummary?.urlRedacted,
        reconnectCount:  _rlReconnectCount,
        disconnectCount: _rlDisconnectCount,
      });
      emit('INFO', 'REDIS_RUNTIME_RECOVERED', {
        source:          'RATE_LIMIT_STORE',
        reconnectCount:  _rlReconnectCount,
        disconnectCount: _rlDisconnectCount,
      });
    }

    emit('INFO', 'REDIS_READINESS_TRUE', {
      source:                    'RATE_LIMIT_STORE',
      reconnectCount:            _rlReconnectCount,
      disconnectCount:           _rlDisconnectCount,
      executionBlocked:          false,
      policyRateLimitStoreReady: true,
    });

    _checkRlReadinessFlapping(true);
    _rlEmitter.emit('ready', { source: 'RATE_LIMIT_STORE', isReconnect });
  });

  _rlClient.on('end', () => {
    if (_rlWasReady) {
      _rlDisconnectCount++;
      _rlWasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:          'RATE_LIMIT_STORE',
        disconnectCount: _rlDisconnectCount,
      });
    }
    emit('WARN', 'REDIS_READINESS_FALSE', {
      source:                    'RATE_LIMIT_STORE',
      reason:                    'connection permanently closed',
      reconnectCount:            _rlReconnectCount,
      disconnectCount:           _rlDisconnectCount,
      executionBlocked:          true,
      policyRateLimitStoreReady: false,
    });
    emit('ERROR', 'REDIS_RUNTIME_DEGRADED', {
      source:          'RATE_LIMIT_STORE',
      message:         'Redis connection permanently closed — rate limit protection fail-closed; restart server to recover',
      reconnectCount:  _rlReconnectCount,
      disconnectCount: _rlDisconnectCount,
    });
    _checkRlReadinessFlapping(false);
    _rlEmitter.emit('degraded', {
      source: 'RATE_LIMIT_STORE',
      reason: 'connection permanently closed',
    });
  });

  emit('INFO', 'REDIS_CONNECTING', {
    source: 'RATE_LIMIT_STORE',
    url:    _rlConfigSummary.urlRedacted,
  });

  _rlConnectPromise = _rlClient.connect().catch(err => {
    emit('ERROR', 'RATE_LIMIT_STORE_CONNECT_FAILED', { error: err.message });
  });

  return _rlClient;
}

function _assertRlReady() {
  if (!_getRlClient().isReady) {
    throw new Error('RATE_LIMIT_STORE: Redis not connected — request blocked (fail-closed)');
  }
}

async function _runRlStartupProbe(client) {
  // a per-process probe key — a fixed key shared by every process made concurrent
  // boots against one Redis fail 9-15% of store inits (A SET, B SET, A GET, A DEL, B GET → null). PX still bounds leftovers.
  const probeKey = `${KEY_PREFIX}_startup_probe:${process.pid}:${require('crypto').randomBytes(6).toString('hex')}`;

  const pong = await client.ping();
  if (pong !== 'PONG') {
    throw new Error(`RATE_LIMIT_STORE: unexpected PING response: ${pong}`);
  }

  await client.set(probeKey, '1', { PX: 5_000 });
  const val = await client.get(probeKey);
  await client.del(probeKey);

  if (val !== '1') {
    throw new Error(`RATE_LIMIT_STORE: namespace probe returned unexpected value: ${String(val)}`);
  }

  const summary = _rlConfigSummary ?? getConfigSummary();

  emit('INFO', 'REDIS_CONNECTIVITY_VALIDATED', {
    source:    'RATE_LIMIT_STORE',
    namespace: KEY_PREFIX,
    pingOk:    true,
    writeOk:   true,
    readOk:    true,
  });
  emit('INFO', 'REDIS_NAMESPACE_READY', { source: 'RATE_LIMIT_STORE', namespace: KEY_PREFIX });

  if (summary.authConfigured) {
    emit('INFO', 'REDIS_AUTH_VALIDATED', {
      source: 'RATE_LIMIT_STORE',
      note:   'probe succeeded with configured credentials',
    });
  }

  if (summary.tlsEnabled) {
    emit('INFO', 'REDIS_TLS_VALIDATED', {
      source:      'RATE_LIMIT_STORE',
      tlsVerified: summary.tlsVerified,
      note:        'probe succeeded over TLS connection',
    });
  }

  emit('INFO', 'REDIS_RUNTIME_READY', {
    source:          'RATE_LIMIT_STORE',
    namespace:       KEY_PREFIX,
    reconnectCount:  _rlReconnectCount,
    disconnectCount: _rlDisconnectCount,
  });

  return { ready: true, namespace: KEY_PREFIX };
}

/**
 * Eagerly connect the rate limit store and validate the namespace.
 * @returns {Promise<{ ready: true, namespace: string }>}
 */
async function initialize() {
  const client = _getRlClient();

  if (client.isReady) {
    try {
      return await _runRlStartupProbe(client);
    } catch (err) {
      emit('ERROR', 'REDIS_NAMESPACE_UNAVAILABLE', {
        source:                    'RATE_LIMIT_STORE',
        namespace:                 KEY_PREFIX,
        error:                     err.message,
        executionBlocked:          true,
        policyRateLimitStoreReady: false,
      });
      throw err;
    }
  }

  await new Promise((resolve, reject) => {
    const summary = _rlConfigSummary ?? getConfigSummary();
    const timer = setTimeout(() => {
      off();
      reject(new Error(
        `RATE_LIMIT_STORE: startup connect timeout (${CONNECT_TIMEOUT}ms) — Redis unavailable at ${summary.urlRedacted}`,
      ));
    }, CONNECT_TIMEOUT);

    function onReady() { off(); resolve(); }
    function onEnd()   { off(); reject(new Error('RATE_LIMIT_STORE: connection ended before becoming ready')); }

    function off() {
      clearTimeout(timer);
      client.off('ready', onReady);
      client.off('end',   onEnd);
    }

    client.once('ready', onReady);
    client.once('end',   onEnd);
  });

  try {
    return await _runRlStartupProbe(client);
  } catch (err) {
    emit('ERROR', 'REDIS_NAMESPACE_UNAVAILABLE', {
      source:                    'RATE_LIMIT_STORE',
      namespace:                 KEY_PREFIX,
      error:                     err.message,
      executionBlocked:          true,
      policyRateLimitStoreReady: false,
    });
    throw err;
  }
}

/**
 * @returns {boolean}
 */
function isReady() {
  return _rlClient ? _rlClient.isReady : false;
}

/**
 * Disconnect and destroy the Redis client.
 */
async function disconnect() {
  if (_rlClient) {
    const c                 = _rlClient;
    _rlClient               = null;
    _rlConnectPromise       = null;
    _rlHadFirstReady        = false;
    _rlWasReady             = false;
    _rlHadAuthError         = false;
    _rlHadTlsError          = false;
    _rlConfigSummary        = null;
    _rlReconnectCount       = 0;
    _rlDisconnectCount      = 0;
    _rlReconnectTimestamps  = [];
    _rlReadinessTransitions = [];
    try { await c.disconnect(); } catch { /* ignore — already closed */ }
  }
}

/**
 * Create a Redis-backed distributed rate limit store.
 * getCount() and increment() are async; compatible with the async engine.
 *
 * Fail-closed: both operations throw if Redis is unavailable, which the engine
 * treats as Infinity (getCount) or silently ignores (increment after ALLOW).
 *
 * @param {{ _haMode?: 'single'|'sentinel'|'cluster' }} [opts]
 *   _haMode: Redis HA-mode override for tests (NEVER use in production —
 *   same convention as validateBoundRequest.js's own _haMode opt, item 17).
 *   Defaults to the real, cached REDIS_MODE resolution.
 */
function createRedisStore({ _haMode } = {}) {
  const _rlHaMode = _haMode !== undefined ? _haMode : _cachedHaMode;

  return {
    async getCount(key, windowSeconds) {
      _assertRlReady();
      try {
        const val = await _getRlClient().get(`${KEY_PREFIX}${key}`);
        if (val === null) return 0;
        const count = parseInt(val, 10);
        return (Number.isFinite(count) && count >= 0) ? count : Infinity;
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', {
          source: 'RATE_LIMIT_STORE',
          key:    `${KEY_PREFIX}${key}`,
          op:     'getCount',
          error:  err.message,
        });
        throw err;
      }
    },

    async increment(key, windowSeconds) {
      _assertRlReady();
      try {
        await _getRlClient().eval(INCR_SCRIPT, {
          keys:      [`${KEY_PREFIX}${key}`],
          arguments: [String(Math.ceil(windowSeconds))],
        });
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', {
          source: 'RATE_LIMIT_STORE',
          key:    `${KEY_PREFIX}${key}`,
          op:     'increment',
          error:  err.message,
        });
        // Best-effort: increment failure does not retroactively change an EXECUTE.
        // Log and swallow so the engine's allSettled handling receives a rejection.
        throw err;
      }
    },

    // Atomic admission check used by the policy engine's RATE_LIMIT evaluator.
    // One EVAL round trip: read, decide, increment-if-admitted, all inside
    // CHECK_AND_INCR_SCRIPT — see the script comment above for why this is race-free.
    async checkAndIncrement(key, windowSeconds, maxRequests) {
      _assertRlReady();
      try {
        const raw = await _getRlClient().eval(CHECK_AND_INCR_SCRIPT, {
          keys:      [`${KEY_PREFIX}${key}`],
          arguments: [String(Math.ceil(windowSeconds)), String(maxRequests)],
        });
        return { allowed: Number(raw[0]) === 1, count: Number(raw[1]) };
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', {
          source: 'RATE_LIMIT_STORE',
          key:    `${KEY_PREFIX}${key}`,
          op:     'checkAndIncrement',
          error:  err.message,
        });
        throw err;
      }
    },

    // weighted atomic charge and signed correction (see the scripts above).
    async chargeBy(key, windowSeconds, amount, max) {
      _assertRlReady();
      try {
        const raw = await _getRlClient().eval(CHARGE_BY_SCRIPT, { keys: [`${KEY_PREFIX}${key}`], arguments: [String(Math.ceil(windowSeconds)), String(amount), String(max)] });
        return { allowed: Number(raw[0]) === 1, count: Number(raw[1]) };
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', { source: 'RATE_LIMIT_STORE', key: `${KEY_PREFIX}${key}`, op: 'chargeBy', error: err.message });
        throw err;
      }
    },

    async adjust(key, windowSeconds, delta) {
      _assertRlReady();
      try {
        return Number(await _getRlClient().eval(ADJUST_SCRIPT, { keys: [`${KEY_PREFIX}${key}`], arguments: [String(Math.ceil(windowSeconds)), String(delta)] }));
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', { source: 'RATE_LIMIT_STORE', key: `${KEY_PREFIX}${key}`, op: 'adjust', error: err.message });
        throw err;
      }
    },

    // Batched admission check (item 16) — one EVAL round trip covering every
    // check in `checks`, in order, stopping at the first denial exactly like
    // CHECK_AND_INCR_SCRIPT run once per check sequentially would. Used by
    // the policy engine only for genuinely-consecutive RATE_LIMIT policies.
    //
    // CHECK_AND_INCR_BATCH_SCRIPT touches KEYS[1..N] — one counter
    // key per consecutive RATE_LIMIT policy — inside a single Lua EVAL.
    // Under REDIS_MODE=cluster those keys are not guaranteed to land on the
    // same hash slot (they are independent, differently-named rate-limit
    // counters, not variants of one logical key), so Redis Cluster rejects
    // the script with CROSSSLOT the first time a run covers >=2 policies —
    // this item's own filed gap. Falls back automatically to a sequential
    // per-key loop over the already-cluster-safe (single-key)
    // CHECK_AND_INCR_SCRIPT, in the same order, stopping at the first
    // denial — reproducing the batch script's own documented semantics
    // exactly (see that script's comment above), the same way the
    // in-memory store's own checkAndIncrementBatch() already does for its
    // (non-Redis) case. Standalone/sentinel keep the original single-round-
    // trip batch path unchanged — no performance regression for the common
    // case.
    async checkAndIncrementBatch(checks) {
      _assertRlReady();
      if (_rlHaMode === 'cluster') {
        const results = [];
        try {
          for (const c of checks) {
            const raw = await _getRlClient().eval(CHECK_AND_INCR_SCRIPT, {
              keys:      [`${KEY_PREFIX}${c.key}`],
              arguments: [String(Math.ceil(c.windowSeconds)), String(c.maxRequests)],
            });
            const allowed = Number(raw[0]) === 1;
            results.push({ allowed, count: Number(raw[1]) });
            if (!allowed) break;
          }
          return results;
        } catch (err) {
          emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', {
            source:   'RATE_LIMIT_STORE',
            op:       'checkAndIncrementBatch',
            mode:     'cluster-fallback',
            keyCount: checks.length,
            error:    err.message,
          });
          throw err;
        }
      }

      try {
        const keys = checks.map(c => `${KEY_PREFIX}${c.key}`);
        const args = [];
        for (const c of checks) args.push(String(Math.ceil(c.windowSeconds)), String(c.maxRequests));

        const raw = await _getRlClient().eval(CHECK_AND_INCR_BATCH_SCRIPT, { keys, arguments: args });
        const results = [];
        for (let i = 0; i < raw.length; i += 2) {
          results.push({ allowed: Number(raw[i]) === 1, count: Number(raw[i + 1]) });
        }
        return results;
      } catch (err) {
        emit('ERROR', 'POLICY_RATE_LIMIT_STORE_ERROR', {
          source:   'RATE_LIMIT_STORE',
          op:       'checkAndIncrementBatch',
          keyCount: checks.length,
          error:    err.message,
        });
        throw err;
      }
    },
  };
}

module.exports = {
  createStore,
  createRedisStore,
  initialize,
  isReady,
  disconnect,
  emitter: _rlEmitter,
  _scripts: { CHARGE_BY_SCRIPT, ADJUST_SCRIPT },   // exercised against a real Redis by test/integration/budgetStore.redis.integration.test.js
};
