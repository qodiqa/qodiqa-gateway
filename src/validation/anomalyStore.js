'use strict';

/**
 * QODIQA V2 Anomaly Store — Redis-backed sliding window counter.
 *
 * Uses a Redis sorted set per tracking key to implement a true sliding window:
 *   ZREMRANGEBYSCORE — evict entries older than the window (atomic in Lua)
 *   ZADD             — record the current hit with a unique member ID
 *   PEXPIRE          — auto-prune the entire key after window + 1s
 *   ZCARD            — return count of events in the current window
 *
 * All four operations execute inside a single Lua script — Redis guarantees
 * single-threaded script execution, so no race condition can exist between
 * the eviction and the count.
 *
 * Key schema:
 *   anomaly:v2:key:<publicKeyId>  — per-key sliding window
 *   anomaly:v2:global             — global sliding window
 *
 * Lazy client lifecycle:
 *   • The Redis client is created and connected on the FIRST call to any public
 *     function — never at module import time.
 *   • initialize() eagerly connects and runs a namespace probe.
 *   • disconnect() tears down the client and resets the singleton.
 *
 * Reconnect semantics (fail-closed):
 * • Exponential backoff, infinite retry — never gives up; past
 *     OLD_MAX_RECONNECTS it keeps retrying forever at a capped, jittered
 *     interval instead of requiring a process restart.
 *   • All anomaly operations fail closed during reconnect intervals.
 *   • No in-memory fallback.  No fail-open path.
 *
 * Observability:
 *   • All connection lifecycle state transitions emit structured JSON events.
 *   • Readiness transitions emit REDIS_READINESS_TRUE / REDIS_READINESS_FALSE.
 *   • Reconnect instability detected via sliding-window counters.
 *   • module.emitter allows server.js to subscribe to degraded/ready transitions.
 *
 * Required env:
 *   REDIS_URL                 — connection string (default: redis://localhost:6379)
 *   REDIS_CONNECT_TIMEOUT_MS  — ms to wait for startup ready (default: 5000)
 *
 * Auth/TLS env: see src/infra/redis/clientConfig.js
 */

const EventEmitter = require('events');
const {
  getConfigSummary,
  isAuthError,
  isTlsError,
} = require('../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../infra/redis/reconnectStrategy');
const { emit } = require('../../services/logger');

const KEY_PREFIX      = 'anomaly:v2:';
// no longer a hard cap — see OLD_MAX_RECONNECTS note in storage.js.
const OLD_MAX_RECONNECTS = 5;
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);

const FLAP_WINDOW_MS = 60_000;
const FLAP_THRESHOLD = 3;

// ── Store-level event emitter ─────────────────────────────────────────────────

const _storeEmitter = new EventEmitter();
_storeEmitter.setMaxListeners(20);

// ── Lua: sliding window INCR ───────────────────────────────────────────────────
const SLIDE_SCRIPT = `
local key      = KEYS[1]
local now      = tonumber(ARGV[1])
local window   = tonumber(ARGV[2])
local cutoff   = now - window

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)

local seq    = redis.call('INCR', key .. ':seq')
local member = tostring(now) .. ':' .. tostring(seq)
redis.call('ZADD', key, now, member)

redis.call('PEXPIRE', key, window + 1000)
redis.call('PEXPIRE', key .. ':seq', window + 1000)

return tonumber(redis.call('ZCARD', key))
`;

// ── Lua: sliding window PEEK (read-only count, no write) ──────────────────────
const PEEK_SCRIPT = `
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cutoff = now - window
return tonumber(redis.call('ZCOUNT', key, '(' .. tostring(cutoff), '+inf'))
`;

// ── Connection state ──────────────────────────────────────────────────────────

let _client         = null;
let _connectPromise = null;
let _hadFirstReady  = false;
let _wasReady       = false;
let _hadAuthError   = false;
let _hadTlsError    = false;
let _configSummary  = null;

// ── Instability counters ──────────────────────────────────────────────────────

let _reconnectCount       = 0;
let _disconnectCount      = 0;
let _reconnectTimestamps  = [];
let _readinessTransitions = [];

// ── Flapping detection helpers ────────────────────────────────────────────────

function _checkReconnectFlapping() {
  const now = Date.now();
  _reconnectTimestamps.push(now);
  _reconnectTimestamps = _reconnectTimestamps.filter(t => now - t < FLAP_WINDOW_MS);
  if (_reconnectTimestamps.length > FLAP_THRESHOLD) {
    emit('WARN', 'REDIS_RECONNECT_FLAPPING', {
      source:         'ANOMALY_STORE',
      reconnectCount: _reconnectTimestamps.length,
      windowMs:       FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:         'ANOMALY_STORE',
      reason:         'reconnect rate exceeds threshold',
      reconnectCount: _reconnectTimestamps.length,
      windowMs:       FLAP_WINDOW_MS,
    });
  }
}

function _checkReadinessFlapping(newState) {
  const now = Date.now();
  _readinessTransitions.push({ time: now, state: newState });
  _readinessTransitions = _readinessTransitions.filter(t => now - t.time < FLAP_WINDOW_MS);
  if (_readinessTransitions.length > FLAP_THRESHOLD) {
    emit('WARN', 'REDIS_READINESS_FLAPPING', {
      source:          'ANOMALY_STORE',
      transitionCount: _readinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:          'ANOMALY_STORE',
      reason:          'readiness flapping detected',
      transitionCount: _readinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
  }
}

// ── Infinite reconnect strategy ──────────────────────────────────────────

const _reconnectStrategy = createInfiniteReconnectStrategy({
  source: 'ANOMALY_STORE',
  oldMaxReconnects: OLD_MAX_RECONNECTS,
  onRetry: ({ retries, delayMs, pastOldThreshold }) => {
    _reconnectCount++;
    _checkReconnectFlapping();
    emit('WARN', 'REDIS_RECONNECTING', {
      source:          'ANOMALY_STORE',
      retries,
      nextDelayMs:     delayMs,
      totalReconnects: _reconnectCount,
      disconnectCount: _disconnectCount,
      pastOldThreshold,
    });
  },
});

// ── Lazy client singleton ─────────────────────────────────────────────────────

function _getClient() {
  if (_client) return _client;

  _configSummary = getConfigSummary();

  if (_configSummary.tlsEnabled) {
    emit('INFO', 'REDIS_TLS_ENABLED', {
      source:      'ANOMALY_STORE',
      tlsVerified: _configSummary.tlsVerified,
      url:         _configSummary.urlRedacted,
    });
  }

  _client = createManagedRedisClient({
    purpose:           'anomaly',
    reconnectStrategy: _reconnectStrategy,
    connectTimeout:    CONNECT_TIMEOUT,
  });

  _client.on('connect', () => {
    emit('INFO', 'REDIS_CONNECTED', {
      source: 'ANOMALY_STORE',
      url:    _configSummary.urlRedacted,
    });
  });

  _client.on('error', err => {
    emit('ERROR', 'ANOMALY_STORE_V2_ERROR', { error: err.message });

    if (!_hadAuthError && isAuthError(err)) {
      _hadAuthError = true;
      emit('ERROR', 'REDIS_AUTH_REJECTED', {
        source: 'ANOMALY_STORE',
        error:  err.message,
      });
    }

    if (!_hadTlsError && isTlsError(err)) {
      _hadTlsError = true;
      emit('ERROR', 'REDIS_TLS_FAILED', {
        source: 'ANOMALY_STORE',
        error:  err.message,
      });
    }

    if (_wasReady) {
      _disconnectCount++;
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:          'ANOMALY_STORE',
        error:           err.message,
        disconnectCount: _disconnectCount,
      });
      emit('WARN', 'REDIS_READINESS_FALSE', {
        source:                  'ANOMALY_STORE',
        reason:                  err.message,
        reconnectCount:          _reconnectCount,
        disconnectCount:         _disconnectCount,
        executionBlocked:        true,
        anomalyProtectionActive: false,
      });
      _checkReadinessFlapping(false);
      _storeEmitter.emit('degraded', { source: 'ANOMALY_STORE', reason: err.message });
    }
  });

  _client.on('ready', () => {
    const isReconnect = _hadFirstReady;
    _hadFirstReady    = true;
    _wasReady         = true;
    _hadAuthError     = false;
    _hadTlsError      = false;

    emit('INFO', 'REDIS_READY', {
      source:          'ANOMALY_STORE',
      url:             _configSummary?.urlRedacted,
      isReconnect,
      reconnectCount:  _reconnectCount,
      disconnectCount: _disconnectCount,
    });

    if (isReconnect) {
      emit('INFO', 'REDIS_RECONNECTED', {
        source:          'ANOMALY_STORE',
        url:             _configSummary?.urlRedacted,
        reconnectCount:  _reconnectCount,
        disconnectCount: _disconnectCount,
      });
      emit('INFO', 'REDIS_RUNTIME_RECOVERED', {
        source:          'ANOMALY_STORE',
        reconnectCount:  _reconnectCount,
        disconnectCount: _disconnectCount,
      });
    }

    emit('INFO', 'REDIS_READINESS_TRUE', {
      source:                  'ANOMALY_STORE',
      reconnectCount:          _reconnectCount,
      disconnectCount:         _disconnectCount,
      executionBlocked:        false,
      anomalyProtectionActive: true,
    });

    _checkReadinessFlapping(true);
    _storeEmitter.emit('ready', { source: 'ANOMALY_STORE', isReconnect });
  });

  _client.on('end', () => {
    if (_wasReady) {
      _disconnectCount++;
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:          'ANOMALY_STORE',
        disconnectCount: _disconnectCount,
      });
    }
    emit('WARN', 'REDIS_READINESS_FALSE', {
      source:                  'ANOMALY_STORE',
      reason:                  'connection closed — automatic recovery in progress',
      reconnectCount:          _reconnectCount,
      disconnectCount:         _disconnectCount,
      executionBlocked:        true,
      anomalyProtectionActive: false,
    });
    emit('ERROR', 'REDIS_RUNTIME_DEGRADED', {
      source:          'ANOMALY_STORE',
      message:         'Redis connection closed — anomaly protection fail-closed while automatic recovery is in progress',
      reconnectCount:  _reconnectCount,
      disconnectCount: _disconnectCount,
    });
    _checkReadinessFlapping(false);
    _storeEmitter.emit('degraded', {
      source: 'ANOMALY_STORE',
      reason: 'connection closed — automatic recovery in progress',
    });
  });

  emit('INFO', 'REDIS_CONNECTING', {
    source: 'ANOMALY_STORE',
    url:    _configSummary.urlRedacted,
  });

  _connectPromise = _client.connect().catch(err => {
    emit('ERROR', 'ANOMALY_STORE_V2_CONNECT_FAILED', { error: err.message });
  });

  return _client;
}

function _assertReady() {
  if (!_getClient().isReady) {
    throw new Error('ANOMALY_STORE_V2: Redis not connected — request blocked (fail-closed)');
  }
}

// ── Startup namespace probe ───────────────────────────────────────────────────

async function _runStartupProbe(client) {
  // a per-process probe key — a fixed key shared by every process made concurrent
  // boots against one Redis fail 9-15% of store inits (A SET, B SET, A GET, A DEL, B GET → null). PX still bounds leftovers.
  const probeKey = `${KEY_PREFIX}_startup_probe:${process.pid}:${require('crypto').randomBytes(6).toString('hex')}`;

  const pong = await client.ping();
  if (pong !== 'PONG') {
    throw new Error(`ANOMALY_STORE: unexpected PING response: ${pong}`);
  }

  await client.set(probeKey, '1', { PX: 5_000 });
  const val = await client.get(probeKey);
  await client.del(probeKey);

  if (val !== '1') {
    throw new Error(`ANOMALY_STORE: namespace probe returned unexpected value: ${String(val)}`);
  }

  const summary = _configSummary ?? getConfigSummary();

  emit('INFO', 'REDIS_CONNECTIVITY_VALIDATED', {
    source:    'ANOMALY_STORE',
    namespace: KEY_PREFIX,
    pingOk:    true,
    writeOk:   true,
    readOk:    true,
  });
  emit('INFO', 'REDIS_NAMESPACE_READY', { source: 'ANOMALY_STORE', namespace: KEY_PREFIX });

  if (summary.authConfigured) {
    emit('INFO', 'REDIS_AUTH_VALIDATED', {
      source: 'ANOMALY_STORE',
      note:   'probe succeeded with configured credentials',
    });
  }

  if (summary.tlsEnabled) {
    emit('INFO', 'REDIS_TLS_VALIDATED', {
      source:      'ANOMALY_STORE',
      tlsVerified: summary.tlsVerified,
      note:        'probe succeeded over TLS connection',
    });
  }

  emit('INFO', 'REDIS_RUNTIME_READY', {
    source:          'ANOMALY_STORE',
    namespace:       KEY_PREFIX,
    reconnectCount:  _reconnectCount,
    disconnectCount: _disconnectCount,
  });
  emit('INFO', 'ANOMALY_STORE_READY', { url: summary.urlRedacted, namespace: KEY_PREFIX });

  return { ready: true, namespace: KEY_PREFIX };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Eagerly connect the anomaly store and validate the anomaly namespace.
 *
 * @returns {Promise<{ ready: boolean, namespace: string }>}
 * @throws  On timeout, connection end, or namespace probe failure.
 */
async function initialize() {
  const client = _getClient();

  if (client.isReady) {
    try {
      return await _runStartupProbe(client);
    } catch (err) {
      emit('ERROR', 'REDIS_NAMESPACE_UNAVAILABLE', {
        source:                  'ANOMALY_STORE',
        namespace:               KEY_PREFIX,
        error:                   err.message,
        executionBlocked:        true,
        anomalyProtectionActive: false,
      });
      throw err;
    }
  }

  await new Promise((resolve, reject) => {
    const summary = _configSummary ?? getConfigSummary();
    const timer = setTimeout(() => {
      off();
      reject(new Error(
        `ANOMALY_STORE: startup connect timeout (${CONNECT_TIMEOUT}ms) — Redis unavailable at ${summary.urlRedacted}`,
      ));
    }, CONNECT_TIMEOUT);

    function onReady() { off(); resolve(); }
    function onEnd()   { off(); reject(new Error('ANOMALY_STORE: connection ended before becoming ready')); }

    function off() {
      clearTimeout(timer);
      client.off('ready', onReady);
      client.off('end',   onEnd);
    }

    client.once('ready', onReady);
    client.once('end',   onEnd);
  });

  try {
    return await _runStartupProbe(client);
  } catch (err) {
    emit('ERROR', 'REDIS_NAMESPACE_UNAVAILABLE', {
      source:                  'ANOMALY_STORE',
      namespace:               KEY_PREFIX,
      error:                   err.message,
      executionBlocked:        true,
      anomalyProtectionActive: false,
    });
    throw err;
  }
}

/**
 * Returns the current readiness state of the anomaly store.
 * @returns {boolean}
 */
function isReady() {
  return _client ? _client.isReady : false;
}

/**
 * Build the fully-prefixed per-key/global Redis key pair for a
 * publicKeyId+tenantId combo — item 17's combined nonce+anomaly Lua script
 * (nonceStore.js's registerAndCheckAnomaly()) runs outside record()'s own
 * KEY_PREFIX-prepending and needs the complete key up front to pass as
 * Lua KEYS[]. MUST stay in sync with checkAnomaly.js's inline
 * `${prefix}key:${publicKeyId}` / `${prefix}global` + this module's own
 * KEY_PREFIX — see nonceStore.test.js's parity assertion.
 *
 * @param {string} publicKeyId
 * @param {string|null} [tenantId]
 * @returns {{ perKeyKey: string, globalKey: string }}
 */
function buildAnomalyKeys(publicKeyId, tenantId) {
  const prefix = tenantId ? `tenant:${tenantId}:` : '';
  return {
    perKeyKey: `${KEY_PREFIX}${prefix}key:${publicKeyId}`,
    globalKey: `${KEY_PREFIX}${prefix}global`,
  };
}

/**
 * Record one event for the given tracking key and return the current window count.
 *
 * @param {string} key       Tracking key.
 * @param {number} nowMs     Current time in epoch-ms.
 * @param {number} windowMs  Sliding window duration in ms.
 * @returns {Promise<{ count: number }>}
 * @throws  If Redis is unavailable — fail-closed BLOCK.
 */
async function record(key, nowMs, windowMs) {
  if (typeof key !== 'string' || !key)                 throw new TypeError('ANOMALY_STORE_V2: key must be a non-empty string');
  if (!Number.isFinite(nowMs)    || nowMs <= 0)        throw new TypeError('ANOMALY_STORE_V2: nowMs must be a positive finite number');
  if (!Number.isFinite(windowMs) || windowMs <= 0)     throw new TypeError('ANOMALY_STORE_V2: windowMs must be a positive finite number');

  _assertReady();

  const count = await _getClient().eval(SLIDE_SCRIPT, {
    keys:      [`${KEY_PREFIX}${key}`],
    arguments: [String(nowMs), String(windowMs)],
  });

  return { count: Number(count) };
}

/**
 * Read-only window count — does NOT record a new event.
 *
 * @param {string} key
 * @param {number} nowMs
 * @param {number} windowMs
 * @returns {Promise<{ count: number }>}
 * @throws  If Redis is unavailable.
 */
async function peek(key, nowMs, windowMs) {
  if (typeof key !== 'string' || !key)                 throw new TypeError('ANOMALY_STORE_V2: key must be a non-empty string');
  if (!Number.isFinite(nowMs)    || nowMs <= 0)        throw new TypeError('ANOMALY_STORE_V2: nowMs must be a positive finite number');
  if (!Number.isFinite(windowMs) || windowMs <= 0)     throw new TypeError('ANOMALY_STORE_V2: windowMs must be a positive finite number');

  _assertReady();

  const count = await _getClient().eval(PEEK_SCRIPT, {
    keys:      [`${KEY_PREFIX}${key}`],
    arguments: [String(nowMs), String(windowMs)],
  });

  return { count: Number(count) };
}

/**
 * Disconnect and destroy the Redis client.
 * @returns {Promise<void>}
 */
async function disconnect() {
  if (_client) {
    const c               = _client;
    _client               = null;
    _connectPromise       = null;
    _hadFirstReady        = false;
    _wasReady             = false;
    _hadAuthError         = false;
    _hadTlsError          = false;
    _configSummary        = null;
    _reconnectCount       = 0;
    _disconnectCount      = 0;
    _reconnectTimestamps  = [];
    _readinessTransitions = [];
    try { await c.disconnect(); } catch { /* ignore — already closed */ }
  }
}

/**
 * Synchronous health snapshot for the anomaly store.
 * @returns {{ storeReady: boolean, persistenceHealthy: null, distributedStateHealthy: boolean,
 *             reconnecting: boolean, degraded: boolean, corruptedStateDetected: false,
 *             executionBlocked: boolean }}
 */
function checkHealth() {
  const storeReady = _wasReady;
  return {
    storeReady,
    persistenceHealthy:      null,
    distributedStateHealthy: storeReady,
    reconnecting:            !storeReady && _reconnectCount > 0 && _client !== null,
    degraded:                !storeReady,
    corruptedStateDetected:  false,
    executionBlocked:        !storeReady,
  };
}

module.exports = {
  record,
  peek,
  buildAnomalyKeys,
  initialize,
  isReady,
  checkHealth,
  disconnect,
  emitter: _storeEmitter,
  get _client() { return _client; },
};
