'use strict';

/**
 * Storage abstraction for the Sliding Window rate limiter —
 *
 * Two implementations behind a common eval(script, keys, args) interface:
 *
 *   MemoryStorage — development/testing, in-process, always ready, no Redis.
 *   RedisStorage  — production, Redis-backed, fail-closed on unavailability.
 *
 * No business logic lives here. Both implementations execute the same
 * slidingWindow.js Lua algorithm (or its in-process equivalent).
 *
 * Key format: rl:v2:{dimension}:{identity}
 *   dimension — e.g. surface:portal, tenant:acme, user:uuid, signingkey:kid
 *   identity  — e.g. ip:1.2.3.4, user:uuid, tenant:tid
 */

const { getConfigSummary,
        isAuthError, isTlsError }              = require('../../infra/redis/clientConfig');
const { createManagedRedisClient }             = require('../../infra/redis/managedClient');
const { createInfiniteReconnectStrategy }      = require('../../infra/redis/reconnectStrategy');
const { emit }                                 = require('../../../services/logger');

const KEY_PREFIX      = 'rl:v2:';
// no longer a hard cap — retries continue forever past this point. Kept
// as a threshold marker so onRetry's pastOldThreshold flag (and tests) can
// still see when a client has crossed into "extended outage" territory.
const OLD_MAX_RECONNECTS = 5;
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const FLAP_WINDOW_MS  = 60_000;
const FLAP_THRESHOLD  = 3;
const SOURCE          = 'RATE_LIMIT_REDIS';

// ── MemoryStorage ─────────────────────────────────────────────────────────────
//
// Simulates the Lua sliding window logic in-process.
// Single-process only — not suitable for distributed deployments.
// Intended for development and testing.

class MemoryStorage {
  constructor() {
    this._counters = new Map();  // key → count
    this._expiry   = new Map();  // key → expiry Unix seconds
  }

  isReady() { return true; }

  async eval(_script, keys, args) {
    const now       = Number(args[0]);
    const window    = Number(args[1]);
    const maxReq    = Number(args[2]);
    const burstCap  = Number(args[3]);
    const burstWin  = Number(args[4]);
    const baseKey   = keys[0];

    const currBucket = Math.floor(now / window);
    const prevBucket = currBucket - 1;
    const elapsed    = now % window;
    const prevWeight = 1 - elapsed / window;

    const currKey = `${baseKey}:c:${currBucket}`;
    const prevKey = `${baseKey}:c:${prevBucket}`;

    const curr = this._incr(currKey, window * 2, now);
    const prev = this._read(prevKey, now);

    const weightedX1000 = Math.floor(prev * prevWeight * 1000) + curr * 1000;
    const swAllowed     = weightedX1000 <= maxReq * 1000 ? 1 : 0;
    const remaining     = Math.max(0, Math.floor(maxReq - weightedX1000 / 1000));
    const resetIn       = Math.max(1, window - elapsed);

    let burstAllowed = 1;
    let burstCount   = 0;
    let burstRem     = burstCap;

    if (burstCap > 0) {
      const burstBucket = Math.floor(now / burstWin);
      const burstKey    = `${baseKey}:b:${burstBucket}`;
      burstCount   = this._incr(burstKey, burstWin * 2, now);
      burstAllowed = burstCount <= burstCap ? 1 : 0;
      burstRem     = Math.max(0, burstCap - burstCount);
    }

    return [curr, prev, swAllowed, burstAllowed, resetIn, remaining, burstCount, burstRem];
  }

  _incr(key, ttlSeconds, nowSeconds) {
    const exp = this._expiry.get(key);
    if (exp === undefined || exp <= nowSeconds) {
      this._counters.set(key, 1);
      this._expiry.set(key, nowSeconds + ttlSeconds);
      return 1;
    }
    const v = (this._counters.get(key) || 0) + 1;
    this._counters.set(key, v);
    return v;
  }

  _read(key, nowSeconds) {
    const exp = this._expiry.get(key);
    if (exp === undefined || exp <= nowSeconds) return 0;
    return this._counters.get(key) || 0;
  }

  _reset() {
    this._counters.clear();
    this._expiry.clear();
  }
}

// ── RedisStorage ──────────────────────────────────────────────────────────────
//
// Production Redis-backed storage.
// Fail-closed: eval() throws if the client is not ready.
// Manages a single Redis connection with exponential-backoff reconnection,
// flap detection, and structured event logging throughout the lifecycle.

class RedisStorage {
  constructor() {
    this._client              = null;
    this._wasReady            = false;
    this._hadFirstReady       = false;
    this._reconnectCount      = 0;
    this._disconnectCount     = 0;
    this._reconnectTimestamps = [];
    this._configSummary       = null;
  }

  isReady() { return this._client?.isReady === true; }

  async eval(script, keys, args) {
    if (!this.isReady()) throw new Error('RATE_LIMIT_REDIS: Redis not ready — fail-closed');
    return this._client.eval(script, { keys, arguments: args });
  }

  _checkFlapping() {
    const now = Date.now();
    this._reconnectTimestamps.push(now);
    this._reconnectTimestamps = this._reconnectTimestamps.filter(t => now - t < FLAP_WINDOW_MS);
    if (this._reconnectTimestamps.length > FLAP_THRESHOLD) {
      emit('WARN', 'REDIS_RECONNECT_FLAPPING', { source: SOURCE, count: this._reconnectTimestamps.length, windowMs: FLAP_WINDOW_MS });
      emit('WARN', 'REDIS_RUNTIME_UNSTABLE',   { source: SOURCE, reason: 'reconnect rate exceeds threshold — rate limiting fail-closed until stable' });
    }
  }

  async initialize() {
    if (this._client) return;

    this._configSummary = getConfigSummary();

    if (this._configSummary.tlsEnabled) {
      emit('INFO', 'REDIS_TLS_ENABLED', { source: SOURCE, tlsVerified: this._configSummary.tlsVerified, url: this._configSummary.urlRedacted });
    }

    this._client = createManagedRedisClient({
      purpose:           'rateLimit',
      // shared infinite-retry strategy — replaces this store's own
      // bespoke bounded strategy, which gave up permanently after
      // OLD_MAX_RECONNECTS attempts (~3.1s), requiring a full process
      // restart to recover. onRetry preserves this store's exact prior
      // side effects (_reconnectCount, _checkFlapping) and event shape.
      reconnectStrategy: createInfiniteReconnectStrategy({
        source: SOURCE,
        oldMaxReconnects: OLD_MAX_RECONNECTS,
        onRetry: ({ retries, delayMs, pastOldThreshold }) => {
          this._reconnectCount++;
          this._checkFlapping();
          emit('WARN', 'REDIS_RECONNECTING', { source: SOURCE, retries, nextDelayMs: delayMs, pastOldThreshold });
        },
      }),
      connectTimeout:    CONNECT_TIMEOUT,
    });

    this._client.on('connect', () =>
      emit('INFO', 'REDIS_CONNECTED', { source: SOURCE, url: this._configSummary.urlRedacted }));

    this._client.on('error', err => {
      emit('ERROR', 'RATE_LIMIT_REDIS_ERROR', { source: SOURCE, error: err.message });
      if (isAuthError(err)) emit('ERROR', 'REDIS_AUTH_REJECTED', { source: SOURCE, error: err.message });
      if (isTlsError(err))  emit('ERROR', 'REDIS_TLS_FAILED',    { source: SOURCE, error: err.message });
      if (this._wasReady) {
        this._disconnectCount++;
        this._wasReady = false;
        emit('WARN', 'REDIS_DISCONNECTED',    { source: SOURCE, error: err.message, disconnectCount: this._disconnectCount });
        emit('WARN', 'REDIS_READINESS_FALSE', { source: SOURCE, reason: err.message, rateLimitProtectionActive: false, executionBlocked: true });
      }
    });

    this._client.on('ready', () => {
      const isReconnect   = this._hadFirstReady;
      this._hadFirstReady = true;
      this._wasReady      = true;
      emit('INFO', 'REDIS_READY', { source: SOURCE, url: this._configSummary?.urlRedacted, isReconnect });
      if (isReconnect) {
        emit('INFO', 'REDIS_RECONNECTED',       { source: SOURCE, reconnectCount: this._reconnectCount, disconnectCount: this._disconnectCount });
        emit('INFO', 'REDIS_RUNTIME_RECOVERED', { source: SOURCE });
      }
      emit('INFO', 'REDIS_READINESS_TRUE', {
        source: SOURCE, rateLimitProtectionActive: true, executionBlocked: false,
        reconnectCount: this._reconnectCount, disconnectCount: this._disconnectCount,
      });
    });

    this._client.on('end', () => {
      if (this._wasReady) {
        this._disconnectCount++;
        this._wasReady = false;
        emit('WARN', 'REDIS_DISCONNECTED', { source: SOURCE, reason: 'connection closed', disconnectCount: this._disconnectCount });
      }
      emit('ERROR', 'REDIS_RUNTIME_DEGRADED', { source: SOURCE, message: 'Redis connection closed — rate limiting fail-closed while automatic recovery is in progress' });
    });

    emit('INFO', 'REDIS_CONNECTING', { source: SOURCE, url: this._configSummary.urlRedacted });

    await this._client.connect().catch(err =>
      emit('ERROR', 'RATE_LIMIT_REDIS_CONNECT_FAILED', { source: SOURCE, error: err.message }));

    if (!this._client.isReady) {
      emit('WARN', 'RATE_LIMIT_REDIS_NOT_READY', {
        source:  SOURCE,
        message: 'Redis not ready after initialize() — rate limiting will fail-closed until connected',
      });
      return;
    }

    try {
      const probeKey = `${KEY_PREFIX}_probe_${Date.now()}`;
      const pong     = await this._client.ping();
      if (pong !== 'PONG') throw new Error(`unexpected PING response: ${pong}`);
      await this._client.set(probeKey, '1', { PX: 5_000 });
      const val = await this._client.get(probeKey);
      await this._client.del(probeKey);
      if (val !== '1') throw new Error('namespace probe: read value mismatch');
      emit('INFO', 'REDIS_CONNECTIVITY_VALIDATED', { source: SOURCE, namespace: KEY_PREFIX, pingOk: true, writeOk: true, readOk: true });
      emit('INFO', 'REDIS_NAMESPACE_READY', { source: SOURCE, namespace: KEY_PREFIX });
      if (this._configSummary.authConfigured) {
        emit('INFO', 'REDIS_AUTH_VALIDATED', { source: SOURCE, note: 'probe succeeded with configured credentials' });
      }
    } catch (err) {
      emit('ERROR', 'RATE_LIMIT_REDIS_PROBE_FAILED', { source: SOURCE, error: err.message });
    }
  }

  async disconnect() {
    if (this._client) {
      await this._client.quit().catch(() => {});
      this._client              = null;
      this._wasReady            = false;
      this._hadFirstReady       = false;
      this._reconnectCount      = 0;
      this._disconnectCount     = 0;
      this._reconnectTimestamps = [];
    }
  }
}

// ── Production singleton ──────────────────────────────────────────────────────

const _prodStorage = new RedisStorage();

module.exports = {
  MemoryStorage,
  RedisStorage,
  KEY_PREFIX,
  getProductionStorage: () => _prodStorage,
  initialize:           () => _prodStorage.initialize(),
  disconnect:           () => _prodStorage.disconnect(),
  isReady:              () => _prodStorage.isReady(),
};
