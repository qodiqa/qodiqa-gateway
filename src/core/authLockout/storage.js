'use strict';

/**
 * Storage abstraction for auth-failure lockout — AUTH-2, extended
 * (credential-identity scoped secondary counter).
 *
 * Mirrors src/core/rateLimit/storage.js's shape (two implementations behind
 * a common interface; MemoryStorage for dev/test, RedisStorage for
 * production/distributed deployments) so failure counters and lockout state
 * use the exact same distributed-storage strategy already established and
 * operationally proven for rate limiting (requirement: "use the same
 * distributed storage strategy already employed for similar security
 * mechanisms").
 *
 * Key format: authlock:v1:{identity}
 *   e.g. authlock:v1:ip:203.0.113.7          (IP-scoped)
 *        authlock:v1:cred:9f86d081884c7d65   (credential-scoped, truncated
 *                                             SHA-256 hex — see index.js)
 * The two identity namespaces (`ip:` / `cred:`) live under the same prefix
 * but never collide, since one is derived from a network address and the
 * other from a hash digest.
 *
 * `precheck`/`recordFailure`/`recordSuccess` all accept `keys` as EITHER a
 * single string (legacy call shape — pre-WP-012 behavior, IP-only, returns
 * the original 4-or-3-field shape unchanged) OR an array of up to two keys
 * `[ipKey, credKey]` (evaluates both identities in one atomic
 * round trip and returns an extended shape with `ip`/`credential`
 * sub-results plus an aggregated top-level decision). This lets every
 * pre-existing single-key call site and test keep working byte-for-byte
 * while the service layer (index.js) opts into dual-identity evaluation by
 * passing an array.
 *
 * Both implementations execute the same algorithm.js Lua scripts (or their
 * synchronous in-process equivalent) so the two backends can never diverge
 * in behavior — only in whether state is shared across processes.
 */

const { getConfigSummary,
        isAuthError, isTlsError }  = require('../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../../infra/redis/reconnectStrategy');
const { emit }                     = require('../../../services/logger');
const { PRECHECK_LUA, RECORD_FAILURE_LUA, RECORD_SUCCESS_LUA } = require('./algorithm');

const KEY_PREFIX       = 'authlock:v1:';
// no longer a hard cap — see OLD_MAX_RECONNECTS note in
// src/core/rateLimit/storage.js.
const OLD_MAX_RECONNECTS = 5;
const CONNECT_TIMEOUT  = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const FLAP_WINDOW_MS   = 60_000;
const FLAP_THRESHOLD   = 3;
const SOURCE           = 'AUTH_LOCKOUT_REDIS';

// ── MemoryStorage ────────────────────────────────────────────────────────────
//
// Single-process only — not suitable for distributed deployments. Intended
// for development and testing (also the fallback when REDIS_URL is unset,
// matching the rate limiter's own dev-mode behavior).

class MemoryStorage {
  constructor() {
    this._state = new Map(); // key -> { count, lockedUntil, expiresAt }
  }

  isReady() { return true; }

  _read(key, now) {
    const entry = this._state.get(key);
    if (!entry || entry.expiresAt <= now) return { count: 0, lockedUntil: 0 };
    return entry;
  }

  // Single-identity check — the exact pre-WP-012 logic, unchanged. Shared by
  // both the legacy single-key call shape and the dual-key path below so
  // the two identities can never diverge in behavior.
  _checkOne(key, now) {
    const entry = this._read(key, now);
    let { count, lockedUntil } = entry;
    let expired = 0;

    if (lockedUntil > 0 && lockedUntil <= now) {
      count = 0;
      lockedUntil = 0;
      expired = 1;
      this._state.delete(key);
    }

    const locked = lockedUntil > now ? 1 : 0;
    return { count, lockedUntil, locked, expired };
  }

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey]. credKey may be omitted/falsy when no credential
   *   was presented.
   */
  async precheck(keys, now) {
    const keyArr  = Array.isArray(keys) ? keys : [keys];
    const primary = this._checkOne(keyArr[0], now);

    if (keyArr.length < 2 || !keyArr[1]) return primary;

    const secondary = this._checkOne(keyArr[1], now);
    return {
      ...primary,
      locked:  (primary.locked || secondary.locked) ? 1 : 0,
      expired: (primary.expired || secondary.expired) ? 1 : 0,
      ip:         primary,
      credential: secondary,
    };
  }

  // Single-identity increment — the exact pre-WP-012 logic, unchanged.
  _recordOne(key, now, maxFailures, lockoutDurationMs, keyTtlSeconds) {
    const entry = this._read(key, now);
    const count = entry.count + 1;
    let lockedUntil = entry.lockedUntil;
    let triggered = 0;

    if (count >= maxFailures && lockedUntil <= now) {
      lockedUntil = now + lockoutDurationMs;
      triggered = 1;
    }

    this._state.set(key, { count, lockedUntil, expiresAt: now + keyTtlSeconds * 1000 });
    return { count, lockedUntil, triggered };
  }

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey].
   */
  async recordFailure(keys, now, maxFailures, lockoutDurationMs, keyTtlSeconds) {
    const keyArr  = Array.isArray(keys) ? keys : [keys];
    const primary = this._recordOne(keyArr[0], now, maxFailures, lockoutDurationMs, keyTtlSeconds);

    if (keyArr.length < 2 || !keyArr[1]) return primary;

    const secondary = this._recordOne(keyArr[1], now, maxFailures, lockoutDurationMs, keyTtlSeconds);
    return {
      ...primary,
      triggered:  (primary.triggered || secondary.triggered) ? 1 : 0,
      ip:         primary,
      credential: secondary,
    };
  }

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey].
   */
  async recordSuccess(keys, now) {
    const keyArr        = Array.isArray(keys) ? keys : [keys];
    const primaryCount  = this._read(keyArr[0], now).count;
    this._state.delete(keyArr[0]);

    if (keyArr.length < 2 || !keyArr[1]) return { priorCount: primaryCount };

    const secondaryCount = this._read(keyArr[1], now).count;
    this._state.delete(keyArr[1]);
    return {
      priorCount: primaryCount,
      ip:         { priorCount: primaryCount },
      credential: { priorCount: secondaryCount },
    };
  }

  _reset() { this._state.clear(); }
}

// ── RedisStorage ─────────────────────────────────────────────────────────────
//
// Production Redis-backed storage. Fail-closed: precheck()/recordFailure()/
// recordSuccess() throw if the client is not ready — the caller (middleware)
// is responsible for deciding the fail-closed HTTP outcome, exactly as
// src/core/rateLimit/middleware.js does for RATE_LIMIT_REDIS_FAILURE.

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

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey]. credKey may be omitted/falsy when no credential
   *   was presented — in that case a single-element `keys` array is
   *   passed to EVAL, leaving Lua's KEYS[2] as nil, so this remains ONE
   *   round trip either way.
   */
  async precheck(keys, now) {
    if (!this.isReady()) throw new Error('AUTH_LOCKOUT_REDIS: Redis not ready — fail-closed');
    const keyArr = (Array.isArray(keys) ? keys : [keys]).filter(Boolean);

    const [count, lockedUntil, locked, expired, credCount, credLockedUntil, credLocked, credExpired] =
      await this._client.eval(PRECHECK_LUA, { keys: keyArr, arguments: [String(now)] });

    const primary = { count: Number(count), lockedUntil: Number(lockedUntil), locked: Number(locked), expired: Number(expired) };
    if (keyArr.length < 2) return primary;

    const secondary = {
      count: Number(credCount), lockedUntil: Number(credLockedUntil),
      locked: Number(credLocked), expired: Number(credExpired),
    };
    return {
      ...primary,
      locked:  (primary.locked || secondary.locked) ? 1 : 0,
      expired: (primary.expired || secondary.expired) ? 1 : 0,
      ip:         primary,
      credential: secondary,
    };
  }

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey].
   */
  async recordFailure(keys, now, maxFailures, lockoutDurationMs, keyTtlSeconds) {
    if (!this.isReady()) throw new Error('AUTH_LOCKOUT_REDIS: Redis not ready — fail-closed');
    const keyArr = (Array.isArray(keys) ? keys : [keys]).filter(Boolean);

    const [count, lockedUntil, triggered, credCount, credLockedUntil, credTriggered] = await this._client.eval(RECORD_FAILURE_LUA, {
      keys: keyArr,
      arguments: [String(now), String(maxFailures), String(lockoutDurationMs), String(keyTtlSeconds)],
    });

    const primary = { count: Number(count), lockedUntil: Number(lockedUntil), triggered: Number(triggered) };
    if (keyArr.length < 2) return primary;

    const secondary = { count: Number(credCount), lockedUntil: Number(credLockedUntil), triggered: Number(credTriggered) };
    return {
      ...primary,
      triggered:  (primary.triggered || secondary.triggered) ? 1 : 0,
      ip:         primary,
      credential: secondary,
    };
  }

  /**
   * @param {string|[string, string?]} keys — single key (legacy) or
   *   [ipKey, credKey].
   */
  async recordSuccess(keys) {
    if (!this.isReady()) throw new Error('AUTH_LOCKOUT_REDIS: Redis not ready — fail-closed');
    const keyArr = (Array.isArray(keys) ? keys : [keys]).filter(Boolean);

    const [priorCount, credPriorCount] = await this._client.eval(RECORD_SUCCESS_LUA, { keys: keyArr, arguments: [] });

    if (keyArr.length < 2) return { priorCount: Number(priorCount) };
    return {
      priorCount: Number(priorCount),
      ip:         { priorCount: Number(priorCount) },
      credential: { priorCount: Number(credPriorCount) },
    };
  }

  _checkFlapping() {
    const now = Date.now();
    this._reconnectTimestamps.push(now);
    this._reconnectTimestamps = this._reconnectTimestamps.filter(t => now - t < FLAP_WINDOW_MS);
    if (this._reconnectTimestamps.length > FLAP_THRESHOLD) {
      emit('WARN', 'REDIS_RECONNECT_FLAPPING', { source: SOURCE, count: this._reconnectTimestamps.length, windowMs: FLAP_WINDOW_MS });
      emit('WARN', 'REDIS_RUNTIME_UNSTABLE',   { source: SOURCE, reason: 'reconnect rate exceeds threshold — auth lockout fail-closed until stable' });
    }
  }

  async initialize() {
    if (this._client) return;

    this._configSummary = getConfigSummary();

    this._client = createManagedRedisClient({
      purpose:           'authLockout',
      // shared infinite-retry strategy — replaces this store's own
      // bespoke bounded strategy, which gave up permanently after
      // OLD_MAX_RECONNECTS attempts (~3.1s), requiring a full process
      // restart to recover.
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
      emit('ERROR', 'AUTH_LOCKOUT_REDIS_ERROR', { source: SOURCE, error: err.message });
      if (isAuthError(err)) emit('ERROR', 'REDIS_AUTH_REJECTED', { source: SOURCE, error: err.message });
      if (isTlsError(err))  emit('ERROR', 'REDIS_TLS_FAILED',    { source: SOURCE, error: err.message });
      if (this._wasReady) {
        this._disconnectCount++;
        this._wasReady = false;
        emit('WARN', 'REDIS_DISCONNECTED', { source: SOURCE, error: err.message, disconnectCount: this._disconnectCount });
      }
    });

    this._client.on('ready', () => {
      const isReconnect   = this._hadFirstReady;
      this._hadFirstReady = true;
      this._wasReady      = true;
      emit('INFO', 'REDIS_READY', { source: SOURCE, url: this._configSummary?.urlRedacted, isReconnect });
      if (isReconnect) {
        emit('INFO', 'REDIS_RECONNECTED', { source: SOURCE, reconnectCount: this._reconnectCount, disconnectCount: this._disconnectCount });
      }
    });

    this._client.on('end', () => {
      if (this._wasReady) {
        this._disconnectCount++;
        this._wasReady = false;
        emit('WARN', 'REDIS_DISCONNECTED', { source: SOURCE, reason: 'connection closed', disconnectCount: this._disconnectCount });
      }
      emit('ERROR', 'REDIS_RUNTIME_DEGRADED', { source: SOURCE, message: 'Redis connection closed — auth lockout fail-closed while automatic recovery is in progress' });
    });

    emit('INFO', 'REDIS_CONNECTING', { source: SOURCE, url: this._configSummary.urlRedacted });

    await this._client.connect().catch(err =>
      emit('ERROR', 'AUTH_LOCKOUT_REDIS_CONNECT_FAILED', { source: SOURCE, error: err.message }));

    if (!this._client.isReady) {
      emit('WARN', 'AUTH_LOCKOUT_REDIS_NOT_READY', {
        source: SOURCE, message: 'Redis not ready after initialize() — auth lockout will fail-closed until connected',
      });
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
