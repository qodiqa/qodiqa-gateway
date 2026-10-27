'use strict';

/**
 * QODIQA V2 Nonce Store — Redis-backed, globally atomic replay protection.
 *
 * Key design invariants:
 *   • One atomic command (SET NX PX) — no WATCH/MULTI/Lua required.
 *   • register() returns { registered: false } on duplicate; never throws for replay.
 *   • register() throws immediately when Redis is unavailable — fail-closed.
 *   • TTL is derived from artifact.expiry; store self-prunes; no background sweeper.
 *   • Key format (QODIQA-PROTOCOL-SPEC.md §27.11) — buildNonceKey() is the single
 *     source of truth for this:
 *       no tenant:  qodiqa:req:v2:<requestId>
 *       tenant:     <tenantId>:qodiqa:req:v2:<requestId>
 *     Note tenantId prefixes the WHOLE key — it is not inserted after KEY_PREFIX.
 *
 * Lazy client lifecycle:
 *   • The Redis client is created and connected on the FIRST call to any public
 *     function — never at module import time.  Importing this module is safe in
 *     test environments; no socket is opened until the client is needed.
 *   • initialize() eagerly connects and runs a namespace probe — call this at
 *     startup to gate traffic on confirmed Redis readiness.
 *   • disconnect() tears down the client and resets the singleton so that the
 *     next operation rebuilds it fresh.  Call this in afterAll() when tests need
 *     a guaranteed clean exit.
 *
 * Reconnect semantics (fail-closed):
 * • reconnectStrategy: exponential backoff, infinite retry — never
 *     gives up; past OLD_MAX_RECONNECTS it keeps retrying forever at a
 *     capped, jittered interval instead of requiring a process restart.
 *   • During reconnect: isReady = false → _assertReady() throws → all
 *     nonce operations fail closed → requests blocked (NONCE_STORE_ERROR).
 *   • After successful reconnect: isReady = true → operations resume.
 * • Retries are never exhausted: the store keeps reconnecting forever, so isReady
 * returns to true on its own once Redis is back; until then every request is blocked. (the old
 *     text claimed a permanent failure state that no longer exists.)
 *   • No in-memory fallback.  No fail-open path.
 *
 * Observability:
 *   • All connection lifecycle state transitions emit structured JSON events.
 *   • Readiness transitions emit REDIS_READINESS_TRUE / REDIS_READINESS_FALSE.
 *   • Reconnect instability detected via sliding-window counters.
 *   • module.emitter allows server.js to subscribe to degraded/ready transitions
 *     for gateway-level runtime state tracking.
 *
 * Required env:
 *   REDIS_URL                 — connection string (default: redis://localhost:6379)
 *   REDIS_CONNECT_TIMEOUT_MS  — ms to wait for startup ready (default: 5000)
 *
 * Auth/TLS env: see src/infra/redis/clientConfig.js
 */

const EventEmitter              = require('events');
const { isValidRequestId }      = require('./requestId');
const { checkRedisPersistence } = require('../infra/redis/persistenceCheck');
const {
  getConfigSummary,
  isAuthError,
  isTlsError,
} = require('../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../infra/redis/managedClient');
const { createInfiniteReconnectStrategy } = require('../infra/redis/reconnectStrategy');
const { emit } = require('../../services/logger');
const { buildAnomalyKeys } = require('./anomalyStore');
const { FUTURE_SKEW_MS } = require('./timeCheck');

const KEY_PREFIX      = 'qodiqa:req:v2:';
// no longer a hard cap — see OLD_MAX_RECONNECTS note in storage.js.
const OLD_MAX_RECONNECTS = 5;
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);

// ── Item 17: combined nonce + anomaly Lua ──────────────────────────────────────
//
// Collapses the 3 sequential round trips (registerNonce, then checkAnomaly's
// per-key window, then its global window) into one EVAL, executed on THIS
// module's client — see ITEM-17-REMEDIATION-REPORT.md §3 for why the nonce
// client, not the anomaly client, was chosen.
//
// Early-exit order mirrors validateBoundRequest.js's existing control flow
// exactly, just server-side instead of via three separate JS awaits:
//   1. SET NX PX the nonce key.  Already set -> stop; anomaly untouched
//      (mirrors step 3 blocking step 4 from ever running today).
//   2. Record the per-key sliding window.  Over threshold -> stop; global
//      untouched (mirrors checkAnomaly.js's own per-key-then-global order).
//   3. Record the global sliding window.
//
// KEYS[1] = nonce key            KEYS[2] = anomaly per-key key   KEYS[3] = anomaly global key
// ARGV[1] = nonce TTL, ms (PX)   ARGV[2] = nowMs   ARGV[3] = window ms   ARGV[4] = perKeyMax   ARGV[5] = globalMax
//
// Returns a flat array whose first element is a stop-phase code — same
// "shorter/coded result tells the caller how far execution got" convention
// as item 16's CHECK_AND_INCR_BATCH_SCRIPT (services/policy/store.js):
//   {-1}                          -> replay (nonce already existed)
//   {-2, redisStartedMs} -> restart barrier: issued before the Redis restart
//   {0, perKeyCount}              -> nonce registered, SIGNATURE_BURST (per-key over)
//   {1, perKeyCount, globalCount} -> nonce + per-key ok, RATE_BURST (global over)
//   {2, perKeyCount, globalCount} -> nonce + per-key + global all ok
// ── the restart barrier ─────────────────────
//
// Nonces live in Redis. With AOF 'everysec' (the production minimum, enforced
// at boot by STRICT_REPLAY) a crash can lose the last ~1 s of nonce writes, so
// a nonce registered just before a restart may be gone — and that artifact,
// still inside its 60 s life, would be replayable. The barrier closes it: an
// artifact ISSUED before the Redis server started (its signed timestamp is at
// or before the server's start time + the 5 s future-skew tolerance) cannot
// prove it was not already used, so it is refused (REPLAY_STATE_UNPROVABLE).
//
// Order matters: the nonce SET NX runs FIRST, so an artifact whose nonce
// survived the restart is still reported as REPLAY_DETECTED; only a nonce the
// restart may have lost reaches the barrier. The server's start time is read
// INSIDE the script (TIME − uptime_in_seconds, rounded to the latest possible
// start), so there is no window between the restart and the barrier.
// Every artifact is affected by a restart for at most its 60 s max age.
//
// ARGV[6] = the artifact's signed timestamp, ms (0 = not supplied: no barrier)
// ARGV[7] = future-skew tolerance, ms
const RESTART_BARRIER_LUA = `
local issued = tonumber(ARGV[6])
if issued and issued > 0 then
  local t = redis.call('TIME')
  local nowMs = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
  local up = tonumber(string.match(redis.call('INFO', 'server'), 'uptime_in_seconds:(%d+)'))
  if up then
    local startedMs = nowMs - up * 1000
    if issued <= startedMs + tonumber(ARGV[7]) then
      return {-2, startedMs}
    end
  end
end
`;

const COMBINED_REGISTER_SCRIPT = `
local nonceOk = redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1])
if not nonceOk then
  return {-1}
end
${RESTART_BARRIER_LUA}

local now    = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local cutoff = now - window

local perKeyKey = KEYS[2]
redis.call('ZREMRANGEBYSCORE', perKeyKey, 0, cutoff)
local perKeySeq = redis.call('INCR', perKeyKey .. ':seq')
redis.call('ZADD', perKeyKey, now, tostring(now) .. ':' .. tostring(perKeySeq))
redis.call('PEXPIRE', perKeyKey, window + 1000)
redis.call('PEXPIRE', perKeyKey .. ':seq', window + 1000)
local perKeyCount = tonumber(redis.call('ZCARD', perKeyKey))

if perKeyCount > tonumber(ARGV[4]) then
  return {0, perKeyCount}
end

local globalKey = KEYS[3]
redis.call('ZREMRANGEBYSCORE', globalKey, 0, cutoff)
local globalSeq = redis.call('INCR', globalKey .. ':seq')
redis.call('ZADD', globalKey, now, tostring(now) .. ':' .. tostring(globalSeq))
redis.call('PEXPIRE', globalKey, window + 1000)
redis.call('PEXPIRE', globalKey .. ':seq', window + 1000)
local globalCount = tonumber(redis.call('ZCARD', globalKey))

if globalCount > tonumber(ARGV[5]) then
  return {1, perKeyCount, globalCount}
end

return {2, perKeyCount, globalCount}
`;

/**
 * Build the canonical nonce-store key — QODIQA-PROTOCOL-SPEC.md §27.11.
 * Single source of truth: every caller (register, isRegistered, and every
 * test double standing in for this store) MUST build keys through this
 * function so the format can never drift between call sites.
 *
 * tenantId prefixes the ENTIRE key (including KEY_PREFIX) — it is not
 * inserted between the prefix and the requestId.
 *
 * @param {string} requestId        — UUID v4, validated by the caller
 * @param {string|null} [tenantId]  - omit, null, or '' for no tenant scoping
 * @returns {string}
 */
function buildNonceKey(requestId, tenantId) {
  return tenantId ? `${tenantId}:${KEY_PREFIX}${requestId}` : `${KEY_PREFIX}${requestId}`;
}

// Accepts anything buildNonceKey() treats as "no tenant" (undefined, null, '')
// plus any non-empty string — keeps this check consistent with the builder's
// own truthiness test rather than imposing a stricter rule the builder doesn't
// enforce.
function _isValidTenantId(tenantId) {
  return tenantId === undefined || tenantId === null || typeof tenantId === 'string';
}

// Sliding-window thresholds for flapping detection.
const FLAP_WINDOW_MS = 60_000;
const FLAP_THRESHOLD = 3;

// ── Store-level event emitter ─────────────────────────────────────────────────
//
// Emits 'degraded' and 'ready' events so the gateway can maintain a unified
// runtime integrity view without polling.  Listeners are registered once at
// server startup; the emitter persists across reconnect cycles.

const _storeEmitter = new EventEmitter();
_storeEmitter.setMaxListeners(20);

// ── Connection state ──────────────────────────────────────────────────────────

let _client               = null;
let _connectPromise       = null;
let _hadFirstReady        = false;
let _wasReady             = false;
let _hadAuthError         = false;
let _hadTlsError          = false;
let _configSummary        = null;

// ── Instability counters (cumulative across reconnect cycles) ─────────────────

let _reconnectCount       = 0;
let _disconnectCount      = 0;
let _reconnectTimestamps  = [];   // epoch-ms timestamps of recent reconnect attempts
let _readinessTransitions = [];   // { time, state } for recent readiness changes

// ── Flapping detection helpers ────────────────────────────────────────────────

function _checkReconnectFlapping() {
  const now = Date.now();
  _reconnectTimestamps.push(now);
  _reconnectTimestamps = _reconnectTimestamps.filter(t => now - t < FLAP_WINDOW_MS);
  if (_reconnectTimestamps.length > FLAP_THRESHOLD) {
    emit('WARN', 'REDIS_RECONNECT_FLAPPING', {
      source:         'NONCE_STORE',
      reconnectCount: _reconnectTimestamps.length,
      windowMs:       FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:         'NONCE_STORE',
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
      source:          'NONCE_STORE',
      transitionCount: _readinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
    emit('WARN', 'REDIS_RUNTIME_UNSTABLE', {
      source:          'NONCE_STORE',
      reason:          'readiness flapping detected',
      transitionCount: _readinessTransitions.length,
      windowMs:        FLAP_WINDOW_MS,
    });
  }
}

// ── Infinite reconnect strategy ──────────────────────────────────────────

const _reconnectStrategy = createInfiniteReconnectStrategy({
  source: 'NONCE_STORE',
  oldMaxReconnects: OLD_MAX_RECONNECTS,
  onRetry: ({ retries, delayMs, pastOldThreshold }) => {
    _reconnectCount++;
    _checkReconnectFlapping();
    emit('WARN', 'REDIS_RECONNECTING', {
      source:          'NONCE_STORE',
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
      source:      'NONCE_STORE',
      tlsVerified: _configSummary.tlsVerified,
      url:         _configSummary.urlRedacted,
    });
  }

  _client = createManagedRedisClient({
    purpose:           'nonce',
    reconnectStrategy: _reconnectStrategy,
    connectTimeout:    CONNECT_TIMEOUT,
  });

  // TCP socket established — before AUTH/SELECT complete.
  _client.on('connect', () => {
    emit('INFO', 'REDIS_CONNECTED', {
      source: 'NONCE_STORE',
      url:    _configSummary.urlRedacted,
    });
  });

  // Error handler: classify auth/TLS failures; track disconnect transitions.
  // Each security error class emitted once per connection lifecycle.
  _client.on('error', err => {
    emit('ERROR', 'NONCE_STORE_V2_ERROR', { error: err.message });

    if (!_hadAuthError && isAuthError(err)) {
      _hadAuthError = true;
      emit('ERROR', 'REDIS_AUTH_REJECTED', {
        source: 'NONCE_STORE',
        error:  err.message,
      });
    }

    if (!_hadTlsError && isTlsError(err)) {
      _hadTlsError = true;
      emit('ERROR', 'REDIS_TLS_FAILED', {
        source: 'NONCE_STORE',
        error:  err.message,
      });
    }

    if (_wasReady) {
      _disconnectCount++;
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:         'NONCE_STORE',
        error:          err.message,
        disconnectCount: _disconnectCount,
      });
      emit('WARN', 'REDIS_READINESS_FALSE', {
        source:                 'NONCE_STORE',
        reason:                 err.message,
        reconnectCount:         _reconnectCount,
        disconnectCount:        _disconnectCount,
        executionBlocked:       true,
        replayProtectionActive: false,
      });
      _checkReadinessFlapping(false);
      _storeEmitter.emit('degraded', { source: 'NONCE_STORE', reason: err.message });
    }
  });

  // Ready: AUTH/SELECT complete — store is operational.
  _client.on('ready', () => {
    const isReconnect = _hadFirstReady;
    _hadFirstReady    = true;
    _wasReady         = true;
    _hadAuthError     = false;
    _hadTlsError      = false;

    emit('INFO', 'REDIS_READY', {
      source:          'NONCE_STORE',
      url:             _configSummary?.urlRedacted,
      isReconnect,
      reconnectCount:  _reconnectCount,
      disconnectCount: _disconnectCount,
    });

    if (isReconnect) {
      emit('INFO', 'REDIS_RECONNECTED', {
        source:          'NONCE_STORE',
        url:             _configSummary?.urlRedacted,
        reconnectCount:  _reconnectCount,
        disconnectCount: _disconnectCount,
      });
      emit('INFO', 'REDIS_RUNTIME_RECOVERED', {
        source:          'NONCE_STORE',
        reconnectCount:  _reconnectCount,
        disconnectCount: _disconnectCount,
      });
    }

    emit('INFO', 'REDIS_READINESS_TRUE', {
      source:                 'NONCE_STORE',
      reconnectCount:         _reconnectCount,
      disconnectCount:        _disconnectCount,
      executionBlocked:       false,
      replayProtectionActive: true,
    });

    _checkReadinessFlapping(true);
    _storeEmitter.emit('ready', { source: 'NONCE_STORE', isReconnect });
  });

  // End: this client instance's bounded reconnect attempts are exhausted.
  // managedClient.js's self-healing supervisor (Finding 49) now takes over
  // from here — it destroys this dead client and keeps recreating a fresh
  // one until Redis is reachable again; no restart required. Readiness
  // becomes true again via the 'ready' handler above once that succeeds.
  _client.on('end', () => {
    if (_wasReady) {
      _disconnectCount++;
      _wasReady = false;
      emit('WARN', 'REDIS_DISCONNECTED', {
        source:          'NONCE_STORE',
        disconnectCount: _disconnectCount,
      });
    }
    emit('WARN', 'REDIS_READINESS_FALSE', {
      source:                 'NONCE_STORE',
      reason:                 'connection closed — automatic recovery in progress',
      reconnectCount:         _reconnectCount,
      disconnectCount:        _disconnectCount,
      executionBlocked:       true,
      replayProtectionActive: false,
    });
    emit('ERROR', 'REDIS_RUNTIME_DEGRADED', {
      source:          'NONCE_STORE',
      message:         'Redis connection closed — replay protection fail-closed while automatic recovery is in progress',
      reconnectCount:  _reconnectCount,
      disconnectCount: _disconnectCount,
    });
    _checkReadinessFlapping(false);
    _storeEmitter.emit('degraded', {
      source: 'NONCE_STORE',
      reason: 'connection closed — automatic recovery in progress',
    });
  });

  emit('INFO', 'REDIS_CONNECTING', {
    source: 'NONCE_STORE',
    url:    _configSummary.urlRedacted,
  });

  _connectPromise = _client.connect().catch(err => {
    emit('ERROR', 'NONCE_STORE_V2_CONNECT_FAILED', { error: err.message });
  });

  return _client;
}

function _assertReady() {
  if (!_getClient().isReady) {
    throw new Error('NONCE_STORE_V2: Redis not connected — request blocked (fail-closed)');
  }
}

// ── Startup namespace probe ───────────────────────────────────────────────────

async function _runStartupProbe(client) {
  // a per-process probe key — a fixed key shared by every process made concurrent
  // boots against one Redis fail 9-15% of store inits (A SET, B SET, A GET, A DEL, B GET → null). PX still bounds leftovers.
  const probeKey = `${KEY_PREFIX}_startup_probe:${process.pid}:${require('crypto').randomBytes(6).toString('hex')}`;

  const pong = await client.ping();
  if (pong !== 'PONG') {
    throw new Error(`NONCE_STORE: unexpected PING response: ${pong}`);
  }

  await client.set(probeKey, '1', { PX: 5_000 });
  const val = await client.get(probeKey);
  await client.del(probeKey);

  if (val !== '1') {
    throw new Error(`NONCE_STORE: namespace probe returned unexpected value: ${String(val)}`);
  }

  const summary = _configSummary ?? getConfigSummary();

  emit('INFO', 'REDIS_CONNECTIVITY_VALIDATED', {
    source:    'NONCE_STORE',
    namespace: KEY_PREFIX,
    pingOk:    true,
    writeOk:   true,
    readOk:    true,
  });
  emit('INFO', 'REDIS_NAMESPACE_READY', { source: 'NONCE_STORE', namespace: KEY_PREFIX });

  if (summary.authConfigured) {
    emit('INFO', 'REDIS_AUTH_VALIDATED', {
      source: 'NONCE_STORE',
      note:   'probe succeeded with configured credentials',
    });
  }

  if (summary.tlsEnabled) {
    emit('INFO', 'REDIS_TLS_VALIDATED', {
      source:      'NONCE_STORE',
      tlsVerified: summary.tlsVerified,
      note:        'probe succeeded over TLS connection',
    });
  }

  emit('INFO', 'REDIS_RUNTIME_READY', {
    source:          'NONCE_STORE',
    namespace:       KEY_PREFIX,
    reconnectCount:  _reconnectCount,
    disconnectCount: _disconnectCount,
  });
  emit('INFO', 'NONCE_STORE_READY', { url: summary.urlRedacted, namespace: KEY_PREFIX });

  return { ready: true, namespace: KEY_PREFIX };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Eagerly connect the nonce store and validate the replay namespace.
 *
 * @returns {Promise<{ ready: boolean, namespace: string }>}
 * @throws  On timeout, connection end, auth failure, or namespace probe failure.
 */
async function initialize() {
  const client = _getClient();

  if (client.isReady) {
    try {
      return await _runStartupProbe(client);
    } catch (err) {
      emit('ERROR', 'REDIS_NAMESPACE_UNAVAILABLE', {
        source:                 'NONCE_STORE',
        namespace:              KEY_PREFIX,
        error:                  err.message,
        executionBlocked:       true,
        replayProtectionActive: false,
      });
      throw err;
    }
  }

  await new Promise((resolve, reject) => {
    const summary = _configSummary ?? getConfigSummary();
    const timer = setTimeout(() => {
      off();
      reject(new Error(
        `NONCE_STORE: startup connect timeout (${CONNECT_TIMEOUT}ms) — Redis unavailable at ${summary.urlRedacted}`,
      ));
    }, CONNECT_TIMEOUT);

    function onReady() { off(); resolve(); }
    function onEnd()   { off(); reject(new Error('NONCE_STORE: connection ended before becoming ready')); }

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
      source:                 'NONCE_STORE',
      namespace:              KEY_PREFIX,
      error:                  err.message,
      executionBlocked:       true,
      replayProtectionActive: false,
    });
    throw err;
  }
}

/**
 * Run Redis persistence diagnostics against the live nonce store connection.
 *
 * @returns {Promise<import('../infra/redis/persistenceCheck').PersistenceDiagnostics>}
 */
async function checkPersistence() {
  const client = _getClient();
  if (!client.isReady) {
    return {
      safe:           false,
      aofEnabled:     null,
      appendfsync:    null,
      lastSave:       null,
      aofCurrentSize: null,
      warnings: [
        'PERSISTENCE_CHECK_FAILED: nonce store Redis client not connected — ' +
        'cannot verify persistence configuration; replay durability is unknown',
      ],
      error: 'NONCE_STORE_NOT_CONNECTED',
    };
  }
  return checkRedisPersistence(client);
}

/**
 * Returns the current readiness state of the nonce store.
 * @returns {boolean}
 */
function isReady() {
  return _client ? _client.isReady : false;
}

/**
 * Atomically register a requestId with a TTL derived from artifact expiry.
 *
 * @param {string} requestId        UUID v4 from artifact.payload.requestId
 * @param {number} expiryMs         artifact.expiry in epoch-ms
 * @param {string|null} [tenantId]  tenant identifier — namespaces the key so two
 *                                  tenants may legitimately reuse a requestId
 * @returns {Promise<{ registered: true } | { registered: false }>}
 * @throws  If inputs are invalid or Redis is unavailable — fail-closed.
 */
// the sequential path's single-key script (SET NX + the same restart barrier).
const REGISTER_SCRIPT = `
local nonceOk = redis.call('SET', KEYS[1], '1', 'NX', 'PX', ARGV[1])
if not nonceOk then
  return {-1}
end
${RESTART_BARRIER_LUA.replace(/ARGV\[6\]/g, 'ARGV[2]').replace(/ARGV\[7\]/g, 'ARGV[3]')}
return {1}
`;

async function register(requestId, expiryMs, tenantId, issuedAtMs = 0) {
  if (!isValidRequestId(requestId)) {
    throw new TypeError('NONCE_STORE_V2: requestId must be a UUID v4');
  }
  if (!_isValidTenantId(tenantId)) {
    throw new TypeError('NONCE_STORE_V2: tenantId must be a non-empty string, null, or undefined');
  }
  if (!Number.isFinite(expiryMs) || expiryMs <= 0) {
    throw new TypeError('NONCE_STORE_V2: expiryMs must be a positive finite number');
  }
  _assertReady();

  const ttlMs = Math.floor(expiryMs - Date.now());
  if (ttlMs <= 0) {
    throw new Error('NONCE_STORE_V2: requestId already expired before registration');
  }

  const raw = await _getClient().eval(REGISTER_SCRIPT, {
    keys:      [buildNonceKey(requestId, tenantId)],
    arguments: [String(ttlMs), String(Number.isFinite(issuedAtMs) ? Math.floor(issuedAtMs) : 0), String(FUTURE_SKEW_MS)],
  });
  const code = Number(raw[0]);

  if (code === -1) {
    emit('WARN', 'NONCE_V2_REPLAY_DETECTED', {
      requestIdPrefix: requestId.slice(0, 8) + '…',
      ...(tenantId ? { tenantId } : {}),
    });
    return { registered: false };
  }
  if (code === -2) {
    emit('WARN', 'NONCE_V2_REPLAY_STATE_UNPROVABLE', { requestIdPrefix: requestId.slice(0, 8) + '…', redisStartedMs: Number(raw[1]), issuedAtMs });
    return { registered: false, unprovable: true };
  }

  return { registered: true };
}

/**
 * Combined nonce-registration + anomaly-detection round trip (item 17).
 * Registers the nonce and, if that succeeds, records both anomaly sliding
 * windows — all in one EVAL on this store's own client. Same fail-closed
 * contract as register(): throws on invalid input or an unavailable store.
 *
 * @param {string} requestId
 * @param {number} expiryMs
 * @param {string|null} tenantId
 * @param {{ publicKeyId: string, nowMs: number, windowMs: number, perKeyMax: number, globalMax: number, issuedAtMs?: number }} anomalyParams
 * @returns {Promise<
 *   { phase: 'REPLAY' } |
 *   { phase: 'SIGNATURE_BURST', perKeyCount: number } |
 *   { phase: 'RATE_BURST',      perKeyCount: number, globalCount: number } |
 *   { phase: 'ALLOWED',         perKeyCount: number, globalCount: number } |
 *   { phase: 'REPLAY_UNPROVABLE', redisStartedMs: number }
 * >}
 * @throws  If inputs are invalid or Redis is unavailable — fail-closed.
 */
async function registerAndCheckAnomaly(requestId, expiryMs, tenantId, { publicKeyId, nowMs, windowMs, perKeyMax, globalMax, issuedAtMs = 0 }) {
  if (!isValidRequestId(requestId)) {
    throw new TypeError('NONCE_STORE_V2: requestId must be a UUID v4');
  }
  if (!_isValidTenantId(tenantId)) {
    throw new TypeError('NONCE_STORE_V2: tenantId must be a non-empty string, null, or undefined');
  }
  if (!Number.isFinite(expiryMs) || expiryMs <= 0) {
    throw new TypeError('NONCE_STORE_V2: expiryMs must be a positive finite number');
  }
  _assertReady();

  const ttlMs = Math.floor(expiryMs - Date.now());
  if (ttlMs <= 0) {
    throw new Error('NONCE_STORE_V2: requestId already expired before registration');
  }

  const nonceKey  = buildNonceKey(requestId, tenantId);
  const { perKeyKey, globalKey } = buildAnomalyKeys(publicKeyId, tenantId);

  const raw = await _getClient().eval(COMBINED_REGISTER_SCRIPT, {
    keys:      [nonceKey, perKeyKey, globalKey],
    arguments: [String(ttlMs), String(nowMs), String(windowMs), String(perKeyMax), String(globalMax),
      String(Number.isFinite(issuedAtMs) ? Math.floor(issuedAtMs) : 0), String(FUTURE_SKEW_MS)],
  });

  const code = Number(raw[0]);

  if (code === -1) {
    emit('WARN', 'NONCE_V2_REPLAY_DETECTED', {
      requestIdPrefix: requestId.slice(0, 8) + '…',
      ...(tenantId ? { tenantId } : {}),
    });
    return { phase: 'REPLAY' };
  }
  if (code === -2) {
    emit('WARN', 'NONCE_V2_REPLAY_STATE_UNPROVABLE', {
      requestIdPrefix: requestId.slice(0, 8) + '…', redisStartedMs: Number(raw[1]), issuedAtMs,
      ...(tenantId ? { tenantId } : {}),
    });
    return { phase: 'REPLAY_UNPROVABLE', redisStartedMs: Number(raw[1]) };
  }

  const perKeyCount = Number(raw[1]);

  if (code === 0) {
    emit('INFO', 'ANOMALY_STATE_INCREMENTED', {
      key: perKeyKey, count: perKeyCount, threshold: perKeyMax, windowMs, type: 'SIGNATURE_BURST',
    });
    emit('WARN', 'ANOMALY_THRESHOLD_EXCEEDED', {
      publicKeyId, key: perKeyKey, count: perKeyCount, threshold: perKeyMax, type: 'SIGNATURE_BURST', executionBlocked: true,
    });
    return { phase: 'SIGNATURE_BURST', perKeyCount };
  }

  const globalCount = Number(raw[2]);
  emit('INFO', 'ANOMALY_STATE_INCREMENTED', {
    key: perKeyKey, count: perKeyCount, threshold: perKeyMax, windowMs, type: 'SIGNATURE_BURST',
  });
  emit('INFO', 'ANOMALY_STATE_INCREMENTED', {
    key: globalKey, count: globalCount, threshold: globalMax, windowMs, type: 'RATE_BURST',
  });

  if (code === 1) {
    emit('WARN', 'ANOMALY_THRESHOLD_EXCEEDED', {
      publicKeyId, key: globalKey, count: globalCount, threshold: globalMax, type: 'RATE_BURST', executionBlocked: true,
    });
    return { phase: 'RATE_BURST', perKeyCount, globalCount };
  }

  return { phase: 'ALLOWED', perKeyCount, globalCount };
}

/**
 * Read-only existence check — does NOT mutate state.
 *
 * @param {string} requestId
 * @param {string|null} [tenantId]
 * @returns {Promise<boolean>}
 * @throws  If Redis is unavailable.
 */
async function isRegistered(requestId, tenantId) {
  if (!isValidRequestId(requestId)) return false;
  if (!_isValidTenantId(tenantId)) return false;
  _assertReady();
  const count = await _getClient().exists(buildNonceKey(requestId, tenantId));
  return count === 1;
}

/**
 * Disconnect and destroy the Redis client.
 *
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

module.exports = {
  register,
  registerAndCheckAnomaly,
  isRegistered,
  initialize,
  checkPersistence,
  isReady,
  disconnect,
  buildNonceKey,
  emitter: _storeEmitter,
  get _client() { return _client; },
};
