'use strict';

/**
 * FROZEN HISTORICAL SNAPSHOT — DO NOT USE IN PRODUCTION CODE.
 *
 * This is the verbatim content of ConsentCache.js exactly as it existed
 * immediately BEFORE the remediation, captured byte-for-byte via
 * this session's first `Read` of the file (the repository's `src/` tree was
 * never committed to git, so there is no commit to `git show` for a diff —
 * this transcript capture is the only faithful record of the pre-fix code).
 *
 * Its sole purpose is `consent3.raceRegression.test.js`, which runs the SAME
 * deterministic race harness against this file and against the real,
 * current ConsentCache.js to prove — not merely assert — that the old
 * implementation resurrects a stale cached ALLOW after a concurrent
 * revocation, and that the fixed implementation does not. It is never
 * required by production code and is not itself a test file.
 *
 * It intentionally lives alongside ConsentCache.js (not in a nested
 * __tests__/__fixtures__ folder) so every relative `require(...)` below
 * resolves identically to the original — no path rewriting was needed or
 * performed; this is exactly what shipped.
 */

/**
 * ConsentCache — Redis read-through cache for consent verification results.
 *
 * Strategy:
 *   - Positive (ACTIVE) results are cached for CONSENT_CACHE_TTL_S seconds (default 60).
 *   - Negative results (DENIED, NOT_FOUND, REVOKED, EXPIRED, SUSPENDED) are cached
 *     for CONSENT_CACHE_NEGATIVE_TTL_S seconds (default 10).
 *   - Cache invalidation is explicit: call invalidate(actor_id, action, tenant_id)
 *     after any state-mutating operation (revoke, suspend, resume, create).
 *   - If Redis is unavailable the cache is transparently bypassed — the caller
 *     falls through to the database. There is NO fail-open path on verification:
 *     the ConsentVerifier treats cache misses as "check the DB" not as "allow".
 *
 * Key format: qodiqa:consent:<actor_id>:<action>:<tenant_id|"*">
 */

const { isAuthError, isTlsError } = require('../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const { emit } = require('../../../services/logger');

const KEY_PREFIX            = 'qodiqa:consent:';
const TTL_POSITIVE_S        = parseInt(process.env.CONSENT_CACHE_TTL_S          || '60',  10);
const TTL_NEGATIVE_S        = parseInt(process.env.CONSENT_CACHE_NEGATIVE_TTL_S || '10',  10);
const CONNECT_TIMEOUT_MS    = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS     || '5000', 10);
const MAX_RECONNECTS        = 5;

let _client         = null;
let _connectPromise = null;
let _ready          = false;

function _cacheKey(actor_id, action, tenant_id) {
  const tenant = tenant_id ?? '*';
  return `${KEY_PREFIX}${actor_id}:${action}:${tenant}`;
}

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'consentCache',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    reconnectStrategy: (attempts) => {
      if (attempts >= MAX_RECONNECTS) return new Error('CONSENT_CACHE_RECONNECT_EXHAUSTED');
      return Math.min(200 * Math.pow(2, attempts), 5000);
    },
  });

  client.on('ready', () => {
    _ready = true;
    emit('INFO', 'CONSENT_CACHE_READY', {});
  });

  client.on('error', (err) => {
    _ready = false;
    if (isAuthError(err)) {
      emit('ERROR', 'CONSENT_CACHE_AUTH_ERROR', { error: err.message });
    } else if (isTlsError(err)) {
      emit('ERROR', 'CONSENT_CACHE_TLS_ERROR', { error: err.message });
    } else {
      emit('WARN', 'CONSENT_CACHE_ERROR', { error: err.message });
    }
  });

  client.on('reconnecting', () => {
    _ready = false;
  });

  return client;
}

async function _getClient() {
  if (_client && _ready) return _client;

  if (!_client) {
    // First call only: create the client once. Subsequent calls after a failed
    // connection return null immediately without creating another client.
    // The Redis client's reconnectStrategy handles reconnection internally;
    // _ready becomes true again via the 'ready' event when it succeeds.
    _client = _buildClient();
    _connectPromise = _client.connect()
      .then(() => { _connectPromise = null; })
      .catch((err) => {
        _connectPromise = null;
        emit('WARN', 'CONSENT_CACHE_CONNECT_FAILED', { error: err.message });
      });
  }

  if (_connectPromise) await _connectPromise;
  return _ready ? _client : null;
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Retrieve a cached verification result.
 * Returns null on cache miss or Redis unavailability.
 *
 * @returns {Promise<object|null>}
 */
async function get(actor_id, action, tenant_id = null) {
  try {
    const client = await _getClient();
    if (!client) return null;

    const raw = await client.get(_cacheKey(actor_id, action, tenant_id));
    if (!raw) return null;

    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Store a verification result.
 * Positive results (pass=true) use the longer TTL.
 *
 * @param {string} actor_id
 * @param {string} action
 * @param {string|null} tenant_id
 * @param {object} result  — the full verification result object
 */
async function set(actor_id, action, tenant_id, result) {
  try {
    const client = await _getClient();
    if (!client) return;

    const ttl = result.pass ? TTL_POSITIVE_S : TTL_NEGATIVE_S;
    await client.set(
      _cacheKey(actor_id, action, tenant_id),
      JSON.stringify({ ...result, cached: true, cachedAt: Date.now() }),
      { EX: ttl },
    );
  } catch {
    // Cache write failures are non-fatal
  }
}

/**
 * Invalidate the cached entry for a specific consent key.
 * Call this after any mutation (create, revoke, suspend, resume).
 */
async function invalidate(actor_id, action, tenant_id = null) {
  try {
    const client = await _getClient();
    if (!client) return;

    await client.del(_cacheKey(actor_id, action, tenant_id));
  } catch {
    // Invalidation failure is non-fatal — negative TTL provides eventual consistency
  }
}

/**
 * Invalidate all cached entries for an actor (e.g., after bulk revocation).
 */
async function invalidateActor(actor_id) {
  try {
    const client = await _getClient();
    if (!client) return;

    const pattern = `${KEY_PREFIX}${actor_id}:*`;
    let cursor = 0;
    do {
      const reply = await client.scan(cursor, { MATCH: pattern, COUNT: 100 });
      cursor = reply.cursor;
      if (reply.keys.length) {
        await client.del(reply.keys);
      }
    } while (cursor !== 0);
  } catch {
    // Non-fatal
  }
}

/**
 * Returns true if the cache client is connected and ready.
 */
function isReady() { return _ready; }

/**
 * Disconnect (used in shutdown / tests).
 */
async function disconnect() {
  if (!_client) return;
  try { await _client.disconnect(); } catch { /* ignore */ }
  _client         = null;
  _connectPromise = null;
  _ready          = false;
}

module.exports = { get, set, invalidate, invalidateActor, isReady, disconnect };
