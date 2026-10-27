'use strict';

/**
 * FROZEN HISTORICAL ARTIFACT — DO NOT USE FROM PRODUCTION CODE.
 *
 * Byte-for-byte copy of ConsentCache.js exactly as it stood after the
 * remediation and before the remediation (captured verbatim
 * from this session's own first `Read` of the file, before any edits
 * were made). Its `_buildClient()` does NOT pass `forceMasterReads` to
 * `createManagedRedisClient()` — that omission is the entire bug.
 *
 * Kept solely so `conc2.raceRegression.test.js` can run the identical
 * interleaving against the literal pre-fix implementation, proving the race
 * it reproduces is real and that the code change (not a test-harness
 * artifact) is what closes it. Never imported by any production module.
 *
 * ── optimistic-concurrency write guard ────────────────────────────
 * Awaiting invalidate() only closes the ORDER-OF-OPERATIONS race on the writer
 * (revoke/suspend) side. It does not close the reader-side race: a verify()
 * call that suffers a cache miss reads the DB, and *after* a concurrent
 * revoke has already run its (awaited) invalidate(), still calls set() with
 * the pre-revocation ACTIVE result it read moments earlier — resurrecting a
 * stale ALLOW for a full TTL_POSITIVE_S window. This is the classic
 * cache-aside "stale write after invalidate" race; no amount of awaiting the
 * DEL prevents it, because the DEL and the late SET are two independent
 * client-side operations with the DB read sandwiched in between.
 *
 * consent_records already carries a monotonic `version` column (bumped by a
 * DB trigger on every UPDATE — see migration 007) that was never wired into
 * the cache layer. set()/invalidate() now use it as an optimistic-concurrency
 * token via a single atomic Lua script (_CAS_SCRIPT): a write only lands if
 * no equal-or-newer version is already cached. invalidate() writes a
 * short-lived version-stamped tombstone (instead of a bare DEL) so that a
 * late writer from an in-flight read that started before the mutation can
 * never overwrite it — get() treats a tombstone exactly like a cache miss.
 * This holds under concurrent nodes too, because the CAS check-and-set
 * executes atomically inside Redis, not as separate client-side GET+SET
 * calls, and because the record's version is propagated cross-node through
 * RevocationEvent (see RevocationSubscriber.js).
 */

const { isAuthError, isTlsError } = require('../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const { emit } = require('../../../services/logger');

const KEY_PREFIX            = 'qodiqa:consent:';
const TTL_POSITIVE_S        = parseInt(process.env.CONSENT_CACHE_TTL_S          || '60',  10);
const TTL_NEGATIVE_S        = parseInt(process.env.CONSENT_CACHE_NEGATIVE_TTL_S || '10',  10);
const TOMBSTONE_TTL_S       = parseInt(process.env.CONSENT_CACHE_TOMBSTONE_TTL_S|| '10',  10);
const CONNECT_TIMEOUT_MS    = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS     || '5000', 10);
const MAX_RECONNECTS        = 5;

// Atomic compare-and-set: only overwrite the key if no cached entry with a
// STRICTLY NEWER `version` field already exists. Runs as a single Redis
// command server-side, so there is no client-observable window between the
// read of the current value and the conditional write — two concurrent
// callers racing to write the same key are serialized by Redis itself, not
// by client-side timing.
const _CAS_SCRIPT = `
local current = redis.call('GET', KEYS[1])
if current then
  local ok, decoded = pcall(cjson.decode, current)
  if ok and decoded.version ~= nil and tonumber(decoded.version) > tonumber(ARGV[2]) then
    return 0
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[3])
return 1
`;

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

    const parsed = JSON.parse(raw);
    // A tombstone is a marker left by invalidate(), not a verification
    // result — treat it exactly like a cache miss so the caller falls
    // through to the DB, which is the whole point of writing it.
    if (parsed && parsed.tombstone) return null;
    return parsed;
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
 * @param {number|null} [version] — consent_records.version at the moment
 *   `result` was computed. When provided, the write is rejected (silently —
 *   a skipped cache write is always safe, just a guaranteed-correct miss on
 *   the next read) if a strictly newer version is already cached, closing
 *   the read-DB / concurrent-revoke race. When omitted (e.g. no record
 *   exists — CONSENT_NOT_FOUND), the write is unconditional, matching the
 *   pre-CONSENT-3 behavior; that path only ever caches a DENY, which is
 *   fail-safe even if briefly stale.
 */
async function set(actor_id, action, tenant_id, result, version = null) {
  try {
    const client = await _getClient();
    if (!client) return;

    const key     = _cacheKey(actor_id, action, tenant_id);
    const ttl     = result.pass ? TTL_POSITIVE_S : TTL_NEGATIVE_S;
    const payload = JSON.stringify({ ...result, cached: true, cachedAt: Date.now(), version });

    if (typeof version === 'number' && Number.isFinite(version)) {
      await client.eval(_CAS_SCRIPT, { keys: [key], arguments: [payload, String(version), String(ttl)] });
    } else {
      await client.set(key, payload, { EX: ttl });
    }
  } catch {
    // Cache write failures are non-fatal — verification already fell back to the DB.
  }
}

/**
 * Invalidate the cached entry for a specific consent key.
 * Call this after any mutation (create, revoke, suspend, resume).
 *
 * @param {string} actor_id
 * @param {string} action
 * @param {string|null} [tenant_id]
 * @param {number|null} [version] — consent_records.version AFTER the mutation
 *   that triggered this call (the row's new version, from `RETURNING *`).
 *   When provided, invalidation writes a short-lived version-stamped
 *   tombstone via the same CAS script instead of a bare DEL, so a verify()
 *   call already in flight (which read the DB under the OLD version) cannot
 *   overwrite it with a stale positive result once its own set() call lands
 * — see the module note above. When omitted, falls back to a
 *   plain DEL (unchanged legacy behavior).
 */
async function invalidate(actor_id, action, tenant_id = null, version = null) {
  try {
    const client = await _getClient();
    if (!client) return;

    const key = _cacheKey(actor_id, action, tenant_id);

    if (typeof version === 'number' && Number.isFinite(version)) {
      const payload = JSON.stringify({ tombstone: true, version, invalidatedAt: Date.now() });
      await client.eval(_CAS_SCRIPT, { keys: [key], arguments: [payload, String(version), String(TOMBSTONE_TTL_S)] });
    } else {
      await client.del(key);
    }
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
