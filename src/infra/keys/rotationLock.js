'use strict';

/**
 * Distributed Key Rotation Lock — Redis-backed, cluster-safety primitive for
 * automatic signing-key rotation.
 *
 * Problem this solves (see docs/deployment/topology.md "Key store sharing"):
 *   Multiple QODIQA instances may share the same keys.json (single PVC / EFS
 *   mount). If two instances both decide "this client's key is due for
 *   rotation" at the same moment, running rotateKey() concurrently on both
 *   would race on the same file, and could produce two different key
 *   generations claiming to be version N+1. Historically this has been a
 *   documented OPERATIONAL requirement ("must be serialised; do not rotate
 *   concurrently") enforced by human discipline. This module makes it a
 *   structural guarantee instead.
 *
 * Design:
 *   • One Redis key per clientId: qodiqa:key-rotation-lock:<clientId>.
 *   • Acquire is a single atomic SET NX PX — identical idiom to the existing
 *     replay-protection nonce store (src/validation/nonceStore.js), so this
 *     reuses a pattern already relied upon elsewhere in the codebase rather
 *     than introducing a new one.
 *   • The lock value is a random per-holder token. Release is a compare-and-
 *     delete Lua script (EVAL), so an instance can never release a lock it
 *     does not hold (e.g. after its own TTL already expired and a different
 *     instance acquired it in the meantime).
 *   • No explicit release is required for correctness: if a holder crashes
 *     mid-rotation, the lock self-expires via PX and another instance's next
 *     scheduled tick simply retries. release() is best-effort cleanup that
 *     lets a healthy instance free the lock early rather than waiting out
 *     the full TTL.
 * • Fencing: acquire() also returns a
 *     per-client fencing token, and assertHeld()/renew() give an ownership
 *     re-check and a compare-and-extend heartbeat. The lease alone lets a
 *     holder that outlives its TTL commit after a second rotator was let in;
 *     the resource must refuse a non-increasing fence to close that.
 *   • Fail-closed: if Redis is unreachable, acquire() rejects. The caller
 *     (the rotation scheduler) treats this as "skip this tick" — a transient
 *     Redis outage delays rotation, it never causes a duplicate rotation.
 *
 * Required env (shared with the rest of QODIQA's Redis usage):
 *   REDIS_URL, REDIS_USERNAME, REDIS_PASSWORD, REDIS_TLS* — see
 *   src/infra/redis/clientConfig.js
 */

const {
  getConfigSummary,
} = require('../redis/clientConfig');
const { createManagedRedisClient } = require('../redis/managedClient');
const { emit } = require('../../../services/logger');

const KEY_PREFIX      = 'qodiqa:key-rotation-lock:';
// the per-client fencing-token counter lives at
// `{<lock key>}:fence` (see buildFenceKey). No TTL — it must outlive every lock
// it numbers.
const FENCE_SUFFIX    = ':fence';
const CONNECT_TIMEOUT = parseInt(process.env.REDIS_CONNECT_TIMEOUT_MS || '5000', 10);
const MAX_RECONNECTS  = 5;

// Compare-and-delete: only removes the key if its value still matches the
// token this instance set when it acquired the lock.
const _RELEASE_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`;

// a lease alone cannot stop a holder that outlives its TTL (process
// pause, slow filesystem/KMS) from committing after a second rotator was let in.
// Three additions close the lock side of that window:
//
// FENCE — issued only while the caller still owns the lock (GET == token checked
// in the same atomic script), so fences are strictly increasing in lock-ownership
// order across every process sharing this Redis. The resource (keys.json) must
// refuse a commit whose fence is not greater than the last one it accepted; that
// check is the only thing that makes a paused holder harmless (see assertHeld's
// comment for why a re-check alone is not enough). The counter is seeded from
// wall-clock milliseconds the first time it is created, so a Redis that lost the
// key (restart without persistence, failover to an empty replica) restarts the
// sequence ABOVE every fence previously handed out, instead of at 1 (which would
// make a fence-checking keystore refuse every rotation until the counter caught
// up). Residual: a backwards wall-clock jump on the Redis host coinciding with a
// key loss; the failure mode is a refused rotation, not a duplicate one.
const _FENCE_SCRIPT = `
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
  return false
end
if redis.call("EXISTS", KEYS[2]) == 0 then
  redis.call("SET", KEYS[2], ARGV[2])
end
return redis.call("INCR", KEYS[2])
`;

// ASSERT-HELD — ownership re-check: remaining lease in ms, or -3 if this token
// no longer holds the lock.
const _ASSERT_HELD_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PTTL", KEYS[1])
else
  return -3
end
`;

// RENEW — compare-and-extend (heartbeat): extends the lease only if this token
// still holds it, so a holder can never resurrect a lock someone else now owns.
const _RENEW_SCRIPT = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
else
  return 0
end
`;

function buildLockKey(clientId) {
  return `${KEY_PREFIX}${clientId}`;
}

// The fence script touches the lock key AND the fence key in one EVAL, which
// REDIS_MODE=cluster (src/infra/redis/haConfig.js) only allows when both keys
// hash to the same slot (else CROSSSLOT — the same constraint
// validateBoundRequest.js documents for the combined nonce script). Wrapping the
// whole lock key in a hash tag makes the fence key's slot = CRC16(lock key) =
// the lock key's own slot, as long as the lock key has no braces of its own
// (keyStore clientIds are /^[A-Za-z0-9_-]{1,64}$/). A clientId containing a
// brace could land on another slot in cluster mode; acquire() then fails closed
// (no rotation), never unfenced.
function buildFenceKey(clientId) {
  return `{${buildLockKey(clientId)}}${FENCE_SUFFIX}`;
}

// ── Lazy client singleton ─────────────────────────────────────────────────────

let _client        = null;
let _configSummary = null;
let _reconnectCount = 0;
// the in-flight initial connect, retained so acquire() can await it.
// _connectPromise() swallows its own rejection (emitting
// KEY_ROTATION_LOCK_REDIS_CONNECT_FAILED), so awaiting this never throws —
// after a failed connect the client simply stays !isReady and the
// fail-closed check below still refuses.
let _connectP      = null;

function _reconnectStrategy(retries) {
  if (retries >= MAX_RECONNECTS) {
    emit('ERROR', 'KEY_ROTATION_LOCK_REDIS_RECONNECT_FAILED', { retries, maxRetries: MAX_RECONNECTS });
    return false;
  }
  _reconnectCount++;
  return Math.min(100 * Math.pow(2, retries), 2_000);
}

function _getClient() {
  if (_client) return _client;

  _configSummary = getConfigSummary();
  _client = createManagedRedisClient({
    purpose:           'keyRotationLock',
    reconnectStrategy: _reconnectStrategy,
    connectTimeout:    CONNECT_TIMEOUT,
  });

  _client.on('error', err => {
    emit('ERROR', 'KEY_ROTATION_LOCK_REDIS_ERROR', { error: err.message });
  });

  _connectP = _connectPromise();

  return _client;
}

function _connectPromise() {
  return _client.connect().catch(err => {
    emit('ERROR', 'KEY_ROTATION_LOCK_REDIS_CONNECT_FAILED', { error: err.message });
  });
}

function _randomToken() {
  return require('crypto').randomBytes(16).toString('hex');
}

/**
 * Acquire the rotation lock for a given clientId.
 *
 * @param {string} clientId
 * @param {number} ttlMs  Lock lifetime — must comfortably exceed the worst-case
 *                        rotation duration (local key generation is near-
 *                        instant; a native signing provider round-trip over
 *                        the network is the dominant cost). Default 30s.
 * @returns {Promise<{ acquired: true, token: string, fence: number } | { acquired: false }>}
 * `fence` is a fencing token, strictly increasing per
 *          clientId in lock-ownership order across every process sharing this
 *          Redis. A resource commit must carry it and be refused when it is not
 *          greater than the last fence the resource accepted.
 * @throws  If Redis is unreachable — the caller must treat this as "skip this
 *          tick", not as permission to proceed unlocked.
 */
async function acquire(clientId, ttlMs = 30_000) {
  if (typeof clientId !== 'string' || !clientId) {
    throw new TypeError('rotationLock.acquire: clientId is required');
  }
  const client = _getClient();
  // the client is created lazily and connect() was previously fired
  // without ever being awaited, so the FIRST acquire() in a process's
  // lifetime always saw isReady=false and failed closed deterministically —
  // even with Redis fully reachable (every key-admin rotation 503'd once,
  // then succeeded on retry). Await the in-flight initial connect (bounded
  // by the client's own CONNECT_TIMEOUT; the promise never rejects — see
  // _connectP's comment) before the fail-closed check. Genuine
  // unreachability still refuses exactly as before: a failed or timed-out
  // connect leaves isReady=false.
  if (!client.isReady && _connectP) {
    await _connectP;
  }
  if (!client.isReady) {
    throw new Error('KEY_ROTATION_LOCK: Redis not connected — refusing to acquire (fail-closed)');
  }

  const token  = _randomToken();
  const result = await client.set(buildLockKey(clientId), token, { NX: true, PX: ttlMs });

  if (result === null) {
    return { acquired: false };
  }

  // number this ownership period. Conditional on still owning the
  // lock, so a caller that stalled past its TTL between the SET and here gets
  // no fence (and no lock) rather than a fence newer than its successor's.
  let fence;
  try {
    fence = await client.eval(_FENCE_SCRIPT, {
      keys:      [buildLockKey(clientId), buildFenceKey(clientId)],
      arguments: [token, String(Date.now())],
    });
  } catch (err) {
    // Fail closed: a lock without a fence must not be used. Free it (best
    // effort) so the next tick is not blocked for a full TTL.
    await release(clientId, token);
    throw new Error(`KEY_ROTATION_LOCK: fencing token could not be issued — refusing to acquire (fail-closed): ${err.message}`);
  }
  if (fence === null || fence === undefined) {
    emit('WARN', 'KEY_ROTATION_LOCK_LOST_BEFORE_FENCE', { clientId });
    return { acquired: false };
  }
  return { acquired: true, token, fence: Number(fence) };
}

/**
 * ownership re-check, to be called immediately before a commit.
 *
 * Throws (code KEY_ROTATION_LOCK_LOST) unless `token` still holds the lock with
 * at least `minRemainingMs` of lease left. This narrows the stale-holder window
 * to the gap between this call and the commit itself, but cannot close it: a
 * process paused in that gap still commits late. Only the resource checking the
 * fence closes it, so callers must do both.
 *
 * @param {string} clientId
 * @param {string} token
 * @param {{ minRemainingMs?: number }} [opts]
 * @returns {Promise<number>} the remaining lease in ms
 */
async function assertHeld(clientId, token, { minRemainingMs = 0 } = {}) {
  const client = _getClient();
  if (!client.isReady) {
    /** @type {any} */ const e = new Error('KEY_ROTATION_LOCK: Redis not connected — cannot confirm ownership (fail-closed)');
    e.code = 'KEY_ROTATION_LOCK_LOST';
    throw e;
  }
  const remaining = Number(await client.eval(_ASSERT_HELD_SCRIPT, {
    keys:      [buildLockKey(clientId)],
    arguments: [String(token)],
  }));
  if (remaining === -3 || remaining === -2 || remaining < minRemainingMs) {
    /** @type {any} */ const e = new Error(`KEY_ROTATION_LOCK_LOST: lock for ${clientId} is no longer held by this token (remaining=${remaining}ms, required=${minRemainingMs}ms)`);
    e.code = 'KEY_ROTATION_LOCK_LOST';
    emit('WARN', 'KEY_ROTATION_LOCK_LOST', { clientId, remaining, minRemainingMs });
    throw e;
  }
  return remaining;
}

/**
 * extend the lease of a lock this token still holds (heartbeat for
 * a slow-but-alive rotation, e.g. a slow KMS round-trip). Never extends a lock
 * held by another token. A paused process cannot heartbeat, which is why the
 * fence, not renewal, is the safety mechanism.
 *
 * @returns {Promise<boolean>} true if the lease was extended
 */
async function renew(clientId, token, ttlMs = 30_000) {
  if (typeof clientId !== 'string' || !clientId || !token) return false;
  const client = _getClient();
  if (!client.isReady) return false;
  try {
    const r = await client.eval(_RENEW_SCRIPT, {
      keys:      [buildLockKey(clientId)],
      arguments: [String(token), String(ttlMs)],
    });
    return Number(r) === 1;
  } catch (err) {
    emit('WARN', 'KEY_ROTATION_LOCK_RENEW_FAILED', { clientId, error: err.message });
    return false;
  }
}

/**
 * Release a previously acquired lock. No-op (returns false) if the lock has
 * already expired or is held by a different token (e.g. another instance
 * acquired it after this instance's TTL lapsed).
 *
 * @param {string} clientId
 * @param {string} token  The token returned by acquire().
 * @returns {Promise<boolean>} true if this call actually removed the lock.
 */
async function release(clientId, token) {
  if (typeof clientId !== 'string' || !clientId || !token) return false;
  const client = _getClient();
  if (!client.isReady) return false;

  try {
    const removed = await client.eval(_RELEASE_SCRIPT, {
      keys:      [buildLockKey(clientId)],
      arguments: [token],
    });
    return removed === 1;
  } catch (err) {
    emit('WARN', 'KEY_ROTATION_LOCK_RELEASE_FAILED', { clientId, error: err.message });
    return false;
  }
}

/**
 * @returns {boolean} Whether the underlying Redis client is currently ready.
 */
function isReady() {
  return _client ? _client.isReady : false;
}

/**
 * Disconnect and destroy the Redis client. Used by graceful shutdown and by
 * tests that need a clean exit.
 */
async function disconnect() {
  if (_client) {
    const c = _client;
    _client = null;
    _configSummary = null;
    _reconnectCount = 0;
    _connectP = null;
    try { await c.disconnect(); } catch { /* already closed */ }
  }
}

module.exports = {
  acquire,
  release,
  assertHeld,
  renew,
  isReady,
  disconnect,
  buildLockKey,
  buildFenceKey,
};
