'use strict';

/**
 * ConsentCache — Redis read-through cache for consent verification results.
 *
 * Strategy:
 *   - Positive (ACTIVE) results are cached for CONSENT_CACHE_TTL_S seconds (default 60).
 *   - Negative results (DENIED, NOT_FOUND, REVOKED, EXPIRED, SUSPENDED) are cached
 *     for CONSENT_CACHE_NEGATIVE_TTL_S seconds (default 10).
 * - an ALLOW's TTL is additionally capped to the record's own
 *     expires_at, and a SUSPENDED DENY's TTL to its suspended_until — see
 *     _effectiveTtl() below. Without this, a cache entry written shortly
 *     before either boundary would keep serving its now-stale result for the
 *     rest of the configured TTL window, since the cache-hit fast path in
 *     ConsentVerifier.verify() never re-reaches effectiveState() on a hit.
 *   - Cache invalidation is explicit: call invalidate(actor_id, action, tenant_id)
 *     after any state-mutating operation (revoke, suspend, resume, create).
 *   - If Redis is unavailable the cache is transparently bypassed — the caller
 *     falls through to the database. There is NO fail-open path on verification:
 *     the ConsentVerifier treats cache misses as "check the DB" not as "allow".
 *
 * Key format: qodiqa:consent:<actor_id>:<action>:<tenant_id|"*">
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
 *
 * ── master-only reads (closes the replica-lag manifestation) ────────
 * The CAS/tombstone guard above closes the race entirely on the WRITE path —
 * a stale set() from an in-flight read can never resurrect an ALLOW once a
 * newer tombstone exists. It adds no protection on the READ path. In Sentinel
 * mode with REDIS_SENTINEL_USE_REPLICAS=true, plain GET is a Redis-classified
 * read-only command and node-redis transparently routes it to a replica
 * (round-robin) — see managedClient.js. Master→replica replication is
 * asynchronous and unbounded: revoke()/suspend() write their CAS-guarded
 * tombstone via EVAL, which — like every write command — always executes
 * against master, so the tombstone can be fully committed and acknowledged
 * on master while a replica still serves the pre-revocation ALLOW it cached
 * moments earlier, with a full, unexpired TTL_POSITIVE_S window. No amount of
 * write-side CAS logic closes this, because the stale read never goes
 * through the CAS script at all — it's a plain GET returning whatever that
 * replica currently holds. `forceMasterReads: true` below makes every
 * command on this client — GET included — target master unconditionally, so
 * a verify() lookup is always read-after-write consistent with the revoke()
 * that just completed, regardless of replication timing.
 */

const { isAuthError, isTlsError } = require('../../infra/redis/clientConfig');
const { createManagedRedisClient } = require('../../infra/redis/managedClient');
const { emit } = require('../../../services/logger');
// every entry is MAC-signed with the shared keystore MAC keyring.
const macKeyring = require('../security/macKeyring');
const { createEventSampler } = require('../../observability/eventSampler');
const _integritySampler = createEventSampler({ summaryEvent: 'CONSENT_CACHE_INTEGRITY_FAILURES_SUPPRESSED' });

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

// actor_id and action may legally contain ':' (ACTOR_RE / ACTION_RE), so (actor 'a:b', action 'c')
// and (actor 'a', action 'b:c') produced the same key and a cached ALLOW could answer the other pair. Each component is now
// escaped (':' and '%' plus the Redis glob metacharacters, which also stops an actor id with '*' from over-matching in
// invalidateActor's SCAN pattern). Ordinary ids are unchanged, so existing keys and the key format documented above still hold.
function _esc(v) {
  return String(v).replace(/[%:*?[\]\\]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));
}

function _cacheKey(actor_id, action, tenant_id) {
  const tenant = tenant_id == null ? '*' : _esc(tenant_id); // null tenant keeps the '*' sentinel; a real tenant id '*' is escaped
  return `${KEY_PREFIX}${_esc(actor_id)}:${_esc(action)}:${tenant}`;
}

// ── signed entries ────────────────────────────────────────────────
// Stored value: { version, p, m } — p is the entry's JSON, m = MAC over
// "<redis key>\n<p>" (so an entry can be neither edited nor moved to another
// actor/action/tenant key). The top-level version stays readable by the CAS
// Lua script above. Anything unsigned, tampered, from an unknown key, expired
// (cacheExpiresAt, signed) or whose version disagrees with the signed one is a
// MISS: the verifier then re-checks PostgreSQL. A Redis writer can therefore
// only force misses (a cache DoS), never a consent decision.
function _seal(key, body) {
  const p = JSON.stringify(body);
  return JSON.stringify({ version: body.version ?? null, p, m: macKeyring.sign(macKeyring.PURPOSES.CONSENT_CACHE, `${key}\n${p}`) });
}

function _integrityFailure(reason, key) {
  try { require('../../observability/metrics').consentCacheIntegrityFailuresTotal.inc({ reason }); } catch { /* metrics never throw */ }
  const s = _integritySampler.sample(reason);
  if (s.log) emit('WARN', 'CONSENT_CACHE_INTEGRITY_FAILURE', { reason, key, countThisMinute: s.countThisWindow });
}

/** @returns {object|null} the verified entry body, or null (miss). */
function _open(key, raw) {
  let outer;
  try { outer = JSON.parse(raw); } catch { _integrityFailure('MALFORMED', key); return null; }
  if (!outer || typeof outer.p !== 'string') { _integrityFailure('UNSIGNED', key); return null; }
  const v = macKeyring.verify(macKeyring.PURPOSES.CONSENT_CACHE, `${key}\n${outer.p}`, outer.m);
  if (!v.ok) { _integrityFailure(/** @type {any} */ (v).reason, key); return null; }
  let body;
  try { body = JSON.parse(outer.p); } catch { _integrityFailure('MALFORMED', key); return null; }
  if ((outer.version ?? null) !== (body.version ?? null)) { _integrityFailure('VERSION_MISMATCH', key); return null; }
  if (typeof body.cacheExpiresAt === 'number' && Date.now() > body.cacheExpiresAt) { _integrityFailure('EXPIRED', key); return null; }
  return body;
}

// ── TTL capped to the record's own time boundary ──────────────────
// The cache-hit fast path in ConsentVerifier.verify() returns a cached
// result WITHOUT ever re-reaching effectiveState() — that's the whole point
// of caching. Without this, a cache entry written just before expires_at (or
// suspended_until) keeps serving its now-stale ALLOW (or SUSPENDED DENY) for
// the rest of its TTL_POSITIVE_S/TTL_NEGATIVE_S window, regardless of that
// boundary having already passed. Clamping the write-time TTL to the
// boundary means the Redis key itself naturally expires no later than the
// moment the cached result stops being true — a genuine cache miss (not a
// stale hit) is what a verify() call sees from then on.
//
// Math.max(1, ...) is a floor, not a fudge factor: a boundary computed as
// already-passed-or-imminent (e.g. a few ms of clock drift between the
// effectiveState() check in ConsentVerifier and this write) would otherwise
// produce a zero/negative TTL, which Redis's `SET ... EX` rejects outright.
// Caching for one extra second in that edge case is the same bounded,
// millisecond-scale race window already inherent to reading `Date.now()`
// twice across two function calls elsewhere in this codebase — not a new
// class of staleness.
//
// Math.floor, not Math.ceil. Rounding the remaining time UP (the prior
// behavior) meant the Redis key's own TTL — and therefore the boundary this
// clamp exists to enforce — outlived expires_at/suspended_until by up to
// ~999ms on every write where the remainder wasn't already a whole number of
// seconds ( Case #11 phase D: witnessed
// 32-131ms overruns via direct Redis PTTL reads). Rounding DOWN instead means
// the key can only expire early, never late — an early expiry is just an
// ordinary cache miss, which re-reads the DB and is always correct; this
// function's entire purpose is to guarantee the key never outlives the
// boundary, not to maximize cache residency. The Math.max(1, ...) floor above
// still allows a small (<1s) overrun exactly at the sub-1-second edge it
// already documents — that residual is unrelated to and unchanged by this
// fix.
function _clampToBoundary(boundary, maxTtlS) {
  const boundaryMs = boundary instanceof Date ? boundary.getTime() : new Date(boundary).getTime();
  if (!Number.isFinite(boundaryMs)) return maxTtlS; // malformed boundary — fall back to the configured default
  const remainingS = Math.floor((boundaryMs - Date.now()) / 1000);
  return Math.max(1, Math.min(maxTtlS, remainingS));
}

function _effectiveTtl(result) {
  if (result.pass && result.expiresAt) {
    return _clampToBoundary(result.expiresAt, TTL_POSITIVE_S);
  }
  if (!result.pass && result.reason === 'CONSENT_SUSPENDED' && result.suspendedUntil) {
    return _clampToBoundary(result.suspendedUntil, TTL_NEGATIVE_S);
  }
  return result.pass ? TTL_POSITIVE_S : TTL_NEGATIVE_S;
}

function _buildClient() {
  const client = createManagedRedisClient({
    purpose:           'consentCache',
    connectTimeout:    CONNECT_TIMEOUT_MS,
    // this cache gates authorization decisions and must be
    // read-after-write consistent with its own CAS/tombstone writes — see
    // the module note above. Without this, a Sentinel deployment with
    // REDIS_SENTINEL_USE_REPLICAS=true can serve a stale cached ALLOW from a
    // lagging replica even after a revoke() has fully committed on master.
    forceMasterReads:  true,
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
async function get(actor_id, action, tenant_id = null, { requiredScope = null } = {}) {
  try {
    const client = await _getClient();
    if (!client) return null;

    const key = _cacheKey(actor_id, action, tenant_id);
    const raw = await client.get(key);
    if (!raw) return null;

    const body = _open(key, raw);
    if (!body || body.tombstone) return null;
    // (NF-1): an entry validated for a different required scope does not
    // answer this request — the verifier must re-run scope validation.
    if ((body.requiredScope ?? null) !== (requiredScope ?? null)) return null;
    const { cacheExpiresAt, requiredScope: _rs, ...result } = body; // eslint-disable-line no-unused-vars
    return result;
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
 * @param {number|null} [version] - consent_records.version at the moment
 *   `result` was computed. When provided, the write is rejected (silently —
 *   a skipped cache write is always safe, just a guaranteed-correct miss on
 *   the next read) if a strictly newer version is already cached, closing
 *   the read-DB / concurrent-revoke race. When omitted (e.g. no record
 *   exists — CONSENT_NOT_FOUND), the write is unconditional, matching the
 *   pre-CONSENT-3 behavior; that path only ever caches a DENY, which is
 *   fail-safe even if briefly stale.
 */
async function set(actor_id, action, tenant_id, result, version = null, { requiredScope = null } = {}) {
  try {
    const client = await _getClient();
    if (!client) return;

    const key     = _cacheKey(actor_id, action, tenant_id);
    const ttl     = _effectiveTtl(result);
    const now     = Date.now();
    // signed, bound to the key, carrying its own expiry and required scope.
    const payload = _seal(key, { ...result, cached: true, cachedAt: now, version, requiredScope: requiredScope ?? null, cacheExpiresAt: now + ttl * 1000 });

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
 * @param {number|null} [version] - consent_records.version AFTER the mutation
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
      const payload = _seal(key, { tombstone: true, version, invalidatedAt: Date.now() }); // signed tombstone
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

    const pattern = `${KEY_PREFIX}${_esc(actor_id)}:*`;
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

module.exports = { get, set, invalidate, invalidateActor, isReady, disconnect, _cacheKey, _seal, _open };
