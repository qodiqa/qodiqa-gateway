'use strict';

/**
 * Auth-Failure Lockout Algorithm — AUTH-2, extended (credential-
 * identity scoped secondary counter).
 *
 * Per-source state: { count, lockedUntil } stored as a Redis HASH (or the
 * equivalent in-process shape for MemoryStorage) keyed by
 * `authlock:v1:{identity}`, where identity is either `ip:{address}` or
 * `cred:{truncatedSha256Hex}` — see index.js's `_credentialIdentity()`. The
 * two identity namespaces never collide (distinct prefixes under the same
 * `authlock:v1:` key space).
 *
 * Three atomic operations, each a single Lua script (single round trip,
 * serialized by Redis's single-threaded command execution — no distributed
 * lock needed). Every script accepts a PRIMARY key (KEYS[1], always the IP
 * identity) and an OPTIONAL SECONDARY key (KEYS[2], the credential identity
 * — omitted entirely from the `keys` array, not passed as an empty string,
 * when no credential was presented). Redis leaves `KEYS[2]` as Lua `nil`
 * when the caller's `keys` array has length 1, so a single EVAL — one round
 * trip — atomically evaluates both counters when a credential is present,
 * and behaves byte-for-byte like the original IP-only script when it is
 * not. No second script, no second round trip, no weakened atomicity:
 *
 *   PRECHECK_LUA  — read-only except for clearing an expired lock. Used
 *                   before evaluating any credential. Detects and clears an
 *                   expired lockout as a side effect (auto-recovery, no
 *                   manual intervention) and reports whether EITHER source
 *                   (IP or credential) is currently locked — the aggregate
 *                   decision is `ip.locked OR credential.locked`.
 *
 *   RECORD_FAILURE_LUA — increments the consecutive-failure counter for
 *                   the IP identity, and — when a credential identity is
 *                   also supplied — the credential identity too, in the
 *                   same EVAL. If either counter's failure crosses the
 *                   configured threshold AND that counter's lock is not
 *                   already active, that counter's lockedUntil = now +
 *                   duration is set independently. A lockout can therefore
 *                   be triggered by the IP counter, the credential counter,
 *                   or both — closing the residual gap where a distributed
 *                   attacker rotates source IPs while repeating the same
 *                   guessed credential: the credential counter accumulates
 *                   across all of those IPs and trips on its own schedule,
 *                   independent of how thin any single IP's slice of the
 *                   attack is.
 *                   The "no lock already active" guard is deliberate and
 *                   applies per-counter: once a lockout episode has begun
 *                   for a given identity, further failures against THAT
 *                   identity that arrive before its lock expires (concurrent
 *                   attackers, retries) must NOT push its lockedUntil
 *                   further out. Without that guard, an attacker who keeps
 *                   firing requests during an active lockout could keep the
 *                   source locked out indefinitely — a denial-of-service
 *                   lever against the legitimate operator that owns that
 *                   source. The duration is fixed at the moment the
 *                   threshold is crossed and cannot be extended by anything
 *                   that happens afterward.
 *
 *   RECORD_SUCCESS_LUA — clears the IP identity's state and, when a
 *                   credential identity is supplied, that identity's state
 *                   too, in the same EVAL. A credential that authenticates
 *                   successfully has no reason to keep either failure
 *                   streak alive.
 *
 * All mutating scripts EXPIRE each key touched to at least the longer of the
 * configured failure-remembering window and the lockout duration itself —
 * the key must outlive lockedUntil, or Redis could silently drop the whole
 * record (via TTL) before the lock timestamp it stores has actually passed,
 * which would let a locked-out source back in early. Both identities share
 * the same threshold/duration/window configuration (`QODIQA_OPS_AUTH_
 * LOCKOUT_*`) — reusing the existing knobs rather than introducing a
 * parallel set for the credential counter, per the requirement to avoid
 * unnecessary configuration complexity.
 */

// KEYS[1] = primary (IP) state key
// KEYS[2] = optional secondary (credential) state key — absent (Lua nil)
//           when no credential was presented; NOT an empty-string sentinel
// ARGV[1] = now (ms, integer)
// Returns: { count, lockedUntil, locked (0|1), expired (0|1),
//            credCount, credLockedUntil, credLocked (0|1), credExpired (0|1) }
// The cred* fields are zero and MUST be ignored by the caller when KEYS[2]
// was not supplied (storage.js only reads them when a second key was passed
// in) — this keeps the single-key call shape byte-for-byte identical to the
// pre-WP-012 return value.
const PRECHECK_LUA = `
local function check_key(key, now)
  local vals = redis.call('HMGET', key, 'count', 'lockedUntil')
  local count = tonumber(vals[1] or '0')
  local locked_until = tonumber(vals[2] or '0')

  local expired = 0
  if locked_until > 0 and locked_until <= now then
    redis.call('HSET', key, 'count', 0)
    redis.call('HDEL', key, 'lockedUntil')
    count = 0
    locked_until = 0
    expired = 1
  end

  local locked = 0
  if locked_until > now then
    locked = 1
  end

  return {count, locked_until, locked, expired}
end

local now = tonumber(ARGV[1])
local primary = check_key(KEYS[1], now)

local secondary = {0, 0, 0, 0}
if KEYS[2] and KEYS[2] ~= '' then
  secondary = check_key(KEYS[2], now)
end

return {primary[1], primary[2], primary[3], primary[4],
        secondary[1], secondary[2], secondary[3], secondary[4]}
`;

// KEYS[1] = primary (IP) state key
// KEYS[2] = optional secondary (credential) state key — absent (Lua nil)
//           when no credential was presented
// ARGV[1] = now (ms, integer)
// ARGV[2] = max_failures (shared threshold for both identities)
// ARGV[3] = lockout_duration_ms (shared)
// ARGV[4] = key_ttl_seconds (shared)
// Returns: { count, lockedUntil, triggered (0|1),
//            credCount, credLockedUntil, credTriggered (0|1) }
// The cred* fields are zero and MUST be ignored by the caller when KEYS[2]
// was not supplied — single-key call shape is unchanged from pre-WP-012.
const RECORD_FAILURE_LUA = `
local function record_one(key, now, max_failures, lockout_duration_ms, key_ttl_seconds)
  local vals = redis.call('HMGET', key, 'count', 'lockedUntil')
  local prior_locked_until = tonumber(vals[2] or '0')

  local count = tonumber(vals[1] or '0') + 1
  redis.call('HSET', key, 'count', count)

  local locked_until = prior_locked_until
  local triggered = 0
  if count >= max_failures and prior_locked_until <= now then
    locked_until = now + lockout_duration_ms
    redis.call('HSET', key, 'lockedUntil', locked_until)
    triggered = 1
  end

  redis.call('EXPIRE', key, key_ttl_seconds)

  return {count, locked_until, triggered}
end

local now = tonumber(ARGV[1])
local max_failures = tonumber(ARGV[2])
local lockout_duration_ms = tonumber(ARGV[3])
local key_ttl_seconds = tonumber(ARGV[4])

local primary = record_one(KEYS[1], now, max_failures, lockout_duration_ms, key_ttl_seconds)

local secondary = {0, 0, 0}
if KEYS[2] and KEYS[2] ~= '' then
  secondary = record_one(KEYS[2], now, max_failures, lockout_duration_ms, key_ttl_seconds)
end

return {primary[1], primary[2], primary[3], secondary[1], secondary[2], secondary[3]}
`;

/**
 * Deterministic exponential backoff, bounded by [0, maxDelayMs].
 * failureCount <= 0 → 0 (no prior failures, nothing to slow down).
 * failureCount N>=1 → min(maxDelayMs, minDelayMs * 2^(N-1)).
 *
 * @param {number} failureCount
 * @param {number} minDelayMs
 * @param {number} maxDelayMs
 * @returns {number} delay in ms, always finite and >= 0
 */
function computeBackoffDelayMs(failureCount, minDelayMs, maxDelayMs) {
  if (!(failureCount > 0)) return 0;
  const exponential = minDelayMs * Math.pow(2, failureCount - 1);
  return Math.min(maxDelayMs, Math.round(exponential));
}

// The key's blanket TTL must outlive lockedUntil by a real margin, not just
// be >= it. With default config failureWindowMs === lockoutDurationMs, so
// without a margin the whole record's TTL and the lock's own expiry
// timestamp land at (numerically) the exact same instant — whichever
// mechanism a reader happens to hit first "wins", making PRECHECK_LUA's
// explicit expired-lock detection (which drives the AUTH_LOCKOUT_EXPIRED
// log and the active-lockout gauge decrement — requirement 8) unreliable
// exactly at the boundary that matters most. The margin guarantees the
// explicit check always observes and reports the transition; the blanket
// TTL is purely a "this identity has been quiet for a long time, garbage
// collect it" backstop, never the primary expiry-detection path.
const _TTL_SAFETY_MARGIN_MS = 60_000;

/**
 * The state key must outlive the lock timestamp it may come to hold, or a
 * TTL-driven expiry could delete the whole record before lockedUntil (a
 * value stored inside it) has actually passed — see module header.
 *
 * @param {number} failureWindowMs
 * @param {number} lockoutDurationMs
 * @returns {number} TTL in whole seconds, >= 1
 */
function computeKeyTtlSeconds(failureWindowMs, lockoutDurationMs) {
  return Math.max(1, Math.ceil((Math.max(failureWindowMs, lockoutDurationMs) + _TTL_SAFETY_MARGIN_MS) / 1000));
}

// KEYS[1] = primary (IP) state key
// KEYS[2] = optional secondary (credential) state key — absent (Lua nil)
//           when no credential was presented
// Returns: { priorCount, credPriorCount } — the failure count each key held
// immediately before being cleared, so the caller can tell "reset after
// previous failures" (requirement 8) from "reset with nothing to reset" in
// a single atomic round trip instead of a separate read-then-delete.
// credPriorCount is 0 and MUST be ignored by the caller when KEYS[2] was
// not supplied — single-key call shape is unchanged from pre-WP-012.
const RECORD_SUCCESS_LUA = `
local function clear_one(key)
  local count = tonumber(redis.call('HGET', key, 'count') or '0')
  redis.call('DEL', key)
  return count
end

local primary = clear_one(KEYS[1])

local secondary = 0
if KEYS[2] and KEYS[2] ~= '' then
  secondary = clear_one(KEYS[2])
end

return {primary, secondary}
`;

module.exports = {
  PRECHECK_LUA,
  RECORD_FAILURE_LUA,
  RECORD_SUCCESS_LUA,
  computeBackoffDelayMs,
  computeKeyTtlSeconds,
};
