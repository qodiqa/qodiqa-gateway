'use strict';

/**
 * Sliding Window Counter —
 *
 * Algorithm: Sliding Window Counter (hybrid two-bucket approach)
 *
 * Choice rationale:
 *   - Sliding Window Log rejected: O(N) memory per identity, O(log N) Redis ops (sorted sets).
 *   - Token Bucket rejected: fractional token storage across distributed Redis nodes is error-prone.
 *   - Fixed Window rejected: 2× burst at window boundary is unacceptable for production.
 *   - Sliding Window Counter chosen: O(1) Redis ops (2 integer keys per identity),
 *     smooth distribution, no boundary burst, deterministic behavior, cluster-safe.
 *
 * How it works:
 *   Two integer counters per identity+dimension:
 *     curr — count in the current time window (bucket)
 *     prev — count in the previous time window (bucket)
 *   Effective rate = prev × (1 − elapsed_fraction) + curr
 *   where elapsed_fraction = (now_s mod window_s) / window_s
 *   Request allowed when effective_rate ≤ maxRequests.
 *
 * Burst protection:
 *   An additional short-window counter (burstWindowSeconds, default 5s) caps
 *   immediate bursts independently of the sustained rate. Both must allow the
 *   request. Setting burstCapacity=0 disables burst checking entirely.
 *
 * Atomicity:
 *   All reads and writes for one decision execute inside a single Lua script,
 *   ensuring atomicity under concurrent distributed access with no TOCTOU races.
 */

// ── Lua script ────────────────────────────────────────────────────────────────
//
// KEYS[1] = base key (e.g. rl:v2:surface:portal:ip:1.2.3.4)
// ARGV[1] = now_seconds        integer Unix time in seconds
// ARGV[2] = window_seconds     sustained window duration
// ARGV[3] = max_requests       sustained request limit
// ARGV[4] = burst_capacity     0 = disabled, else max requests in burst window
// ARGV[5] = burst_window_secs  burst window duration in seconds
//
// Returns an 8-element array (all integers):
//   [0] curr            — current window count after increment
//   [1] prev            — previous window count (read-only)
//   [2] sw_allowed      — 1 if sustained limit allows, 0 if exceeded
//   [3] burst_allowed   — 1 if burst allows (or burst disabled), 0 if exceeded
//   [4] reset_in        — seconds until sustained window resets (≥ 1)
//   [5] remaining       — floor(max_requests − effective_rate), clamped ≥ 0
//   [6] burst_count     — current burst window count (0 when burst disabled)
//   [7] burst_remaining — max(0, burst_capacity − burst_count)

const SW_LUA = `
local base_key  = KEYS[1]
local now       = tonumber(ARGV[1])
local window    = tonumber(ARGV[2])
local max_req   = tonumber(ARGV[3])
local burst_cap = tonumber(ARGV[4])
local burst_win = tonumber(ARGV[5])

local curr_bucket = math.floor(now / window)
local prev_bucket = curr_bucket - 1
local elapsed     = now % window
local prev_weight = 1.0 - (elapsed / window)

local curr_key = base_key .. ':c:' .. curr_bucket
local prev_key = base_key .. ':c:' .. prev_bucket

local curr = tonumber(redis.call('INCR', curr_key))
if curr == 1 then
  redis.call('EXPIRE', curr_key, window * 2)
end

local prev_raw = redis.call('GET', prev_key)
local prev = prev_raw and tonumber(prev_raw) or 0

local prev_contrib_x1000 = math.floor(prev * prev_weight * 1000)
local weighted_x1000 = prev_contrib_x1000 + curr * 1000
local max_x1000 = max_req * 1000

local sw_allowed = weighted_x1000 <= max_x1000 and 1 or 0
local remaining  = math.max(0, math.floor(max_req - weighted_x1000 / 1000.0))
local reset_in   = math.max(1, window - elapsed)

local burst_allowed = 1
local burst_count   = 0
local burst_rem     = burst_cap

if burst_cap > 0 then
  local burst_bucket = math.floor(now / burst_win)
  local burst_key    = base_key .. ':b:' .. burst_bucket
  burst_count = tonumber(redis.call('INCR', burst_key))
  if burst_count == 1 then
    redis.call('EXPIRE', burst_key, burst_win * 2)
  end
  if burst_count > burst_cap then
    burst_allowed = 0
  end
  burst_rem = math.max(0, burst_cap - burst_count)
end

return {curr, prev, sw_allowed, burst_allowed, reset_in, remaining, burst_count, burst_rem}
`;

/**
 * @typedef {Object} SWResult
 * @property {boolean}     allowed
 * @property {boolean}     swAllowed
 * @property {boolean}     burstAllowed
 * @property {number}      count
 * @property {number}      prev
 * @property {number}      remaining
 * @property {number}      resetIn
 * @property {number}      burstCount
 * @property {number}      burstRemaining
 * @property {string|null} blockedBy   'SUSTAINED' | 'BURST' | null
 */

/**
 * Evaluate sliding window counter for one identity+dimension key.
 *
 * @param {(script: string, keys: string[], args: string[]) => Promise<any[]>} evalFn
 * @param {string} baseKey              Base Redis key (without bucket suffix)
 * @param {number} nowSeconds           Current Unix time in whole seconds
 * @param {number} windowSeconds        Sustained window duration
 * @param {number} maxRequests          Sustained limit
 * @param {number} [burstCapacity=0]    0 = disabled
 * @param {number} [burstWindowSeconds=5]
 * @returns {Promise<SWResult>}
 */
async function evaluate(
  evalFn, baseKey, nowSeconds, windowSeconds, maxRequests,
  burstCapacity = 0, burstWindowSeconds = 5,
) {
  const raw = await evalFn(SW_LUA, [baseKey], [
    String(nowSeconds),
    String(windowSeconds),
    String(maxRequests),
    String(burstCapacity),
    String(burstWindowSeconds),
  ]);

  const count          = Number(raw[0]);
  const prev           = Number(raw[1]);
  const swAllowed      = Number(raw[2]) === 1;
  const burstAllowed   = Number(raw[3]) === 1;
  const resetIn        = Number(raw[4]);
  const remaining      = Number(raw[5]);
  const burstCount     = Number(raw[6]);
  const burstRemaining = Number(raw[7]);

  const allowed   = swAllowed && burstAllowed;
  const blockedBy = allowed ? null : (!swAllowed ? 'SUSTAINED' : 'BURST');

  return { allowed, swAllowed, burstAllowed, count, prev, remaining, resetIn, burstCount, burstRemaining, blockedBy };
}

module.exports = { SW_LUA, evaluate };
