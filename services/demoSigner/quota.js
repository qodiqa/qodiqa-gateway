'use strict';

/**
 * Demo signer quotas (launch plan R-02): per-client per-minute, per-client per-day
 * and a global per-minute budget, as fixed windows in Redis.
 *
 * One Lua script checks ALL three counters before incrementing ANY of them, so a
 * refused request consumes no budget. The client key is an HMAC of the client IP
 * (never the raw address). Any Redis error is FAIL-CLOSED: check() throws
 * QuotaUnavailableError and the caller must refuse the request (503). There is no
 * in-memory fallback, by design: a per-process fallback would multiply the global
 * budget by the number of processes.
 */

const crypto = require('crypto');

class QuotaUnavailableError extends Error {
  constructor(cause) {
    super('DEMO_QUOTA_UNAVAILABLE');
    this.name = 'QuotaUnavailableError';
    this.cause = cause;
  }
}

// KEYS[1..3] = ip-minute, ip-day, global-minute
// ARGV[1..3] = limits, ARGV[4..6] = ttl seconds
// Returns {1, 0} when admitted, {0, i} when counter i (1-based) is exhausted.
const QUOTA_LUA = `
for i = 1, 3 do
  local c = tonumber(redis.call('GET', KEYS[i]) or '0')
  if c >= tonumber(ARGV[i]) then return {0, i} end
end
for i = 1, 3 do
  local n = redis.call('INCR', KEYS[i])
  if n == 1 then redis.call('EXPIRE', KEYS[i], tonumber(ARGV[i + 3])) end
end
return {1, 0}
`;

const SCOPES = ['per_client_minute', 'per_client_day', 'global_minute'];

function hashClient(ip, secret) {
  return crypto.createHmac('sha256', secret).update(String(ip || 'unknown')).digest('hex').slice(0, 32);
}

/**
 * @param {{ sendCommand: (args: string[]) => Promise<any> }} redis  — a connected node-redis client (or test double)
 * @param {{ perIpPerMin: number, perIpPerDay: number, globalPerMin: number, prefix?: string, now?: () => number }} opts
 */
function createQuota(redis, { perIpPerMin, perIpPerDay, globalPerMin, prefix = 'qodiqa:demo:quota', now = Date.now }) {
  async function check(clientHash) {
    const t = now();
    const minute = Math.floor(t / 60000);
    const day = Math.floor(t / 86400000);
    const keys = [
      `${prefix}:ip:${clientHash}:m:${minute}`,
      `${prefix}:ip:${clientHash}:d:${day}`,
      `${prefix}:global:m:${minute}`,
    ];
    let res;
    try {
      res = await redis.sendCommand([
        'EVAL', QUOTA_LUA, '3', ...keys,
        String(perIpPerMin), String(perIpPerDay), String(globalPerMin),
        '120', '172800', '120',
      ]);
    } catch (err) {
      throw new QuotaUnavailableError(err);
    }
    if (!Array.isArray(res) || res.length !== 2) throw new QuotaUnavailableError(new Error('unexpected quota reply'));
    const admitted = Number(res[0]) === 1;
    if (admitted) return { allowed: true };
    const which = Number(res[1]);
    const scope = SCOPES[which - 1] || 'unknown';
    const windowEnd = scope === 'per_client_day' ? (day + 1) * 86400000 : (minute + 1) * 60000;
    return { allowed: false, scope, retryAfterSeconds: Math.max(1, Math.ceil((windowEnd - t) / 1000)) };
  }
  return { check };
}

module.exports = { createQuota, hashClient, QuotaUnavailableError, QUOTA_LUA };
