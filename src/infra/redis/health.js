'use strict';

/**
 * Redis connection health registry —.
 *
 * Every ManagedRedisClient (managedClient.js) registers itself here under its
 * `purpose` label at construction time. This module is the single place that
 * can answer "what is the health of every Redis-backed store right now?" —
 * used by the new GET /health/redis endpoint (src/api/routes/healthRedis.js)
 * and available for any future operational tooling.
 *
 * Deliberately NOT wired into the existing GET /ready endpoint — that
 * endpoint's response shape (and the exact set of components it reports) is
 * asserted on by src/api/routes/__tests__/ready.test.js with `toEqual`
 * (exact-match) checks that predate. Extending /ready's contract is a
 * behavior change those tests did not sign up for; must not break
 * existing tests, so the fuller multi-store view lives at its own new route
 * instead of overloading /ready.
 */

const _registry = new Map(); // purpose -> () => healthSnapshot

/**
 * @param {string} purpose
 * @param {() => object} getHealth
 */
function register(purpose, getHealth) {
  _registry.set(purpose, getHealth);
}

function unregister(purpose) {
  _registry.delete(purpose);
}

/**
 * @returns {Record<string, object>} purpose -> current health snapshot
 */
function getAllHealth() {
  const out = {};
  for (const [purpose, getHealth] of _registry) {
    try {
      out[purpose] = getHealth();
    } catch (err) {
      out[purpose] = { state: 'UNKNOWN', error: err.message };
    }
  }
  return out;
}

/**
 * Aggregate overall status across every registered store:
 *   - 'healthy'      every store is HEALTHY
 *   - 'recovering'   no store is DISCONNECTED, but at least one is RECOVERING
 *   - 'degraded'     at least one store is DEGRADED (and none DISCONNECTED)
 *   - 'disconnected' at least one store is DISCONNECTED
 *
 * @returns {'healthy'|'degraded'|'disconnected'|'recovering'}
 */
function getOverallStatus() {
  const all = getAllHealth();
  const states = Object.values(all).map(h => h.state);
  if (states.length === 0) return 'healthy';
  if (states.includes('DISCONNECTED')) return 'disconnected';
  if (states.includes('DEGRADED'))     return 'degraded';
  if (states.includes('RECOVERING'))   return 'recovering';
  return 'healthy';
}

module.exports = { register, unregister, getAllHealth, getOverallStatus };
