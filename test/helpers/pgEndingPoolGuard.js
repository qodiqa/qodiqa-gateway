'use strict';

/**
 * — the intermittent "Unhandled error. (error: terminating connection
 * due to administrator command)" (57P01) in serial component suites, REPRODUCED and root-caused:
 *
 *   pg-pool 3.14 `pool.end()` resolves as soon as every client has been dropped from its list — it calls
 *   `client.end()` without waiting for the socket to close, and the idle client's error listener (which re-emits on
 *   the POOL) stays attached. A suite's teardown `DROP DATABASE … WITH (FORCE)` issued right after `await pool.end()`
 *   can terminate a backend whose client is still closing; pg's Client emits that FATAL as 'error' even while ending
 *   (client.js _handleErrorMessage → _handleErrorEvent), the idle listener re-emits it on the pool, and a pool with no
 *   'error' listener throws from an EventEmitter. Measured: 11 of 300 end-then-drop cycles against a PostgreSQL 17
 * container, 0 of 100 against the local server.
 *
 * The guard: when `end()` is called on a pool that has NO 'error' listener, it gets one that absorbs (and counts)
 * errors from then on — an error raised by a pool that is already being torn down cannot affect any test result.
 * Pools that are live (end() not called) and pools that have their own listener (every product pool:
 * src/infra/postgres/pool.js, rolePools.js, retentionPool.js) are untouched, so an unguarded product pool still fails
 * loudly.
 */

const KEY = Symbol.for('qodiqa.test.endingPoolGuard');
const stats = { absorbed: 0, codes: {} };

function installEndingPoolGuard(pg) {
  const Pool = pg && pg.Pool;
  if (!Pool || !Pool.prototype || Pool.prototype[KEY]) return false;
  const originalEnd = Pool.prototype.end;
  Pool.prototype.end = function endWithTeardownGuard(...args) {
    if (this.listenerCount('error') === 0) {
      this.on('error', (err) => {
        stats.absorbed++;
        const code = (err && err.code) || 'unknown';
        stats.codes[code] = (stats.codes[code] || 0) + 1;
      });
    }
    return originalEnd.apply(this, args);
  };
  Object.defineProperty(Pool.prototype, KEY, { value: true });
  return true;
}

module.exports = { installEndingPoolGuard, stats };
