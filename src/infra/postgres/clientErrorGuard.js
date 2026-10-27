'use strict';

/**
 * — an abrupt PostgreSQL connection
 * loss must never crash the gateway.
 *
 * node-pg emits 'error' on a Client when its socket dies ("Connection terminated
 * unexpectedly"). pg-pool listens for that ONLY while a client is idle in the
 * pool; while a client is CHECKED OUT (inside withTransaction / withAdvisoryLock /
 * a role-pool query / a migration) nothing listens, so the event becomes an
 * uncaught exception and the process exits. The audit reproduced this under load
 * (1 of 2 runs): FATAL UNCAUGHT_EXCEPTION at pg/lib/client.js:199.
 *
 * The fix is one permanent 'error' listener on every PHYSICAL client, attached
 * when the pool creates it ('connect' event). It does not swallow the failure
 * where it matters:
 *   - the in-flight query on that client still REJECTS (fail-closed — the caller
 *     sees the error and, e.g., refuses with AUDIT_PERSISTENCE_FAILED);
 *   - pg-pool 3.x discards a client that is no longer queryable on release
 *     (index.js: `!client._queryable || client._ending` → remove), so the dead
 *     connection never returns to service;
 *   - the event is counted and logged (aggregated) so the outage is visible.
 */

const { emit } = require('../../../services/logger');

let _count = 0;
let _lastEmitAt = 0;
const EMIT_EVERY_MS = 5000; // a dying server can error every client at once — aggregate the log line

function onClientError(poolLabel, err) {
  _count++;
  const now = Date.now();
  if (now - _lastEmitAt >= EMIT_EVERY_MS) {
    _lastEmitAt = now;
    emit('ERROR', 'PG_CLIENT_CONNECTION_LOST', {
      pool: poolLabel, error: err && err.message, code: (err && err.code) || null, totalSinceBoot: _count,
      message: 'A PostgreSQL connection failed while in use; the affected query fails closed and the connection is discarded.',
    });
  }
}

/** Attach the guard to a pg Pool. Idempotent per pool. Returns the pool. */
function guardPool(pool, poolLabel) {
  // Test doubles without an event interface are passed through unchanged.
  if (!pool || typeof pool.on !== 'function' || pool.__qodiqaClientErrorGuard) return pool;
  Object.defineProperty(pool, '__qodiqaClientErrorGuard', { value: true });
  pool.on('connect', (client) => {
    client.on('error', (err) => onClientError(poolLabel, err));
  });
  return pool;
}

function clientErrorCount() { return _count; }
function _resetForTests() { _count = 0; _lastEmitAt = 0; }

module.exports = { guardPool, onClientError, clientErrorCount, _resetForTests };
