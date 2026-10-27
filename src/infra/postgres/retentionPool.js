'use strict';

/**
 * QODIQA Dedicated Retention PostgreSQL Pool —
 *
 * ROOT CAUSE (see retention.js's former module header and migration
 * 027_platform_audit_events_retention_grants_fix.sql): the automated
 * retention cleanup cycle (stampRetentionDates()/expireEvents() in
 * retention.js) previously ran through the same qodiqa_app role every
 * request-serving code path uses — broader privileges than an unattended
 * background job deleting audit rows actually needs. This module gives that
 * cycle its own connection pool, authenticated as the dedicated
 * `qodiqa_retention` role created by migration
 * 038_retention_dedicated_role.sql, which holds only SELECT on
 * audit_retention_policies, SELECT/INSERT on audit_retention_runs, and
 * SELECT/UPDATE/DELETE on platform_audit_events — nothing else.
 *
 * WHY A SEPARATE, SIMPLER POOL RATHER THAN A SECOND "MODE" ON pool.js:
 *   pool.js's circuit breaker, acquire-failure metrics, and background
 *   readiness monitor all exist to protect the request-serving path from a
 *   degraded database — none of that applies here. A stalled or unreachable
 *   retention connection only delays a scheduled background job (the next
 *   run tries again); it can never fail a live HTTP request, so carrying
 *   that request-path resilience machinery onto this pool would be
 *   complexity with no corresponding benefit. This module is intentionally
 *   the minimum needed: initialize/query/isEnabled/shutdown.
 *
 * Same physical database as the main application pool — only the login role
 * differs — so connection target settings (host/port/database/SSL/statement
 * timeout) are read from the exact same QODIQA_PG_* environment variables
 * pool.js uses. Only QODIQA_PG_RETENTION_USER/QODIQA_PG_RETENTION_PASSWORD
 * are distinct, defaulting to the qodiqa_retention role migration 038 creates.
 *
 * Environment variables:
 *   QODIQA_PG_RETENTION_USER      — Username (default 'qodiqa_retention')
 *   QODIQA_PG_RETENTION_PASSWORD  — Password (from secret manager in production)
 *   QODIQA_PG_RETENTION_POOL_MAX  — Max connections (default 2 — low, scheduled-job-only volume)
 *   (host/port/database/SSL/statement_timeout: shared with pool.js's QODIQA_PG_* variables)
 */

const { Pool }  = require('pg');
const { emit }  = require('../../../services/logger');
const { resolvePgSslOptions } = require('./pgSsl');
const { guardPool } = require('./clientErrorGuard');

function _loadConfig() {
  // Shared resolution with pool.js / migrate.js.
  const ssl = resolvePgSslOptions(process.env);

  return Object.freeze({
    host:             process.env.QODIQA_PG_HOST     || 'localhost',
    port:             parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database:         process.env.QODIQA_PG_DATABASE  || 'qodiqa',
    user:             process.env.QODIQA_PG_RETENTION_USER     || 'qodiqa_retention',
    password:         process.env.QODIQA_PG_RETENTION_PASSWORD || undefined,
    ssl:              ssl || false,

    max:              parseInt(process.env.QODIQA_PG_RETENTION_POOL_MAX || '2', 10),
    idleTimeoutMillis: parseInt(process.env.QODIQA_PG_POOL_IDLE_MS || '30000', 10),
    connectionTimeoutMillis: 5000,

    statement_timeout: parseInt(process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS || '30000', 10),

    application_name: 'qodiqa-retention',
  });
}

const SLOW_QUERY_MS = parseInt(process.env.QODIQA_PG_SLOW_MS || '1000', 10);

let _pool    = null;
let _enabled = false;

/**
 * Initialize the dedicated retention pool. Safe to call multiple times —
 * only creates one pool. No-op unless QODIQA_PG_ENABLED='true' (same gate
 * as pool.js — there is nothing to retain against without PostgreSQL).
 */
function initialize() {
  if (_pool) return;
  if (process.env.QODIQA_PG_ENABLED !== 'true') return;

  _enabled = true;
  const config = _loadConfig();
  _pool = guardPool(new Pool(config), 'retention'); //

  _pool.on('error', (err) => {
    emit('ERROR', 'PG_RETENTION_POOL_ERROR', { error: err.message, code: err.code ?? null });
  });

  emit('INFO', 'PG_RETENTION_POOL_INITIALIZED', {
    host:     config.host,
    database: config.database,
    user:     config.user,
  });
}

/** Returns true if the retention pool is enabled and initialized. */
function isEnabled() { return _enabled && !!_pool; }

/**
 * Execute a parameterized query through the dedicated retention role.
 * No circuit breaker — see module header for why that's intentional here.
 *
 * @param {string} sql
 * @param {any[]} [params]
 * @param {string} [label]
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(sql, params = [], label = 'retention_query') {
  if (!_pool) throw new Error('Retention PG pool not initialized');

  const start = Date.now();
  try {
    const result = await _pool.query(sql, params);
    const ms = Date.now() - start;
    if (ms >= SLOW_QUERY_MS) {
      emit('WARN', 'PG_RETENTION_SLOW_QUERY', { label, ms, rows: result.rowCount });
    }
    return result;
  } catch (e) {
    emit('ERROR', 'PG_RETENTION_QUERY_ERROR', {
      label,
      ms:     Date.now() - start,
      error:  e.message,
      code:   e.code ?? null,
      detail: e.detail ?? null,
    });
    throw e;
  }
}

/** Shut down the retention pool. Safe to call multiple times. */
async function shutdown() {
  if (!_pool) return;
  emit('INFO', 'PG_RETENTION_POOL_SHUTDOWN', {});
  await _pool.end().catch(e => emit('ERROR', 'PG_RETENTION_POOL_SHUTDOWN_ERROR', { error: e.message }));
  _pool    = null;
  _enabled = false;
}

module.exports = {
  initialize,
  isEnabled,
  query,
  shutdown,
};
