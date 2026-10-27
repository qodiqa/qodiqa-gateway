'use strict';

/**
 * Dedicated PostgreSQL pools for the two sanctioned cross-tenant readers —
 *.
 *
 *   system     qodiqa_system     platform integrity + background + boot hydration
 *                                (audit-chain tail/verifier/hydrate, transparency
 *                                root scheduler + gap scanner, tenant-config
 *                                hydration, emergency sweep, GDPR erase function)
 *   reporting  qodiqa_reporting  RBAC-gated operator consoles (/audit-store,
 *                                /alerts, /compliance, /evidence-chain,
 *                                /audit-viewer, /evidence, transparency admin)
 *
 * The request-serving app pool (pool.js, qodiqa_app) can no longer EXECUTE any
 * cross-tenant SECURITY DEFINER function (migration 061); code that needs one
 * must go through the matching pool here. Neither role has BYPASSRLS or any
 * table grant — they can only call the functions granted to them.
 *
 * Credentials: QODIQA_PG_SYSTEM_USER / _PASSWORD (default user qodiqa_system),
 * QODIQA_PG_REPORTING_USER / _PASSWORD (default user qodiqa_reporting); host,
 * port, database and TLS are shared with pool.js. Fail-closed: when PostgreSQL
 * is enabled but a role's password is not provided, query() throws
 * PG_ROLE_POOL_NOT_CONFIGURED — there is deliberately no fallback to the app
 * pool (that would silently restore the cross-tenant grant this removed).
 * Production boot refuses a missing password (bootValidator rule secret.pg_passwords).
 *
 * Pools are created lazily on first use and closed by pool.js#shutdown().
 */

const { Pool } = require('pg');
const { emit } = require('../../../services/logger');
const { resolvePgSslOptions } = require('./pgSsl');
const { guardPool } = require('./clientErrorGuard');
const pgCircuitBreaker = require('./pgCircuitBreaker');

const SLOW_QUERY_MS = parseInt(process.env.QODIQA_PG_SLOW_MS || '1000', 10);

const ROLES = Object.freeze({
  system:    { envPrefix: 'QODIQA_PG_SYSTEM',    defaultUser: 'qodiqa_system',    appName: 'qodiqa-system',    defaultMax: 4 },
  reporting: { envPrefix: 'QODIQA_PG_REPORTING', defaultUser: 'qodiqa_reporting', appName: 'qodiqa-reporting', defaultMax: 4 },
  // the control-plane store (control_plane_records only).
  control:   { envPrefix: 'QODIQA_PG_CONTROL',   defaultUser: 'qodiqa_control',   appName: 'qodiqa-control',   defaultMax: 4 },
});

function _notConfigured(name, reason) {
  /** @type {any} */ const e = new Error(`PostgreSQL ${name} pool is not configured (${reason})`);
  e.code = 'PG_ROLE_POOL_NOT_CONFIGURED';
  return e;
}

function createRolePool(name) {
  const spec = ROLES[name];
  if (!spec) throw new TypeError(`unknown role pool: ${name}`);
  let _pool = null;
  // one circuit breaker per role pool (was: none) — a degraded database fast-fails with PG_CIRCUIT_OPEN instead of
  // making every call wait out connectionTimeoutMillis.
  const breaker = pgCircuitBreaker.createBreaker();

  function config() {
    const user = process.env[`${spec.envPrefix}_USER`] || spec.defaultUser;
    const password = process.env[`${spec.envPrefix}_PASSWORD`] || undefined;
    // (NF-15): target EXACTLY the database the app pool (pool.js) targets.
    // pool.js prefers QODIQA_PG_URL as a connectionString; a role pool that
    // only read QODIQA_PG_DATABASE (default 'qodiqa') could connect to a
    // DIFFERENT database than the app pool whenever the URL was the only
    // target configured (it did, once, in a DR test — refused by the target's
    // grants). Same URL, role credentials swapped, every other parameter kept.
    let target;
    if (process.env.QODIQA_PG_URL) {
      const u = new URL(process.env.QODIQA_PG_URL);
      u.username = encodeURIComponent(user);
      u.password = password ? encodeURIComponent(password) : '';
      target = { connectionString: u.toString() };
    } else {
      target = {
        host:     process.env.QODIQA_PG_HOST || 'localhost',
        port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
        database: process.env.QODIQA_PG_DATABASE || 'qodiqa',
      };
    }
    return {
      ...target,
      user,
      password,
      ssl:      resolvePgSslOptions(process.env) || false,
      max:      parseInt(process.env[`${spec.envPrefix}_POOL_MAX`] || String(spec.defaultMax), 10),
      idleTimeoutMillis: parseInt(process.env.QODIQA_PG_POOL_IDLE_MS || '30000', 10),
      connectionTimeoutMillis: 5000,
      statement_timeout: parseInt(process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS || '30000', 10),
      application_name: spec.appName,
    };
  }

  function _ensure() {
    if (_pool) return _pool;
    if (process.env.QODIQA_PG_ENABLED !== 'true') throw _notConfigured(name, 'QODIQA_PG_ENABLED is not true');
    const cfg = /** @type {any} */ (config());
    if (!cfg.password) throw _notConfigured(name, `${spec.envPrefix}_PASSWORD is not set`);
    _pool = guardPool(new Pool(cfg), name); //
    _pool.on('error', (err) => emit('ERROR', 'PG_ROLE_POOL_ERROR', { pool: name, error: err.message, code: err.code ?? null }));
    // Never log cfg.connectionString — it carries the role password.
    const where = cfg.connectionString ? new URL(cfg.connectionString) : null;
    emit('INFO', 'PG_ROLE_POOL_INITIALIZED', { pool: name, host: where ? where.hostname : cfg.host,
      database: where ? decodeURIComponent(where.pathname.slice(1)) : cfg.database, user: cfg.user });
    return _pool;
  }

  function isConfigured() {
    return process.env.QODIQA_PG_ENABLED === 'true' && !!process.env[`${spec.envPrefix}_PASSWORD`];
  }

  async function query(sql, params = [], label = `${name}_query`) {
    const pool = _ensure();
    const start = Date.now();
    try {
      const result = await pgCircuitBreaker.runGated(breaker, () => pool.query(sql, params));
      const ms = Date.now() - start;
      if (ms >= SLOW_QUERY_MS) emit('WARN', 'PG_ROLE_POOL_SLOW_QUERY', { pool: name, label, ms, rows: result.rowCount });
      return result;
    } catch (e) {
      emit('ERROR', 'PG_ROLE_POOL_QUERY_ERROR', { pool: name, label, ms: Date.now() - start, error: e.message, code: e.code ?? null });
      throw e;
    }
  }

  // (step 9): one REPEATABLE READ READ ONLY transaction on a dedicated connection, so a caller can page
  // through a large result (e.g. with a cursor) and still see exactly ONE snapshot — what a single query would
  // have seen — without materializing every row in this process at once. fn receives { query(sql, params) }.
  async function withReadOnlySnapshot(fn, label = `${name}_snapshot`) {
    const pool = _ensure();
    const start = Date.now();
    if (!breaker.allowRequest()) throw pgCircuitBreaker.circuitOpenError();
    let client;
    try { client = await pool.connect(); } catch (e) { breaker.onError(e); throw e; }
    try {
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const out = await fn({ query: (sql, params = []) => client.query(sql, params) });
      await client.query('COMMIT');
      breaker.onSuccess();
      const ms = Date.now() - start;
      if (ms >= SLOW_QUERY_MS) emit('WARN', 'PG_ROLE_POOL_SLOW_QUERY', { pool: name, label, ms, rows: null });
      return out;
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch { /* the connection may already be gone */ }
      if (e && e.expectedRefusal) breaker.onSuccess(); else breaker.onError(e);
      emit('ERROR', 'PG_ROLE_POOL_QUERY_ERROR', { pool: name, label, ms: Date.now() - start, error: e.message, code: e.code ?? null });
      throw e;
    } finally {
      client.release();
    }
  }

  // one READ COMMITTED read-write transaction on a dedicated connection, for a write whose precondition
  // spans rows (e.g. "another enabled admin exists") and must be re-checked under a lock, not on a replica snapshot.
  // fn receives { query(sql, params) }; any throw rolls back.
  async function withTransaction(fn, label = `${name}_tx`) {
    const pool = _ensure();
    const start = Date.now();
    if (!breaker.allowRequest()) throw pgCircuitBreaker.circuitOpenError();
    let client;
    try { client = await pool.connect(); } catch (e) { breaker.onError(e); throw e; }
    try {
      await client.query('BEGIN');
      const out = await fn({ query: (sql, params = []) => client.query(sql, params) });
      await client.query('COMMIT');
      breaker.onSuccess();
      const ms = Date.now() - start;
      if (ms >= SLOW_QUERY_MS) emit('WARN', 'PG_ROLE_POOL_SLOW_QUERY', { pool: name, label, ms, rows: null });
      return out;
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch { /* the connection may already be gone */ }
      if (e && e.expectedRefusal) breaker.onSuccess(); else breaker.onError(e);
      if (!e || !e.expectedRefusal) emit('ERROR', 'PG_ROLE_POOL_QUERY_ERROR', { pool: name, label, ms: Date.now() - start, error: e.message, code: e.code ?? null });
      throw e;
    } finally {
      client.release();
    }
  }

  async function shutdown() {
    if (!_pool) return;
    const p = _pool; _pool = null;
    await p.end().catch((e) => emit('ERROR', 'PG_ROLE_POOL_SHUTDOWN_ERROR', { pool: name, error: e.message }));
  }

  return Object.freeze({ name, breaker, query, withReadOnlySnapshot, withTransaction, isConfigured, shutdown, _config: config });
}

const system = createRolePool('system');
const reporting = createRolePool('reporting');
const control = createRolePool('control');

async function shutdownAll() { await Promise.all([system.shutdown(), reporting.shutdown(), control.shutdown()]); }

module.exports = { system, reporting, control, shutdownAll, ROLES };
