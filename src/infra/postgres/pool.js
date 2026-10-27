'use strict';

/**
 * QODIQA PostgreSQL Connection Pool
 *
 * Manages a pg.Pool with:
 *   - TLS enforcement configurable via env
 *   - Health monitoring with circuit-breaker semantics
 *   - Graceful shutdown integration
 *   - Query telemetry (slow query logging)
 *   - Structured error classification
 *
 * Environment variables:
 *   QODIQA_PG_URL           — Full connection URL (preferred in production)
 *   QODIQA_PG_HOST          — Hostname (fallback if URL not set)
 *   QODIQA_PG_PORT          — Port (default 5432)
 *   QODIQA_PG_DATABASE      — Database name (default 'qodiqa')
 *   QODIQA_PG_USER          — Username (default 'qodiqa_app'). Not shared with
 *                              the migration runner — src/infra/postgres/
 *                              migrate.js reads its own QODIQA_PG_MIG_USER /
 *                              QODIQA_PG_MIG_PASSWORD, so the schema-modifying
 *                              migration identity and this request-serving
 *                              identity stay independently configurable.
 *   QODIQA_PG_PASSWORD      — Password (from secret manager in production)
 *   QODIQA_PG_SSL           — 'true' to require TLS (default true in production)
 *   QODIQA_PG_SSL_CA        — Path to CA certificate file
 *   QODIQA_PG_SSL_CERT      — Path to client certificate file
 *   QODIQA_PG_SSL_KEY       — Path to client key file
 * QODIQA_PG_POOL_MAX — Max connections
 * QODIQA_PG_ACQUIRE_TIMEOUT_MS — connection acquire timeout
 *   QODIQA_PG_POOL_IDLE_MS  — Idle timeout ms (default 30000)
 *   QODIQA_PG_SLOW_MS       — Slow query threshold ms (default 1000)
 *   QODIQA_PG_STATEMENT_TIMEOUT_MS — Per-query timeout ms (default 30000)
 */

const { Pool }  = require('pg');
const { emit }  = require('../../../services/logger');
// (step 5): repeated error events are aggregated (first per 10 s window per key + one summary with the count).
const { aggregatedEmit: _aggregatedEmit } = require('../../observability/aggregatedEmit');
const { resolvePgSslOptions } = require('./pgSsl');
const { guardPool } = require('./clientErrorGuard');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');
const pgCircuitBreaker   = require('./pgCircuitBreaker');

// ── Configuration ─────────────────────────────────────────────────────────────

function _loadConfig() {
  // TLS required in production by default — shared resolution.
  const ssl = resolvePgSslOptions(process.env);

  const config = {
    // Connection
    connectionString: process.env.QODIQA_PG_URL || null,
    host:             process.env.QODIQA_PG_HOST     || 'localhost',
    port:             parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database:         process.env.QODIQA_PG_DATABASE  || 'qodiqa',
    user:             process.env.QODIQA_PG_USER       || 'qodiqa_app',
    password:         process.env.QODIQA_PG_PASSWORD   || undefined,
    ssl:              ssl || false,

    // Pool sizing
    // (step 5, D3): 16 = the /ai/chat admission in-flight limit (src/api/admission.js), so every admitted request
    // can hold a connection at its peak; measured demand at the ceiling is far below (~10 ms of PG per request,
    //). Was 10.
    max:              parseInt(process.env.QODIQA_PG_POOL_MAX    || '16',    10),
    idleTimeoutMillis: parseInt(process.env.QODIQA_PG_POOL_IDLE_MS || '30000', 10),
    // (step 5, D3): fail fast (was 5,000 ms) — under admission control a long acquire only converts a PG stall into
    // request latency; a failed evidence write goes to the durable recovery queue / journal instead.
    connectionTimeoutMillis: parseInt(process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS || '1500', 10),

    // Per-query statement timeout (guards against runaway queries)
    statement_timeout: parseInt(process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS || '30000', 10),

    // FINDING-PG-CONNECT-HANDLER-QUERY-COLLISION: timezone set as a libpq
    // startup parameter (server applies it during the connection handshake,
    // before the connection is usable) instead of a client.query() call from
    // the 'connect' event handler — see that handler below for why the query
    // form is a real concurrency defect, not just a style preference.
    options: '-c TimeZone=UTC',

    // Application name visible in pg_stat_activity
    application_name: 'qodiqa-app',
  };

  return Object.freeze(config);
}

// ── Thresholds ────────────────────────────────────────────────────────────────

const SLOW_QUERY_MS = parseInt(process.env.QODIQA_PG_SLOW_MS || '1000', 10);

// Readiness probe monitor — keeps isHealthy() fresh via a bounded background
// interval, decoupled from the request path. GET /ready must never issue a
// query per probe (see docs/deployment/kubernetes-probes.md — readiness is polled every
// few seconds); it reads the cached _healthy flag instead. See README-50.
const READY_CHECK_INTERVAL_MS = (() => {
  const v = parseInt(process.env.QODIQA_PG_READY_CHECK_INTERVAL_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 5_000;
})();
const READY_CHECK_TIMEOUT_MS = (() => {
  const v = parseInt(process.env.QODIQA_PG_READY_TIMEOUT_MS, 10);
  return Number.isFinite(v) && v > 0 ? v : 2_000;
})();

// ── Singleton pool ────────────────────────────────────────────────────────────

let _pool = null;
let _healthy = false;
let _enabled = false;
let _readyMonitorTimer   = null;
let _readyCheckInFlight  = false;
// count of failed connection ACQUISITIONS (pool.connect() rejecting —
// e.g. pool exhausted + connectionTimeoutMillis elapsed), distinct from
// query-execution failures already covered by PG_QUERY_ERROR. Local counter
// (read synchronously by poolStats()/diagnostics) mirrored into the
// Prometheus counter on every increment — see _recordAcquireFailure().
let _acquireFailures = 0;

function _buildPool() {
  const config = _loadConfig();
  const pool   = guardPool(new Pool(config), 'app'); // no uncaught error from a checked-out client

  pool.on('connect', (_client) => {
    // Timezone is now set via the 'options' startup parameter in
    // _loadConfig() above, not here. This handler used to fire an unawaited
    // client.query("SET TIME ZONE 'UTC'") — pg-pool hands this SAME new
    // client to the pending caller synchronously, right after this
    // synchronous 'connect' emit returns (_acquireClient() in
    // node_modules/pg-pool/index.js), so that caller's own client.query()
    // could fire while the SET TIME ZONE query was still in flight on the
    // same connection — a real, reproducible concurrency defect (see
    // FINDING-PG-CONNECT-HANDLER-QUERY-COLLISION-REPORT.md), not a
    // theoretical one. pg-pool does not await async 'connect' listeners, so
    // this could not have been fixed by awaiting in place.
    emit('INFO', 'PG_POOL_CONNECT', {
      host:     config.host,
      database: config.database,
      user:     config.user,
    });
  });

  pool.on('acquire', () => {
    // Connection checked out from pool
  });

  pool.on('error', (err) => {
    _healthy = false;
    emit('ERROR', 'PG_POOL_ERROR', {
      error:   err.message,
      code:    err.code ?? null,
    });
  });

  pool.on('remove', () => {
    // Connection destroyed (idle timeout or error)
  });

  return pool;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialize the PostgreSQL pool.
 * Safe to call multiple times — only creates one pool.
 * Call from server.js startup sequence.
 */
function initialize() {
  if (_pool) return;
  if (process.env.QODIQA_PG_ENABLED !== 'true') {
    emit('WARN', 'PG_DISABLED', {
      message: 'PostgreSQL backend disabled (QODIQA_PG_ENABLED not set to "true"). '
             + 'File-based persistence is active.',
    });
    return;
  }
  _enabled = true;
  _pool    = _buildPool();
  emit('INFO', 'PG_POOL_INITIALIZED', {
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    database: process.env.QODIQA_PG_DATABASE || 'qodiqa',
  });
  // Readiness monitoring is started explicitly by server.js (mirrors
  // pgLagMonitor/gapScanner/rotationScheduler — background monitors are
  // opt-in steps, not implicit side effects of pool construction, so unit
  // tests that call initialize() against a mocked pg.Pool never need to
  // account for a live timer).
}

/**
 * Returns true if PostgreSQL backend is enabled and pool is initialized.
 */
function isEnabled() { return _enabled && !!_pool; }

/**
 * Returns true if the last health probe succeeded.
 */
function isHealthy() { return _healthy; }

function _circuitOpenError() {
  /** @type {any} */ const err = new Error('PostgreSQL circuit breaker is OPEN — fast-failing without contacting the database');
  err.code  = 'PG_CIRCUIT_OPEN';
  return err;
}

/**
 * Execute a parameterized query with telemetry.
 *
 * Gated by the PostgreSQL query circuit breaker (FAILOVER-2,
 * pgCircuitBreaker.js): while OPEN, this fast-fails with PG_CIRCUIT_OPEN
 * before ever calling `_pool.query()`, rather than every caller
 * independently stalling for the full statement_timeout during a sustained
 * outage. Only connection/timeout-class errors (see
 * isCircuitBreakerFailure()) count against the breaker — a query error from
 * a caller bug (bad SQL, constraint violation) never trips it.
 *
 * @param {string}   sql    — Parameterized SQL string
 * @param {any[]}    params — Bound parameters
 * @param {string}  [label] - Optional label for telemetry
 * @returns {Promise<import('pg').QueryResult>}
 */
async function query(sql, params = [], label = 'query') {
  if (!_pool) throw new Error('PG pool not initialized');

  const breaker = pgCircuitBreaker.getCircuitBreaker();
  if (!breaker.allowRequest()) {
    _aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label }, label); // first per window, then counted
    throw _circuitOpenError();
  }

  const start = Date.now();
  try {
    const result = await _pool.query(sql, params);
    const ms = Date.now() - start;
    breaker.onSuccess();

    if (ms >= SLOW_QUERY_MS) {
      emit('WARN', 'PG_SLOW_QUERY', { label, ms, rows: result.rowCount });
    }

    return result;
  } catch (e) {
    const ms = Date.now() - start;
    breaker.onError(e); // PH16-D1: every settled error is classified (see pgCircuitBreaker.onError)
    _aggregatedEmit(emit, 'ERROR', 'PG_QUERY_ERROR', {
      label,
      ms,
      error:  e.message,
      code:   e.code ?? null,
      detail: e.detail ?? null,
    }, `${label}|${e.code ?? ''}`);
    throw e;
  }
}

/**
 * Record a failed connection acquisition (pool.connect() rejecting) —
 * distinct from a query-execution failure. Never throws: metrics/telemetry
 * must not affect the caller, which is about to rethrow the original error.
 */
function _recordAcquireFailure(e) {
  try {
    _acquireFailures++;
    require('../../observability/metrics').pgPoolAcquireFailuresTotal.inc({});
    _aggregatedEmit(emit, 'ERROR', 'PG_POOL_ACQUIRE_FAILED', { error: e.message, code: e.code ?? null }, e.code ?? null);
  } catch { /* telemetry must never mask the original acquisition error */ }
}

/**
 * Execute a function inside an explicit-isolation transaction.
 * The function receives a client with .query(sql, params) bound.
 * On throw, the transaction is rolled back automatically.
 *
 * @param {function} fn                           — Async function receiving transactional client
 * @param {object}  [opts]
 * @param {string}  [opts.isolationLevel='REPEATABLE READ'] - PostgreSQL isolation level
 * @returns {Promise<any>} Return value of fn
 */
/**
 * (BOOT_REPORT): observed transport security of ONE pooled connection, from
 * both ends of the same backend — the client socket this process actually
 * holds (TLS or not, protocol, whether the server certificate verified) and
 * the server's own view (pg_stat_ssl for pg_backend_pid()). They legitimately
 * differ when TLS terminates at a proxy in front of PostgreSQL, so both are
 * reported rather than one standing in for the other. Read-only.
 */
async function connectionSecurity() {
  if (!_pool) throw new Error('PG pool not initialized');
  const client = await _pool.connect();
  try {
    const stream = client.connection && client.connection.stream;
    const tls = !!(stream && typeof stream.getProtocol === 'function' && stream.encrypted);
    const cipher = tls && typeof stream.getCipher === 'function' ? stream.getCipher() : null;
    const { rows } = await client.query(
      'SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()');
    const row = rows[0] || {};
    return {
      client: {
        tls,
        protocol:   tls ? stream.getProtocol() : null,
        cipher:     cipher ? cipher.name : null,
        authorized: tls ? stream.authorized === true : null,
      },
      server: { ssl: row.ssl === true, protocol: row.version || null, cipher: row.cipher || null },
    };
  } finally {
    client.release();
  }
}

// closure diagnostic (bench only): connect() wait of withTransaction() callers. Measured only when
// QODIQA_BENCH_STAGE_TIMING=true (refused in production by bootValidator rule bench.stage_timing) or when a caller
// passes onAcquireWait; otherwise no clock is read. query() acquires inside pg itself and is not covered.
const _BENCH = process.env.QODIQA_BENCH_STAGE_TIMING === 'true';
const _benchAcq = { n: 0, sumMs: 0, maxMs: 0, over10: 0, over50: 0 };
function _benchAcquireStats() { return { ..._benchAcq }; }

async function withTransaction(fn, { isolationLevel = 'REPEATABLE READ', onAcquireWait = null } = {}) {
  if (!_pool) throw new Error('PG pool not initialized');

  const breaker = pgCircuitBreaker.getCircuitBreaker();
  if (!breaker.allowRequest()) {
    _aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'withTransaction' }, 'withTransaction');
    throw _circuitOpenError();
  }

  let client;
  try {
    const _acqT0 = (_BENCH || onAcquireWait) ? process.hrtime.bigint() : 0n;
    client = await _pool.connect();
    if (_acqT0) {
      const ms = Number(process.hrtime.bigint() - _acqT0) / 1e6;
      _benchAcq.n++; _benchAcq.sumMs += ms; if (ms > _benchAcq.maxMs) _benchAcq.maxMs = ms;
      if (ms > 10) _benchAcq.over10++; if (ms > 50) _benchAcq.over50++;
      if (onAcquireWait) { try { onAcquireWait(ms); } catch { /* instrumentation never affects the caller */ } }
    }
    breaker.onSuccess();
  } catch (e) {
    breaker.onError(e); // PH16-D1: every settled error is classified (see pgCircuitBreaker.onError)
    _recordAcquireFailure(e);
    throw e;
  }
  try {
    await client.query(`BEGIN ISOLATION LEVEL ${isolationLevel}`);
    const result = await fn({
      query: (sql, params) => client.query(sql, params),
    });
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

/**
 * Execute a function inside a transaction with tenant context pre-set.
 *
 * Sets qodiqa.tenant_id as transaction-local (third param = true) before
 * calling fn.  The context resets automatically at transaction end — no
 * tenant context can leak to the next request on the same pooled connection.
 *
 * ALL tenant-scoped database operations MUST use this method.
 * Never use withTransaction() for tenant-scoped operations — context would
 * not be set and RLS policies would return 0 rows (fail-closed).
 *
 * @param {string}   tenantId                     — Tenant identifier
 * @param {function} fn                            — Async function receiving transactional client
 * @param {object}  [opts]
 * @param {string}  [opts.isolationLevel]          - Forwarded to withTransaction
 * @returns {Promise<any>} Return value of fn
 * @throws {TypeError}  if tenantId is invalid (validation is pre-transaction)
 */
async function withTenantTransaction(tenantId, fn, opts = {}) {
  const { validate, setLocal } = require('./tenantContext');
  validate(tenantId);  // throw before acquiring a connection
  return withTransaction(async (tx) => {
    await setLocal(tx, tenantId);
    return fn(tx);
  }, opts);
}

/**
 * Runs `fn` while holding a PostgreSQL session-scoped advisory lock
 * (guards against concurrent auto-migrate races).
 *
 * Session-scoped (pg_advisory_lock/pg_advisory_unlock), not the transaction-
 * scoped pg_advisory_xact_lock variant, and deliberately so: `fn` receives a
 * client bound to the SAME single connection that holds the lock, and is
 * expected to run its own independent statements against it — including,
 * for the migration-runner use case this exists for, multiple self-contained
 * BEGIN/COMMIT pairs (each migration file manages its own transaction; see
 * src/infra/postgres/migrate.js). Wrapping the lock itself in a transaction
 * would make those nested BEGIN calls either warn-and-continue-in-the-same-
 * transaction or error, depending on the exact statements involved — neither
 * is correct here. Session scope is still safe against a crash or dropped
 * connection: PostgreSQL releases every advisory lock held by a session
 * automatically when that session's connection closes, so a killed process
 * can never leave the lock stuck.
 *
 * Blocks (does not fail fast) waiting for the lock — appropriate for a rare,
 * startup-time, bounded critical section (verify-and-possibly-apply
 * migrations), not a hot request path. Concurrent callers (e.g. multiple
 * distributed-mode replicas starting at once) simply queue here in FIFO
 * order rather than racing each other's DDL.
 *
 * @param {number} lockKey — Postgres bigint advisory lock key. Callers must
 *   use a value reserved for their specific purpose (see this file's own
 *   MIGRATION_ADVISORY_LOCK_KEY constant, below, for the one currently
 *   defined) — advisory
 *   locks are a single global keyspace per database with no namespacing of
 *   their own, so an unrelated future caller reusing the same key would
 *   silently serialize against this one.
 * @param {function} fn — async (client) => any, where client exposes
 *   .query(sql, params). Called only after the lock is held.
 * @returns {Promise<any>} fn's return value
 */
async function withAdvisoryLock(lockKey, fn) {
  if (!_pool) throw new Error('PG pool not initialized');

  const breaker = pgCircuitBreaker.getCircuitBreaker();
  if (!breaker.allowRequest()) {
    _aggregatedEmit(emit, 'WARN', 'PG_CIRCUIT_OPEN', { label: 'withAdvisoryLock' }, 'withAdvisoryLock');
    throw _circuitOpenError();
  }

  let client;
  try {
    client = await _pool.connect();
    breaker.onSuccess();
  } catch (e) {
    breaker.onError(e); // PH16-D1: every settled error is classified (see pgCircuitBreaker.onError)
    _recordAcquireFailure(e);
    throw e;
  }

  const boundClient = { query: (sql, params) => client.query(sql, params) };
  try {
    await client.query('SELECT pg_advisory_lock($1::bigint)', [lockKey]);
    try {
      return await fn(boundClient);
    } catch (e) {
      // Roll back any dangling transaction state before attempting to
      // unlock — mirrors withTransaction()'s existing recovery pattern
      // above. fn (e.g. migrate.js applying a migration's own self-
      // contained BEGIN/COMMIT content) can throw mid-transaction, which
      // leaves this session "in an aborted transaction block" (SQLSTATE
      // 25P02: "current transaction is aborted, commands ignored until end
      // of transaction block"). Without this rollback, the pg_advisory_unlock
      // call in the finally block below would itself be rejected with that
      // same error before ever executing — silently swallowed by its own
      // .catch() — leaving the advisory lock held by this session even
      // after the connection is released back to the pool. ROLLBACK is a
      // safe no-op (just a WARNING) if fn never actually opened a
      // transaction, so this is unconditionally safe to attempt on any error.
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      // Best-effort: if the connection dropped mid-fn, this call itself will
      // fail, but the lock is released automatically when the session ends
      // regardless — see the function header comment.
      await client.query('SELECT pg_advisory_unlock($1::bigint)', [lockKey]).catch(() => {});
    }
  } finally {
    client.release();
  }
}

/**
 * Execute a function inside a SERIALIZABLE transaction with automatic retry.
 * Retries on SQLSTATE 40001 (serialization failure) up to maxAttempts times.
 *
 * Use this for operations where write-skew prevention is required and the
 * workload is read-heavy enough that REPEATABLE READ + FOR UPDATE is insufficient.
 *
 * @param {function} fn                     — Async function receiving transactional client
 * @param {object}  [opts]
 * @param {number}  [opts.maxAttempts=5]    - Maximum total attempts (not retries)
 * @param {string}  [opts.label='']         - Used in retry log events
 * @returns {Promise<any>} Return value of fn
 */
async function withSerializableTransaction(fn, { maxAttempts = 5, label = '' } = {}) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await withTransaction(fn, { isolationLevel: 'SERIALIZABLE' });
    } catch (e) {
      if (e.code === '40001' && attempt < maxAttempts) {
        emit('WARN', 'PG_SERIALIZATION_RETRY', {
          label,
          attempt,
          maxAttempts,
          error: e.message,
        });
        continue;
      }
      throw e;
    }
  }
}

/**
 * Health probe — SELECT 1 with 2s timeout.
 * Updates internal _healthy flag.
 * @returns {Promise<{ healthy: boolean, latencyMs: number, error?: string }>}
 */
async function healthCheck() {
  if (!_pool) return { healthy: false, latencyMs: 0, error: 'pool_not_initialized' };

  const start = Date.now();
  try {
    await query('SELECT 1 AS ping', [], 'health_check');
    _healthy = true;
    return { healthy: true, latencyMs: Date.now() - start };
  } catch (e) {
    _healthy = false;
    return { healthy: false, latencyMs: Date.now() - start, error: e.message };
  }
}

/**
 * Bounded variant of healthCheck() — races the probe against a hard client-side
 * timeout so a stalled connection can never hold the readiness monitor open
 * indefinitely. A timeout marks the pool unhealthy but does not (and cannot)
 * cancel the in-flight query server-side; the pool's own idle/connection
 * timeouts and pg's statement_timeout eventually reclaim it independently. If
 * that abandoned query later settles on its own (success or failure), it will
 * still run healthCheck()'s own _healthy assignment at that point — this
 * function's job is only to guarantee _healthy is already correctly false
 * the moment the bound elapses, not to cancel or await the orphaned probe.
 *
 * @param {number} timeoutMs
 * @returns {Promise<{ healthy: boolean, latencyMs: number, error?: string }>}
 */
async function _boundedHealthCheck(timeoutMs) {
  const start = Date.now();
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      // Must assign _healthy directly here, not just resolve a value — the
      // caller (startReadinessMonitor) only reacts to a REJECTED promise via
      // .catch(); this branch resolves, so a discarded return value would
      // silently leave isHealthy() reporting a stale prior state forever.
      _healthy = false;
      emit('WARN', 'PG_HEALTH_CHECK_TIMEOUT', { timeoutMs });
      resolve({ healthy: false, latencyMs: Date.now() - start, error: 'timeout' });
    }, timeoutMs);
  });
  try {
    return await Promise.race([healthCheck(), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Start the background readiness probe interval. No-op if PG is disabled or
 * already running. Runs a bounded, lightweight `SELECT 1` on a fixed cadence
 * (QODIQA_PG_READY_CHECK_INTERVAL_MS, default 5s) so isHealthy() stays fresh
 * without GET /ready ever issuing a query itself. An in-flight guard skips a
 * tick rather than piling up concurrent probes if PostgreSQL is slow to
 * respond — bounded load regardless of probe frequency or PG latency.
 */
// Finding 3.6: shared by both the recurring interval tick and the
// immediate startup seed below. Runs through BackgroundTaskRunner for
// consistent isolation/logging/metrics; the `!result.ok` branch preserves
// the pre-existing _healthy=false side effect and PG_READY_MONITOR_ERROR
// event that isHealthy()/dashboards already depend on (BackgroundTaskRunner
// separately emits its own generic BACKGROUND_TASK_FAILED/metric).
function _runReadinessCheck({ _taskRunner = _defaultTaskRunner } = {}) {
  _readyCheckInFlight = true;
  return _taskRunner.runTask('postgres-readiness-monitor', () => _boundedHealthCheck(READY_CHECK_TIMEOUT_MS))
    .then((result) => {
      if (!result.ok) {
        _healthy = false;
        emit('ERROR', 'PG_READY_MONITOR_ERROR', { error: result.error.message });
      }
    })
    .finally(() => { _readyCheckInFlight = false; });
}

function startReadinessMonitor() {
  if (_readyMonitorTimer || !_pool) return;

  _readyMonitorTimer = setInterval(() => {
    _refreshPoolMetrics(); // sync, zero-cost — independent of the in-flight guard below
    if (_readyCheckInFlight) return;
    _runReadinessCheck();
  }, READY_CHECK_INTERVAL_MS);

  if (typeof _readyMonitorTimer.unref === 'function') _readyMonitorTimer.unref();

  // Seed an immediate check rather than waiting for the first interval tick,
  // so isHealthy() reflects reality as soon as possible after startup.
  _refreshPoolMetrics();
  _runReadinessCheck();
}

/** Stop the background readiness probe interval. Safe to call multiple times. */
function stopReadinessMonitor() {
  if (_readyMonitorTimer) {
    clearInterval(_readyMonitorTimer);
    _readyMonitorTimer = null;
  }
  _readyCheckInFlight = false;
}

/**
 * Operational stats from pg_stat_activity and pool internals.
 * Used by /diagnostics and /dashboard/status endpoints.
 */
async function stats() {
  if (!_pool) return { enabled: false };

  const [connResult, pgStats] = await Promise.all([
    query(`
      SELECT
        count(*)                                     AS total,
        count(*) FILTER (WHERE state = 'active')    AS active,
        count(*) FILTER (WHERE state = 'idle')      AS idle,
        count(*) FILTER (WHERE state = 'idle in transaction') AS idle_in_txn,
        max(EXTRACT(EPOCH FROM (NOW() - query_start)) * 1000) AS max_query_age_ms
      FROM pg_stat_activity
      WHERE datname = current_database()
        AND pid <> pg_backend_pid()
    `, [], 'pool_stats'),
    query(`
      SELECT
        pg_database_size(current_database()) AS db_size_bytes,
        (SELECT count(*) FROM audit_chain)   AS audit_chain_rows,
        (SELECT count(*) FROM policies)      AS policy_rows,
        (SELECT count(*) FROM rbac_users)    AS rbac_user_rows,
        (SELECT count(*) FROM investigations) AS investigation_rows
    `, [], 'table_stats').catch(() => ({ rows: [{}] })),
  ]);

  const c = connResult.rows[0] ?? {};
  const s = pgStats.rows[0]    ?? {};

  return {
    enabled:        true,
    healthy:        _healthy,
    pool: {
      total:        Number(c.total         ?? 0),
      active:       Number(c.active        ?? 0),
      idle:         Number(c.idle          ?? 0),
      idleInTxn:    Number(c.idle_in_txn   ?? 0),
      maxQueryAgeMs: Number(c.max_query_age_ms ?? 0),
      poolMax:      _pool.options?.max ?? null,
      poolWaiting:  _pool.waitingCount ?? 0,
    },
    storage: {
      dbSizeBytes:      Number(s.db_size_bytes     ?? 0),
      auditChainRows:   Number(s.audit_chain_rows  ?? 0),
      policyRows:       Number(s.policy_rows        ?? 0),
      rbacUserRows:     Number(s.rbac_user_rows     ?? 0),
      investigationRows: Number(s.investigation_rows ?? 0),
    },
  };
}

/**
 * Lightweight, synchronous pool telemetry —.
 *
 * Unlike stats(), this issues NO query: total/idle/waiting connection counts
 * come straight from the pg.Pool instance's own in-process counters
 * (totalCount/idleCount/waitingCount), which the pg driver already maintains
 * on every acquire/release. Safe to call as often as needed (every /ready
 * tick, every /diagnostics hit) with zero added database load — this is what
 * `pgPool.waitingCount` refers to specifically, not a
 * pg_stat_activity query.
 *
 * @returns {{enabled:boolean, healthy?:boolean, size?:number, active?:number,
 *            idle?:number, waiting?:number, max?:number|null,
 *            saturated?:boolean, acquireFailures?:number}}
 */
function poolStats() {
  if (!_pool) return { enabled: false };

  const size    = _pool.totalCount   ?? 0;
  const idle    = _pool.idleCount    ?? 0;
  const waiting = _pool.waitingCount ?? 0;
  const active  = Math.max(size - idle, 0);
  const max     = _pool.options?.max ?? null;

  return {
    enabled:         true,
    healthy:         _healthy,
    size,
    active,
    idle,
    waiting,
    max,
    // Saturated — true under either condition:
    //   • waiting > 0:  genuine exhaustion, callers are actively blocked on
    //     pool.connect() right now. (node-pg only ever queues a caller once
    //     totalCount has already reached max with no idle client available,
    //     so this alone is sufficient regardless of the second clause.)
    //   • size >= max && idle === 0 (with nobody queued yet): zero spare
    //     capacity — the pool is fully checked out but no caller has arrived
    //     to be queued. A leading indicator, not exhaustion itself: the very
    //     next connect() call is what will start queuing.
    saturated:       waiting > 0 || (max != null && size >= max && idle === 0),
    acquireFailures: _acquireFailures,
  };
}

/**
 * Push current pool telemetry into the Prometheus gauges. Called from
 * the readiness monitor tick — sync, zero-cost, no additional query beyond
 * what the tick already does for isHealthy(). Never throws.
 */
function _refreshPoolMetrics() {
  try {
    const s = poolStats();
    if (!s.enabled) return;
    const metrics = require('../../observability/metrics');
    metrics.pgPoolSize.set({}, s.size);
    metrics.pgPoolActive.set({}, s.active);
    metrics.pgPoolIdle.set({}, s.idle);
    metrics.pgPoolWaiting.set({}, s.waiting);
    metrics.pgPoolMax.set({}, s.max ?? 0);
  } catch { /* metrics must never affect pool operation */ }
}

/**
 * Drain the pool gracefully.  Call during server shutdown.
 */
async function shutdown() {
  stopReadinessMonitor();
  // the dedicated cross-tenant pools (rolePools.js) share this
  // process's lifecycle — closing the app pool closes them too.
  await require('./rolePools').shutdownAll().catch(() => {});
  if (!_pool) return;
  emit('INFO', 'PG_POOL_SHUTDOWN', {});
  await _pool.end().catch(e => emit('ERROR', 'PG_POOL_SHUTDOWN_ERROR', { error: e.message }));
  _pool             = null;
  _healthy          = false;
  _enabled          = false;
  _acquireFailures  = 0;
}

// ── Idempotent migration runner (simplified — see migrate.js for full runner) ─

// Reserved advisory lock key for serializing migration application across
// concurrent processes — e.g.
// multiple distributed-mode replicas starting simultaneously against a
// freshly-provisioned database with QODIQA_PG_AUTO_MIGRATE=true, all
// discovering the same pending migration(s) at once. Fixed and reserved:
// nothing else in this codebase may call withAdvisoryLock() with this same
// key. Value has no meaning beyond being a stable constant.
const MIGRATION_ADVISORY_LOCK_KEY = 946812026;

/**
 * Run all pending SQL migrations from the migrations directory.
 * Called optionally at startup when QODIQA_PG_AUTO_MIGRATE=true.
 *
 * Single-writer protection: the entire migrate.js run — its own
 * fresh query of qodiqa_migrations for pending versions through applying and
 * recording each one — executes while holding a session-scoped PostgreSQL
 * advisory lock (see withAdvisoryLock() above), on one connection dedicated
 * to this call for its duration. Concurrent callers (other replicas racing
 * the same discovery) queue on the lock rather than racing migrate.js's DDL
 * against each other. This also gives correct double-checked-locking
 * behavior for free: migrate.js always re-queries qodiqa_migrations fresh at
 * the start of its own run, so a caller that was queued behind the winner
 * simply finds nothing left pending once it acquires the lock, and returns
 * a no-op — no separate pre/post-lock re-check is needed here.
 */
async function runMigrations() {
  return withAdvisoryLock(MIGRATION_ADVISORY_LOCK_KEY, (client) => {
    const { runMigrations: _run } = require('./migrate');
    return _run({ pool: client });
  });
}

module.exports = {
  initialize,
  isEnabled,
  connectionSecurity,
  isHealthy,
  query,
  withTransaction,
  withTenantTransaction,
  withSerializableTransaction,
  withAdvisoryLock,
  MIGRATION_ADVISORY_LOCK_KEY, // ER 2026-10-06: exported so migrate.js's CLI path is pinned to the same key
  healthCheck,
  stats,
  poolStats,
  _benchAcquireStats,
  shutdown,
  runMigrations,
  startReadinessMonitor,
  stopReadinessMonitor,
};
