'use strict';

/**
 * Control plane —.
 *
 * The control-plane stores (signing identities, RBAC users and custom roles,
 * tenants, organizations, tenant-portal users, the policy state, the
 * signing-key status timeline) used to be JSON files, loaded once per process
 * and rewritten whole from each process's memory. A revocation on one replica
 * never reached another, and a stale replica's next write put the revoked
 * record back on disk (audit F-S02).
 *
 * Backends (resolveBackend):
 *   pg      PostgreSQL is authoritative (control_plane_records, migrations
 *           065/066, role qodiqa_control). Every replica keeps a snapshot of
 *           the rows and pulls changes incrementally: every SYNC_INTERVAL_MS
 *           (default 1 s), and immediately on a signed change notification
 * (./notifier.js, the MAC keyring). Notifications are only an
 *           optimisation — the GUARANTEE is the staleness bound: any read
 * taken more than MAX_STALENESS_MS after the last
 *           successful pull is REFUSED with CONTROL_PLANE_STALE (HTTP 503),
 *           so a revocation committed at t is in force on every replica by
 *           t + 5 s, or that replica refuses to answer. Writes are row-level
 *           and versioned: a replica writes the version it read, and a stale
 *           replica's write matches nothing (409 CONTROL_PLANE_VERSION_CONFLICT).
 *   memory  development/test only (never production): each collection is
 *           seeded ONCE from its legacy JSON file, if present, and never
 *           written back. Nothing is persisted.
 *
 * Production always resolves to 'pg' (bootValidator rule control_plane refuses
 * an explicit 'memory'). Elsewhere the PostgreSQL backend is opt-in, explicitly:
 * QODIQA_CONTROL_PLANE_BACKEND=pg; anything else is the memory mode.
 */

const crypto = require('crypto');
const { emit } = require('../../../services/logger');
const { monoNowMs, wallFromMono } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
const rolePools = require('../../infra/postgres/rolePools');

const STORES = Object.freeze([
  'rbac_user', 'rbac_custom_role', 'tenant', 'organization',
  'portal_user', 'policy', 'signing_identity', 'signing_key_status', 'kill_switch', 'provider_registry',   // kill_switch: migration 096; provider_registry: migration 107
]);

const MAX_STALENESS_MS = 5000; // the propagation guarantee
const TOUCH_INTERVAL_MS = 60_000; // touchLastUsed at most once per record per minute

function _intEnv(name, dflt, min, max) {
  const n = parseInt(process.env[name], 10);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(Math.max(n, min), max);
}

// A test/ops override may TIGHTEN the bound, never loosen it past.
function maxStalenessMs() { return _intEnv('QODIQA_CONTROL_PLANE_MAX_STALENESS_MS', MAX_STALENESS_MS, 200, MAX_STALENESS_MS); }
function syncIntervalMs() { return _intEnv('QODIQA_CONTROL_PLANE_SYNC_INTERVAL_MS', 1000, 50, 2500); }

class ControlPlaneError extends Error {
  constructor(message, code, status, details) {
    super(message);
    this.name = 'ControlPlaneError';
    this.code = code;
    this.status = status;
    if (details) this.details = details;
  }
}

function isControlPlaneError(err) { return !!err && err.name === 'ControlPlaneError'; }

function resolveBackend(env = process.env) {
  if (env.NODE_ENV === 'production') return 'pg';
  return env.QODIQA_CONTROL_PLANE_BACKEND === 'pg' ? 'pg' : 'memory';
}

// ── state ─────────────────────────────────────────────────────────────────────
let _backend = null;
const _collections = new Map();          // store -> Collection
const _origin = crypto.randomBytes(8).toString('hex');
const _st = {
  started: false, startPromise: null, horizon: '0', lastSyncOkAt: 0,
  timer: null, syncing: null, again: false, lastError: null, syncCount: 0,
  touchPending: new Map(), touchFlushedAt: new Map(), touchTimer: null,
};
let _pool = null;   // injectable for tests: { query(sql, params) }
let _notifier = null;

function backend() {
  if (_backend === null) {
    _backend = resolveBackend();
    if (_backend === 'memory') {
      emit(process.env.NODE_ENV === 'test' ? 'DEBUG' : 'WARN', 'CONTROL_PLANE_MEMORY_MODE', {
        message: 'Control plane runs in development/test memory mode: state is seeded once from the legacy JSON files and never persisted.',
      });
    }
  }
  return _backend;
}
function isPg() { return backend() === 'pg'; }

function _db() {
  if (_pool) return _pool;
  return rolePools.control;
}

// Rows pulled for a store whose module has not been required yet. A pull must
// never drop them (the horizon moves past them), so they wait here and are
// applied the moment the store registers its collection.
const _unclaimed = new Map(); // store -> Map(record_id -> row)

function registerCollection(col) {
  if (!STORES.includes(col.store)) throw new TypeError(`unknown control-plane store ${col.store}`);
  _collections.set(col.store, col);
  const waiting = _unclaimed.get(col.store);
  if (waiting) { _unclaimed.delete(col.store); col._applyRows([...waiting.values()], { deferNotify: true }); }
  // A store required after start() still gets its post-start hook (expiry
  // backfill, policy import) — deferred, since the store assigns the hook
  // right after constructing its collection.
  if (_st.started) {
    setImmediate(() => {
      if (typeof col._afterStart === 'function') {
        col._afterStart().catch((err) => emit('WARN', 'CONTROL_PLANE_AFTER_START_FAILED', { store: col.store, error: err.message }));
      }
    });
  }
}

/** then-helper: run fn on a value that is either synchronous (memory) or a Promise (pg). */
function after(result, fn) {
  return result && typeof result.then === 'function' ? result.then(fn) : fn(result);
}

// ── freshness ─────────────────────────────────────────────────────────────────
function assertFresh(store) {
  if (!isPg()) return;
  const age = _st.lastSyncOkAt ? monoNowMs() - _st.lastSyncOkAt : Infinity; // monotonic (same-process)
  if (age > maxStalenessMs()) {
    emit('WARN', 'CONTROL_PLANE_STALE_REFUSED', { store, ageMs: Number.isFinite(age) ? age : null, lastError: _st.lastError });
    throw new ControlPlaneError(
      `control plane snapshot is stale (${Number.isFinite(age) ? `${age} ms` : 'never synced'}; bound ${maxStalenessMs()} ms)`,
      'CONTROL_PLANE_STALE', 503, { store, ageMs: Number.isFinite(age) ? age : null });
  }
}

function status() {
  return {
    backend: backend(), started: _st.started, lastSyncOkAt: wallFromMono(_st.lastSyncOkAt), // wall-clock equivalent for display
    ageMs: _st.lastSyncOkAt ? monoNowMs() - _st.lastSyncOkAt : null, maxStalenessMs: maxStalenessMs(), // monotonic (same-process)
    syncIntervalMs: syncIntervalMs(), syncCount: _st.syncCount, lastError: _st.lastError,
    notifier: _notifier ? _notifier.status() : null,
  };
}

// ── pull ──────────────────────────────────────────────────────────────────────
const PULL_SQL = `
  SELECT s.horizon::text AS horizon, r.store, r.record_id, r.data, r.version::text AS version,
         r.deleted, r.last_used_at
    FROM (SELECT pg_snapshot_xmin(pg_current_snapshot()) AS horizon) s
    LEFT JOIN control_plane_records r ON r.change_xid >= $1::xid8`;

async function _pullOnce() {
  const startedAt = monoNowMs(); // monotonic (same-process)
  const res = await _db().query(PULL_SQL, [_st.horizon], 'control_plane_pull');
  const byStore = new Map();
  let horizon = _st.horizon;
  for (const row of res.rows) {
    horizon = row.horizon;
    if (!row.store) continue;
    if (!byStore.has(row.store)) byStore.set(row.store, []);
    byStore.get(row.store).push(row);
  }
  for (const [store, rows] of byStore) {
    const col = _collections.get(store);
    if (col) { col._applyRows(rows); continue; }
    if (!_unclaimed.has(store)) _unclaimed.set(store, new Map());
    const m = _unclaimed.get(store);
    for (const row of rows) {
      const prev = m.get(row.record_id);
      if (!prev || Number(prev.version) <= Number(row.version)) m.set(row.record_id, row);
    }
  }
  _st.horizon = horizon;
  _st.lastSyncOkAt = startedAt; // the snapshot is at least as new as the moment the query started
  _st.lastError = null;
  _st.syncCount++;
  return { rows: res.rows.filter((r) => r.store).length };
}

/** Pull now. Concurrent callers share one in-flight pull; a request during a pull schedules one more. */
function syncNow() {
  if (!isPg()) return Promise.resolve({ rows: 0 });
  if (_st.syncing) { _st.again = true; return _st.syncing; }
  _st.syncing = (async () => {
    try {
      do {
        _st.again = false;
        await _pullOnce();
      } while (_st.again);
    } catch (err) {
      _st.lastError = err.message;
      emit('WARN', 'CONTROL_PLANE_SYNC_FAILED', { error: err.message, code: err.code ?? null, ageMs: _st.lastSyncOkAt ? monoNowMs() - _st.lastSyncOkAt : null }); // monotonic (same-process)
      throw err;
    } finally {
      _st.syncing = null;
    }
  })();
  return _st.syncing;
}

/**
 * Start the replica (pg only): initial full pull (must succeed), then the
 * periodic pull and the change notifier. Idempotent; memory mode is a no-op.
 */
function start({ notifier = true } = {}) {
  if (!isPg()) return Promise.resolve(status());
  if (_st.startPromise) return _st.startPromise;
  _st.startPromise = (async () => {
    try {
      await syncNow();
    } catch (err) {
      _st.startPromise = null;
      throw new ControlPlaneError(`control plane initial sync failed: ${err.message}`, 'CONTROL_PLANE_UNAVAILABLE', 503);
    }
    _st.timer = setInterval(() => { syncNow().catch(() => {}); }, syncIntervalMs());
    if (_st.timer.unref) _st.timer.unref();
    _st.touchTimer = setInterval(() => { _flushTouches().catch(() => {}); }, TOUCH_INTERVAL_MS);
    if (_st.touchTimer.unref) _st.touchTimer.unref();
    _st.started = true;
    if (notifier && !_notifier) {
      try {
        _notifier = require('./notifier').create({ origin: _origin, onChange: () => { syncNow().catch(() => {}); } });
        _notifier.start().catch((err) => emit('WARN', 'CONTROL_PLANE_NOTIFIER_START_FAILED', { error: err.message }));
      } catch (err) {
        emit('WARN', 'CONTROL_PLANE_NOTIFIER_START_FAILED', { error: err.message });
      }
    }
    for (const col of _collections.values()) { if (typeof col._afterStart === 'function') await col._afterStart(); }
    emit('INFO', 'CONTROL_PLANE_STARTED', { backend: 'pg', ...status(), notifier: undefined });
    return status();
  })();
  return _st.startPromise;
}

async function stop() {
  if (_st.timer) clearInterval(_st.timer);
  if (_st.touchTimer) clearInterval(_st.touchTimer);
  _st.timer = null; _st.touchTimer = null;
  try { await _flushTouches(); } catch { /* best effort */ }
  if (_notifier) { const n = _notifier; _notifier = null; await n.stop().catch(() => {}); }
  _st.started = false; _st.startPromise = null;
}

async function _ensureStarted() {
  if (!_st.started) await start();
}

// ── writes (pg) ───────────────────────────────────────────────────────────────
function _conflict(store, id, why) {
  syncNow().catch(() => {});
  return new ControlPlaneError(`control-plane write refused: ${store}/${id} ${why}`, 'CONTROL_PLANE_VERSION_CONFLICT', 409, { store, recordId: id });
}

/**
 * a versioned write whose precondition spans OTHER rows (the last-admin rule). The per-row version check
 * cannot see a concurrent write to a different row, so two replicas could each demote "the other" admin and leave
 * none. Here the precondition is re-evaluated by PostgreSQL inside one transaction, after a transaction-scoped
 * advisory lock that every such write takes, so concurrent guarded writes serialize and the second one sees the
 * first one's committed row. invariant = { lockKey, sql, params, holds(rows) -> bool, refusal() -> Error }.
 */
async function _writeUnderInvariant(store, id, { data, expectedVersion, deleted, updatedBy }, invariant) {
  if (expectedVersion === null || expectedVersion === undefined) throw new TypeError('a guarded write updates an existing row');
  const db = _db();
  if (typeof db.withTransaction !== 'function') {
    throw new ControlPlaneError('control-plane guarded write needs a transactional pool', 'CONTROL_PLANE_UNAVAILABLE', 503, { store, recordId: id });
  }
  return db.withTransaction(async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [`qodiqa.controlPlane.${invariant.lockKey}`]);
    const pre = await tx.query(invariant.sql, invariant.params || []);
    if (!invariant.holds(pre.rows)) {
      const err = invariant.refusal();
      err.expectedRefusal = true;
      throw err;
    }
    const r = await tx.query(
      `UPDATE control_plane_records
          SET data = $3::jsonb, version = version + 1, deleted = $4, updated_by = $5
        WHERE store = $1 AND record_id = $2 AND version = $6 AND NOT deleted
        RETURNING version::text AS version`,
      [store, id, JSON.stringify(data), !!deleted, updatedBy, String(expectedVersion)]);
    if (r.rowCount !== 1) {
      const err = /** @type {any} */ (_conflict(store, id, `is not at version ${expectedVersion} (stale replica or concurrent write)`));
      err.expectedRefusal = true;
      throw err;
    }
    return r;
  }, 'control_plane_guarded_write');
}

/**
 * Versioned row write. expectedVersion null = create (fails if the id exists,
 * including as a tombstone). Returns { version }.
 */
async function writeRow(store, id, { data, expectedVersion, deleted = false, updatedBy = null, invariant = null }) {
  await _ensureStarted();
  let res;
  try {
    if (invariant) {
      res = await _writeUnderInvariant(store, id, { data, expectedVersion, deleted, updatedBy }, invariant);
    } else if (expectedVersion === null || expectedVersion === undefined) {
      res = await _db().query(
        `INSERT INTO control_plane_records (store, record_id, data, version, deleted, updated_by)
         VALUES ($1, $2, $3::jsonb, 1, $4, $5)
         ON CONFLICT (store, record_id) DO NOTHING
         RETURNING version::text AS version`,
        [store, id, JSON.stringify(data), !!deleted, updatedBy], 'control_plane_insert');
      if (res.rowCount !== 1) throw _conflict(store, id, 'already exists');
    } else {
      res = await _db().query(
        `UPDATE control_plane_records
            SET data = $3::jsonb, version = version + 1, deleted = $4, updated_by = $5
          WHERE store = $1 AND record_id = $2 AND version = $6 AND NOT deleted
          RETURNING version::text AS version`,
        [store, id, JSON.stringify(data), !!deleted, updatedBy, String(expectedVersion)], 'control_plane_update');
      if (res.rowCount !== 1) throw _conflict(store, id, `is not at version ${expectedVersion} (stale replica or concurrent write)`);
    }
  } catch (err) {
    if (isControlPlaneError(err) || (err && err.expectedRefusal)) throw err;
    if (err.code === '23505') {
      throw new ControlPlaneError(`control-plane unique constraint: ${err.constraint || err.message}`, 'CONTROL_PLANE_UNIQUE_CONFLICT', 409, { store, recordId: id, constraint: err.constraint || null });
    }
    throw new ControlPlaneError(`control-plane write failed: ${err.message}`, 'CONTROL_PLANE_UNAVAILABLE', 503, { store, recordId: id });
  }
  const version = Number(res.rows[0].version);
  if (_notifier) _notifier.publish({ store, recordId: id }).catch(() => {});
  return { version };
}

// ── touchLastUsed ────────
function touch(store, id, atIso) {
  if (!isPg()) return;
  const key = `${store}\u0000${id}`;
  const prev = _st.touchPending.get(key);
  if (!prev || prev.at < atIso) _st.touchPending.set(key, { store, id, at: atIso });
  const last = _st.touchFlushedAt.get(key) || 0;
  if (monoNowMs() - last >= TOUCH_INTERVAL_MS) _flushTouches([key]).catch(() => {}); // monotonic (same-process)
}

async function _flushTouches(keys = [..._st.touchPending.keys()]) {
  for (const key of keys) {
    const t = _st.touchPending.get(key);
    if (!t) continue;
    _st.touchPending.delete(key);
    _st.touchFlushedAt.set(key, monoNowMs()); // monotonic (same-process)
    try {
      await _db().query(
        `UPDATE control_plane_records
            SET last_used_at = GREATEST(COALESCE(last_used_at, '-infinity'::timestamptz), $3::timestamptz)
          WHERE store = $1 AND record_id = $2 AND NOT deleted`,
        [t.store, t.id, t.at], 'control_plane_touch');
    } catch (err) {
      emit('WARN', 'CONTROL_PLANE_TOUCH_FAILED', { store: t.store, recordId: t.id, error: err.message });
    }
  }
}

// ── test hooks ────────────────────────────────────────────────────────────────
function _setPoolForTest(pool) { _pool = pool; }
async function _resetForTest() {
  await stop();
  _backend = null;
  _st.horizon = '0'; _st.lastSyncOkAt = 0; _st.lastError = null; _st.syncCount = 0;
  _st.touchPending.clear(); _st.touchFlushedAt.clear(); _unclaimed.clear();
  for (const col of _collections.values()) col._reset();
}
function _touchStats() { return { pending: _st.touchPending.size, flushed: _st.touchFlushedAt.size }; }

module.exports = {
  STORES, MAX_STALENESS_MS, TOUCH_INTERVAL_MS,
  ControlPlaneError, isControlPlaneError,
  resolveBackend, backend, isPg, registerCollection, after,
  assertFresh, status, syncNow, start, stop, writeRow, touch,
  _setPoolForTest, _resetForTest, _touchStats, _flushTouches,
};
