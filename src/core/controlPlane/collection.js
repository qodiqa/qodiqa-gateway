'use strict';

/**
 * One control-plane collection — the storage behind one store's
 * existing interface. See ./index.js for the backends and the guarantee.
 *
 * The store keeps its own API and validation; this replaces only where its
 * records live:
 *   ensure()          before every read: memory = seed once; pg = refuse a stale snapshot (503)
 *   get/has/values    the snapshot
 *   put/remove        memory: synchronous, returns the record
 *                     pg:     returns a Promise; the row is written (versioned) FIRST and
 *                             applied to the snapshot only after the commit, so a refused
 *                             write never leaves this replica showing uncommitted state
 *   touch(id, iso)    lastUsedAt-style observability field: never a versioned write
 *
 * The snapshot is PROCESS-wide (one per store per process, held under a
 * global symbol), exactly like the database it mirrors: a module instance
 * created later in the same process (jest.resetModules / isolateModules) sees
 * the same records instead of an empty store. Each instance tracks the
 * snapshot's change generation and re-runs onChange() (index rebuilds) when
 * another instance changed it.
 */

const cp = require('./index');

const REGISTRY = Symbol.for('qodiqa.w6.controlPlane.snapshots');

function _shared(store) {
  if (!globalThis[REGISTRY]) globalThis[REGISTRY] = new Map();
  const reg = globalThis[REGISTRY];
  if (!reg.has(store)) {
    reg.set(store, { records: new Map(), versions: new Map(), tombstones: new Map(), seeded: false, gen: 0 });
  }
  return reg.get(store);
}

class Collection {
  constructor(store, { seed = () => ({}), onChange = () => {}, touchField = null } = {}) {
    this.store = store;
    this._seed = seed;
    this._onChangeFn = onChange;
    this._touchField = touchField;
    this._s = _shared(store);
    this._seenGen = -1;
    cp.registerCollection(this);
  }

  _changed() { this._s.gen++; this._sync(); }
  _sync() { if (this._seenGen !== this._s.gen) { this._seenGen = this._s.gen; this._onChangeFn(); } }

  // ── reads ──────────────────────────────────────────────────────────────────
  ensure() {
    if (cp.isPg()) { cp.assertFresh(this.store); this._sync(); return; }
    if (!this._s.seeded) {
      this._s.seeded = true;
      const seeded = this._seed() || {};
      for (const [id, rec] of Object.entries(seeded)) {
        this._s.records.set(id, rec);
        this._s.versions.set(id, 1);
      }
      this._s.gen++;
    }
    this._sync();
  }

  get(id) { this.ensure(); return this._s.records.has(id) ? this._s.records.get(id) : null; }
  has(id) { this.ensure(); return this._s.records.has(id); }
  values() { this.ensure(); return [...this._s.records.values()]; }
  entries() { this.ensure(); return [...this._s.records.entries()]; }
  size() { this.ensure(); return this._s.records.size; }
  version(id) { return this._s.versions.get(id) ?? null; }
  /** Raw snapshot access for index rebuilds (no freshness check — called from onChange). */
  rawValues() { return [...this._s.records.values()]; }

  // ── writes ─────────────────────────────────────────────────────────────────
  /**
   * @param {string} id
   * @param {object} record  the complete new record
   * @param {{ create?: boolean, updatedBy?: string, invariant?: any }} [opts]  create: the id must not exist
   * @returns {object | Promise<object>} the record as stored
   */
  put(id, record, { create = false, updatedBy = null, invariant = null } = {}) {
    if (!cp.isPg()) {
      this.ensure();
      this._s.records.set(id, record);
      this._s.versions.set(id, (this._s.versions.get(id) || 0) + 1);
      this._changed();
      return record;
    }
    const expectedVersion = create ? null : (this._s.versions.has(id) ? this._s.versions.get(id) : null);
    if (!create && expectedVersion === null && this._s.tombstones.has(id)) {
      return Promise.reject(new cp.ControlPlaneError(`${this.store}/${id} was deleted`, 'CONTROL_PLANE_VERSION_CONFLICT', 409, { store: this.store, recordId: id }));
    }
    return cp.writeRow(this.store, id, { data: record, expectedVersion, updatedBy, invariant }).then(({ version }) => {
      this._apply(id, record, version, false, null);
      this._changed();
      return record;
    });
  }

  /** Delete (pg: soft delete — a tombstone that can never be un-deleted). */
  remove(id, { updatedBy = null, invariant = null } = {}) {
    if (!cp.isPg()) {
      this.ensure();
      this._s.records.delete(id);
      this._s.versions.delete(id);
      this._changed();
      return true;
    }
    const current = this._s.records.get(id);
    const expectedVersion = this._s.versions.get(id);
    if (!current || expectedVersion === undefined) {
      return Promise.reject(new cp.ControlPlaneError(`${this.store}/${id} not found`, 'CONTROL_PLANE_VERSION_CONFLICT', 409, { store: this.store, recordId: id }));
    }
    return cp.writeRow(this.store, id, { data: current, expectedVersion, deleted: true, updatedBy, invariant }).then(({ version }) => {
      this._apply(id, current, version, true, null);
      this._changed();
      return true;
    });
  }

  /** Observability-only timestamp: local immediately; pg coalesced (≤ 1 write/record/minute). */
  touch(id, atIso) {
    const rec = this._s.records.get(id);
    if (!rec || !this._touchField) return;
    this._s.records.set(id, Object.freeze({ ...rec, [this._touchField]: atIso }));
    cp.touch(this.store, id, atIso);
  }

  // ── replication ────────────────────────────────────────────────────────────
  _apply(id, data, version, deleted, lastUsedAt) {
    const s = this._s;
    const local = s.versions.get(id);
    const tomb = s.tombstones.get(id);
    if (tomb !== undefined && version <= tomb) return false;
    if (deleted) {
      s.records.delete(id);
      s.versions.delete(id);
      s.tombstones.set(id, version);
      return true;
    }
    if (local !== undefined && version < local) return false;
    if (local !== undefined && version === local) {
      // Same version: only the observability timestamp may have moved.
      if (this._touchField && lastUsedAt) {
        const rec = s.records.get(id);
        const iso = new Date(lastUsedAt).toISOString();
        if (rec && (!rec[this._touchField] || rec[this._touchField] < iso)) s.records.set(id, Object.freeze({ ...rec, [this._touchField]: iso }));
      }
      return false;
    }
    let rec = data;
    if (this._touchField && lastUsedAt) {
      const iso = new Date(lastUsedAt).toISOString();
      if (!rec[this._touchField] || rec[this._touchField] < iso) rec = { ...rec, [this._touchField]: iso };
    }
    s.records.set(id, Object.isFrozen(rec) ? rec : Object.freeze(rec));
    s.versions.set(id, version);
    return true;
  }

  /** deferNotify: applied during registration (inside this constructor) — the store's first read runs onChange. */
  _applyRows(rows, { deferNotify = false } = {}) {
    let changed = false;
    for (const r of rows) {
      if (this._apply(r.record_id, r.data, Number(r.version), r.deleted, r.last_used_at)) changed = true;
    }
    if (changed) { if (deferNotify) this._s.gen++; else this._changed(); }
    return changed;
  }

  /** Test/dev-tooling only: write this collection's snapshot as its seed fixture (memory mode). */
  exportSeedFixture() {
    this.ensure();
    return require('./seed').writeSeedFixture(this.store, Object.fromEntries(this._s.records));
  }

  _reset() {
    this._s.records.clear();
    this._s.versions.clear();
    this._s.tombstones.clear();
    this._s.seeded = false;
    this._changed();
  }
}

/** Tooling (scripts/controlPlane/import.js): the process-wide snapshot of one store, as { id: record }. */
function snapshotRecords(store) {
  const reg = globalThis[REGISTRY];
  const s = reg && reg.get(store);
  return s ? Object.fromEntries(s.records) : {};
}

module.exports = { Collection, snapshotRecords };
