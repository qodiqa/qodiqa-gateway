'use strict';

/**
 * Global policy store (admin policy state + the ENFORCED global policy set).
 *
 * the state lives in the control plane (src/core/controlPlane) —
 * PostgreSQL in production. Every replica derives its enforced set from the
 * store (enforcedPolicies(), recomputed whenever a change is pulled), so a
 * policy published on one replica is enforced on every replica within the 5 s
 * bound, and a superseded version can never come back from a stale replica
 * (versioned writes). POLICY_FILE and data/policy-store.json are import-only:
 * the running system never writes either (it used to rewrite both on every
 * change, and each process enforced only what IT had loaded).
 *
 * Seeding: memory mode (dev/test) seeds once from data/policy-store.json, or
 * — if absent/corrupt — imports POLICY_FILE, exactly as before. pg mode imports
 * POLICY_FILE only if the store is empty after the first pull (create-only,
 * idempotent across replicas); scripts/controlPlane/import.js does the same.
 *
 * Mutators return synchronously in memory mode and a Promise in pg mode.
 */

const fs   = require('fs');
const path = require('path');

const { validateAndPrepare, resolvePolicyFilePath } = require('../../../services/policy/loader');
const { computePolicyHash }  = require('../../../services/policyHash');
const { emit }               = require('../../../services/logger');
const cp                     = require('../controlPlane');
const { Collection }         = require('../controlPlane/collection');
const { readSeed }           = require('../controlPlane/seed');

// ── Paths ─────────────────────────────────────────────────────────────────────

// this module has its own independent POLICY_FILE resolution (it can be
// required standalone by DR tooling/tests, outside a full server boot) — it
// applies the SAME production rule as server/startup.js via the shared
// resolvePolicyFilePath() helper, rather than duplicating the logic. In a
// real, fully-booted production server this is pure defense in depth: since
// server.js requires server/startup.js (and its own fail-closed POLICY_FILE
// check) BEFORE it ever requires src/app.js — the only path that pulls this
// module in via policyManagement.js/policyProvenance.js — a real production
// boot with POLICY_FILE unset never reaches this line at all. POLICY_FILE
// resolving to `null` here (only reachable outside that gated path) is
// handled below by degrading exactly like this module's own pre-existing
// "can't read/parse policies.json" bootstrap-skip path — never a crash,
// since this module is also required by disposable scripts and tests that
// have no reason to hard-exit the whole process.
let POLICY_FILE;
try {
  POLICY_FILE = resolvePolicyFilePath(path.join(__dirname, '..', '..', '..', 'policies.json'));
} catch (err) {
  emit('WARN', 'POLICY_STORE_BOOTSTRAP_SKIPPED', { reason: err.message });
  POLICY_FILE = null;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const POLICY_ID_RE   = /^[A-Za-z0-9_-]{1,64}$/;
// the types the store accepts ARE the types the engine can evaluate - one list (services/policy/evaluators), so a rule type added to the engine
// (DLP, ABAC, BUDGET, CONTENT_RULE, DATA_RESIDENCY, DATA_RETENTION, ...) can be created through governance and four-eyes without a second edit here.
const VALID_TYPES    = new Set(Object.keys(require('../../../services/policy/evaluators')));
const STORE_VERSION  = 1;

// ── Storage ───────────────────────────────────────────────────────────────────

function _importFromPoliciesJson(now = new Date().toISOString()) {
  // POLICY_FILE resolved to null (production, no explicit choice) — the
  // WARN explaining why was already emitted where that happened; nothing to
  // import.
  if (POLICY_FILE === null) return {};

  let doc;
  try {
    const raw = fs.readFileSync(POLICY_FILE, 'utf8');
    doc = JSON.parse(raw);
  } catch (err) {
    emit('WARN', 'POLICY_STORE_BOOTSTRAP_SKIPPED', { reason: err.message });
    return {};
  }

  if (!Array.isArray(doc.policies)) return {};

  const out = {};
  for (const p of doc.policies) {
    if (!p || typeof p.id !== 'string') continue;
    out[p.id] = _buildRecord(p, {
      name:        p.id,
      description: '',
      actor:       'system',
      comment:     'Initial import',
      now,
      version:     1,
    });
  }
  emit('INFO', 'POLICY_STORE_BOOTSTRAPPED', { count: Object.keys(out).length, source: 'POLICY_FILE' });
  return out;
}

function _seed() {
  const s = readSeed('policy');
  if (s.exists && Object.keys(s.records).length > 0) return s.records;
  if (s.exists) {
    try { const d = JSON.parse(s.raw); if (d && typeof d.policies === 'object' && !Array.isArray(d.policies)) return {}; } catch { /* corrupt: import */ }
  }
  return _importFromPoliciesJson();
}

let _enforced = null; // cached validateAndPrepare() of the whole set

const _col = new Collection('policy', { seed: _seed, onChange: () => { _enforced = null; } });
_col._afterStart = async () => {
  if (_col.rawValues().length > 0) return;
  for (const [id, rec] of Object.entries(_importFromPoliciesJson())) {
    await _col.put(id, rec, { create: true, updatedBy: 'system' }).catch(() => { /* another replica imported it */ });
  }
};

function _all() { return _col.values(); }
function _get(id) { return _col.get(id); }
function _clone(rec) { return JSON.parse(JSON.stringify(rec)); }

// ── Record construction helpers ───────────────────────────────────────────────

function _buildRecord(p, { name, description, actor, comment, now, version }) {
  const status  = p.enabled ? 'ACTIVE' : 'DISABLED';
  const snapshot = {
    id:          p.id,
    name:        name || p.id,
    description: description || '',
    type:        p.type,
    priority:    p.priority,
    enabled:     p.enabled,
    config:      p.config,
    status,
  };

  return {
    id:               p.id,
    name:             name || p.id,
    description:      description || '',
    type:             p.type,
    priority:         p.priority,
    enabled:          p.enabled,
    config:           p.config,
    status,
    currentVersion:   version,
    validationStatus: 'VALID',
    validationErrors: [],
    createdAt:        now,
    createdBy:        actor,
    updatedAt:        now,
    updatedBy:        actor,
    versions: [
      {
        v:               version,
        createdAt:       now,
        createdBy:       actor,
        summary:         comment || 'Initial version',
        snapshot:        { ...snapshot },
        validationStatus: 'VALID',
        validationErrors: [],
      },
    ],
    history: [
      {
        event:     'POLICY_IMPORTED',
        timestamp: now,
        actor,
        version,
        comment:   comment || 'Initial import',
        changes:   null,
      },
    ],
  };
}

// ── Deep diff ─────────────────────────────────────────────────────────────────

function _deepDiff(a, b, prefix) {
  prefix = prefix || '';
  const diffs = [];

  const aIsObj = a !== null && typeof a === 'object' && !Array.isArray(a);
  const bIsObj = b !== null && typeof b === 'object' && !Array.isArray(b);

  if (aIsObj && bIsObj) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const key of keys) {
      const subPath = prefix ? `${prefix}.${key}` : key;
      const hasA = Object.prototype.hasOwnProperty.call(a, key);
      const hasB = Object.prototype.hasOwnProperty.call(b, key);
      if (!hasA) {
        diffs.push({ path: subPath, op: 'ADDED', from: undefined, to: b[key] });
      } else if (!hasB) {
        diffs.push({ path: subPath, op: 'REMOVED', from: a[key], to: undefined });
      } else {
        diffs.push(..._deepDiff(a[key], b[key], subPath));
      }
    }
    return diffs;
  }

  // Primitives or arrays — compare by stable JSON representation
  const aStr = JSON.stringify(a);
  const bStr = JSON.stringify(b);
  if (aStr !== bStr) {
    diffs.push({ path: prefix || '(root)', op: 'MODIFIED', from: a, to: b });
  }
  return diffs;
}

// ── Validation helper ─────────────────────────────────────────────────────────

/**
 * Build the minimal policy doc accepted by validateAndPrepare from the current
 * store, optionally replacing or adding one policy (for candidate validation).
 */
function _buildValidationDoc(overridePolicy, excludeId) {
  const arr = [];
  for (const rec of _all()) {
    if (excludeId && rec.id === excludeId) continue;
    arr.push({
      id:       rec.id,
      type:     rec.type,
      priority: rec.priority,
      enabled:  rec.enabled,
      config:   rec.config,
    });
  }
  if (overridePolicy) {
    arr.push({
      id:       overridePolicy.id,
      type:     overridePolicy.type,
      priority: overridePolicy.priority,
      enabled:  overridePolicy.enabled,
      config:   overridePolicy.config,
    });
  }
  return { policies: arr };
}

function _validateSet(doc) {
  // Throws on failure; returns frozen array on success
  return validateAndPrepare(doc);
}

// ── Exported API ──────────────────────────────────────────────────────────────

/**
 * getDashboard()
 * Returns aggregate stats and last 10 cross-policy history events.
 */
function getDashboard() {
  const policies = _all();
  const total    = policies.length;
  const active   = policies.filter(p => p.enabled).length;
  const disabled = total - active;

  let versionCount = 0;
  const allHistory = [];
  let validationFailures = 0;

  for (const p of policies) {
    versionCount += Array.isArray(p.versions) ? p.versions.length : 0;
    if (Array.isArray(p.history)) {
      for (const h of p.history) {
        allHistory.push({ ...h, policyId: p.id, policyName: p.name });
      }
    }
    if (p.validationStatus !== 'VALID') validationFailures++;
  }

  allHistory.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  const recentChanges = allHistory.slice(0, 10);

  return { total, active, disabled, versionCount, recentChanges, validationFailures };
}

/**
 * listPolicies({ page, pageSize, status, search, sortBy, sortDir })
 */
function listPolicies({ page = 1, pageSize = 50, status, search, sortBy, sortDir } = {}) {
  let policies = _all();

  if (status === 'ACTIVE') {
    policies = policies.filter(p => p.enabled);
  } else if (status === 'DISABLED') {
    policies = policies.filter(p => !p.enabled);
  }

  if (search) {
    const q = search.toLowerCase();
    policies = policies.filter(p =>
      p.id.toLowerCase().includes(q) || (p.name || '').toLowerCase().includes(q)
    );
  }

  const field = sortBy || 'updatedAt';
  const dir   = sortDir === 'asc' ? 1 : -1;
  policies.sort((a, b) => {
    const av = a[field];
    const bv = b[field];
    if (av < bv) return -1 * dir;
    if (av > bv) return  1 * dir;
    return 0;
  });

  const total  = policies.length;
  const start  = (page - 1) * pageSize;
  const paged  = policies.slice(start, start + pageSize).map(p => ({
    id:               p.id,
    name:             p.name,
    type:             p.type,
    status:           p.status,
    enabled:          p.enabled,
    priority:         p.priority,
    currentVersion:   p.currentVersion,
    updatedAt:        p.updatedAt,
    updatedBy:        p.updatedBy,
    validationStatus: p.validationStatus,
  }));

  return { total, page, pageSize, policies: paged };
}

/**
 * getPolicy(id)
 * Returns the full record or null.
 */
function getPolicy(id) {
  if (typeof id !== 'string') return null;
  const rec = _get(id);
  if (!rec) return null;
  return JSON.parse(JSON.stringify(rec)); // deep clone, no freeze on mutable data
}

/**
 * listEnabledPolicies()
 * the live global-policy floor reads this — every currently-enabled
 * global policy, minimal shape (id/type/priority/config), deep-cloned so a
 * caller can never mutate the store through it.
 * @returns {{id:string, type:string, priority:number, config:object}[]}
 */
function listEnabledPolicies() {
  return _all()
    .filter((p) => p.enabled === true)
    .map((p) => JSON.parse(JSON.stringify({ id: p.id, type: p.type, priority: p.priority, config: p.config })));
}

/**
 * createPolicy({ id, name, description, type, priority, config, actor, comment })
 */
function createPolicy({ id, name, description, type, priority, config, actor, comment } = {}) {
  if (typeof id !== 'string' || !POLICY_ID_RE.test(id)) {
    const err = new Error('VALIDATION_FAILED: id must match /^[A-Za-z0-9_-]{1,64}$/');
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  if (_get(id)) {
    const err = new Error(`POLICY_ALREADY_EXISTS: policy "${id}" already exists`);
    err.code  = 'POLICY_ALREADY_EXISTS';
    throw err;
  }

  if (!VALID_TYPES.has(type)) {
    const err = new Error(`VALIDATION_FAILED: unknown type "${type}"`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  if (typeof priority !== 'number' || !Number.isInteger(priority) || priority < 0 || priority > 999999) {
    const err = new Error('VALIDATION_FAILED: priority must be an integer in [0, 999999]');
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    const err = new Error('VALIDATION_FAILED: config must be a plain object');
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const candidate = { id, type, priority, enabled: true, config };
  const doc = _buildValidationDoc(candidate, null);

  try {
    _validateSet(doc);
  } catch (loadErr) {
    const err = new Error(`VALIDATION_FAILED: ${loadErr.message}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const now    = new Date().toISOString();
  const _actor = actor || 'system';
  const record = _buildRecord(candidate, {
    name:        name        || id,
    description: description || '',
    actor:       _actor,
    comment:     comment     || 'Policy created',
    now,
    version:     1,
  });

  // Override the history event to POLICY_CREATED
  record.history[0].event = 'POLICY_CREATED';

  return cp.after(_col.put(id, record, { create: true, updatedBy: _actor }), () => {
    emit('INFO', 'POLICY_CREATED', { policyId: id, actor: _actor, version: 1 });
    return Object.freeze(JSON.parse(JSON.stringify(record)));
  });
}

/**
 * updatePolicy(id, updates, { actor, comment })
 * updates: { name?, description?, priority?, config? }
 */
function updatePolicy(id, updates = {}, { actor, comment } = {}) {
  const _cur = _get(id);
  const rec = _cur ? _clone(_cur) : null; // copy-on-write: the snapshot changes only after the commit
  if (!rec) {
    const err = new Error(`NOT_FOUND: policy "${id}" not found`);
    err.code  = 'NOT_FOUND';
    throw err;
  }

  const _actor   = actor || 'system';
  const now      = new Date().toISOString();
  const newName  = 'name'        in updates ? updates.name        : rec.name;
  const newDesc  = 'description' in updates ? updates.description : rec.description;
  const newPri   = 'priority'    in updates ? updates.priority    : rec.priority;
  const newConf  = 'config'      in updates ? updates.config      : rec.config;

  if ('priority' in updates) {
    if (typeof newPri !== 'number' || !Number.isInteger(newPri) || newPri < 0 || newPri > 999999) {
      const err = new Error('VALIDATION_FAILED: priority must be an integer in [0, 999999]');
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
  }

  if ('config' in updates) {
    if (newConf === null || typeof newConf !== 'object' || Array.isArray(newConf)) {
      const err = new Error('VALIDATION_FAILED: config must be a plain object');
      err.code  = 'VALIDATION_FAILED';
      throw err;
    }
  }

  const candidate = {
    id:       id,
    type:     rec.type,
    priority: newPri,
    enabled:  rec.enabled,
    config:   newConf,
  };

  const doc = _buildValidationDoc(candidate, id);
  try {
    _validateSet(doc);
  } catch (loadErr) {
    const err = new Error(`VALIDATION_FAILED: ${loadErr.message}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const prevSnapshot = {
    id:          rec.id,
    name:        rec.name,
    description: rec.description,
    type:        rec.type,
    priority:    rec.priority,
    enabled:     rec.enabled,
    config:      rec.config,
    status:      rec.status,
  };

  const newVersion = rec.currentVersion + 1;
  const status     = rec.enabled ? 'ACTIVE' : 'DISABLED';

  const newSnapshot = {
    id:          id,
    name:        newName,
    description: newDesc,
    type:        rec.type,
    priority:    newPri,
    enabled:     rec.enabled,
    config:      newConf,
    status,
  };

  const changes = _deepDiff(prevSnapshot, newSnapshot);

  const versionEntry = {
    v:               newVersion,
    createdAt:       now,
    createdBy:       _actor,
    summary:         comment || 'Policy updated',
    snapshot:        { ...newSnapshot },
    validationStatus: 'VALID',
    validationErrors: [],
  };

  const historyEntry = {
    event:     'POLICY_UPDATED',
    timestamp: now,
    actor:     _actor,
    version:   newVersion,
    comment:   comment || 'Policy updated',
    changes,
  };

  rec.name           = newName;
  rec.description    = newDesc;
  rec.priority       = newPri;
  rec.config         = newConf;
  rec.status         = status;
  rec.currentVersion = newVersion;
  rec.validationStatus = 'VALID';
  rec.validationErrors = [];
  rec.updatedAt      = now;
  rec.updatedBy      = _actor;
  rec.versions.push(versionEntry);
  rec.history.push(historyEntry);

  return cp.after(_col.put(id, rec, { updatedBy: _actor }), () => {
    emit('INFO', 'POLICY_UPDATED', { policyId: id, actor: _actor, version: newVersion, changeCount: changes.length });
    return Object.freeze(JSON.parse(JSON.stringify(rec)));
  });
}

/**
 * setEnabled(id, enabled, { actor, comment })
 */
function setEnabled(id, enabled, { actor, comment } = {}) {
  const _cur = _get(id);
  const rec = _cur ? _clone(_cur) : null; // copy-on-write: the snapshot changes only after the commit
  if (!rec) {
    const err = new Error(`NOT_FOUND: policy "${id}" not found`);
    err.code  = 'NOT_FOUND';
    throw err;
  }

  if (typeof enabled !== 'boolean') {
    const err = new Error('VALIDATION_FAILED: enabled must be a boolean');
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const _actor       = actor || 'system';
  const previousState = rec.enabled;

  // Always validate the full set with the new enabled state
  const candidate = {
    id:       rec.id,
    type:     rec.type,
    priority: rec.priority,
    enabled,
    config:   rec.config,
  };

  const doc = _buildValidationDoc(candidate, id);
  try {
    _validateSet(doc);
  } catch (loadErr) {
    const err = new Error(`VALIDATION_FAILED: ${loadErr.message}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const now        = new Date().toISOString();
  const newStatus  = enabled ? 'ACTIVE' : 'DISABLED';
  const newVersion = rec.currentVersion + 1;
  const eventName  = enabled ? 'POLICY_ENABLED' : 'POLICY_DISABLED';

  const prevSnapshot = {
    id: rec.id, name: rec.name, description: rec.description,
    type: rec.type, priority: rec.priority, enabled: rec.enabled,
    config: rec.config, status: rec.status,
  };
  const newSnapshot = { ...prevSnapshot, enabled, status: newStatus };
  const changes = _deepDiff(prevSnapshot, newSnapshot);

  const versionEntry = {
    v:               newVersion,
    createdAt:       now,
    createdBy:       _actor,
    summary:         comment || (enabled ? 'Policy enabled' : 'Policy disabled'),
    snapshot:        { ...newSnapshot },
    validationStatus: 'VALID',
    validationErrors: [],
  };

  const historyEntry = {
    event:     eventName,
    timestamp: now,
    actor:     _actor,
    version:   newVersion,
    comment:   comment || (enabled ? 'Policy enabled' : 'Policy disabled'),
    changes,
  };

  rec.enabled        = enabled;
  rec.status         = newStatus;
  rec.currentVersion = newVersion;
  rec.validationStatus = 'VALID';
  rec.validationErrors = [];
  rec.updatedAt      = now;
  rec.updatedBy      = _actor;
  rec.versions.push(versionEntry);
  rec.history.push(historyEntry);

  return cp.after(_col.put(id, rec, { updatedBy: _actor }), () => {
    emit('INFO', eventName, { policyId: id, actor: _actor, previousState, newState: enabled });
    return Object.freeze({
      previousState,
      newState:    enabled,
      changedBy:   _actor,
      timestamp:   now,
    });
  });
}

/**
 * rollbackPolicy(id, { toVersion, actor, comment })
 */
function rollbackPolicy(id, { toVersion, actor, comment } = {}) {
  const _cur = _get(id);
  const rec = _cur ? _clone(_cur) : null; // copy-on-write: the snapshot changes only after the commit
  if (!rec) {
    const err = new Error(`NOT_FOUND: policy "${id}" not found`);
    err.code  = 'NOT_FOUND';
    throw err;
  }

  const targetVersion = rec.versions.find(v => v.v === toVersion);
  if (!targetVersion) {
    const err = new Error(`VERSION_NOT_FOUND: version ${toVersion} not found for policy "${id}"`);
    err.code  = 'VERSION_NOT_FOUND';
    throw err;
  }

  const _actor    = actor || 'system';
  const snap      = targetVersion.snapshot;

  const candidate = {
    id:       id,
    type:     snap.type || rec.type,
    priority: snap.priority,
    enabled:  snap.enabled,
    config:   snap.config,
  };

  const doc = _buildValidationDoc(candidate, id);
  try {
    _validateSet(doc);
  } catch (loadErr) {
    const err = new Error(`VALIDATION_FAILED: ${loadErr.message}`);
    err.code  = 'VALIDATION_FAILED';
    throw err;
  }

  const now        = new Date().toISOString();
  const newVersion = rec.currentVersion + 1;
  const status     = snap.enabled ? 'ACTIVE' : 'DISABLED';

  const prevSnapshot = {
    id: rec.id, name: rec.name, description: rec.description,
    type: rec.type, priority: rec.priority, enabled: rec.enabled,
    config: rec.config, status: rec.status,
  };

  const restoredSnapshot = {
    id:          id,
    name:        snap.name        || rec.name,
    description: snap.description || rec.description,
    type:        snap.type        || rec.type,
    priority:    snap.priority,
    enabled:     snap.enabled,
    config:      snap.config,
    status,
  };

  const changes = _deepDiff(prevSnapshot, restoredSnapshot);

  const versionEntry = {
    v:               newVersion,
    createdAt:       now,
    createdBy:       _actor,
    summary:         comment || `Rollback to v${toVersion}`,
    snapshot:        { ...restoredSnapshot },
    validationStatus: 'VALID',
    validationErrors: [],
  };

  const historyEntry = {
    event:     'POLICY_ROLLED_BACK',
    timestamp: now,
    actor:     _actor,
    version:   newVersion,
    comment:   comment || `Rolled back to v${toVersion}`,
    changes,
  };

  rec.name           = restoredSnapshot.name;
  rec.description    = restoredSnapshot.description;
  rec.priority       = restoredSnapshot.priority;
  rec.enabled        = restoredSnapshot.enabled;
  rec.config         = restoredSnapshot.config;
  rec.status         = status;
  rec.currentVersion = newVersion;
  rec.validationStatus = 'VALID';
  rec.validationErrors = [];
  rec.updatedAt      = now;
  rec.updatedBy      = _actor;
  rec.versions.push(versionEntry);
  rec.history.push(historyEntry);

  return cp.after(_col.put(id, rec, { updatedBy: _actor }), () => {
    emit('INFO', 'POLICY_ROLLED_BACK', {
      policyId:       id,
      actor:          _actor,
      rolledBackTo:   toVersion,
      newVersion,
    });
    return Object.freeze(JSON.parse(JSON.stringify(rec)));
  });
}

/**
 * getVersions(id)
 * Returns array of version metadata (no snapshot) or null if policy not found.
 */
function getVersions(id) {
  if (typeof id !== 'string') return null;
  const rec = _get(id);
  if (!rec) return null;
  return (rec.versions || []).map(v => ({
    v:               v.v,
    createdAt:       v.createdAt,
    createdBy:       v.createdBy,
    summary:         v.summary,
    validationStatus: v.validationStatus,
    validationErrors: v.validationErrors,
  }));
}

/**
 * getVersion(id, v)
 * Returns single version object including snapshot or null.
 */
function getVersion(id, v) {
  if (typeof id !== 'string') return null;
  const rec = _get(id);
  if (!rec) return null;
  const found = (rec.versions || []).find(ver => ver.v === v);
  return found ? JSON.parse(JSON.stringify(found)) : null;
}

/**
 * getHistory(id)
 * Returns array of history events or null.
 */
function getHistory(id) {
  if (typeof id !== 'string') return null;
  const rec = _get(id);
  if (!rec) return null;
  return JSON.parse(JSON.stringify(rec.history || []));
}

const DATA_RETENTION_NOT_APPLIED_WARNING = 'DATA_RETENTION is stored and hashed but is not applied automatically: no request stage or job applies it, so this rule does not change retention until an operator applies it (docs/ROADMAP.md)';

/**
 * validatePolicyCandidate(candidate, currentId)
 * Validates a candidate policy object in context of the full policy set.
 * If currentId is provided, the existing policy with that id is replaced by candidate.
 *
 * Returns: { valid, errors, warnings, score (0-100) }
 */
function validatePolicyCandidate(candidate, currentId) {
  const errors   = [];
  const warnings = [];

  // Basic structural checks first
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    errors.push('candidate must be a plain object');
    return { valid: false, errors, warnings, score: 0 };
  }

  if (typeof candidate.id !== 'string' || !POLICY_ID_RE.test(candidate.id)) {
    errors.push('id must match /^[A-Za-z0-9_-]{1,64}$/');
  }

  if (!VALID_TYPES.has(candidate.type)) {
    errors.push(`type "${candidate.type}" is not a valid policy type`);
  }

  if (typeof candidate.priority !== 'number' || !Number.isInteger(candidate.priority)
      || candidate.priority < 0 || candidate.priority > 999999) {
    errors.push('priority must be an integer in [0, 999999]');
  }

  if (typeof candidate.enabled !== 'boolean') {
    errors.push('enabled must be a boolean');
  }

  if (candidate.config === null || typeof candidate.config !== 'object' || Array.isArray(candidate.config)) {
    errors.push('config must be a plain object');
  }

  // Warnings — advisory checks
  if (typeof candidate.priority === 'number' && candidate.priority === 0) {
    warnings.push('priority 0 gives this policy highest precedence; confirm this is intentional');
  }

  // Audit remediation 2026-10-27: DATA_RETENTION is validated and hashed like every rule, but nothing in the request path or a scheduled job calls
  // dataGovernance/categories.applyRetention, so the rule does not change what is kept. Say so wherever a candidate is validated.
  if (candidate.type === 'DATA_RETENTION') {
    warnings.push(DATA_RETENTION_NOT_APPLIED_WARNING);
  }

  if (candidate.enabled === false && candidate.type === 'REQUIRE_CONSENT') {
    // Check if there's at least one other enabled REQUIRE_CONSENT
    const others = _all().filter(p =>
      p.id !== (currentId || candidate.id) && p.type === 'REQUIRE_CONSENT' && p.enabled
    );
    if (others.length === 0) {
      warnings.push('disabling this REQUIRE_CONSENT policy will leave no active consent enforcement');
    }
  }

  // If no structural errors, try full validation through the loader
  if (errors.length === 0) {
    const doc = _buildValidationDoc(candidate, currentId || null);
    try {
      _validateSet(doc);
    } catch (loadErr) {
      errors.push(loadErr.message.replace(/^PolicyLoader:\s*/i, ''));
    }
  }

  const valid = errors.length === 0;

  // Score: start at 100, deduct for errors and warnings
  let score = 100;
  score -= errors.length   * 20;
  score -= warnings.length * 5;
  if (score < 0) score = 0;

  return { valid, errors, warnings, score };
}

/**
 * enforcedPolicies()
 * the enforced global policy set — validateAndPrepare() over the
 * store's current records, cached until the next applied change (local or
 * pulled). This replaces loading POLICY_FILE once per process: every replica
 * enforces what the control plane holds. Throws (fail closed) if the set does
 * not validate, or (pg) if the snapshot is stale.
 */
function enforcedPolicies() {
  const all = _all(); // freshness-checked
  if (_enforced) return _enforced;
  _enforced = validateAndPrepare({
    policies: all.map(p => ({ id: p.id, type: p.type, priority: p.priority, enabled: p.enabled, config: p.config })),
  });
  return _enforced;
}

/**
 * writePoliciesJson()
 * the running system no longer writes policies.json. This is kept
 * for offline dev tooling only (memory mode, never production): it writes the
 * clean { id, type, priority, enabled, config } list to POLICY_FILE.
 */
function writePoliciesJson() {
  if (process.env.NODE_ENV === 'production' || cp.isPg()) {
    throw new Error('writePoliciesJson refused: POLICY_FILE is import-only; policy state lives in the control plane');
  }
  if (POLICY_FILE === null) return;
  const clean = _all().map(p => ({
    id:       p.id,
    type:     p.type,
    priority: p.priority,
    enabled:  p.enabled,
    config:   p.config,
  }));
  fs.mkdirSync(path.dirname(POLICY_FILE), { recursive: true });
  fs.writeFileSync(POLICY_FILE, JSON.stringify({ policies: clean }, null, 2), 'utf8');
  emit('INFO', 'POLICIES_JSON_WRITTEN', { count: clean.length });
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }
function _reset() { _col._reset(); }

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  getDashboard,
  listPolicies,
  listEnabledPolicies,
  getPolicy,
  createPolicy,
  updatePolicy,
  setEnabled,
  rollbackPolicy,
  getVersions,
  getVersion,
  getHistory,
  validatePolicyCandidate,
  writePoliciesJson,
  enforcedPolicies,
  exportSeedFixture,
  _reset,
  // scripts/controlPlane/import.js: POLICY_FILE-derived records with a fixed timestamp (idempotent import)
  importRecordsFromPolicyFile: (nowIso) => _importFromPoliciesJson(nowIso),
  policyFilePath: () => POLICY_FILE,
};
