'use strict';

/**
 * QODIQA — Tenant Registry (Component #39 upgrade).
 *
 * Tenants must be explicitly registered before their artifacts can be validated.
 * The clientId IS the tenantId — pulled from the publicKeyId prefix.
 *
 * Component #39 additions:
 *   • organizationId — owning organization (set after org assignment)
 *   • quotas/limits  — per-tenant overrides (fall through to org quotas if absent)
 *   • status         — 'active' | 'suspended' | 'disabled' (extended from 'inactive')
 *   • updateTenant() — mutable lifecycle transitions
 *
 * Storage: the control plane (src/core/controlPlane) — PostgreSQL
 * in production, so a suspension on one replica is enforced by
 * assertActiveTenant() on every replica within the 5 s bound (or that replica
 * refuses with CONTROL_PLANE_STALE), and no replica's later write can bring a
 * suspended tenant back. The legacy data/tenants.json (TENANT_STORE_PATH) is
 * import-only: dev/test memory mode seeds from it once and never writes it
 * (it used to be rewritten whole, best-effort, errors swallowed).
 *
 * Mutators return synchronously in memory mode and a Promise in pg mode.
 * _reset() is provided for test isolation — never call in production.
 */

const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { readSeed } = require('../controlPlane/seed');

const TENANT_ID_RE    = /^[A-Za-z0-9_-]{1,64}$/;
const VALID_STATUSES  = new Set(['active', 'suspended', 'disabled', 'inactive']);

function _normalize(t) {
  return Object.freeze({
    tenantId:       t.tenantId,
    tenantName:     typeof t.tenantName === 'string' ? t.tenantName : t.tenantId,
    organizationId: typeof t.organizationId === 'string' ? t.organizationId : null,
    status:         VALID_STATUSES.has(t.status) ? t.status : 'active',
    quotas:         (t.quotas && typeof t.quotas === 'object') ? { ...t.quotas } : null,
    // (V2-FREEZE 7.3): lowest protocol version this tenant accepts; stored in the signed control plane
    minProtocolVersion: t.minProtocolVersion === 2 ? 2 : 1,
    createdAt:      t.createdAt || new Date().toISOString(),
    updatedAt:      t.updatedAt || new Date().toISOString(),
  });
}

function _seed() {
  const out = {};
  for (const [id, t] of Object.entries(readSeed('tenant').records)) {
    if (TENANT_ID_RE.test(id)) out[id] = _normalize(t);
  }
  return out;
}

// tenantId → { tenantId, tenantName, organizationId, status, quotas, createdAt, updatedAt }
const _col = new Collection('tenant', { seed: _seed });

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Register a tenant.  Idempotent — registering the same tenantId again is a no-op.
 *
 * @param {string} tenantId
 * @param {{
 *   tenantName?:     string
 *   organizationId?: string
 *   status?:         'active' | 'suspended' | 'disabled'
 *   quotas?:         object
 * }} [opts]
 * @returns {object | Promise<object>} The tenant record
 * @throws {Error} if tenantId format is invalid
 */
function registerTenant(tenantId, opts = {}) {
  if (typeof tenantId !== 'string' || !TENANT_ID_RE.test(tenantId)) {
    throw new Error(`TENANT_CONTEXT_MISSING: tenantId "${tenantId}" is invalid or missing`);
  }

  // pg: a registration may arrive before the replica's first pull (the key
  // store registers a tenant when it provisions a key at boot) — start first,
  // then decide on the authoritative snapshot, never on an empty one.
  if (cp.isPg()) {
    return cp.start().then(() => _register(tenantId, opts)).then((r) => r);
  }
  return _register(tenantId, opts);
}

function _register(tenantId, opts) {
  const existing = _col.get(tenantId);
  if (existing) return existing;

  const now    = new Date().toISOString();
  const status = VALID_STATUSES.has(opts.status) ? opts.status : 'active';

  const record = Object.freeze({
    tenantId,
    tenantName:     (typeof opts.tenantName === 'string' && opts.tenantName) ? opts.tenantName : tenantId,
    organizationId: (typeof opts.organizationId === 'string' && opts.organizationId) ? opts.organizationId : null,
    status,
    quotas:         (opts.quotas && typeof opts.quotas === 'object') ? { ...opts.quotas } : null,
    createdAt:      now,
    updatedAt:      now,
  });

  const r = _col.put(tenantId, record, { create: true });
  if (r && typeof r.then === 'function') {
    // Another replica registered it first: the registration is idempotent, so
    // the authoritative row (pulled by the conflict) is the answer.
    return r.catch((err) => {
      if (err && err.code === 'CONTROL_PLANE_VERSION_CONFLICT') {
        return cp.syncNow().then(() => _col.get(tenantId) || Promise.reject(err));
      }
      throw err;
    });
  }
  return r;
}

/**
 * Update a tenant's mutable fields.
 * Immutable fields (tenantId, createdAt) are ignored.
 *
 * @param {string} tenantId
 * @param {{ tenantName?, organizationId?, status?, quotas?, minProtocolVersion? }} updates
 * @returns {object|null|Promise<object|null>} Updated record, or null if tenant not found
 * @throws {Error} if status is not a valid value
 */
function updateTenant(tenantId, updates = {}) {
  const existing = _col.get(tenantId);
  if (!existing) return null;

  const mutable = { ...existing };

  if (typeof updates.tenantName === 'string' && updates.tenantName) {
    mutable.tenantName = updates.tenantName;
  }
  if (typeof updates.organizationId === 'string') {
    mutable.organizationId = updates.organizationId || null;
  }
  if (updates.status !== undefined) {
    if (!VALID_STATUSES.has(updates.status)) {
      throw new Error(`INVALID_TENANT_STATUS: status must be one of: ${[...VALID_STATUSES].join(', ')}`);
    }
    mutable.status = updates.status;
  }
  if (updates.quotas && typeof updates.quotas === 'object') {
    mutable.quotas = { ...(existing.quotas || {}), ...updates.quotas };
  }
  if (updates.minProtocolVersion !== undefined) {
    if (updates.minProtocolVersion !== 1 && updates.minProtocolVersion !== 2) throw new Error('INVALID_MIN_PROTOCOL_VERSION: minProtocolVersion must be 1 or 2');
    mutable.minProtocolVersion = updates.minProtocolVersion;
  }
  mutable.updatedAt = new Date().toISOString();

  const updated = Object.freeze(mutable);
  return _col.put(tenantId, updated);
}

/**
 * Retrieve a tenant record by tenantId.
 *
 * @param {string} tenantId
 * @returns {object|null}
 */
function getTenant(tenantId) {
  if (typeof tenantId !== 'string' || !tenantId) return null;
  return _col.get(tenantId);
}

/**
 * Assert that a tenant is known and active.
 * 'suspended' and 'disabled' statuses both block execution.
 *
 * @param {string} tenantId
 * @returns {{ valid: true, tenant: object } | { valid: false, reason: string }}
 */
function assertActiveTenant(tenantId) {
  if (typeof tenantId !== 'string' || !tenantId) {
    return { valid: false, reason: 'TENANT_CONTEXT_MISSING' };
  }

  const tenant = _col.get(tenantId);
  if (!tenant) {
    return { valid: false, reason: 'TENANT_UNKNOWN' };
  }

  if (tenant.status === 'suspended') {
    return { valid: false, reason: 'TENANT_SUSPENDED' };
  }
  if (tenant.status === 'disabled' || tenant.status === 'inactive') {
    return { valid: false, reason: 'TENANT_INACTIVE' };
  }
  if (tenant.status !== 'active') {
    return { valid: false, reason: 'TENANT_INACTIVE' };
  }

  return { valid: true, tenant };
}

/**
 * Return all registered tenants as an array.
 *
 * @returns {Array<object>}
 */
function listTenants() {
  return _col.values();
}

/**
 * Return the number of registered tenants.
 */
function tenantCount() {
  return _col.size();
}

/**
 * Clear all tenant registrations.  TEST USE ONLY.
 */
function _reset() {
  _col._reset();
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }

module.exports = {
  registerTenant,
  updateTenant,
  getTenant,
  assertActiveTenant,
  listTenants,
  tenantCount,
  _reset,
  exportSeedFixture,
};
