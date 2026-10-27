'use strict';

/**
 * QODIQA — Organization Registry (Component #39).
 *
 * An Organization is the top-level billing and administrative entity above
 * tenants.  One organization owns one or more tenants; a tenant belongs to
 * exactly one organization.
 *
 * Data model:
 *   organizationId   — UUID v4, immutable primary key
 *   organizationName — Human-readable display name (mutable)
 *   status           — 'active' | 'suspended' | 'disabled'
 *   createdAt        — ISO-8601 creation timestamp
 *   updatedAt        — ISO-8601 last-modified timestamp
 *   metadata         — Arbitrary key/value pairs (mutable)
 *   quotas           — Per-org limits enforced at request time
 *   tenantIds        — Set of tenantIds owned by this org
 *
 * Quotas enforced by the enforcement pipeline:
 *   maxRequestsPerMinute  — per-org global anomaly window ceiling
 *   maxRequestsPerKeyPerMin — per-key anomaly window ceiling
 *   maxStreamingSessions  — concurrent SSE sessions
 *   retentionDays         — audit log retention period
 *
 * Storage: the control plane (src/core/controlPlane) — PostgreSQL
 * in production (every field, including status), with a per-replica snapshot
 * refused once stale (5 s). The legacy data/organizations.json (ORG_STORE_PATH)
 * is import-only: dev/test memory mode seeds from it once and never writes it.
 * Mutators return synchronously in memory mode and a Promise in pg mode.
 *
 * ── bounded multi-worker status propagation ──────────────────────────
 *
 * The in-memory Map above is process-local: in a multi-worker deployment,
 * each worker has its own copy, and historically nothing ever reconciled
 * them (the JSON file is loaded once at module load and never re-read).
 * A suspension applied on one worker was therefore never observed by any
 * other worker short of a process restart.
 *
 * `status` specifically (the field that gates request execution) is now
 * additionally synchronized through a Redis-backed authoritative store with
 * bounded propagation — see src/core/organizations/status/*.js. All other
 * fields (name, quotas, metadata, tenant assignments) remain owned solely by
 * this process-local registry, unchanged.
 *
 * assertActiveOrganization() below consults the injected OrgStatusSubscriber's
 * isReady() and a per-org freshness timestamp before trusting a cached
 * `status`; see that function's comments and docs/architecture/multi-tenancy.md for the
 * full consistency model, the documented maximum propagation delay, and
 * fail-closed behavior.
 *
 * ── Dependency inversion (Finding 64 /) ────────────────────────────────
 *
 * This module and OrgStatusSubscriber.js used to require() each other
 * directly, forming a circular dependency papered over with lazy in-function
 * require() calls. That cycle is now broken: OrgStatusSubscriber is never
 * require()'d here. The composition root (server.js) wires the two modules
 * together after both are loaded via setOrgStatusSubscriber() below (mirrors
 * setKeyInfoResolver() in src/infra/postgres/pg-audit-backend.js). Until
 * wired, the subscriber is treated exactly like "never started" — this is
 * what preserves 100% backward compatibility for tests and minimal
 * deployments that never call setOrgStatusSubscriber().
 *
 * _applyRemoteStatus() / _touchStatusFreshness() are called ONLY by
 * OrgStatusSubscriber (pub/sub message handler + reconciliation sweep) —
 * never call them directly.
 *
 * _reset() is provided for test isolation — never call in production.
 */

const crypto = require('crypto');
const orgStatusMetrics = require('./status/OrgStatusMetrics');
const _orgStatusClock = require('./status/orgStatusClock'); // monotonic freshness stamps
const { emit } = require('../../../services/logger');
const cp = require('../controlPlane');
const { Collection } = require('../controlPlane/collection');
const { readSeed } = require('../controlPlane/seed');

const ORG_ID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ORG_NAME_RE = /^[\w\s\-_.]{1,128}$/;
const VALID_STATUSES = new Set(['active', 'suspended', 'disabled']);

// ── State ────────────────────────────────────────────────────────────────────
// Records (organizationId → { organizationId, organizationName, status,
// createdAt, updatedAt, metadata, quotas, tenantIds: string[] }) live in the
// collection declared below; tenantId → organizationId is a derived index.
const _tenantOrgIndex = new Map();

// organizationId → { syncedAt: ms, updatedAt: ms } — bounded-
// propagation freshness tracking for the `status` field. syncedAt is when
// THIS worker last confirmed status against the shared authoritative store
// (pub/sub push or reconciliation sweep); updatedAt is the authoritative
// event's own timestamp, used as a monotonic guard against out-of-order
// delivery. Populated only by OrgStatusSubscriber.
const _statusFreshness = new Map();

// Injected by the composition root (server.js) via setOrgStatusSubscriber(),
// AFTER both this module and OrgStatusSubscriber have been require()'d —
// replaces the former lazy require() cycle. null until wired, which is
// treated identically to "subscriber never started" (see
// assertActiveOrganization() below).
let _orgStatusSubscriber = null;

/**
 * Inject the OrgStatusSubscriber instance used by assertActiveOrganization()
 * to gate on bounded-propagation readiness/freshness. Called once, at
 * startup, by the composition root — never by this module or
 * OrgStatusSubscriber itself.
 *
 * @param {{ isStarted: () => boolean, isReady: () => boolean, MAX_PROPAGATION_WINDOW_MS: number }} instance
 */
function setOrgStatusSubscriber(instance) {
  _orgStatusSubscriber = instance;
}

// ── Default quotas applied to all new organizations ─────────────────────────

const DEFAULT_QUOTAS = Object.freeze({
  maxRequestsPerMinute:    5_000,
  maxRequestsPerKeyPerMin: 100,
  maxStreamingSessions:    500,
  retentionDays:           365,
});

// ── Storage ──────────────────────────────────────────────────────────────────

function _normalize(o) {
  return Object.freeze({
    organizationId:   o.organizationId,
    organizationName: o.organizationName || o.organizationId,
    status:           VALID_STATUSES.has(o.status) ? o.status : 'active',
    createdAt:        o.createdAt || new Date().toISOString(),
    updatedAt:        o.updatedAt || new Date().toISOString(),
    metadata:         (o.metadata && typeof o.metadata === 'object') ? o.metadata : {},
    quotas:           { ...DEFAULT_QUOTAS, ...(o.quotas || {}) },
    tenantIds:        Object.freeze([...new Set(Array.isArray(o.tenantIds) ? o.tenantIds : [])]),
  });
}

function _rebuildIndex() {
  _tenantOrgIndex.clear();
  for (const o of _col.rawValues()) {
    for (const tid of (o.tenantIds || [])) _tenantOrgIndex.set(tid, o.organizationId);
  }
}

const _col = new Collection('organization', {
  seed: () => {
    const out = {};
    for (const [id, o] of Object.entries(readSeed('organization').records)) out[id] = _normalize(o);
    return out;
  },
  onChange: () => _rebuildIndex(),
});

function _view(o) { return { ...o, tenantIds: Array.from(o.tenantIds || []) }; }

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Register a new organization.
 *
 * @param {{
 *   organizationId?:   string   // if omitted, a UUID v4 is generated
 *   organizationName?: string
 *   status?:           'active' | 'suspended' | 'disabled'
 *   metadata?:         object
 *   quotas?:           object
 * }} opts
 * @returns {{ organizationId, organizationName, status, createdAt, updatedAt, metadata, quotas, tenantIds }}
 * @throws {Error} if organizationId is provided and already registered
 */
function registerOrganization(opts = {}) {
  const orgId = typeof opts.organizationId === 'string' && ORG_ID_RE.test(opts.organizationId)
    ? opts.organizationId
    : crypto.randomUUID();

  const existing = _col.get(orgId);
  if (existing) {
    return _view(existing);
  }

  const now    = new Date().toISOString();
  const record = {
    organizationId:   orgId,
    organizationName: (typeof opts.organizationName === 'string' && ORG_NAME_RE.test(opts.organizationName))
      ? opts.organizationName
      : orgId,
    status:    VALID_STATUSES.has(opts.status) ? opts.status : 'active',
    createdAt: now,
    updatedAt: now,
    metadata:  (opts.metadata && typeof opts.metadata === 'object') ? { ...opts.metadata } : {},
    quotas:    { ...DEFAULT_QUOTAS, ...(opts.quotas || {}) },
    tenantIds: Object.freeze([]),
  };

  return cp.after(_col.put(orgId, Object.freeze(record), { create: true }), () => _view(record));
}

/**
 * Retrieve an organization by ID.
 *
 * @param {string} organizationId
 * @returns {object|null}
 */
function getOrganization(organizationId) {
  if (typeof organizationId !== 'string' || !organizationId) return null;
  const o = _col.get(organizationId);
  if (!o) return null;
  return _view(o);
}

/**
 * Update an organization's mutable fields.
 * Immutable fields (organizationId, createdAt) are silently ignored.
 *
 * @param {string} organizationId
 * @param {{ organizationName?, status?, metadata?, quotas? }} updates
 * @returns {object|null} Updated record, or null if not found
 * @throws {Error} if status is invalid
 */
function updateOrganization(organizationId, updates = {}) {
  const current = _col.get(organizationId);
  if (!current) return null;
  const record = { ...current };

  if (typeof updates.organizationName === 'string' && ORG_NAME_RE.test(updates.organizationName)) {
    record.organizationName = updates.organizationName;
  }
  if (updates.status !== undefined) {
    if (!VALID_STATUSES.has(updates.status)) {
      throw new Error(`INVALID_ORG_STATUS: status must be one of: ${[...VALID_STATUSES].join(', ')}`);
    }
    record.status = updates.status;
  }
  if (updates.metadata && typeof updates.metadata === 'object') {
    record.metadata = { ...record.metadata, ...updates.metadata };
  }
  if (updates.quotas && typeof updates.quotas === 'object') {
    record.quotas = { ...record.quotas, ...updates.quotas };
  }
  record.updatedAt = new Date().toISOString();
  return cp.after(_col.put(organizationId, Object.freeze(record)), () => _view(record));
}

/**
 * Change an organization's status AND durably propagate that change to
 * every other worker in the deployment, bounded per status/OrgStatusSubscriber.js
 *. This is the only supported way to change `status` in production
 * — updateOrganization() above still exists (and is still used directly for
 * organizationName/metadata/quotas, and by tests), but a bare
 * updateOrganization({status}) call only updates THIS process; it does not
 * write through to the shared authoritative store, so other workers would
 * never observe it.
 *
 * @param {string} organizationId
 * @param {string} status — 'active' | 'suspended' | 'disabled'
 * @param {{ updatedBy?: string|null, correlationId?: string|null }} [opts]
 * @returns {Promise<object>} the updated organization record
 * @throws {Error} INVALID_ORG_STATUS, ORG_NOT_FOUND, or
 *   ORG_STATUS_PROPAGATION_UNAVAILABLE if the change could not be durably
 *   written to the shared store — callers (the admin API) MUST treat this as
 *   a failed request, not a partial success, since other workers would
 *   otherwise never learn of the change.
 */
async function publishOrganizationStatus(organizationId, status, { updatedBy = null, correlationId = null } = {}) {
  if (!VALID_STATUSES.has(status)) {
    throw new Error(`INVALID_ORG_STATUS: status must be one of: ${[...VALID_STATUSES].join(', ')}`);
  }
  if (!_col.get(organizationId)) {
    throw new Error('ORG_NOT_FOUND');
  }

  // with the PostgreSQL control plane, PostgreSQL is the single
  // authority for status too. Write it FIRST (versioned); every replica pulls
  // it within the 5 s bound. The Redis store/channel is then fed as
  // before, but only for its readiness/freshness gate — _applyRemoteStatus()
  // no longer changes the status value in pg mode, so a Redis write that
  // fails or lags can never revert a committed PostgreSQL status.
  if (cp.isPg()) {
    const updated = await updateOrganization(organizationId, { status });
    try {
      const publisher = /** @type {any} */ (require('./status/OrgStatusPublisher'));
      const { updatedAt } = await publisher.publishStatusChange({ organizationId, status, updatedBy, correlationId, minUpdatedAt: _nextStatusStampFloor(organizationId) });
      _touchStatusFreshness(organizationId, updatedAt);
    } catch (err) {
      emit('WARN', 'ORG_STATUS_REDIS_PUBLISH_FAILED', {
        organizationId, status, error: err.message,
        message: 'Status committed to PostgreSQL (authoritative); the Redis channel was not updated.',
      });
    }
    return updated;
  }

  // Propagate FIRST: if the shared authoritative write fails, this throws
  // and local state is left untouched — we never want THIS worker to show
  // one answer while the rest of the cluster is stuck on the old value.
  const publisher = require('./status/OrgStatusPublisher');
  const { updatedAt } = await publisher.publishStatusChange({ organizationId, status, updatedBy, correlationId, minUpdatedAt: _nextStatusStampFloor(organizationId) });

  const updated = await updateOrganization(organizationId, { status });
  _touchStatusFreshness(organizationId, updatedAt);
  return updated;
}

/**
 * Apply a status update received from the org-status pub/sub channel or a
 * reconciliation sweep. Called ONLY by OrgStatusSubscriber — never call
 * this directly; it bypasses validation-by-exception (invalid input is
 * silently ignored, not thrown) because it processes untrusted network
 * input, not a direct API call.
 *
 * Monotonic guard: an incoming update strictly OLDER than the last-applied
 * one for this org is ignored — protects against out-of-order pub/sub
 * delivery or a reconciliation sweep racing a fresher push (
 * race-condition requirement). Millisecond timestamps can genuinely tie
 * under real concurrency (Date.now() resolution), so an update with the
 * SAME updatedAtMs as the prior one is still applied — a single Redis
 * channel delivers messages to every subscriber in the same order, so
 * "last one processed wins" on a tie is a consistent, cluster-wide
 * tie-break, not an arbitrary per-worker one.
 *
 * @param {string} organizationId
 * @param {string} status
 * @param {number} updatedAtMs
 * @returns {boolean} true if applied, false if ignored (invalid/stale)
 */
function _applyRemoteStatus(organizationId, status, updatedAtMs) {
  if (!VALID_STATUSES.has(status)) return false;
  if (typeof updatedAtMs !== 'number' || !Number.isFinite(updatedAtMs)) return false;

  const prior = _statusFreshness.get(organizationId);
  if (prior && prior.updatedAt > updatedAtMs) return false;

  _statusFreshness.set(organizationId, { syncedAt: _orgStatusClock.now(), updatedAt: updatedAtMs }); // monotonic

  // pg: the status value comes from PostgreSQL (see publishOrganizationStatus).
  if (cp.isPg()) return true;

  const record = _col.rawValues().find((o) => o.organizationId === organizationId);
  if (record && record.status !== status) {
    _col.put(organizationId, Object.freeze({ ...record, status, updatedAt: new Date(updatedAtMs).toISOString() }));
  }
  return true;
}

// the floor for a new status stamp — one past the last updatedAt this worker applied
// for the organization, so a backward Date.now() step can never produce a stamp every worker drops as stale.
function _nextStatusStampFloor(organizationId) {
  const prior = _statusFreshness.get(organizationId);
  return prior ? prior.updatedAt + 1 : 0;
}

/**
 * Mark this worker's knowledge of organizationId's status as confirmed
 * current as of updatedAtMs, WITHOUT changing the locally-cached status
 * value. Used when a reconciliation sweep discovers an org that Redis
 * doesn't know about yet (this worker's local status becomes the seed).
 * Same monotonic guard as _applyRemoteStatus.
 *
 * @param {string} organizationId
 * @param {number} updatedAtMs
 */
function _touchStatusFreshness(organizationId, updatedAtMs) {
  const prior = _statusFreshness.get(organizationId);
  if (prior && prior.updatedAt > updatedAtMs) return;
  _statusFreshness.set(organizationId, { syncedAt: _orgStatusClock.now(), updatedAt: updatedAtMs }); // monotonic
}

/**
 * Assign a tenant to an organization.
 * A tenant can belong to exactly one organization — re-assigning is blocked
 * unless the tenant is first removed from its current organization.
 *
 * @param {string} tenantId
 * @param {string} organizationId
 * @throws {Error} if organization not found, or tenant already assigned to a different org
 */
function assignTenantToOrg(tenantId, organizationId) {
  if (typeof tenantId !== 'string' || !tenantId) {
    throw new Error('INVALID_TENANT_ID');
  }

  const record = _col.get(organizationId);
  if (!record) throw new Error('ORG_NOT_FOUND');

  const currentOrg = _tenantOrgIndex.get(tenantId);
  if (currentOrg && currentOrg !== organizationId) {
    throw new Error(`TENANT_ALREADY_ASSIGNED: tenant "${tenantId}" already belongs to org "${currentOrg}"`);
  }
  if (record.tenantIds.includes(tenantId)) return undefined;

  return cp.after(_col.put(organizationId, Object.freeze({
    ...record, tenantIds: Object.freeze([...record.tenantIds, tenantId]), updatedAt: new Date().toISOString(),
  })), () => undefined);
}

/**
 * Remove a tenant from an organization.
 *
 * @param {string} tenantId
 * @param {string} organizationId
 * @returns {boolean} true if the tenant was removed, false if not found
 */
function removeTenantFromOrg(tenantId, organizationId) {
  const record = _col.get(organizationId);
  if (!record) return false;
  if (!record.tenantIds.includes(tenantId)) return false;

  return cp.after(_col.put(organizationId, Object.freeze({
    ...record, tenantIds: Object.freeze(record.tenantIds.filter((t) => t !== tenantId)), updatedAt: new Date().toISOString(),
  })), () => true);
}

/**
 * Resolve the organization for a given tenantId.
 *
 * @param {string} tenantId
 * @returns {object|null} Organization record or null if not assigned
 */
function getOrganizationForTenant(tenantId) {
  if (typeof tenantId !== 'string' || !tenantId) return null;
  _col.ensure();
  const orgId = _tenantOrgIndex.get(tenantId);
  if (!orgId) return null;
  return getOrganization(orgId);
}

/**
 * Assert that the organization owning a tenant is active.
 * If the tenant has no organization assignment, this is a no-op (passes).
 * This preserves backward compatibility for pre-existing tenants not yet
 * assigned to an organization.
 *
 * before trusting the locally-cached `status`, this also enforces
 * the bounded-propagation guarantee documented in status/OrgStatusSubscriber.js:
 *   - If the org-status subscriber has been started but is not currently
 *     connected, the request is denied (ORG_STATUS_SYNC_UNAVAILABLE) —
 *     unknown status must never result in EXECUTE.
 *   - If this worker's last confirmed sync for this org is older than the
 *     documented maximum propagation window, the request is denied
 *     (ORG_STATUS_STALE) rather than trusting expired state.
 *   Both checks are skipped entirely if no subscriber has been injected via
 *   setOrgStatusSubscriber(), or it was injected but never started
 *   (isStarted() === false) — this is what keeps unit tests and minimal
 *   deployments that don't wire up the Redis-backed subscriber behaving
 *   exactly as before this remediation.
 *
 * @param {string} tenantId
 * @returns {{ valid: true, organizationId: string|null } | { valid: false, reason: string }}
 */
function assertActiveOrganization(tenantId) {
  if (typeof tenantId !== 'string' || !tenantId) {
    return { valid: false, reason: 'TENANT_CONTEXT_MISSING' };
  }

  _col.ensure();
  const orgId = _tenantOrgIndex.get(tenantId);
  if (!orgId) {
    // Tenant has no org assignment — allow (backward compatibility for
    // pre-existing tenants provisioned before Component #39).
    return { valid: true, organizationId: null };
  }

  const org = _col.get(orgId);
  if (!org) {
    // Index references a deleted org — treat as unassigned (allow).
    return { valid: true, organizationId: null };
  }

  const sub = _orgStatusSubscriber;
  if (sub && sub.isStarted()) {
    if (!sub.isReady()) {
      orgStatusMetrics.staleDenials.inc({ reason: 'sync_unavailable' });
      return { valid: false, reason: 'ORG_STATUS_SYNC_UNAVAILABLE' };
    }
    const freshness = _statusFreshness.get(orgId);
    const syncedAt  = freshness ? freshness.syncedAt : 0;
    const age = _orgStatusClock.now() - syncedAt; // same clock as syncedAt / connectedSince / lastSweepFailureAt
    if (age > sub.MAX_PROPAGATION_WINDOW_MS) {
      // a merely LATE sweep under CPU saturation must not deny a healthy tenant. Grace only when
      // the subscription has been connected continuously since this org's last confirmation and no sweep has failed
      // since (see OrgStatusSubscriber GRACE_MS). A never-synced org, a reconnect, or a failed sweep keeps the
      // strict bound exactly as before.
      const g = typeof sub.graceState === 'function' ? sub.graceState() : null;
      const graced = !!g && syncedAt > 0 && g.graceMs > 0
        && g.connectedSince > 0 && g.connectedSince <= syncedAt
        && g.lastSweepFailureAt < syncedAt
        && age <= sub.MAX_PROPAGATION_WINDOW_MS + g.graceMs;
      if (!graced) {
        orgStatusMetrics.staleDenials.inc({ reason: 'stale' });
        return { valid: false, reason: 'ORG_STATUS_STALE' };
      }
      orgStatusMetrics.staleGraceAllowed.inc();
    }
  }

  if (org.status === 'suspended') {
    return { valid: false, reason: 'ORG_SUSPENDED' };
  }
  if (org.status === 'disabled') {
    return { valid: false, reason: 'ORG_DISABLED' };
  }

  return { valid: true, organizationId: orgId };
}

/**
 * Retrieve the effective quota thresholds for a tenant.
 * Returns org-level quotas if the tenant is assigned to an org,
 * otherwise returns the platform defaults.
 *
 * @param {string} tenantId
 * @returns {{ maxRequestsPerMinute, maxRequestsPerKeyPerMin, maxStreamingSessions, retentionDays }}
 */
function getQuotasForTenant(tenantId) {
  _col.ensure();
  const orgId = (typeof tenantId === 'string') ? _tenantOrgIndex.get(tenantId) : null;
  if (orgId) {
    const org = _col.get(orgId);
    if (org) return { ...org.quotas };
  }
  return { ...DEFAULT_QUOTAS };
}

/**
 * Return all registered organizations.
 *
 * @returns {Array<object>}
 */
function listOrganizations() {
  return _col.values().map(_view);
}

/**
 * Return the number of registered organizations.
 */
function orgCount() {
  return _col.size();
}

/**
 * Return this worker's last-confirmed sync timestamp (epoch ms) for an
 * organization's status, or 0 if never synced. Exposed for test/observability.
 *
 * @param {string} organizationId
 * @returns {number}
 */
function _statusSyncedAt(organizationId) {
  const f = _statusFreshness.get(organizationId);
  return f ? f.syncedAt : 0;
}

/**
 * Clear all organization registrations, the tenant→org index, and
 * status-freshness tracking. TEST USE ONLY — never call in production.
 */
function _reset() {
  _col._reset();
  _tenantOrgIndex.clear();
  _statusFreshness.clear();
}

// Tests / offline dev tooling (memory mode only): write the snapshot as the seed fixture.
function exportSeedFixture() { return _col.exportSeedFixture(); }

module.exports = {
  registerOrganization,
  getOrganization,
  updateOrganization,
  publishOrganizationStatus,
  assignTenantToOrg,
  removeTenantFromOrg,
  getOrganizationForTenant,
  assertActiveOrganization,
  getQuotasForTenant,
  listOrganizations,
  orgCount,
  DEFAULT_QUOTAS,
  _reset,
  exportSeedFixture,
  setOrgStatusSubscriber,
  // internals — used only by status/OrgStatusSubscriber.js and tests.
  _applyRemoteStatus,
  _touchStatusFreshness,
  _statusSyncedAt,
};
