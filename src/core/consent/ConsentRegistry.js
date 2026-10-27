'use strict';

/**
 * ConsentRegistry — runtime consent management service.
 *
 * Single entry point for all consent lifecycle operations:
 *   - grant(opts)              create or replace a consent record
 *   - revoke(opts)             permanently revoke a record
 *   - suspend(opts)            temporarily hold a record
 *   - resume(opts)             lift a suspension
 *   - verify(opts)             verify consent on the hot path (cached)
 *   - get(actor_id, action)    direct DB lookup (bypass cache)
 *   - list(filters)            paginated record listing
 *   - getAuditLog(opts)        paginated audit log
 *   - revokeAll(actor_id)      revoke every active/pending/suspended record for an actor
 *
 * This module is the authoritative consent API.  Callers (policy evaluators,
 * management routes) should import from src/core/consent/index.js, not directly
 * from this file.
 */

const store     = require('./ConsentStore');
const cache     = require('./ConsentCache');
const verifier  = require('./ConsentVerifier');
const publisher = require('./revocation/RevocationPublisher');
const pool      = require('../../infra/postgres/pool');
const { emit }  = require('../../../services/logger');

// ── Grant ─────────────────────────────────────────────────────────────────────

/**
 * Grant or re-grant consent.  If a record already exists for the
 * (actor_id, action, tenant_id) triple it is reset to ACTIVE — unless that
 * record is REVOKED or EXPIRED (terminal), in which case this throws rather
 * than reactivating it. See ConsentStore.create().
 *
 * @returns {Promise<object>} created/updated consent record
 */
async function grant(opts) {
  const record = await store.create(opts);
  await cache.invalidate(record.actor_id, record.action, record.tenant_id, record.version);
  // (NF-6): tell the other nodes too, so none keeps serving a cached
  // NOT_FOUND deny for up to the negative TTL. Same signed channel and the same
  // versioned tombstone as a revocation; best-effort — a publish failure is
  // logged and never fails the grant (the staleness it leaves is the earlier
  // ≤ CONSENT_CACHE_NEGATIVE_TTL_S window).
  try {
    const published = await publisher.publish({
      consentId:        record.id,
      subjectId:        record.actor_id,
      action:           record.action,
      tenantId:         record.tenant_id ?? null,
      revokedBy:        null,
      revocationReason: 'CONSENT_GRANTED_INVALIDATE',
      consentVersion:   record.version,
    });
    if (!published) emit('WARN', 'CONSENT_GRANT_INVALIDATION_PUBLISH_FAILED', { consentId: record.id, error: 'publish returned false' });
  } catch (e) {
    emit('WARN', 'CONSENT_GRANT_INVALIDATION_PUBLISH_FAILED', { consentId: record.id, error: e.message });
  }
  return record;
}

// ── Revoke ────────────────────────────────────────────────────────────────────

/**
 * Permanently revoke a consent record.
 *
 * @param {object} opts
 * @param {string} opts.id               — consent record UUID
 * @param {string} opts.revoked_by       — identity of the revoking actor
 * @param {string} [opts.revocation_reason]
 * @param {string} [opts.request_id]
 * @returns {Promise<object>}
 */
async function revoke(opts) {
  const record = await store.revoke(opts);
  // record.version is the row's version AFTER this UPDATE (bumped by the
  // consent_records_updated_at trigger, returned via `RETURNING *`) — this is
  // the CAS token that closes the read-DB/concurrent-revoke race.
  await cache.invalidate(record.actor_id, record.action, record.tenant_id, record.version);

  // Publish the revocation event to the Redis pub/sub channel so that all other
  // nodes in the cluster immediately invalidate their cached consent entries.
  // This is a required propagation step — if it fails, other nodes cannot be
  // notified and may continue serving stale cached ALLOW results.
  // Those nodes will be fail-closed by their own subscriber readiness check
  // (ConsentVerifier blocks when subscriber.isReady() === false), but operators
  // must be alerted to restore pub/sub connectivity.
  const propagated = await publisher.publish({
    consentId:        record.id,
    subjectId:        record.actor_id,
    action:           record.action,
    tenantId:         record.tenant_id        ?? null,
    revocationReason: record.revocation_reason ?? null,
    revokedBy:        record.revoked_by        ?? null,
    correlationId:    opts.request_id          ?? null,
    consentVersion:   record.version,
  });

  if (!propagated) {
    emit('CRITICAL', 'CONSENT_REVOCATION_PROPAGATION_FAILED', {
      consentId:     record.id,
      actorId:       record.actor_id,
      action:        record.action,
      tenantId:      record.tenant_id ?? null,
      correlationId: opts.request_id  ?? null,
      destination:   'redis-pubsub',
      // publisher.publish() is single-attempt at the command level (only its
      // underlying Redis *connection* retries, independently, via
      // reconnectStrategy) — reported honestly rather than implying a
      // per-call retry loop that doesn't exist. See RevocationPublisher.js.
      retryAttempts: 0,
      willRetry:     false,
      message:   'Revocation committed to PostgreSQL and local cache invalidated, but ' +
                 'could not publish revocation event to Redis pub/sub channel. ' +
                 'Other nodes cannot receive instant notification. ' +
                 'Their subscriber health check will block consent-dependent requests ' +
                 'if their connection is also degraded. ' +
                 'Restore Redis pub/sub connectivity immediately.',
    });
  }

  return record;
}

// ── Suspend ───────────────────────────────────────────────────────────────────

/**
 * Temporarily suspend a consent record.
 *
 * @param {object} opts
 * @param {string} opts.id
 * @param {string} opts.suspended_by
 * @param {string} [opts.suspension_reason]
 * @param {Date}   [opts.suspended_until]  - auto-resume after this timestamp
 * @param {string} [opts.request_id]
 * @returns {Promise<object>}
 */
async function suspend(opts) {
  const record = await store.suspend(opts);
  await cache.invalidate(record.actor_id, record.action, record.tenant_id, record.version);

  // Suspension reduces access exactly like revocation does, so it carries the
  // same multi-node stale-ALLOW risk and needs the same pub/sub
  // propagation — prior to this fix suspend() only invalidated the LOCAL
  // cache, leaving other nodes to serve a stale cached ALLOW for up to
  // TTL_POSITIVE_S even with pub/sub healthy elsewhere in the system.
  const propagated = await publisher.publish({
    consentId:        record.id,
    subjectId:        record.actor_id,
    action:           record.action,
    tenantId:         record.tenant_id       ?? null,
    revocationReason: record.suspension_reason ?? null,
    revokedBy:        record.suspended_by      ?? null,
    correlationId:    opts.request_id          ?? null,
    consentVersion:   record.version,
  });

  if (!propagated) {
    emit('CRITICAL', 'CONSENT_SUSPENSION_PROPAGATION_FAILED', {
      consentId:     record.id,
      actorId:       record.actor_id,
      action:        record.action,
      tenantId:      record.tenant_id ?? null,
      correlationId: opts.request_id  ?? null,
      destination:   'redis-pubsub',
      retryAttempts: 0,
      willRetry:     false,
      message:   'Suspension committed to PostgreSQL and local cache invalidated, but ' +
                 'could not publish suspension event to Redis pub/sub channel. ' +
                 'Other nodes cannot receive instant notification. ' +
                 'Their subscriber health check will block consent-dependent requests ' +
                 'if their connection is also degraded. ' +
                 'Restore Redis pub/sub connectivity immediately.',
    });
  }

  return record;
}

// ── Resume ────────────────────────────────────────────────────────────────────

/**
 * Lift a suspension.
 *
 * @param {object} opts
 * @param {string} opts.id
 * @param {string} opts.resumed_by
 * @param {string} [opts.request_id]
 * @returns {Promise<object>}
 */
async function resume(opts) {
  const record = await store.resume(opts);
  // resume() only ever WIDENS access, so — unlike revoke()/suspend() — a
  // stale cached entry from a slow cross-node propagation is fail-safe (it
  // denies a now-valid request, not the reverse) and doesn't need pub/sub
  // propagation to satisfy the guarantee. Still pass the new
  // version so the local cache write is CAS-guarded like every other path.
  await cache.invalidate(record.actor_id, record.action, record.tenant_id, record.version);
  return record;
}

// ── Verify ────────────────────────────────────────────────────────────────────

/**
 * Verify consent on the enforcement hot path.
 * Returns a structured result; never throws.
 *
 * @param {object} opts
 * @param {string} opts.actor_id
 * @param {string} opts.action
 * @param {string|null} [opts.tenant_id]
 * @param {string|null} [opts.required_scope]
 * @param {string|null} [opts.request_id]
 * @returns {Promise<{ pass: boolean, reason: string, consentId?: string, consentProvenance?: any }>}
 */
async function verify(opts) {
  return verifier.verify(opts);
}

// ── Direct lookup (no cache) ──────────────────────────────────────────────────

/**
 * Direct database lookup — bypasses cache.  For management API reads.
 *
 * @returns {Promise<object|null>}
 */
async function get(actor_id, action, tenant_id = null) {
  return store.findByKey(actor_id, action, tenant_id);
}

/**
 * Lookup by UUID.
 *
 * tenant_id is optional — the caller only has the record's id, not
 * its tenant, so it must supply tenant_id explicitly to see a tenant-scoped
 * record (see ConsentStore.findById() for the RLS rationale).
 *
 * @param {string} id
 * @param {string|null} [tenant_id]
 * @returns {Promise<object|null>}
 */
async function getById(id, tenant_id = null) {
  return store.findById(id, tenant_id);
}

// ── List ──────────────────────────────────────────────────────────────────────

/**
 * Paginated listing with optional filters.
 *
 * @param {object} [filters]
 * @returns {Promise<{ records: object[], total: number }>}
 */
async function list(filters = {}) {
  return store.list(filters);
}

// ── Audit log ─────────────────────────────────────────────────────────────────

/**
 * Paginated audit log.
 *
 * @param {object} opts
 * @returns {Promise<object[]>}
 */
async function getAuditLog(opts) {
  return store.getAuditLog(opts);
}

// Tenant ids known to the tenant registry (used by revokeAll to reach tenant-scoped consents under RLS).
// Fail closed: if the registry cannot be enumerated, the bulk revocation must not pretend to be complete.
function _allTenantIds() {
  try {
    const { listTenants } = require('../tenancy/tenantRegistry');
    return listTenants().map((t) => t.tenantId || t.id).filter(Boolean);
  } catch (err) {
    throw Object.assign(new Error(`CONSENT_REVOKE_ALL_TENANT_ENUMERATION_FAILED: ${err.message}`), { code: 'CONSENT_REVOKE_ALL_TENANT_ENUMERATION_FAILED' });
  }
}


// ── Bulk revocation ───────────────────────────────────────────────────────────

/**
 * Revoke all active, pending, or suspended consent records for an actor.
 * Used when an actor is decommissioned or their consent is globally withdrawn.
 *
 * @param {string} actor_id
 * @param {string} revoked_by
 * @param {string} [revocation_reason]
 * @param {{ tenantIds?: string[] }} [opts]  restrict the sweep to these tenants (default: platform scope + every registered tenant)
 * @returns {Promise<{ count: number }>}
 */
async function revokeAll(actor_id, revoked_by, revocation_reason = 'ACTOR_DECOMMISSIONED', /** @type {{ tenantIds?: string[] }} */ { tenantIds } = {}) {
  if (!pool.isEnabled()) {
    throw new Error('Consent store unavailable — PostgreSQL not enabled');
  }

  // consent_records is under FORCE ROW LEVEL SECURITY (migration 018) — a list()/revoke()
  // without a tenant context only ever sees platform-level (tenant_id IS NULL) rows, so the previous implementation silently
  // skipped every tenant-scoped consent of the actor. We now cover the platform scope PLUS each tenant, each inside that
  // tenant's own RLS context, and page through all records (the old single page was capped at 200).
  const scopes = [null, ...(Array.isArray(tenantIds) ? tenantIds : _allTenantIds())];

  let count = 0;
  const PAGE = 200;
  for (const tenant_id of scopes) {
    for (let offset = 0; ; offset += PAGE) {
      const { records } = await store.list({ actor_id, tenant_id: tenant_id || undefined, limit: PAGE, offset });
      const revocable   = records.filter(r => !['REVOKED', 'EXPIRED'].includes(r.state));

      for (const record of revocable) {
        try {
          const updated = await store.revoke({ id: record.id, tenant_id, revoked_by, revocation_reason });
          // Per-record CAS-guarded invalidation closes the read-DB
          // race on THIS node immediately, ahead of the coarser invalidateActor()
          // sweep below — that sweep is a plain unconditional DEL and, on its
          // own, is subject to the same stale-write-after-invalidate race as the
          // pre-fix single-record path.
          await cache.invalidate(updated.actor_id, updated.action, updated.tenant_id, updated.version);
          count++;
        } catch (err) {
          emit('WARN', 'CONSENT_BULK_REVOKE_RECORD_FAILED', { id: record.id, tenantId: tenant_id, error: err.message });
        }
      }
      if (records.length < PAGE) break;
    }
  }

  await cache.invalidateActor(actor_id);

  // Publish an actor-level revocation event.  Subscribers call invalidateActor()
  // on their local cache rather than issuing per-record invalidations.
  const propagated = await publisher.publish({
    consentId:        null,
    subjectId:        actor_id,
    revocationReason: revocation_reason,
    revokedBy:        revoked_by,
  });

  if (!propagated) {
    emit('CRITICAL', 'CONSENT_REVOCATION_ACTOR_PROPAGATION_FAILED', {
      actorId:      actor_id,
      revokedCount: count,
      // No single tenantId/correlationId applies here — revokeAll() is an
      // actor-scoped bulk operation with no per-request correlation id in
      // its own signature, unlike revoke()/suspend() above.
      tenantId:      null,
      correlationId: null,
      destination:   'redis-pubsub',
      retryAttempts: 0,
      willRetry:     false,
      message:      'Bulk revocation committed to PostgreSQL and local cache invalidated, ' +
                    'but could not publish actor revocation event to Redis pub/sub channel. ' +
                    'Other nodes cannot receive instant notification. ' +
                    'Restore Redis pub/sub connectivity immediately.',
    });
  }

  emit('INFO', 'CONSENT_ACTOR_ALL_REVOKED', { actorId: actor_id, revokedCount: count, revokedBy: revoked_by });

  return { count };
}

// ── Health ────────────────────────────────────────────────────────────────────

function health() {
  return {
    pgEnabled:   pool.isEnabled(),
    pgHealthy:   pool.isHealthy(),
    cacheReady:  cache.isReady(),
  };
}

module.exports = { grant, revoke, suspend, resume, verify, get, getById, list, getAuditLog, revokeAll, health };
