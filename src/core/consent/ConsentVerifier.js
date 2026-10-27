'use strict';

/**
 * ConsentVerifier — hot-path consent verification for the enforcement pipeline.
 *
 * Called once per policy evaluation that has type=REQUIRE_CONSENT.
 * Enforces fail-closed behavior: any error (DB unavailable, unexpected exception)
 * results in DENIED, never ALLOWED.
 *
 * Performance contract:
 *   - Cache hit: < 1ms (Redis GET)
 *   - Cache miss: < 5ms P99 (single indexed PG query)
 *   - DB unavailable: immediate throw (no retry on hot path)
 *
 * Verification steps:
 *   1. Cache lookup (Redis)
 *   2. If miss: DB lookup (PostgreSQL)
 *   3. Compute effective state (handles expires_at and suspended_until)
 *   4. Scope validation (if required_scope set on the record or config)
 *   5. Cache the result
 *   6. Write audit log entry (non-blocking, non-fatal)
 */

const pool       = require('../../infra/postgres/pool');
const cache      = require('./ConsentCache');
const store      = require('./ConsentStore');
const { effectiveState, STATE } = require('./ConsentStateModel');
const { emit }   = require('../../../services/logger');
// Lazy-required at call time to avoid circular dependencies at module load.
// Must remain a function — do not hoist to module scope.
function _subscriber() { return require('./revocation/RevocationSubscriber'); }

// ── Result builders ───────────────────────────────────────────────────────────

// Builds the immutable provenance snapshot for a consent record AT THE MOMENT
// of this verification (TRACE-2 remediation). Only genuinely immutable
// identity/lifecycle facts are included — deliberately excludes the
// GDPR-rectifiable/erasable fields (subject_name, metadata, tags — see
// ConsentStore.RECTIFIABLE_FIELDS / anonymize()) so a later DSR erasure never
// mutates historical audit/evidence records. `revocationStatus` is the
// *effective* state at this exact verification (ACTIVE, REVOKED, EXPIRED,
// SUSPENDED, ...) — a fact about this decision, not a live pointer to the
// record's current state.
// pg returns timestamp/timestamptz columns as native Date instances, not
// strings. This snapshot is hash-protected (stableStringify, TRACE-2) and
// stableStringify deliberately has no canonical representation for Date —
// QODIQA-PROTOCOL-SPEC.md §6.1 requires every hashed value to already be in
// its canonical form, so the conversion belongs here, not in stableStringify.
function _isoOrNull(v) {
  return v instanceof Date ? v.toISOString() : (v ?? null);
}

function _buildConsentProvenance(record, effectiveState) {
  if (!record) return null;
  return {
    consentId:         record.id,
    consentVersion:    record.version ?? null,
    consentCreatedAt:  _isoOrNull(record.created_at),
    consentApprovedAt: _isoOrNull(record.granted_at),
    consentIssuer:     record.granted_by ?? null,
    tenantId:           record.tenant_id ?? null,
    subject:            record.actor_id ?? null,
    scope:              record.scope ?? null,
    requiredScope:      record.required_scope ?? null,
    expiresAt:          _isoOrNull(record.expires_at),
    revocationStatus:   effectiveState,
    recordHash:         record.record_hash ?? null,
  };
}

function _allow(record, { cached = false } = {}) {
  return {
    pass:             true,
    reason:           'CONSENT_VERIFIED',
    consentId:        record.id,
    state:            STATE.ACTIVE,
    scope:            record.scope ?? null,
    expiresAt:        record.expires_at ?? null,
    consentProvenance: _buildConsentProvenance(record, STATE.ACTIVE),
    cached,
  };
}

function _deny(reason, detail = {}) {
  return {
    pass:   false,
    reason,
    ...detail,
  };
}

// ── Scope validation ──────────────────────────────────────────────────────────

function _validateScope(record, requiredScope) {
  // If no scope requirement — any scope accepted
  if (!requiredScope && !record.required_scope) return null;

  const required = requiredScope || record.required_scope;
  if (!record.scope) return `CONSENT_SCOPE_MISSING (required: ${required})`;
  if (record.scope !== required) return `CONSENT_SCOPE_MISMATCH (has: ${record.scope}, required: ${required})`;

  return null; // scope ok
}

// ── Core verify ───────────────────────────────────────────────────────────────

/**
 * @param {object} opts
 * @param {string} opts.actor_id
 * @param {string} opts.action
 * @param {string|null} [opts.tenant_id]
 * @param {string|null} [opts.required_scope]   - override from policy config
 * @param {string|null} [opts.request_id]       - for audit correlation
 * @returns {Promise<{ pass: boolean, reason: string, consentId?: string, state?: string, scope?: string, expiresAt?: Date|null, cached?: boolean, consentProvenance?: object|null }>}
 *   consentProvenance (TRACE-2) — immutable snapshot of the consent record at
 *   this verification, present whenever a record was found (pass or deny),
 *   null when no record exists (CONSENT_NOT_FOUND / store unavailable / etc).
 */
async function verify({ actor_id, action, tenant_id = null, required_scope = null, request_id = null }) {
  if (!actor_id || !action) {
    return _deny('CONSENT_INVALID_INPUT', { detail: 'actor_id and action are required' });
  }

  // ── 0. Revocation synchronization gate ───────────────────────────────────────
  // This node must be actively subscribed to the revocation channel to receive
  // instant revocation notifications.  If the subscriber has been started but
  // is no longer connected, consent verification is fail-closed: any cached
  // ALLOW result may be stale and cannot be trusted.
  //
  // Note: the isStarted() guard distinguishes "never initialized" (safe during
  // server startup before the subscriber has been started) from "initialized then
  // disconnected" (fail-closed required).  In production the subscriber is always
  // started before traffic is accepted; the guard exists only so that module-level
  // unit tests that do not initialize the subscriber can still run.
  const sub = _subscriber();
  if (sub.isStarted() && !sub.isReady()) {
    const result = _deny('CONSENT_REVOCATION_SYNC_UNAVAILABLE');
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result });
    return result;
  }

  // ── 1. Cache lookup ─────────────────────────────────────────────────────────
  // (NF-1): the cached result answers only a request with the SAME required scope.
  const cached = await cache.get(actor_id, action, tenant_id, { requiredScope: required_scope });
  if (cached) {
    emit('DEBUG', 'CONSENT_CACHE_HIT', { actorId: actor_id, action, tenantId: tenant_id });
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result: cached });
    return cached;
  }

  // ── 2. Database lookup ──────────────────────────────────────────────────────
  if (!pool.isEnabled()) {
    const result = _deny('CONSENT_STORE_UNAVAILABLE');
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result });
    return result;
  }

  let record;
  try {
    record = await store.findByKey(actor_id, action, tenant_id);
  } catch (err) {
    emit('ERROR', 'CONSENT_STORE_LOOKUP_FAILED', { error: err.message, actorId: actor_id, action });
    const result = _deny('CONSENT_STORE_ERROR');
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result });
    return result;
  }

  // ── 3. Not found ─────────────────────────────────────────────────────────────
  if (!record) {
    // No record → no version to CAS against; unconditional write is fine
    // here since this only ever caches a DENY (fail-safe direction).
    const result = _deny('CONSENT_NOT_FOUND');
    await cache.set(actor_id, action, tenant_id, result, null, { requiredScope: required_scope });
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result });
    return result;
  }

  // ── 4. Effective state ───────────────────────────────────────────────────────
  const effective = effectiveState(record);

  if (effective !== STATE.ACTIVE) {
    const reasonMap = {
      [STATE.REVOKED]:   'CONSENT_REVOKED',
      [STATE.EXPIRED]:   'CONSENT_EXPIRED',
      [STATE.SUSPENDED]: 'CONSENT_SUSPENDED',
      [STATE.PENDING]:   'CONSENT_NOT_ACTIVE',
    };
    const denyDetail = {
      consentId: record.id,
      state: effective,
      consentProvenance: _buildConsentProvenance(record, effective),
    };
    // ConsentCache needs suspended_until on the cached payload to clamp
    // this DENY's TTL to the boundary — see ConsentCache.js's _effectiveTtl().
    // Only set for SUSPENDED so every other deny reason's response shape is
    // unchanged.
    if (effective === STATE.SUSPENDED) denyDetail.suspendedUntil = record.suspended_until ?? null;
    const result = _deny(reasonMap[effective] ?? 'CONSENT_INACTIVE', denyDetail);
    await cache.set(actor_id, action, tenant_id, result, record.version, { requiredScope: required_scope });
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result, consent_id: record.id });
    // Audit remediation 2026-10-27: persist ACTIVE -> EXPIRED instead of only deriving it at read time. Non-fatal; the deny above is already decided.
    if (effective === STATE.EXPIRED && record.state === STATE.ACTIVE) _persistExpiry(record, request_id);
    return result;
  }

  // ── 5. Scope validation ───────────────────────────────────────────────────────
  const scopeError = _validateScope(record, required_scope);
  if (scopeError) {
    const result = _deny('CONSENT_SCOPE_MISMATCH', {
      consentId: record.id,
      detail: scopeError,
      consentProvenance: _buildConsentProvenance(record, effective),
    });
    await cache.set(actor_id, action, tenant_id, result, record.version, { requiredScope: required_scope });
    _writeAuditAsync({ actor_id, action, tenant_id, request_id, result, consent_id: record.id });
    return result;
  }

  // ── 6. ALLOW ─────────────────────────────────────────────────────────────────
  // This is the security-critical call: record.version makes the
  // write conditional on no concurrent revoke/suspend having already landed
  // a newer-versioned tombstone for this key — see ConsentCache's module
  // note. Without it, this SET is exactly the race the finding describes.
  const result = _allow(record);
  await cache.set(actor_id, action, tenant_id, result, record.version, { requiredScope: required_scope });
  _writeAuditAsync({ actor_id, action, tenant_id, request_id, result, consent_id: record.id });
  return result;
}

// ── Persist expiry (fire-and-forget, non-fatal) ──────────────────────────────

function _persistExpiry(record, request_id) {
  Promise.resolve()
    .then(() => store.markExpired({ id: record.id, tenant_id: record.tenant_id ?? null, request_id: request_id ?? null }))
    .catch((err) => emit('WARN', 'CONSENT_EXPIRY_PERSIST_FAILED', { consentId: record.id, error: err && err.message }));
}

// ── Async audit write (fire-and-forget, non-fatal) ───────────────────────────

function _writeAuditAsync({ actor_id, action, tenant_id, request_id, result, consent_id = null }) {
  store.logVerification({
    consent_id:         consent_id ?? result.consentId ?? null,
    actor_id,
    action,
    tenant_id,
    result:             result.pass ? 'VERIFIED' : 'DENIED',
    denial_reason:      result.pass ? null : result.reason,
    request_id,
  }).catch(err => emit('WARN', 'CONSENT_AUDIT_WRITE_FAILED', { error: err.message }));
}

module.exports = { verify };
