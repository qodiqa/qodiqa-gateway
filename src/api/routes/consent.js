'use strict';

/**
 * Consent Registry Management API
 *
 * All routes require authentication and MANAGE_CONSENT permission.
 * Mounted at /consent in server.js.
 *
 * Routes:
 *   POST   /consent                       — Grant consent
 *   GET    /consent                       — List records (paginated, filterable)
 *   GET    /consent/health                — Registry health
 *   GET    /consent/:id                   — Get record by UUID
 *   POST   /consent/:id/revoke            — Revoke record
 *   POST   /consent/:id/suspend           — Suspend record
 *   POST   /consent/:id/resume            — Resume record
 *   POST   /consent/actor/:actorId/revoke — Revoke all records for actor
 *   DELETE /consent/actor/:actorId        — DEPRECATED alias for the above; see below
 *   GET    /consent/:id/audit             — Audit log for a record
 *   POST   /consent/verify                — Ad-hoc verification check
 *
 * remediation note: `DELETE /consent/actor/:actorId` was
 * previously the only way to revoke every consent record for an actor. It
 * only ever performed a state transition (registry.revokeAll() → REVOKED),
 * never a row deletion — but the DELETE verb strongly implies deletion,
 * which could mislead an operator into believing it satisfies a GDPR
 * Article 17 erasure request. It does not: records remain in
 * consent_records (state REVOKED) and consent_audit_log is untouched, by
 * design (see docs/guides/dsr.md §3, §7).
 *
 * `POST /consent/actor/:actorId/revoke` is the semantically correct
 * replacement — same behavior, a verb that doesn't imply deletion. The
 * legacy DELETE route is kept, calling the identical handler, for backward
 * compatibility: it now returns Deprecation/Sunset/Link headers and emits a
 * CONSENT_DELETE_ACTOR_DEPRECATED_USED warning event on every call (see
 * COMP-4-REMEDIATION-REPORT.md).
 *
 * GDPR Article 17 erasure is a *distinct* operation from consent
 * revocation and is never reachable through this router — it is
 * implemented in src/core/dsr/ErasureService.js and exposed at
 * POST /v1/admin/dsr/:id/erase (see docs/guides/dsr.md).
 */

const { Router }  = require('express');
const registry    = require('../../core/consent');
const ConsentStore = require('../../core/consent/ConsentStore'); // (D8-A): special-category scope lookup
const publisher   = require('../../core/consent/revocation/RevocationPublisher');
const subscriber  = require('../../core/consent/revocation/RevocationSubscriber');
const { emit }    = require('../../../services/logger');
const { sendDeprecationHeaders } = require('../../middleware/deprecation');
const { parsePagination, buildPaginationMeta } = require('../../utils/pagination');
const {
  consentGrantSchema,
  consentVerifySchema,
  consentRevokeSchema,
  consentSuspendSchema,
  consentResumeSchema,
  consentIdParamSchema,
  consentActorParamSchema,
  consentListQuerySchema,
  CONSENT_STATES,
  CONSENT_GRANT_ALIASES,
  CONSENT_VERIFY_ALIASES,
  CONSENT_REVOKE_ALIASES,
  CONSENT_SUSPEND_ALIASES,
  CONSENT_RESUME_ALIASES,
  CONSENT_LIST_QUERY_ALIASES,
} = require('../../validation/schemas/consent.schema');
const { normalizeLegacyBody } = require('../../validation/normalizeLegacyBody');
const { success, failure, internalError } = require('../response');

// _str / _int retained for optional query-string parameters that are
// passed through to the registry as flexible filter values (not validated).
function _str(v) { return typeof v === 'string' ? v.trim() : null; }
function _int(v, def) { const n = parseInt(v, 10); return Number.isFinite(n) && n >= 0 ? n : def; }

// API-5 remediation: ?tenantId= is canonical; ?tenant_id= still accepted
// (deprecated) for the handful of routes below that read this single query
// param directly rather than through a full body/query schema.
function _queryTenantId(req, res) {
  if (req.query.tenantId !== undefined) return _str(req.query.tenantId);
  if (req.query.tenant_id !== undefined) {
    sendDeprecationHeaders(res, {
      warnEvent: 'CONSENT_LEGACY_FIELD_CASING_USED',
      warnDetails: {
        path: req.path, requestId: req.requestId ?? null, legacyFieldsUsed: ['tenant_id'],
        message: 'Query param tenant_id is deprecated. Use tenantId instead — see docs/api/overview.md.',
      },
    });
    return _str(req.query.tenant_id);
  }
  return null;
}

function _badRequest(res, message) {
  return failure(res, 'BAD_REQUEST', message, 400);
}

function _notFound(res) {
  return failure(res, 'NOT_FOUND', 'Not found', 404);
}

// defense-in-depth mapping for any consent-mutation write path that
// still reaches the route layer with an unresolved PostgreSQL serialization
// conflict (40001) or deadlock (40P01) — every ConsentStore mutation path is
// now pinned to READ COMMITTED (see ConsentStore.js), under which 40001
// cannot occur at all, so this branch should not fire for those paths in
// practice. It exists for any other write path reaching this handler that
// this remediation didn't trace, so a genuine conflict is never
// indistinguishable from a generic server fault: 409 tells the caller the
// failure is retryable, which a bare 500 does not. Same code name policyGovernance.js already
// uses for ConcurrentModificationError, for consistency across the API.
const _RETRYABLE_PG_CODES = new Set(['40001', '40P01']);

function _serverError(res, req, err, label) {
  // only the consent store's own transition errors are client errors — a bare 'Cannot …' prefix also matched
  // infrastructure messages (e.g. pg 'Cannot use a pool after calling end'), echoing them to the caller.
  const isClient = /^Cannot revoke consent in terminal state: /.test(err.message) || /^Invalid transition: /.test(err.message);
  if (isClient) {
    emit('ERROR', label, { error: err.message });
    return failure(res, 'BAD_REQUEST', err.message, 400);
  }
  if (/^Cannot grant consent: existing record for actor_id=.+ is in terminal state [A-Z_]+ and cannot be reactivated$/.test(err.message)) {
    // re-granting a REVOKED consent is a business
    // conflict the caller can understand and act on (the store's own guard, CONSENT_REACTIVATION_BLOCKED) — it used to surface as
    // 500 INTERNAL_ERROR. A revoked record is terminal by design; a new grant needs a different action/tenant or an explicit policy.
    emit('WARN', label, { error: err.message });
    return failure(res, 'CONSENT_TERMINAL_STATE', err.message, 409);
  }
  if (_RETRYABLE_PG_CODES.has(err.code)) {
    emit('WARN', label, { error: err.message, code: err.code });
    return failure(res, 'CONCURRENT_MODIFICATION', 'Concurrent modification — retry the request', 409);
  }
  return internalError(res, req, err, { label, code: 'INTERNAL_ERROR' });
}

// API-5 remediation: normalize a request body's legacy snake_case
// fields to their canonical camelCase equivalent (see
// src/validation/schemas/consent.schema.js's *_ALIASES exports and
// src/validation/normalizeLegacyBody.js), then flag the caller with a
// Deprecation header + WARN log event if any legacy field name was used —
// same "still works, marked deprecated" pattern as the legacy PUT routes
// and the legacy DELETE /consent/actor/:actorId route below.
function _normalizeAndFlag(req, res, body, aliasMap) {
  const { body: normalized, usedLegacyKeys } = normalizeLegacyBody(body ?? {}, aliasMap);
  if (usedLegacyKeys.length > 0) {
    sendDeprecationHeaders(res, {
      warnEvent: 'CONSENT_LEGACY_FIELD_CASING_USED',
      warnDetails: {
        path:            req.path,
        requestId:       req.requestId ?? null,
        legacyFieldsUsed: usedLegacyKeys,
        message: `Request used deprecated snake_case field name(s) (${usedLegacyKeys.join(', ')}). ` +
                 'Use the camelCase equivalent instead — see docs/api/overview.md.',
      },
    });
  }
  return normalized;
}

// lifecycle attribution comes from the AUTHENTICATED operator.
// Before: granted_by/revoked_by/suspended_by/resumed_by were "<body value> || req.user?.id || 'api'". req.user is never
// set anywhere in this codebase (operator identity is req.rbacUser, attached by opsAuth/portalAuth and required by the
// MANAGE_CONSENT admin stack), so every record carried a caller-chosen string — any operator could attribute a
// grant/revocation to someone else.
// Now: when the request is authenticated (req.rbacUser present — always the case behind the production admin stack),
// the recorded actor is that operator (username, else id). A body-supplied *By value is still ACCEPTED (API
// compatibility — existing clients that send it keep working) but is never recorded as the actor: if it differs
// from the operator it is logged as a claimed on-behalf-of value (CONSENT_ACTOR_CLAIM_NOT_RECORDED) and nothing else.
// Without req.rbacUser (only reachable when this router is mounted without the admin stack, e.g. unit harnesses) the
// previous behaviour is kept: body value, else 'api'.
function _lifecycleActor(req, claimed, field) {
  const op = req.rbacUser;
  const operator = op && (typeof op.username === 'string' && op.username ? op.username : (op.id != null ? String(op.id) : null));
  if (!operator) return claimed || 'api';
  if (claimed && claimed !== operator) {
    emit('WARN', 'CONSENT_ACTOR_CLAIM_NOT_RECORDED', {
      field, operator, claimedOnBehalfOf: String(claimed).slice(0, 128), requestId: req.requestId ?? null, path: req.originalUrl ?? req.path ?? null,
    });
  }
  return operator;
}

// ── Route factory ──────────────────────────────────────────────────────────────

function createConsentRouter() {
  const router = Router();

  // ── Health ─────────────────────────────────────────────────────────────────

  router.get('/health', (_req, res) => {
    success(res, {
      ...registry.health(),
      revocationPublisherReady:  publisher.isReady(),
      revocationSubscriberReady: subscriber.isReady(),
    });
  });

  // ── Revoked (convenience listing) ─────────────────────────────────────────
  // Semantic alias for GET /?state=REVOKED.  Placed before /:id to avoid
  // Express treating "revoked" as a UUID parameter.

  router.get('/revoked', async (req, res) => {
    // Canonical page/pageSize (API-4 remediation) take precedence over the
    // legacy limit/offset when both are supplied; either still works.
    const { page, pageSize, limit, offset } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 200 });
    // API-5 remediation: actorId/tenantId are canonical; actor_id/tenant_id
    // still accepted (deprecated).
    const q = _normalizeAndFlag(req, res, req.query, CONSENT_LIST_QUERY_ALIASES);
    const filters = {
      actor_id:  _str(q.actorId)  || undefined,
      action:    _str(q.action)   || undefined,
      tenant_id: _str(q.tenantId) || undefined,
      state:     'REVOKED',
      limit,
      offset,
    };
    try {
      const result = await registry.list(filters);
      return success(res, { ...result, ...buildPaginationMeta({ page, pageSize, totalItems: result.total }) });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_REVOKED_LIST_ERROR');
    }
  });

  // ── Grant ──────────────────────────────────────────────────────────────────

  router.post('/', async (req, res) => {
    // API-5 remediation: camelCase is canonical; snake_case still accepted
    // (deprecated) — normalized here before the .strict() schema below.
    const body = _normalizeAndFlag(req, res, req.body, CONSENT_GRANT_ALIASES);
    const parsed = consentGrantSchema.safeParse(body);
    if (!parsed.success) {
      return _badRequest(res, parsed.error.issues[0]?.message ?? 'Invalid request');
    }

    const {
      actorId, action, grantedBy: _gb, scope, requiredScope, tenantId,
      grantReference, subjectName, actionDisplay, policyReference,
      tags, metadata, expiresAt: _ea, durationDays: _dd,
      lawfulBasis, purpose, purposeCode, specialCategoryCondition,
    } = parsed.data;

    // a grant for a GDPR Art. 9(1) special-category scope
    // must state its Art. 9(2) condition.
    const _scopeToCheck = scope || requiredScope || null;
    if (!specialCategoryCondition && _scopeToCheck) {
      let special = false;
      try { special = await ConsentStore.isSpecialCategoryScope(_scopeToCheck); } catch (err) {
        return _serverError(res, req, err, 'CONSENT_ROUTE_GRANT_ERROR');
      }
      if (special) {
        return failure(res, 'SPECIAL_CATEGORY_CONDITION_REQUIRED',
          `scope '${_scopeToCheck}' is a GDPR Art. 9(1) special category: specialCategoryCondition (art9_2_a … art9_2_j) is required`, 400);
      }
    }

    const granted_by = _lifecycleActor(req, _gb, 'grantedBy');

    // Resolve expires_at as a plain, canonical ISO-UTC string — never a
    // Date object. _ea is already validated by consentGrantSchema (a
    // parseable, future date string) but not normalized — a non-UTC-
    // canonical form (e.g. a bare date, or a non-UTC offset) is stringified
    // to canonical UTC here so every downstream consumer (the SQL
    // TIMESTAMPTZ param and the audit-log stableStringify call) sees one
    // consistent, serializable value regardless of how the client phrased
    // it. The ephemeral Date used for the conversion never leaves this
    // expression.
    let expires_at = _ea ? new Date(_ea).toISOString() : null;
    let duration_days = null;
    if (_dd !== null && _dd !== undefined) {
      duration_days = parseInt(String(_dd), 10);
      if (!expires_at) {
        expires_at = new Date(Date.now() + duration_days * 86_400_000).toISOString();
      }
    }

    // (verification): a consent under a tenant that is not in the registry is invisible to revokeAll()'s sweep
    // (it enumerates registered tenants under RLS), so it could never be bulk-revoked. Refuse to create one.
    if (tenantId && !require('../../core/tenancy/tenantRegistry').getTenant(tenantId)) {
      return _badRequest(res, `tenantId '${tenantId}' is not a registered tenant`);
    }

    try {
      // The consent registry/store layer is unaffected by API-5 — it keeps
      // its own snake_case contract, matching the Postgres column names.
      const record = await registry.grant({
        actor_id: actorId, action, tenant_id: tenantId || null, scope: scope || null,
        required_scope: requiredScope || null,
        granted_by, granted_via: 'API', grant_reference: grantReference || null,
        expires_at, duration_days,
        subject_name: subjectName || null,
        action_display: actionDisplay || null,
        policy_reference: policyReference || null,
        tags: tags || [], metadata: metadata || {},
        request_id: req.requestId ?? null,
        lawful_basis: lawfulBasis, purpose, purpose_code: purposeCode || null,
        special_category_condition: specialCategoryCondition || null,
      });
      return success(res, { record }, 201);
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_GRANT_ERROR');
    }
  });

  // ── List ───────────────────────────────────────────────────────────────────

  router.get('/', async (req, res) => {
    // API-5 remediation: actorId/tenantId are canonical; actor_id/tenant_id
    // still accepted (deprecated).
    const q = _normalizeAndFlag(req, res, req.query, CONSENT_LIST_QUERY_ALIASES);
    const qParsed = consentListQuerySchema.safeParse(q);
    if (!qParsed.success) {
      return _badRequest(res, qParsed.error.issues[0]?.message ?? 'Invalid query parameters');
    }
    const { actorId, action, tenantId, state } = qParsed.data;
    // Canonical page/pageSize (API-4 remediation) take precedence over the
    // legacy limit/offset when both are supplied; either still works.
    const { page, pageSize, limit, offset } = parsePagination(qParsed.data, { defaultPageSize: 50, maxPageSize: 200 });
    const filters = {
      actor_id:  actorId  || undefined,
      action:    action   || undefined,
      tenant_id: tenantId || undefined,
      state:     state    || undefined,
      limit,
      offset,
    };

    try {
      const result = await registry.list(filters);
      return success(res, { ...result, ...buildPaginationMeta({ page, pageSize, totalItems: result.total }) });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_LIST_ERROR');
    }
  });

  // ── Get by ID ──────────────────────────────────────────────────────────────

  router.get('/:id', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    try {
      // the route only has the record's id, not its tenant, so an
      // optional ?tenantId= (canonical) / ?tenant_id= (deprecated, API-5)
      // lets a caller who knows which tenant they're looking in supply it —
      // required to see a tenant-scoped record at all (see
      // ConsentStore.findById()'s RLS rationale). Omitted, this behaves
      // exactly as before: platform-level records only.
      const record = await registry.getById(req.params.id, _queryTenantId(req, res));
      if (!record) return _notFound(res);
      return success(res, { record });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_GET_ERROR');
    }
  });

  // ── Revoke ─────────────────────────────────────────────────────────────────

  router.post('/:id/revoke', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    // API-5 remediation: camelCase is canonical; snake_case still accepted (deprecated).
    const body = _normalizeAndFlag(req, res, req.body, CONSENT_REVOKE_ALIASES);
    const rParsed = consentRevokeSchema.safeParse(body);
    if (!rParsed.success) {
      return _badRequest(res, rParsed.error.issues[0]?.message ?? 'Invalid request');
    }

    const revoked_by        = _lifecycleActor(req, rParsed.data.revokedBy, 'revokedBy');
    const revocation_reason = rParsed.data.revocationReason || null;
    const tenant_id         = rParsed.data.tenantId || null;

    try {
      const record = await registry.revoke({
        id: req.params.id, tenant_id, revoked_by, revocation_reason, request_id: req.requestId ?? null,
      });
      return success(res, { record });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_REVOKE_ERROR');
    }
  });

  // ── Suspend ────────────────────────────────────────────────────────────────

  router.post('/:id/suspend', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    // API-5 remediation: camelCase is canonical; snake_case still accepted (deprecated).
    const body = _normalizeAndFlag(req, res, req.body, CONSENT_SUSPEND_ALIASES);
    const sParsed = consentSuspendSchema.safeParse(body);
    if (!sParsed.success) {
      return _badRequest(res, sParsed.error.issues[0]?.message ?? 'Invalid request');
    }
    const suspended_by      = _lifecycleActor(req, sParsed.data.suspendedBy, 'suspendedBy');
    const suspension_reason = sParsed.data.suspensionReason || null;
    // suspendedUntil as a plain, canonical ISO-UTC string — never a Date
    // object; same stableStringify-audit-log rationale as expires_at above
    // (see that comment for the full explanation). The ephemeral Date used
    // for the conversion never leaves this expression.
    const suspended_until   = sParsed.data.suspendedUntil ? new Date(sParsed.data.suspendedUntil).toISOString() : null;
    const tenant_id         = sParsed.data.tenantId || null;

    try {
      const record = await registry.suspend({
        id: req.params.id, tenant_id, suspended_by, suspension_reason, suspended_until, request_id: req.requestId ?? null,
      });
      return success(res, { record });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_SUSPEND_ERROR');
    }
  });

  // ── Resume ─────────────────────────────────────────────────────────────────

  router.post('/:id/resume', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    // API-5 remediation: camelCase is canonical; snake_case still accepted (deprecated).
    const body = _normalizeAndFlag(req, res, req.body, CONSENT_RESUME_ALIASES);
    const rsParsed = consentResumeSchema.safeParse(body);
    if (!rsParsed.success) {
      return _badRequest(res, rsParsed.error.issues[0]?.message ?? 'Invalid request');
    }

    const resumed_by = _lifecycleActor(req, rsParsed.data.resumedBy, 'resumedBy');
    const tenant_id   = rsParsed.data.tenantId || null;

    try {
      const record = await registry.resume({
        id: req.params.id, tenant_id, resumed_by, request_id: req.requestId ?? null,
      });
      return success(res, { record });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_RESUME_ERROR');
    }
  });

  // ── Revoke all for actor ───────────────────────────────────────────────────
  //
  // Bulk revocation only — a state transition to REVOKED for every non-terminal
  // record belonging to the actor. This is NOT a GDPR Article 17 erasure: no
  // row is deleted, no PII field is scrubbed, and consent_audit_log is
  // untouched. For actual erasure, use POST /v1/admin/dsr/:id/erase
  // (src/core/dsr/ErasureService.js; see docs/guides/dsr.md).

  // DEPRECATED_DELETE_SUNSET is a fixed advisory date given to callers via the
  // Sunset header (RFC 8594) — it does not enforce removal; the legacy route
  // keeps working past this date until an operator explicitly decides to drop it.
  const DEPRECATED_DELETE_SUNSET = 'Wed, 21 Jan 2027 00:00:00 GMT';

  async function _revokeAllForActor(req, res, { legacy = false } = {}) {
    const actorParsed = consentActorParamSchema.safeParse(req.params);
    if (!actorParsed.success) return _badRequest(res, 'Invalid actorId');
    const actorId = actorParsed.data.actorId;

    if (legacy) {
      sendDeprecationHeaders(res, {
        sunset:        DEPRECATED_DELETE_SUNSET,
        successorLink: `/consent/actor/${encodeURIComponent(actorId)}/revoke`,
        warnEvent:     'CONSENT_DELETE_ACTOR_DEPRECATED_USED',
        warnDetails: {
          actorId,
          message: 'DELETE /consent/actor/:actorId is deprecated: it only revokes consent, it never ' +
                   'deletes or erases data. Use POST /consent/actor/:actorId/revoke instead. For GDPR ' +
                   'Article 17 erasure, use POST /v1/admin/dsr/:id/erase — see docs/guides/dsr.md.',
        },
      });
    }

    const revoked_by        = _lifecycleActor(req, _str(req.body?.revoked_by), 'revoked_by');
    const revocation_reason = _str(req.body?.revocation_reason) || 'ACTOR_DECOMMISSIONED';

    try {
      const result = await registry.revokeAll(actorId, revoked_by, revocation_reason);
      return success(res, result);
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_REVOKE_ALL_ERROR');
    }
  }

  router.post('/actor/:actorId/revoke', (req, res) => _revokeAllForActor(req, res));

  // Legacy alias — kept for backward compatibility. See the deprecation note
  // at the top of this file and COMP-4-REMEDIATION-REPORT.md.
  router.delete('/actor/:actorId', (req, res) => _revokeAllForActor(req, res, { legacy: true }));

  // ── Audit log for a record ─────────────────────────────────────────────────

  router.get('/:id/audit', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    // Range read, not classic offset pagination (no stable total count) — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // limit/offset parsing through the shared utility (accepts pageSize/page too).
    const { limit, offset } = parsePagination(req.query, { defaultPageSize: 100, maxPageSize: 500 });

    try {
      // tenant_id is optional, same convention as the
      // sibling /:id and /:id/status routes -- required only to see a
      // tenant-scoped record's audit trail.
      const entries = await registry.getAuditLog({
        consent_id: req.params.id, tenant_id: _queryTenantId(req, res), limit, offset,
      });
      return success(res, { entries });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_AUDIT_ERROR');
    }
  });

  // ── Revocation status (with propagation metadata) ─────────────────────────

  router.get('/:id/status', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    try {
      // see GET /:id above — tenantId/tenant_id is optional,
      // required only to see a tenant-scoped record.
      const record = await registry.getById(req.params.id, _queryTenantId(req, res));
      if (!record) return _notFound(res);

      return success(res, {
        id:              record.id,
        state:           record.state,
        revokedAt:       record.revoked_at         ?? null,
        revokedBy:       record.revoked_by         ?? null,
        revocationReason:record.revocation_reason  ?? null,
        propagation: {
          publisherReady:  publisher.isReady(),
          subscriberReady: subscriber.isReady(),
        },
      });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_STATUS_ERROR');
    }
  });

  // ── Revocation history — audit entries filtered to REVOKE events ───────────

  router.get('/:id/history', async (req, res) => {
    if (!consentIdParamSchema.safeParse(req.params).success) return _badRequest(res, 'Invalid id format');

    const { page, pageSize, limit, offset } = parsePagination(req.query, { defaultPageSize: 100, maxPageSize: 500 });

    try {
      // same tenant_id threading as GET /:id/audit above.
      const allEntries = await registry.getAuditLog({
        consent_id: req.params.id, tenant_id: _queryTenantId(req, res), limit: 500, offset: 0,
      });
      const revocationEvents = allEntries.filter(e =>
        ['CONSENT_REVOKED', 'CONSENT_SUSPENDED', 'CONSENT_RESUMED'].includes(e.event_type)
      );
      const entries = revocationEvents.slice(offset, offset + limit);
      return success(res, {
        entries, total: revocationEvents.length,
        ...buildPaginationMeta({ page, pageSize, totalItems: revocationEvents.length }),
      });
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_HISTORY_ERROR');
    }
  });

  // ── Ad-hoc verify ──────────────────────────────────────────────────────────

  router.post('/verify', async (req, res) => {
    // API-5 remediation: camelCase is canonical; snake_case still accepted (deprecated).
    const body = _normalizeAndFlag(req, res, req.body, CONSENT_VERIFY_ALIASES);
    const vParsed = consentVerifySchema.safeParse(body);
    if (!vParsed.success) {
      return _badRequest(res, vParsed.error.issues[0]?.message ?? 'Invalid request');
    }
    const { actorId, action, tenantId, requiredScope } = vParsed.data;

    try {
      const result = await registry.verify({
        actor_id: actorId, action, tenant_id: tenantId, required_scope: requiredScope, request_id: req.requestId ?? null,
      });
      if (result.pass) return success(res, result, 200);
      return failure(res, result.reason || 'CONSENT_VERIFICATION_FAILED', 'Consent verification failed', 403, result);
    } catch (err) {
      return _serverError(res, req, err, 'CONSENT_ROUTE_VERIFY_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = { createConsentRouter };
