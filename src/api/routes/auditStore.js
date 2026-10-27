'use strict';

/**
 * QODIQA Centralized Audit Store API
 *
 * Mounts at /audit-store (ops-protected, RBAC-gated).
 *
 * Routes:
 *   GET  /audit-store/events                     — paginated full-text search
 *   GET  /audit-store/events/:eventId             — single event by UUID
 *   GET  /audit-store/correlate/:requestId        — all events for a request
 *   GET  /audit-store/artifact/:artifactId/timeline — cross-subsystem artifact view
 *   GET  /audit-store/actor/:actorId/activity     — actor audit trail
 *   GET  /audit-store/stats                       — aggregate statistics
 *   GET  /audit-store/ingestion-rate              — per-minute ingestion rate
 *   GET  /audit-store/top-events                  — top event types by volume
 *   GET  /audit-store/retention/policies          — list retention policies
 *   POST /audit-store/retention/policies          — create / update policy
 *   POST /audit-store/retention/apply             — trigger retention cycle
 *   GET  /audit-store/retention/holds             — list active legal holds
 *   POST /audit-store/retention/holds             — place legal hold
 *   DELETE /audit-store/retention/holds/:holdName — release legal hold
 *   GET  /audit-store/retention/runs              — retention run history
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const express      = require('express');
const centralStore = require('../../core/audit/centralStore');
const retention    = require('../../core/audit/retention');
const { emit }     = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const {
  parsePagination, parseSortOrder, withPaginationMeta, paginateArray, isPaginationRequested,
} = require('../../utils/pagination');
const {
  eventIdParamSchema,
  requestIdParamSchema,
  artifactIdParamSchema,
  actorIdParamSchema,
  retentionPolicyBodySchema,
  legalHoldBodySchema,
  releaseLegalHoldQuerySchema,
} = require('../../validation/schemas/auditStore.schema');


function createAuditStoreRouter({ requirePermission } = {}) {
  const router = express.Router();

  const _canRead    = permissionGuard(requirePermission, 'READ_AUDIT', 'auditStore');
  const _canRetain  = permissionGuard(requirePermission, 'MANAGE_RETENTION', 'auditStore');

  // ── Search ─────────────────────────────────────────────────────────────────

  router.get('/events', _canRead, async (req, res) => {
    const {
      artifactId, requestId, correlationId,
      actorId, actorUsername, keyId, policyId, tenantId,
      eventType, eventCategory, severity, outcome, component,
      startTime, endTime,
    } = req.query;

    // Canonical page/pageSize (+ legacy limit/offset aliases) and sortOrder
    // (+ legacy sort/sortDir aliases) via the shared utility (API-4 remediation).
    const { page: pg, pageSize: ps } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
    const sortOrder = parseSortOrder(req.query);

    try {
      const result = await centralStore.search({
        artifactId, requestId, correlationId,
        actorId, actorUsername, keyId, policyId, tenantId,
        eventType, eventCategory, severity, outcome, component,
        startTime, endTime,
        page: pg, pageSize: ps, sortOrder,
      });

      emit('INFO', 'AUDIT_STORE_SEARCH', {
        requestId:   req.requestId,
        actor:       req.rbacUser?.username ?? null,
        filters:     { artifactId, requestId, eventType, eventCategory, severity, startTime, endTime },
        resultCount: result.total,
      });

      return success(res, withPaginationMeta(result));
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_SEARCH_FAILED', code: 'SEARCH_FAILED' });
    }
  });

  router.get('/events/:eventId', _canRead, async (req, res) => {
    if (!eventIdParamSchema.safeParse(req.params).success) {
      return failure(res, 'INVALID_EVENT_ID', 'Invalid eventId', 400);
    }
    const { eventId } = req.params;

    try {
      const event = await centralStore.getEvent(eventId);
      if (!event) return failure(res, 'EVENT_NOT_FOUND', 'Event not found', 404);

      emit('INFO', 'AUDIT_STORE_EVENT_FETCH', {
        requestId: req.requestId,
        actor:     req.rbacUser?.username ?? null,
        eventId,
      });

      return success(res, { event });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_FETCH_FAILED', code: 'FETCH_FAILED' });
    }
  });

  // ── Correlation ────────────────────────────────────────────────────────────

  router.get('/correlate/:requestId', _canRead, async (req, res) => {
    if (!requestIdParamSchema.safeParse(req.params).success) {
      return failure(res, 'INVALID_REQUEST_ID', 'Invalid requestId', 400);
    }
    const { requestId } = req.params;

    try {
      const events = await centralStore.correlate(requestId);

      emit('INFO', 'AUDIT_STORE_CORRELATE', {
        requestId:   req.requestId,
        actor:       req.rbacUser?.username ?? null,
        targetRequestId: requestId,
        count:       events.length,
      });

      return success(res, { requestId, events, count: events.length });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_CORRELATE_FAILED', code: 'CORRELATE_FAILED' });
    }
  });

  router.get('/artifact/:artifactId/timeline', _canRead, async (req, res) => {
    if (!artifactIdParamSchema.safeParse(req.params).success) {
      return failure(res, 'INVALID_ARTIFACT_ID', 'Invalid artifactId', 400);
    }
    const { artifactId } = req.params;

    try {
      const events = await centralStore.artifactTimeline(artifactId);

      emit('INFO', 'AUDIT_STORE_ARTIFACT_TIMELINE', {
        requestId:  req.requestId,
        actor:      req.rbacUser?.username ?? null,
        artifactId,
        count:      events.length,
      });

      return success(res, { artifactId, events, count: events.length });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_TIMELINE_FAILED', code: 'TIMELINE_FAILED' });
    }
  });

  router.get('/actor/:actorId/activity', _canRead, async (req, res) => {
    if (!actorIdParamSchema.safeParse(req.params).success) {
      return failure(res, 'INVALID_ACTOR_ID', 'Invalid actorId', 400);
    }
    const { actorId } = req.params;
    const { startTime, endTime } = req.query;
    // Range read, not classic offset pagination (no stable total count) — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // limit/offset parsing through the shared utility (accepts page/pageSize too).
    const { limit, offset } = parsePagination(req.query, { defaultPageSize: 200, maxPageSize: 1000 });

    try {
      const events = await centralStore.actorActivity(actorId, {
        limit,
        offset,
        startTime,
        endTime,
      });

      emit('INFO', 'AUDIT_STORE_ACTOR_ACTIVITY', {
        requestId: req.requestId,
        actor:     req.rbacUser?.username ?? null,
        actorId,
        count:     events.length,
      });

      return success(res, { actorId, events, count: events.length });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_ACTIVITY_FAILED', code: 'ACTIVITY_FAILED' });
    }
  });

  // ── Analytics ──────────────────────────────────────────────────────────────

  router.get('/stats', _canRead, async (req, res) => {
    try {
      const [s, topEvents] = await Promise.all([
        centralStore.stats(),
        centralStore.topEventTypes(24, 20),
      ]);
      return success(res, { stats: s, topEventTypes: topEvents });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_STATS_FAILED', code: 'STATS_FAILED' });
    }
  });

  router.get('/ingestion-rate', _canRead, async (req, res) => {
    const window = Math.min(parseInt(req.query.windowMinutes, 10) || 60, 1440);
    try {
      const rate = await centralStore.ingestionRate(window);
      return success(res, { windowMinutes: window, rate });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_RATE_FAILED', code: 'RATE_FAILED' });
    }
  });

  router.get('/top-events', _canRead, async (req, res) => {
    const hours = Math.min(parseInt(req.query.hours, 10) || 24, 168);
    // Top-N ranking, not classic offset pagination — see
    // API-4-REMEDIATION-REPORT.md "justified exceptions". Still centralizes
    // the limit clamp via the shared utility.
    const { limit } = parsePagination(req.query, { defaultPageSize: 20, maxPageSize: 100 });
    try {
      const events = await centralStore.topEventTypes(hours, limit);
      return success(res, { hours, events });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_TOP_EVENTS_FAILED', code: 'TOP_EVENTS_FAILED' });
    }
  });

  // ── Retention: policies ────────────────────────────────────────────────────

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them slices `policies` and adds
  // canonical pagination metadata.
  router.get('/retention/policies', _canRead, async (req, res) => {
    try {
      const policies = await retention.listPolicies();
      if (!isPaginationRequested(req.query)) {
        return success(res, { policies });
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
      const { items, ...meta } = paginateArray(policies, { page, pageSize });
      return success(res, { policies: items, ...meta });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_POLICIES_FAILED', code: 'POLICIES_FAILED' });
    }
  });

  router.post('/retention/policies', _canRetain, async (req, res) => {
    const rpParsed = retentionPolicyBodySchema.safeParse(req.body ?? {});
    if (!rpParsed.success) {
      const firstCode = rpParsed.error.issues[0]?.path?.[0] === 'retainDays'
        ? 'INVALID_RETAIN_DAYS' : 'INVALID_NAME';
      return failure(res, firstCode, 'Invalid retention policy body', 400);
    }
    const {
      name, description, eventCategory, eventTypePattern,
      tenantId, severity, retainDays, complianceProfile,
    } = rpParsed.data;

    try {
      const policy = await retention.upsertPolicy({
        name, description, eventCategory, eventTypePattern,
        tenantId, severity, retainDays, complianceProfile,
      });
      emit('INFO', 'AUDIT_RETENTION_POLICY_UPSERTED', {
        requestId: req.requestId, actor: req.rbacUser?.username, name, retainDays,
      });
      return success(res, { policy });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_POLICY_UPSERT_FAILED', code: 'POLICY_UPSERT_FAILED' });
    }
  });

  // ── Retention: cycle ───────────────────────────────────────────────────────

  router.post('/retention/apply', _canRetain, async (req, res) => {
    try {
      emit('INFO', 'AUDIT_RETENTION_APPLY_REQUESTED', {
        requestId: req.requestId, actor: req.rbacUser?.username,
      });
      const result = await retention.runRetentionCycle();
      return success(res, result);
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_RETENTION_FAILED', code: 'RETENTION_FAILED' });
    }
  });

  router.get('/retention/runs', _canRead, async (req, res) => {
    // "Recent N runs" read, not classic offset pagination (no stable total
    // count, no offset support in the store) — see API-4-REMEDIATION-REPORT.md
    // "justified exceptions". Still centralizes the limit clamp via the
    // shared utility (accepts `pageSize` as an alias for `limit`).
    const { limit } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 200 });
    try {
      const runs = await retention.listRuns(limit);
      return success(res, { runs });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_RUNS_FAILED', code: 'RUNS_FAILED' });
    }
  });

  // ── Retention: legal holds ─────────────────────────────────────────────────

  // Opt-in pagination (API-4 remediation): omitting page/pageSize/limit/offset
  // preserves this endpoint's original unbounded response for backward
  // compatibility; supplying any of them slices `holds` and adds canonical
  // pagination metadata.
  router.get('/retention/holds', _canRead, async (req, res) => {
    try {
      const holds = await retention.listLegalHolds();
      if (!isPaginationRequested(req.query)) {
        return success(res, { holds });
      }
      const { page, pageSize } = parsePagination(req.query, { defaultPageSize: 50, maxPageSize: 500 });
      const { items, ...meta } = paginateArray(holds, { page, pageSize });
      return success(res, { holds: items, ...meta });
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_HOLDS_FAILED', code: 'HOLDS_FAILED' });
    }
  });

  router.post('/retention/holds', _canRetain, async (req, res) => {
    const lhParsed = legalHoldBodySchema.safeParse(req.body ?? {});
    if (!lhParsed.success) {
      const lhIssue = lhParsed.error.issues[0];
      const lhPath0 = lhIssue?.path?.[0];
      const code = lhPath0 === 'holdName' ? 'INVALID_HOLD_NAME'
        : lhPath0 === 'reason' ? 'INVALID_HOLD_REASON'
        : 'HOLD_SCOPE_REQUIRED';
      return failure(res, code, lhIssue?.message ?? 'Invalid legal hold request', 400);
    }
    const { holdName, reason, artifactId, tenantId, eventCategory } = lhParsed.data;
    const heldBy = req.rbacUser?.username ?? req.rbacUser?.id ?? 'unknown';

    try {
      const result = await retention.placeLegalHold({
        holdName, reason, artifactId, tenantId, eventCategory, heldBy,
      });
      return success(res, result);
    } catch (e) {
      return internalError(res, req, e, { label: 'AUDIT_STORE_HOLD_FAILED', code: 'HOLD_FAILED' });
    }
  });

  router.delete('/retention/holds/:holdName', _canRetain, async (req, res) => {
    const { holdName } = req.params;
    const releasedBy = req.rbacUser?.username ?? req.rbacUser?.id ?? 'unknown';
    const query = releaseLegalHoldQuerySchema.safeParse(req.query ?? {});
    if (!query.success) return failure(res, 'INVALID_QUERY', query.error.issues[0]?.message ?? 'Invalid query');

    try {
      const hold = await retention.releaseLegalHold(holdName, releasedBy, query.data.tenantId ?? null);
      return success(res, { hold });
    } catch (e) {
      if (e.message.startsWith('No active hold')) {
        return failure(res, 'HOLD_NOT_FOUND', `No active legal hold found: ${holdName}`, 404);
      }
      return internalError(res, req, e, { label: 'AUDIT_STORE_RELEASE_FAILED', code: 'RELEASE_FAILED' });
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((_req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405));

  return router;
}

module.exports = createAuditStoreRouter;
