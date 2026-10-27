'use strict';

/**
 * QODIQA Webhooks API — Component #28
 *
 * Allows tenants to register and manage webhook endpoints that receive
 * signed HTTP notifications when long-running operations complete.
 *
 * All endpoints require ops auth + RBAC (mounted in server.js with middleware).
 * Secrets are returned exactly once (on creation) and never again.
 *
 * Mounted at /v1/webhooks in server.js.
 *
 * createWebhooksAdminRouter({ requirePermission })
 *   POST   /v1/webhooks                     — create endpoint (MANAGE_WEBHOOKS)
 *   GET    /v1/webhooks                     — list endpoints  (READ_WEBHOOKS)
 *   GET    /v1/webhooks/:id                 — get endpoint    (READ_WEBHOOKS)
 *   PATCH  /v1/webhooks/:id                 — update endpoint (MANAGE_WEBHOOKS)
 *   DELETE /v1/webhooks/:id                 — disable endpoint (MANAGE_WEBHOOKS)
 *   POST   /v1/webhooks/:id/test            — send test event (MANAGE_WEBHOOKS)
 *   GET    /v1/webhooks/:id/deliveries      — delivery log    (READ_WEBHOOKS)
 *   GET    /v1/webhooks/metrics             — delivery metrics (READ_WEBHOOKS)
 */

const { permissionGuard } = require('./permissionGuard'); // fail-closed permission wiring
const { Router }        = require('express');
const { createRateLimitMiddleware } = require('../../core/rateLimit');
const { emit }          = require('../../../services/logger');
const { success, failure, internalError } = require('../response');
const webhookStore      = require('../../core/webhooks/webhookStore');
const webhookDelivery   = require('../../core/webhooks/webhookDelivery');
const webhookMetrics    = require('../../core/webhooks/webhookMetrics');
const {
  parsePagination, parseSortOrder, withPaginationMeta,
} = require('../../utils/pagination');
const {
  webhookCreateSchema,
  webhookUpdateSchema,
  webhookIdParamSchema,
  SUPPORTED_EVENT_TYPES,
} = require('../../validation/schemas/webhooks.schema');

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_PAGE_SIZE     = 500;
const DEFAULT_PAGE_SIZE = 50;
const API_VERSION       = 'v1';

// ── Response helpers ──────────────────────────────────────────────────────────

// Thin adapters over the canonical envelope (src/api/response.js) that keep
// this file's existing (data, req, status) call-site ergonomics — the actual
// envelope shape is built in exactly one place, response.js.
function _ok(res, data, req, status) {
  return success(res, { ...data, apiVersion: API_VERSION }, status || 200);
}

function _notFound(res, req, message) {
  return failure(res, 'NOT_FOUND', message, 404, { apiVersion: API_VERSION });
}

function _badRequest(res, req, message) {
  return failure(res, 'INVALID_PARAM', message, 400, { apiVersion: API_VERSION });
}

// API-2: delegates to the centralized src/api/response.js implementation —
// this thin wrapper only preserves this file's existing (res, req, err,
// label) call-site signature and its apiVersion detail field.
function _internalError(res, req, err, label) {
  return internalError(res, req, err, { label: label || 'WEBHOOK_API_ERROR', details: { apiVersion: API_VERSION } });
}

// Delegates to the canonical pagination utility (src/utils/pagination.js —
// API-4 remediation). Also accepts the legacy `limit`/`offset`/`sortDir`/
// `sort` aliases via that shared parser.
function _pagination(query) {
  const { page, pageSize } = parsePagination(query, { defaultPageSize: DEFAULT_PAGE_SIZE, maxPageSize: MAX_PAGE_SIZE });
  const sortOrder = parseSortOrder(query);
  return { page, pageSize, sortOrder };
}

function _clientIp(req) {
  return req.clientIp || req.ip || null;
}

function _actor(req) {
  return req.rbacUser?.username ?? 'external';
}

// ── Admin router factory ──────────────────────────────────────────────────────

function createWebhooksAdminRouter({ requirePermission } = {}) {
  const router = Router();
  router.use(createRateLimitMiddleware('webhooks_admin', { envelope: 'management' }));

  const _canRead   = permissionGuard(requirePermission, 'READ_WEBHOOKS', 'webhooks');
  const _canManage = permissionGuard(requirePermission, 'MANAGE_WEBHOOKS', 'webhooks');

  // ── POST / — create endpoint ───────────────────────────────────────────────
  //
  // Creates a new webhook endpoint for a tenant.
  // Generates a signing secret and returns it once in the response.
  // The secret is stored encrypted — it cannot be retrieved after this call.
  //
  // Body: { tenantId, url, eventTypes[], description? }
  // Response includes `secret` (plaintext, returned once only).

  router.post('/', _canManage, async (req, res) => {
    const parsed = webhookCreateSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _badRequest(res, req, parsed.error.issues[0]?.message ?? 'Invalid request body');
    }

    // Validate URL safety before storing (SSRF protection at API layer)
    const urlCheck = webhookDelivery.validateUrl(parsed.data.url);
    if (!urlCheck.ok) {
      return _badRequest(res, req, urlCheck.error);
    }

    try {
      const result = await webhookStore.createEndpoint({
        tenantId:    parsed.data.tenantId,
        url:         parsed.data.url,
        eventTypes:  parsed.data.eventTypes,
        description: parsed.data.description,
        createdBy:   _actor(req),
      });

      if (!result) {
        return _badRequest(res, req, 'PostgreSQL is not enabled — webhook persistence unavailable');
      }

      emit('INFO', 'WEBHOOK_ENDPOINT_REGISTERED', {
        endpointId:  result.endpoint.id,
        tenantId:    parsed.data.tenantId,
        eventTypes:  parsed.data.eventTypes,
        requestedBy: _actor(req),
        requestIp:   _clientIp(req),
      });

      return _ok(res, {
        endpoint: result.endpoint,
        secret:   result.secret,
        notice:   'The secret is returned once only and cannot be retrieved again. Store it securely.',
      }, req, 201);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_CREATE_ERROR');
    }
  });

  // ── GET / — list endpoints ─────────────────────────────────────────────────
  //
  // Returns paginated list of webhook endpoints for a tenant.
  // Query params: tenantId (required), enabledOnly?, page?, pageSize?, sortOrder?
  // (legacy aliases limit?/offset?/sortDir? also accepted — see src/utils/pagination.js)

  router.get('/', _canRead, async (req, res) => {
    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    try {
      const { page, pageSize, sortOrder } = _pagination(req.query);
      const enabledOnly = req.query.enabledOnly === 'true';

      const result = await webhookStore.listEndpoints({ tenantId, enabledOnly, page, pageSize, sortOrder });
      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_LIST_ERROR');
    }
  });

  // ── GET /metrics — delivery metrics ───────────────────────────────────────
  //
  // Returns in-process delivery metrics snapshot.
  // Must be mounted BEFORE /:id to prevent /metrics being treated as an ID.

  router.get('/metrics', _canRead, (req, res) => {
    return _ok(res, { webhookMetrics: webhookMetrics.snapshot() }, req);
  });

  // ── GET /:id — get endpoint ────────────────────────────────────────────────
  //
  // Query params: tenantId (required) — establishes the RLS tenant context
  // for the lookup; a valid id belonging to a different tenant is invisible
  // (returns 404), matching the tenant-scoping already required by GET /.

  router.get('/:id', _canRead, async (req, res) => {
    const paramCheck = webhookIdParamSchema.safeParse(req.params);
    if (!paramCheck.success) {
      return _badRequest(res, req, 'id must be a valid UUID');
    }

    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    try {
      const endpoint = await webhookStore.getEndpointById(req.params.id, tenantId);
      if (!endpoint) {
        return _notFound(res, req, `Webhook endpoint not found: ${req.params.id}`);
      }
      return _ok(res, { endpoint }, req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_GET_ERROR');
    }
  });

  // ── PATCH /:id — update endpoint ──────────────────────────────────────────
  //
  // Update url, enabled, eventTypes, or description.
  // Validates new URL for SSRF safety if url is updated.
  // Query params: tenantId (required) — see GET /:id.

  router.patch('/:id', _canManage, async (req, res) => {
    const paramCheck = webhookIdParamSchema.safeParse(req.params);
    if (!paramCheck.success) {
      return _badRequest(res, req, 'id must be a valid UUID');
    }

    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    const parsed = webhookUpdateSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return _badRequest(res, req, parsed.error.issues[0]?.message ?? 'Invalid request body');
    }

    if (parsed.data.url) {
      const urlCheck = webhookDelivery.validateUrl(parsed.data.url);
      if (!urlCheck.ok) {
        return _badRequest(res, req, urlCheck.error);
      }
    }

    try {
      const existing = await webhookStore.getEndpointById(req.params.id, tenantId);
      if (!existing) {
        return _notFound(res, req, `Webhook endpoint not found: ${req.params.id}`);
      }

      const updated = await webhookStore.updateEndpoint(req.params.id, parsed.data, tenantId);

      emit('INFO', 'WEBHOOK_ENDPOINT_UPDATED', {
        endpointId:  req.params.id,
        updates:     Object.keys(parsed.data),
        requestedBy: _actor(req),
      });

      return _ok(res, { endpoint: updated }, req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_UPDATE_ERROR');
    }
  });

  // ── DELETE /:id — disable endpoint ────────────────────────────────────────
  //
  // Soft-deletes (disables) an endpoint.  Hard deletes are not permitted via
  // the application role to preserve delivery log referential integrity.
  // Query params: tenantId (required) — see GET /:id.

  router.delete('/:id', _canManage, async (req, res) => {
    const paramCheck = webhookIdParamSchema.safeParse(req.params);
    if (!paramCheck.success) {
      return _badRequest(res, req, 'id must be a valid UUID');
    }

    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    try {
      const existing = await webhookStore.getEndpointById(req.params.id, tenantId);
      if (!existing) {
        return _notFound(res, req, `Webhook endpoint not found: ${req.params.id}`);
      }

      const disabled = await webhookStore.deleteEndpoint(req.params.id, tenantId);

      emit('INFO', 'WEBHOOK_ENDPOINT_DISABLED', {
        endpointId:  req.params.id,
        requestedBy: _actor(req),
      });

      return _ok(res, { endpoint: disabled }, req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_DELETE_ERROR');
    }
  });

  // ── POST /:id/test — send test event ──────────────────────────────────────
  //
  // Delivers a synthetic test event to the endpoint immediately (synchronous).
  // Allows operators to verify endpoint reachability and signature verification.
  // Uses the first configured event type as the test event type.
  // Query params: tenantId (required) — see GET /:id.

  router.post('/:id/test', _canManage, async (req, res) => {
    const paramCheck = webhookIdParamSchema.safeParse(req.params);
    if (!paramCheck.success) {
      return _badRequest(res, req, 'id must be a valid UUID');
    }

    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    try {
      const endpoint = await webhookStore._getEndpointForDelivery(req.params.id, tenantId);
      if (!endpoint) {
        return _notFound(res, req, `Webhook endpoint not found or disabled: ${req.params.id}`);
      }

      const eventType  = endpoint.event_types[0] ?? SUPPORTED_EVENT_TYPES[0];
      const { randomUUID } = require('crypto');
      const testEventId = randomUUID();
      const testPayload = {
        eventId:   testEventId,
        eventType,
        timestamp: new Date().toISOString(),
        test:      true,
        message:   'QODIQA webhook test delivery',
      };

      const result = await webhookDelivery.deliver({
        endpointId: endpoint.id,
        url:        endpoint.url,
        secret:     endpoint._secret,
        eventId:    testEventId,
        eventType,
        payload:    testPayload,
        attempt:    1,
      });

      emit('INFO', 'WEBHOOK_TEST_SENT', {
        endpointId:  endpoint.id,
        eventType,
        ok:          result.ok,
        httpStatus:  result.httpStatus,
        durationMs:  result.durationMs,
        requestedBy: _actor(req),
      });

      return _ok(res, {
        test:       true,
        ok:         result.ok,
        httpStatus: result.httpStatus,
        durationMs: result.durationMs,
        error:      result.error ?? null,
        eventId:    testEventId,
        eventType,
      }, req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_TEST_ERROR');
    }
  });

  // ── GET /:id/deliveries — delivery history ─────────────────────────────────
  //
  // Query params: tenantId (required, see GET /:id), page?, pageSize?,
  // sortOrder?, failedOnly?
  // (legacy aliases limit?/offset?/sortDir? also accepted — see src/utils/pagination.js)

  router.get('/:id/deliveries', _canRead, async (req, res) => {
    const paramCheck = webhookIdParamSchema.safeParse(req.params);
    if (!paramCheck.success) {
      return _badRequest(res, req, 'id must be a valid UUID');
    }

    const { tenantId } = req.query;
    if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
      return _badRequest(res, req, 'tenantId query parameter is required');
    }

    try {
      const existing = await webhookStore.getEndpointById(req.params.id, tenantId);
      if (!existing) {
        return _notFound(res, req, `Webhook endpoint not found: ${req.params.id}`);
      }

      const { page, pageSize, sortOrder } = _pagination(req.query);
      const failedOnly = req.query.failedOnly === 'true';

      const result = await webhookStore.listDeliveries({
        endpointId: req.params.id,
        tenantId,
        page,
        pageSize,
        failedOnly,
        sortOrder,
      });

      return _ok(res, withPaginationMeta(result), req);
    } catch (err) {
      return _internalError(res, req, err, 'WEBHOOK_DELIVERIES_ERROR');
    }
  });

  // ── 405 catch-all — reject unsupported methods/paths under this mount ──────
  router.use((req, res) => failure(res, 'METHOD_NOT_ALLOWED', 'Method not allowed', 405, { apiVersion: API_VERSION }));

  return router;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = { createWebhooksAdminRouter };
