'use strict';

/**
 * QODIQA Alerting Framework — REST API
 *
 * OpenAPI-compatible routes for alert management.
 *
 * All routes require RBAC authentication enforced by the opsAuth middleware
 * mounted in server.js. Alert creation is internal-only.
 *
 * Routes:
 *   GET    /alerts              — List alerts (with filtering and pagination)
 *   POST   /alerts              — Create alert (internal use / admin)
 *   GET    /alerts/stats        — Aggregate statistics
 *   GET    /alerts/stream       — SSE real-time alert stream
 *   GET    /alerts/:id          — Alert details
 *   POST   /alerts/:id/acknowledge  — Acknowledge alert
 *   POST   /alerts/:id/resolve      — Resolve alert
 *   POST   /alerts/:id/suppress     — Suppress alert
 *   POST   /alerts/:id/false-positive — Mark as false positive
 *   GET    /alerts/:id/history      — Alert audit history
 * GET /alerts/:id/exposure-notification — Drafts of the notifications for a DATA_EXPOSURE alert
 *   GET    /alerts/health           — Channel health check
 *   POST   /alerts/test/:channel    — Test notification channel
 *   GET    /alerts/counters         — Real-time anomaly counters (dashboard)
 */

const { resolveOperatorActor } = require('../../core/audit/actorAttribution');
const { Router } = require('express');

const alertEngine           = require('../engine/AlertEngine');
const alertStore            = require('../storage/AlertStore');
const notificationService   = require('../notification/NotificationService');
const anomalyDetector       = require('../detection/AnomalyDetector');

const {
  ALERT_TYPE, ALERT_STATUS, SEVERITY, CHANNEL,
} = require('../constants');
const { parsePagination, withPaginationMeta } = require('../../utils/pagination');

// ── Input validation helpers ──────────────────────────────────────────────────

const VALID_ALERT_TYPES   = new Set(Object.values(ALERT_TYPE));
const VALID_SEVERITIES    = new Set(Object.values(SEVERITY));
const VALID_STATUSES      = new Set(Object.values(ALERT_STATUS));
const VALID_CHANNELS      = new Set(Object.values(CHANNEL));
const UUID_RE             = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function _isUUID(s) { return UUID_RE.test(s); }

function _parseDate(val, defaultVal) {
  if (!val) return defaultVal;
  const d = new Date(val);
  return isNaN(d.getTime()) ? defaultVal : d;
}

function _err(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

// ── Router ────────────────────────────────────────────────────────────────────

function createAlertRouter(opts = {}) {
  const router = Router();
  // (NF-8): mutations need MANAGE_ALERTS; suppressing an alert (which hides
  // it from on-call) additionally needs MFA step-up. The mount (src/app.js)
  // keeps READ_AUDIT for every route. Without the options (unit tests that
  // build the router alone) the guards are no-ops, as before.
  const _pass = (_req, _res, next) => next();
  const _canManage = opts.requirePermission ? opts.requirePermission('MANAGE_ALERTS') : _pass;
  const _stepUp = opts.stepUp || _pass;

  // ── GET /alerts/stats ───────────────────────────────────────────────────────
  // Must be before /:id route to avoid conflicts
  router.get('/stats', async (req, res) => {
    try {
      const from = _parseDate(req.query.from, new Date(Date.now() - 24 * 3600_000));
      const to   = _parseDate(req.query.to,   new Date());
      const stats = await alertStore.getStats({ from, to });
      return res.json({ ok: true, stats });
    } catch (err) {
      return _err(res, 500, 'STATS_FAILED', err.message);
    }
  });

  // ── GET /alerts/health ──────────────────────────────────────────────────────
  router.get('/health', async (req, res) => {
    try {
      const channels = await notificationService.healthCheck();
      const allOk    = Object.values(channels).every(c => !c.enabled || c.ok);
      return res.status(allOk ? 200 : 207).json({ ok: allOk, channels });
    } catch (err) {
      return _err(res, 500, 'HEALTH_FAILED', err.message);
    }
  });

  // ── GET /alerts/counters ────────────────────────────────────────────────────
  router.get('/counters', (req, res) => {
    try {
      return res.json({ ok: true, counters: anomalyDetector.getCounterSnapshot() });
    } catch (err) {
      return _err(res, 500, 'COUNTERS_FAILED', err.message);
    }
  });

  // ── POST /alerts/test/:channel ──────────────────────────────────────────────
  router.post('/test/:channel', _canManage, async (req, res) => {
    const channelName = (req.params.channel ?? '').toUpperCase();
    if (!VALID_CHANNELS.has(channelName)) {
      return _err(res, 400, 'INVALID_CHANNEL', `Unknown channel: ${channelName}`);
    }
    try {
      const result = await notificationService.testChannel(channelName);
      return res.status(result.sent ? 200 : 502).json({ ok: result.sent, result });
    } catch (err) {
      return _err(res, 500, 'TEST_FAILED', err.message);
    }
  });

  // ── GET /alerts/stream — Server-Sent Events ─────────────────────────────────
  router.get('/stream', (req, res) => {
    res.setHeader('Content-Type',  'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection',    'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const sendEvent = (channel, alert) => {
      try {
        res.write(`event: ${channel}\n`);
        res.write(`data: ${JSON.stringify(alert)}\n\n`);
      } catch (_) {}
    };

    const handler = (payload) => sendEvent(payload.channel, payload.alert);
    const { eventBus } = require('../../../services/logger');
    eventBus.on('alert', handler);

    // Heartbeat every 30s to keep connection alive through proxies
    const hb = setInterval(() => {
      try { res.write(':heartbeat\n\n'); } catch (_) { clearInterval(hb); }
    }, 30_000);

    req.on('close', () => {
      clearInterval(hb);
      eventBus.off('alert', handler);
    });
  });

  // ── GET /alerts ─────────────────────────────────────────────────────────────
  router.get('/', async (req, res) => {
    try {
      const q = req.query;

      // Validate optional filters
      if (q.severity && !VALID_SEVERITIES.has(q.severity))
        return _err(res, 400, 'INVALID_SEVERITY', `severity must be one of: ${[...VALID_SEVERITIES].join(', ')}`);
      if (q.status && !VALID_STATUSES.has(q.status))
        return _err(res, 400, 'INVALID_STATUS', `status must be one of: ${[...VALID_STATUSES].join(', ')}`);
      if (q.type && !VALID_ALERT_TYPES.has(q.type))
        return _err(res, 400, 'INVALID_TYPE', `type must be one of: ${[...VALID_ALERT_TYPES].join(', ')}`);
      if (q.requestId && !_isUUID(q.requestId))
        return _err(res, 400, 'INVALID_REQUEST_ID', 'requestId must be a valid UUID');

      // `sort` here is a named-field enum (e.g. `risk_score_desc`), not a
      // direction toggle — it is a justified exception to the canonical
      // `sortOrder` model (see API-4-REMEDIATION-REPORT.md) and is passed
      // through untouched. page/pageSize (+ legacy limit/offset aliases) go
      // through the shared pagination utility for the max-page-size clamp
      // that this route previously left entirely to the store layer.
      const { page, pageSize } = parsePagination(q, { defaultPageSize: 50, maxPageSize: 200 });

      const result = await alertStore.listAlerts({
        status:     q.status,
        severity:   q.severity,
        type:       q.type,
        tenantId:   q.tenantId,
        requestId:  q.requestId,
        artifactId: q.artifactId,
        incidentId: q.incidentId,
        from:       _parseDate(q.from, null),
        to:         _parseDate(q.to,   null),
        page,
        pageSize,
        sort:       q.sort,
      });

      return res.json({ ok: true, ...withPaginationMeta(result) });
    } catch (err) {
      return _err(res, 500, 'LIST_FAILED', err.message);
    }
  });

  // ── POST /alerts ─────────────────────────────────────────────────────────────
  // Internal use only — normally alerts are created by the DetectionEngine.
  // Exposed for admin injection and integration testing.
  router.post('/', _canManage, async (req, res) => {
    const spec = req.body ?? {};

    if (!spec.type || !VALID_ALERT_TYPES.has(spec.type))
      return _err(res, 400, 'INVALID_TYPE', 'type is required');
    if (!spec.subtype || typeof spec.subtype !== 'string')
      return _err(res, 400, 'INVALID_SUBTYPE', 'subtype is required');
    if (!spec.severity || !VALID_SEVERITIES.has(spec.severity))
      return _err(res, 400, 'INVALID_SEVERITY', 'severity is required');
    if (!spec.title || typeof spec.title !== 'string' || spec.title.length > 256)
      return _err(res, 400, 'INVALID_TITLE', 'title is required (max 256 chars)');

    try {
      const alert = await alertEngine.createAlert(spec);
      if (!alert) return res.status(200).json({ ok: true, suppressed: true });
      return res.status(201).json({ ok: true, alert });
    } catch (err) {
      return _err(res, 500, 'CREATE_FAILED', err.message);
    }
  });

  // ── GET /alerts/:id ─────────────────────────────────────────────────────────
  router.get('/:id', async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const alert = await alertStore.getAlert(req.params.id);
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      return res.json({ ok: true, alert });
    } catch (err) {
      return _err(res, 500, 'GET_FAILED', err.message);
    }
  });

  // ── POST /alerts/:id/acknowledge ────────────────────────────────────────────
  router.post('/:id/acknowledge', _canManage, async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const actor = resolveOperatorActor(req); // audit 4.4: the AUTHENTICATED operator — a body-supplied `actor` can no longer name someone else
      const note  = req.body?.note;
      const alert = await alertEngine.acknowledgeAlert(req.params.id, { actor, note });
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      return res.json({ ok: true, alert });
    } catch (err) {
      if (err.message.includes('Cannot acknowledge')) return _err(res, 409, 'INVALID_TRANSITION', err.message);
      return _err(res, 500, 'ACKNOWLEDGE_FAILED', err.message);
    }
  });

  // ── POST /alerts/:id/resolve ─────────────────────────────────────────────────
  router.post('/:id/resolve', _canManage, async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const actor = resolveOperatorActor(req); // audit 4.4: the AUTHENTICATED operator — a body-supplied `actor` can no longer name someone else
      const note  = req.body?.note;
      const alert = await alertEngine.resolveAlert(req.params.id, { actor, note });
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      return res.json({ ok: true, alert });
    } catch (err) {
      if (err.message.includes('already')) return _err(res, 409, 'INVALID_TRANSITION', err.message);
      return _err(res, 500, 'RESOLVE_FAILED', err.message);
    }
  });

  // ── POST /alerts/:id/suppress ────────────────────────────────────────────────
  router.post('/:id/suppress', _canManage, _stepUp, async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const actor = resolveOperatorActor(req); // audit 4.4: the AUTHENTICATED operator — a body-supplied `actor` can no longer name someone else
      const alert = await alertEngine.suppressAlert(req.params.id, { actor });
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      return res.json({ ok: true, alert });
    } catch (err) {
      return _err(res, 500, 'SUPPRESS_FAILED', err.message);
    }
  });

  // ── POST /alerts/:id/false-positive ─────────────────────────────────────────
  router.post('/:id/false-positive', _canManage, async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const actor = resolveOperatorActor(req); // audit 4.4: the AUTHENTICATED operator — a body-supplied `actor` can no longer name someone else
      const note  = req.body?.note;
      const alert = await alertEngine.markFalsePositive(req.params.id, { actor, note });
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      return res.json({ ok: true, alert });
    } catch (err) {
      return _err(res, 500, 'MARK_FP_FAILED', err.message);
    }
  });

  // ── GET /alerts/:id/history ──────────────────────────────────────────────────
  router.get('/:id/history', async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');

    try {
      const history = await alertStore.getAlertHistory(req.params.id);
      return res.json({ ok: true, alertId: req.params.id, history });
    } catch (err) {
      return _err(res, 500, 'HISTORY_FAILED', err.message);
    }
  });

  // ── GET /alerts/:id/exposure-notification ──────────────────────────────────────
  // Drafts built from the alert's facts (no values): an internal summary and the text of the notifications commonly required. Read-only; sending anything is the operator's decision.
  router.get('/:id/exposure-notification', async (req, res) => {
    if (!_isUUID(req.params.id))
      return _err(res, 400, 'INVALID_ID', 'id must be a valid UUID');
    try {
      const alert = await alertStore.getAlert(req.params.id);
      if (!alert) return _err(res, 404, 'NOT_FOUND', `Alert ${req.params.id} not found`);
      if (alert.subtype !== 'DATA_EXPOSURE') return _err(res, 409, 'NOT_AN_EXPOSURE_ALERT', 'notification drafts exist only for DATA_EXPOSURE alerts');
      const q = req.query || {};
      const text = (v) => (typeof v === 'string' ? v.trim().slice(0, 200) : '');
      const drafts = require('../../core/incidents/exposureNotifications').exposureDrafts(alert, {
        controller: text(q.organisation) ? { name: text(q.organisation) } : undefined, dpo: text(q.contact) ? { contact: text(q.contact) } : undefined,
      });
      return res.json({ ok: true, alertId: alert.id, ...drafts });
    } catch (err) {
      return _err(res, 500, 'EXPOSURE_NOTIFICATION_FAILED', err.message);
    }
  });

  return router;
}

module.exports = { createAlertRouter };
