'use strict';

/**
 * QODIQA Alert Engine
 *
 * Central lifecycle manager for all alerts.
 * Responsibilities:
 *   - Accept raw alert specifications from the DetectionEngine
 *   - Apply suppression rules
 *   - Compute composite risk score and final severity
 *   - Assign retention periods
 *   - Persist to AlertStore
 *   - Publish to EventBus for SSE subscribers and downstream consumers
 *   - Trigger NotificationService for immediate channels
 *   - Schedule escalation timers
 *
 * All operations are fire-and-forget safe: errors are logged and swallowed
 * so the alert subsystem never crashes the main request path.
 */

const crypto  = require('crypto');
const { EventEmitter } = require('events');

const { computeRiskScore, maxSeverity } = require('./RiskScorer');
const { getNextEscalation, isImmediateNotification } = require('./SeverityModel');
const alertStore = require('../storage/AlertStore');
const {
  ALERT_STATUS, SEVERITY,
} = require('../constants');

// Internal event bus for alert lifecycle events.
// Subscribers: CorrelationEngine, EscalationService, SSE dashboard
const alertBus = new EventEmitter();
alertBus.setMaxListeners(100);

// Lazy-loaded to avoid circular dependency at module init time
let _notificationService = null;
let _escalationService   = null;

function registerNotificationService(svc) { _notificationService = svc; }
function registerEscalationService(svc)   { _escalationService   = svc; }

// ── Alert creation ────────────────────────────────────────────────────────────

/**
 * Create and persist a new alert from a raw detection specification.
 *
 * @param {object} spec  — Alert spec from a detector
 * @returns {Promise<object|null>}  — Saved alert, or null if suppressed
 */
async function createAlert(spec) {
  try {
    // 1. Compute composite risk score
    const { riskScore, derivedSeverity, factors } = computeRiskScore({
      severity:   spec.severity,
      subtype:    spec.subtype,
      confidence: spec.confidence ?? 100,
      context:    spec.context    ?? {},
    });

    // Use the higher of declared severity and score-derived severity
    const finalSeverity = maxSeverity(spec.severity, derivedSeverity);

    // 2. Build the alert object
    const alert = {
      id:          crypto.randomUUID(),
      type:        spec.type,
      subtype:     spec.subtype,
      severity:    finalSeverity,
      status:      ALERT_STATUS.OPEN,
      riskScore,
      confidence:  spec.confidence ?? 100,
      title:       spec.title,
      description: spec.description ?? '',
      tags:        spec.tags        ?? [],
      sourceEvent: spec.sourceEvent,
      requestId:   spec.requestId   ?? null,
      artifactId:  spec.artifactId  ?? null,
      tenantId:    spec.tenantId    ?? null,
      publicKeyId: spec.publicKeyId ?? null,
      clientIp:    spec.clientIp    ?? null,
      actorId:     spec.actorId     ?? null,
      component:   spec.component   ?? null,
      evidence:    spec.evidence    ?? {},
      context:     { ...(spec.context ?? {}), riskFactors: factors },
      detectedAt:  new Date(),
      escalationLevel: 0,
    };

    // 3. Compute next escalation deadline
    const esc = getNextEscalation(finalSeverity, 0, alert.detectedAt.getTime());
    alert.nextEscalationAt = esc.nextEscalationAt;

    // 4. Suppression check
    const suppressed = await alertStore.isSuppressed(alert);
    if (suppressed) {
      _emit('alert.suppressed', alert);
      return null;
    }

    // 5. Persist
    const saved = await alertStore.saveAlert(alert);

    // 6. Publish lifecycle event
    _emit('alert.created', saved);

    // 7. Immediate notifications for actionable severities
    if (isImmediateNotification(finalSeverity) && _notificationService) {
      _notificationService.notify(saved).catch(e =>
        require('../../../services/logger').emit('ERROR', 'ALERT_NOTIFICATION_FAILED',
          { alertId: saved.id, error: e.message })
      );
    }

    // 8. Schedule escalation
    if (_escalationService && esc.nextEscalationAt) {
      _escalationService.schedule(saved);
    }

    return saved;
  } catch (err) {
    require('../../../services/logger').emit('ERROR', 'ALERT_ENGINE_CREATE_FAILED', {
      error: err.message, type: spec.type, subtype: spec.subtype,
    });
    return null;
  }
}

// ── Alert lifecycle transitions ───────────────────────────────────────────────

/**
 * Acknowledge an alert.
 * @param {string} alertId
 * @param {object} meta  — { actor, note }
 */
async function acknowledgeAlert(alertId, meta = {}) {
  const alert = await alertStore.getAlert(alertId);
  if (!alert) return null;
  if (alert.status !== ALERT_STATUS.OPEN && alert.status !== ALERT_STATUS.INVESTIGATING) {
    throw new Error(`Cannot acknowledge alert in status ${alert.status}`);
  }

  // the UPDATE ran without the alert's tenant context, so under qa_tenant_update (RLS) it matched zero rows for a
  // tenant-scoped alert and the route answered 404. getAlert() already returned the alert (full-read bypass) — its tenant is known.
  const updated = await alertStore.updateAlertStatus(alertId, ALERT_STATUS.ACKNOWLEDGED, { ...meta, tenantId: meta.tenantId ?? alert.tenantId ?? undefined });
  if (updated) {
    _emit('alert.acknowledged', updated);
    if (_escalationService) _escalationService.cancel(alertId);
  }
  return updated;
}

/**
 * Mark an alert as resolved.
 */
async function resolveAlert(alertId, meta = {}) {
  const alert = await alertStore.getAlert(alertId);
  if (!alert) return null;
  if (alert.status === ALERT_STATUS.RESOLVED || alert.status === ALERT_STATUS.CLOSED) {
    throw new Error(`Alert ${alertId} is already ${alert.status}`);
  }

  const updated = await alertStore.updateAlertStatus(alertId, ALERT_STATUS.RESOLVED, { ...meta, tenantId: meta.tenantId ?? alert.tenantId ?? undefined }); // 4.4: tenant context for RLS
  if (updated) {
    _emit('alert.resolved', updated);
    if (_escalationService) _escalationService.cancel(alertId);
  }
  return updated;
}

/**
 * RC-10: resolve the still-unresolved alerts a recovery event makes stale.
 * Only alerts whose subtype AND sourceEvent match are touched, so an alert raised
 * by a different producer of the same subtype (e.g. Redis HA) stays open.
 *
 * @param {object}   match  — { type, subtype, sourceEvents: string[] }
 * @param {object}   meta   — { actor, note }
 * @returns {Promise<number>}  number of alerts resolved
 */
async function resolveRecovered(match, meta = {}) {
  let resolved = 0;
  for (const status of [ALERT_STATUS.OPEN, ALERT_STATUS.ACKNOWLEDGED, ALERT_STATUS.INVESTIGATING]) {
    const { alerts } = await alertStore.listAlerts({ status, type: match.type, pageSize: 200 });
    for (const a of alerts) {
      if (a.subtype !== match.subtype || !match.sourceEvents.includes(a.sourceEvent)) continue;
      try {
        if (await resolveAlert(a.id, meta)) resolved += 1;
      } catch (_) { /* resolved concurrently — nothing to do */ }
    }
  }
  return resolved;
}

/**
 * Suppress an alert.
 */
async function suppressAlert(alertId, meta = {}) {
  const alert = meta.tenantId === undefined ? await alertStore.getAlert(alertId) : null; // 4.4: tenant context for RLS
  const updated = await alertStore.updateAlertStatus(alertId, ALERT_STATUS.SUPPRESSED, { ...meta, tenantId: meta.tenantId ?? alert?.tenantId ?? undefined });
  if (updated) _emit('alert.suppressed', updated);
  return updated;
}

/**
 * Mark as false positive.
 */
async function markFalsePositive(alertId, meta = {}) {
  const alert = meta.tenantId === undefined ? await alertStore.getAlert(alertId) : null; // 4.4: tenant context for RLS
  const updated = await alertStore.updateAlertStatus(alertId, ALERT_STATUS.FALSE_POSITIVE, { ...meta, tenantId: meta.tenantId ?? alert?.tenantId ?? undefined });
  if (updated) _emit('alert.false_positive', updated);
  return updated;
}

// ── Subscription API ──────────────────────────────────────────────────────────

/**
 * Subscribe to alert lifecycle events.
 * @param {string}   channel  — 'alert.created' | 'alert.acknowledged' | etc.
 * @param {Function} handler
 */
function on(channel, handler) { alertBus.on(channel, handler); }
function off(channel, handler) { alertBus.off(channel, handler); }

// ── Internal ──────────────────────────────────────────────────────────────────

function _emit(channel, payload) {
  alertBus.emit(channel, payload);

  // Also publish to the main logger eventBus for SSE dashboard integration
  try {
    const { eventBus } = require('../../../services/logger');
    eventBus.emit('alert', { channel, alert: payload });
  } catch (_) {}
}

module.exports = {
  createAlert,
  acknowledgeAlert,
  resolveAlert,
  resolveRecovered,
  suppressAlert,
  markFalsePositive,
  registerNotificationService,
  registerEscalationService,
  on,
  off,
  alertBus,
};
