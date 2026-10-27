'use strict';

/**
 * QODIQA Escalation Service
 *
 * Manages time-based escalation workflows for unacknowledged alerts.
 *
 * Escalation chain:
 *   1. Alert created → schedule first escalation at (detectedAt + ackWindowMs)
 *   2. If not acknowledged by deadline → escalate to next level → reschedule
 *   3. Max escalation level reached → stop escalation
 *   4. Alert acknowledged/resolved → cancel all pending timers
 *
 * Timer accuracy: setInterval-based at 30s resolution.
 * All timer state is in-memory. On server restart, active alerts
 * that missed their escalation window are re-evaluated at startup.
 *
 * Security: Escalation logic is fail-closed — if the notification
 * service fails, the escalation is still recorded in the audit trail.
 */

const { emit } = require('../../../services/logger');
const alertStore = require('../storage/AlertStore');
const { getNextEscalation } = require('../engine/SeverityModel');
const { ALERT_STATUS } = require('../constants');
const _defaultTaskRunner = require('../../runtime/backgroundTasks/BackgroundTaskRunner');

// Lazy-loaded to break circular dependency
let _notificationService = null;
function registerNotificationService(svc) { _notificationService = svc; }

// ── Timer registry ────────────────────────────────────────────────────────────

// alertId → { timerId, scheduledAt, escalationLevel }
const _timers = new Map();

// Scan interval: check all pending escalations every 30 seconds
let _scanInterval = null;
const SCAN_INTERVAL_MS = 30_000;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Schedule escalation for a newly created alert.
 * No-op if severity is INFO or the severity has no escalation steps.
 */
function schedule(alert) {
  if (!alert.nextEscalationAt) return;

  const deadline = new Date(alert.nextEscalationAt).getTime();
  if (isNaN(deadline)) return;

  _timers.set(alert.id, {
    alertId:         alert.id,
    deadline,
    severity:        alert.severity,
    escalationLevel: alert.escalationLevel ?? 0,
  });
}

/**
 * Cancel all pending escalation timers for an alert.
 * Called on acknowledge or resolve.
 */
function cancel(alertId) {
  _timers.delete(alertId);
}

/**
 * Start the background escalation scan loop.
 * Called by AlertingFramework.initialize().
 */
function start({ _taskRunner = _defaultTaskRunner } = {}) {
  if (_scanInterval) return;

  // Finding 3.6: the scan tick runs through BackgroundTaskRunner for
  // consistent isolation/logging/metrics across every background job.
  // _scan() already isolates each individual alert's escalation failure
  // (see the try/catch around _escalate() below) — that stays unchanged;
  // this wraps the scan tick itself as defense-in-depth for anything
  // outside that inner loop (e.g. a future change to the due-alert
  // selection logic above it).
  _scanInterval = setInterval(() => {
    _taskRunner.runTask('alert-escalation-scan', _scan).catch(() => { /* non-critical task never rejects; belt-and-suspenders */ });
  }, SCAN_INTERVAL_MS);
  _scanInterval.unref();  // don't prevent process exit

  emit('INFO', 'ESCALATION_SERVICE_STARTED', {
    scanIntervalMs: SCAN_INTERVAL_MS,
  });
}

/**
 * Stop the scan loop.
 */
function stop() {
  if (_scanInterval) {
    clearInterval(_scanInterval);
    _scanInterval = null;
  }
  _timers.clear();
}

/**
 * Re-hydrate escalation timers from the database on startup.
 * Picks up any alerts that were open before a server restart.
 */
async function rehydrate() {
  try {
    const { alerts } = await alertStore.listAlerts({
      status:   'OPEN',
      pageSize: 200,
    });

    let scheduled = 0;
    for (const alert of alerts) {
      if (alert.nextEscalationAt) {
        schedule(alert);
        scheduled++;
      }
    }

    emit('INFO', 'ESCALATION_SERVICE_REHYDRATED', { scheduled });
  } catch (err) {
    emit('ERROR', 'ESCALATION_SERVICE_REHYDRATE_FAILED', { error: err.message });
  }
}

// ── Scan loop ─────────────────────────────────────────────────────────────────

async function _scan() {
  const now = Date.now();
  const due = [];

  for (const [alertId, timer] of _timers) {
    if (timer.deadline <= now) {
      due.push({ alertId, timer });
      _timers.delete(alertId);
    }
  }

  for (const { alertId, timer } of due) {
    try {
      await _escalate(alertId, timer);
    } catch (err) {
      emit('ERROR', 'ESCALATION_SCAN_ERROR', { alertId, error: err.message });
    }
  }
}

async function _escalate(alertId, timer) {
  // Fetch current state — may have been acknowledged since timer was set
  const alert = await alertStore.getAlert(alertId);
  if (!alert) return;
  if (alert.status === ALERT_STATUS.ACKNOWLEDGED ||
      alert.status === ALERT_STATUS.RESOLVED     ||
      alert.status === ALERT_STATUS.CLOSED       ||
      alert.status === ALERT_STATUS.FALSE_POSITIVE) {
    return;
  }

  const fromLevel  = alert.escalationLevel ?? 0;
  const esc        = getNextEscalation(alert.severity, fromLevel, new Date(alert.detectedAt).getTime());

  if (!esc.nextLevel && !esc.nextEscalationAt) {
    // No further escalation configured
    return;
  }

  const toLevel = esc.nextLevel ?? fromLevel + 1;
  const roles   = esc.notifyRoles ?? [];
  const reason  = esc.reason ?? 'ACK_TIMEOUT';

  emit('WARN', 'ALERT_ESCALATED', {
    alertId,
    fromLevel,
    toLevel,
    reason,
    severity: alert.severity,
    title:    alert.title,
  });

  // Persist escalation record
  // alert.tenantId threaded through so the qodiqa_alerts UPDATE
  // inside recordEscalation() runs with the correct tenant context instead
  // of silently affecting 0 rows for a tenant-scoped alert.
  await alertStore.recordEscalation(alertId, {
    tenantId: alert.tenantId ?? null,
    fromLevel,
    toLevel,
    reason,
    notifiedRoles: roles,
    detail: {
      deadlineMs:   timer.deadline,
      escalatedAt:  new Date().toISOString(),
    },
  });

  // Dispatch escalation notifications
  if (_notificationService) {
    await _notificationService.notifyEscalation(alert, toLevel, roles).catch(err => {
      emit('ERROR', 'ESCALATION_NOTIFY_FAILED', { alertId, error: err.message });
    });
  }

  // Schedule next escalation if applicable
  const nextEsc = getNextEscalation(alert.severity, toLevel, new Date(alert.detectedAt).getTime());
  if (nextEsc.nextEscalationAt) {
    _timers.set(alertId, {
      alertId,
      deadline:        nextEsc.nextEscalationAt.getTime(),
      severity:        alert.severity,
      escalationLevel: toLevel,
    });
  }
}

module.exports = {
  schedule,
  cancel,
  start,
  stop,
  rehydrate,
  registerNotificationService,
};
