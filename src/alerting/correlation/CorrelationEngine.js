'use strict';

/**
 * QODIQA Alert Correlation Engine
 *
 * Groups related alerts into security incidents.
 * Reduces noise and enables root-cause analysis.
 *
 * Correlation strategies:
 *
 *   1. REQUEST CORRELATION
 *      Same requestId across different alert types → single incident
 *      (e.g., replay + signature failure on same request = likely coordinated attack)
 *
 *   2. TENANT CORRELATION
 *      Multiple alerts for the same tenant within a time window
 *      → tenant-level incident
 *
 *   3. TYPE CORRELATION
 *      Multiple alerts of the same type within a window (e.g., 5 signature failures in 5 min)
 *      → pattern-based incident
 *
 *   4. CROSS-TYPE CORRELATION
 *      Replay attack + Signature failure + Policy failure in same window
 *      → complex attack incident (highest severity)
 *
 *   5. KEY CORRELATION
 *      Multiple alerts pointing to the same publicKeyId
 *      → possible key compromise incident
 *
 * Deduplication: Each alert can belong to at most one incident.
 * Once assigned, it stays in that incident.
 */

const crypto     = require('crypto');
const { emit }   = require('../../../services/logger');
const alertStore = require('../storage/AlertStore');
const { maxSeverity } = require('../engine/RiskScorer');
const {
  CORRELATION, ALERT_TYPE, SEVERITY, ALERT_STATUS,
} = require('../constants');

// ── In-memory correlation windows ─────────────────────────────────────────────

// correlationKey → { incidentId, alertIds: Set, firstSeen, lastSeen, severity, types: Set }
const _windows = new Map();

// alertId → incidentId (prevents double-correlation)
const _alertToIncident = new Map();
const MAX_WINDOWS = 10_000;
const MAX_ALERT_MAP = 100_000;

// ── Correlation key builders ──────────────────────────────────────────────────

function _requestKey(alert) {
  if (!alert.requestId) return null;
  return `req:${alert.requestId}`;
}

function _tenantWindowKey(alert) {
  if (!alert.tenantId) return null;
  const bucket = Math.floor(Date.now() / CORRELATION.INCIDENT_WINDOW_MS);
  return `tenant:${alert.tenantId}:${bucket}`;
}

function _typeWindowKey(alert) {
  const bucket = Math.floor(Date.now() / CORRELATION.INCIDENT_WINDOW_MS);
  return `type:${alert.type}:${bucket}`;
}

function _keyIdWindowKey(alert) {
  if (!alert.publicKeyId) return null;
  const bucket = Math.floor(Date.now() / CORRELATION.INCIDENT_WINDOW_MS);
  return `key:${alert.publicKeyId}:${bucket}`;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Correlate an incoming alert against existing windows.
 * Creates or updates an incident if correlation criteria are met.
 *
 * Called by AlertEngine after each alert is created.
 *
 * @param {object} alert  — Freshly saved alert
 */
async function correlate(alert) {
  if (!alert?.id) return;

  // Don't correlate INFO/LOW unless they match an existing incident
  const minSeverityForNewIncident = SEVERITY.MEDIUM;
  const canCreateIncident = _severityWeight(alert.severity) >= _severityWeight(minSeverityForNewIncident);

  // Generate all candidate correlation keys
  const keys = [
    _requestKey(alert),
    _tenantWindowKey(alert),
    _typeWindowKey(alert),
    _keyIdWindowKey(alert),
  ].filter(Boolean);

  let matched = false;

  for (const key of keys) {
    const window = _windows.get(key);

    if (window) {
      // Existing incident window — add this alert
      if (_alertToIncident.has(alert.id)) continue;  // already correlated

      window.alertIds.add(alert.id);
      window.types.add(alert.type);
      window.lastSeen  = Date.now();
      window.severity  = maxSeverity(window.severity, alert.severity);

      _alertToIncident.set(alert.id, window.incidentId);
      _evictOldWindows();

      await _updateIncident(window);
      matched = true;
      break;
    } else if (canCreateIncident) {
      // New correlation window — don't create incident yet (need MIN_ALERTS_FOR_INCIDENT)
      _windows.set(key, {
        incidentId: null,
        correlationKey: key,
        alertIds:   new Set([alert.id]),
        types:      new Set([alert.type]),
        firstSeen:  Date.now(),
        lastSeen:   Date.now(),
        severity:   alert.severity,
        tenantId:   alert.tenantId,
      });
      _capMaps();
    }
  }

  // Check if any window has reached the minimum alert count for incident creation
  if (!matched) {
    for (const key of keys) {
      const window = _windows.get(key);
      if (window && !window.incidentId && window.alertIds.size >= CORRELATION.MIN_ALERTS_FOR_INCIDENT) {
        await _createIncident(window, alert);
        break;
      }
    }
  }
}

// ── Incident management ───────────────────────────────────────────────────────

async function _createIncident(window, triggeringAlert) {
  const incidentId = crypto.randomUUID();
  window.incidentId = incidentId;

  // Mark all alerts in window as part of this incident
  for (const aid of window.alertIds) {
    _alertToIncident.set(aid, incidentId);
  }

  const alertTypes = [...window.types];
  const title      = _buildIncidentTitle(alertTypes, window.severity, triggeringAlert);

  const incident = {
    id:             incidentId,
    title,
    description:    `Correlated incident from ${window.alertIds.size} related alerts. ` +
                    `Types: ${alertTypes.join(', ')}. ` +
                    `Correlation key: ${window.correlationKey}.`,
    severity:       window.severity,
    status:         ALERT_STATUS.OPEN,
    alertCount:     window.alertIds.size,
    alertIds:       [...window.alertIds],
    alertTypes,
    tenantId:       window.tenantId,
    correlationKey: window.correlationKey,
    openedAt:       new Date(window.firstSeen),
  };

  await alertStore.saveIncident(incident);

  emit('WARN', 'ALERT_INCIDENT_CREATED', {
    incidentId,
    alertCount:    incident.alertCount,
    alertTypes,
    severity:      incident.severity,
    correlationKey: window.correlationKey,
  });
}

async function _updateIncident(window) {
  if (!window.incidentId) return;

  const incident = {
    id:             window.incidentId,
    title:          _buildIncidentTitle([...window.types], window.severity, null),
    severity:       window.severity,
    status:         ALERT_STATUS.OPEN,
    alertCount:     window.alertIds.size,
    alertIds:       [...window.alertIds],
    alertTypes:     [...window.types],
    tenantId:       window.tenantId,
    correlationKey: window.correlationKey,
    openedAt:       new Date(window.firstSeen),
  };

  await alertStore.saveIncident(incident);
}

function _buildIncidentTitle(types, severity, triggeringAlert) {
  // Cross-type incident gets most descriptive title
  if (types.length > 1) {
    return `[${severity}] Multi-vector security incident: ${types.join(' + ')}`;
  }

  const typeLabel = {
    [ALERT_TYPE.REPLAY_ATTACK]:     'Replay attack campaign',
    [ALERT_TYPE.SIGNATURE_FAILURE]: 'Signature integrity failure cluster',
    [ALERT_TYPE.POLICY_FAILURE]:    'Policy enforcement failure cluster',
    [ALERT_TYPE.ANOMALY]:           'Anomalous activity cluster',
    [ALERT_TYPE.OPERATIONAL]:       'Operational failure cluster',
    [ALERT_TYPE.GOVERNANCE]:        'Governance violation cluster',
  }[types[0]] ?? 'Security incident';

  const context = triggeringAlert?.tenantId
    ? ` — tenant ${triggeringAlert.tenantId}`
    : '';

  return `[${severity}] ${typeLabel}${context}`;
}

function _severityWeight(s) {
  return { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 }[s] ?? 0;
}

// Evict windows that are older than the correlation window
function _evictOldWindows() {
  const cutoff = Date.now() - CORRELATION.INCIDENT_WINDOW_MS;
  for (const [key, window] of _windows) {
    if (window.lastSeen < cutoff && window.alertIds.size < CORRELATION.MIN_ALERTS_FOR_INCIDENT) {
      _windows.delete(key);
    }
  }
  // windows that formed an incident were never evicted and _alertToIncident only ever grew — unbounded memory
  // on a long-running process. Hard caps (oldest first; both maps keep insertion order) bound them without changing correlation inside
  // the window: the entries dropped are the oldest, long outside any correlation window.
  _capMaps();
}

// O(1) amortised: drops the OLDEST entries beyond the caps (Map iteration order = insertion order). Also called when a window is created,
// because _evictOldWindows() only runs when an alert matches an existing window — a stream of unrelated alerts never reached it.
function _capMaps() {
  while (_windows.size > MAX_WINDOWS) _windows.delete(_windows.keys().next().value);
  while (_alertToIncident.size > MAX_ALERT_MAP) _alertToIncident.delete(_alertToIncident.keys().next().value);
}

module.exports = { correlate, _capMaps, _stateForTests: () => ({ windows: _windows.size, alertToIncident: _alertToIncident.size }), _limits: { MAX_WINDOWS, MAX_ALERT_MAP } };
