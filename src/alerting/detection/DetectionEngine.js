'use strict';

/**
 * QODIQA Detection Engine
 *
 * The single point of integration between the QODIQA platform event bus
 * and the alerting framework.
 *
 * On every platform event:
 *   1. Ingest into anomaly counters (AnomalyDetector.ingest)
 *   2. Run all detectors in priority order
 *   3. Take the first triggered detector result
 *   4. Pass the alert spec to AlertEngine.createAlert
 *
 * Design constraints:
 *   - Never throw — all errors are caught and logged
 *   - Never block the event bus (all work is async fire-and-forget)
 *   - Minimal per-event overhead (detector logic is synchronous O(1))
 *   - Deduplication: suppress rapid duplicate alerts on the same event
 */

const { eventBus, emit } = require('../../../services/logger');
const alertEngine        = require('../engine/AlertEngine');
const replayDetector     = require('./ReplayDetector');
const signatureDetector  = require('./SignatureDetector');
const policyDetector     = require('./PolicyDetector');
const anomalyDetector    = require('./AnomalyDetector');
const operationalDetector = require('./OperationalDetector');
const { monoNowMs } = require('../../infra/time/monotonicClock'); // monotonic (same-process) deadlines/windows
const { ALERT_TYPE, OPERATIONAL_SUBTYPE } = require('../constants');

// RC-10: the source events of the gateway Redis-store alerts that a full recovery makes stale.
// REDIS_HA_* alerts share the subtype but come from a different producer and are left alone.
const REDIS_RECOVERY_RESOLVES = [
  'REPLAY_PROTECTION_DEGRADED',
  'GATEWAY_RUNTIME_DEGRADED',
  'GATEWAY_RUNTIME_PARTIAL_FAILURE',
];

// ── Ordered detector pipeline ─────────────────────────────────────────────────
// Detectors run in order; first match wins per event.
// Operational detector runs last since most events are not operational failures.

const DETECTORS = [
  replayDetector,
  signatureDetector,
  policyDetector,
  operationalDetector,
  anomalyDetector,   // runs last: anomaly counters are already updated by ingest()
];

// ── Event exclusion list ──────────────────────────────────────────────────────
// High-frequency events that carry no security signal — excluded from detection
// to keep CPU cost near-zero on the hot path.

const EXCLUDED_EVENTS = new Set([
  'GATEWAY_ALLOW',          // normal allow decisions — handled by anomaly counter only
  'AUDIT_EXECUTION_RECORDED',
  'PG_POOL_CONNECT',
  'PG_POOL_INITIALIZED',
  'PG_POOL_SHUTDOWN',
  'STARTUP_DIAGNOSTICS_EMITTED',
  'AUDIT_RETENTION_SCHEDULED',
  'PROVIDER_EXECUTION_START',
  'PROVIDER_EXECUTION_COMPLETE',
  'KEY_MANAGER_READY',
  'POLICIES_LOADED',
  'POLICIES_RELOADED',
  'GATEWAY_START',
  'SHUTDOWN_STARTED',
  'SHUTDOWN_COMPLETE',
]);

// Track if engine is initialized
let _initialized = false;

// ── Deduplication window ──────────────────────────────────────────────────────
// Prevents the same alert from being created multiple times within a short window
// when the same event fires repeatedly (e.g., Redis reconnect storms).

const DEDUP_WINDOW_MS = parseInt(process.env.ALERT_DEDUP_WINDOW_MS ?? '60000', 10);
const _recentAlerts   = new Map();  // dedupKey → lastFiredAt timestamp

function _isDuplicate(alert) {
  const key = [alert.type, alert.subtype, alert.tenantId ?? 'global',
               alert.sourceEvent ?? ''].join(':');
  const last = _recentAlerts.get(key);
  const now  = monoNowMs(); // monotonic (same-process)

  if (last && now - last < DEDUP_WINDOW_MS) return true;

  _recentAlerts.set(key, now);

  // Prune stale entries (keep Map size bounded)
  if (_recentAlerts.size > 1000) {
    for (const [k, ts] of _recentAlerts) {
      if (now - ts > DEDUP_WINDOW_MS * 2) _recentAlerts.delete(k);
    }
  }

  return false;
}

// ── Event handler ─────────────────────────────────────────────────────────────

async function _handleEvent(record) {
  const eventName = record.eventType ?? '';

  // Skip excluded high-frequency events from detection, but still update anomaly counters
  anomalyDetector.ingest(record);

  if (EXCLUDED_EVENTS.has(eventName)) return;

  // RC-10: server/startup.js emits GATEWAY_RUNTIME_RECOVERED only when all three Redis
  // stores are ready again after a degradation. Before this, nothing consumed it, so the
  // REDIS_DEGRADED alerts raised on the way down stayed OPEN and kept escalating.
  if (eventName === 'GATEWAY_RUNTIME_RECOVERED') {
    alertEngine.resolveRecovered(
      {
        type:         ALERT_TYPE.OPERATIONAL,
        subtype:      OPERATIONAL_SUBTYPE.REDIS_DEGRADED,
        sourceEvents: REDIS_RECOVERY_RESOLVES,
      },
      { actor: 'system:auto-recovery', note: `auto-resolved on GATEWAY_RUNTIME_RECOVERED (source=${record.source ?? '?'})` },
    ).then((n) => {
      if (n > 0) emit('INFO', 'ALERTS_AUTO_RESOLVED', { trigger: eventName, resolved: n });
    }).catch((err) => {
      emit('ERROR', 'ALERTS_AUTO_RESOLVE_FAILED', { trigger: eventName, error: err.message });
    });
    return;
  }

  // Run detector pipeline
  for (const detector of DETECTORS) {
    let result;
    try {
      result = detector.analyze(record);
    } catch (err) {
      emit('ERROR', 'DETECTION_ENGINE_DETECTOR_ERROR', {
        detector: detector.constructor?.name ?? 'unknown',
        event:    eventName,
        error:    err.message,
      });
      continue;
    }

    if (!result.triggered) continue;

    const alertSpec = result.alert;
    if (!alertSpec) continue;

    // Deduplication check
    if (_isDuplicate(alertSpec)) break;

    // Fire-and-forget alert creation (never await on the eventBus handler)
    alertEngine.createAlert(alertSpec).catch(err => {
      emit('ERROR', 'DETECTION_ENGINE_ALERT_CREATE_ERROR', {
        error:   err.message,
        type:    alertSpec.type,
        subtype: alertSpec.subtype,
        event:   eventName,
      });
    });

    break;  // Only create one alert per event
  }
}

// ── Initialization ────────────────────────────────────────────────────────────

let _logHandler = null; // this engine's own eventBus subscription (so shutdown() removes only it)

/**
 * Subscribe the detection engine to the platform event bus.
 * Safe to call multiple times — only subscribes once.
 */
function initialize() {
  if (_initialized) return;
  _initialized = true;

  // keep a reference to OUR handler — shutdown() used eventBus.removeAllListeners('log'), which also detached the
  // log shipper, the dashboard feed and the audit-event dispatcher.
  _logHandler = (record) => {
    // Never throw on the eventBus handler — catch everything
    _handleEvent(record).catch(err => {
      try {
        emit('ERROR', 'DETECTION_ENGINE_HANDLER_ERROR', { error: err.message });
      } catch (_) {}
    });
  };
  eventBus.on('log', _logHandler);

  emit('INFO', 'DETECTION_ENGINE_INITIALIZED', {
    component:        'DETECTION_ENGINE',
    detectorCount:    DETECTORS.length,
    dedupWindowMs:    DEDUP_WINDOW_MS,
    excludedEvents:   EXCLUDED_EVENTS.size,
  });
}

/**
 * Unsubscribe (useful for testing teardown).
 */
function shutdown() {
  if (!_initialized) return;
  _initialized = false;
  if (_logHandler) { eventBus.removeListener('log', _logHandler); _logHandler = null; } // only this engine's own subscription
}

module.exports = { initialize, shutdown };
