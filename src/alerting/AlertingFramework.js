'use strict';

/**
 * QODIQA Alerting & Notification Framework — Main Orchestrator
 *
 * Wires together all alerting subsystems:
 *   DetectionEngine → AlertEngine → CorrelationEngine
 *                                 → NotificationService
 *                                 → EscalationService
 *
 * Call AlertingFramework.initialize() once during server startup,
 * after the logger eventBus is live and before serving traffic.
 *
 * All subsystem failures are isolated: a broken notification channel
 * or escalation timer CANNOT crash the main request path.
 */

const { emit } = require('../../services/logger');

const detectionEngine    = require('./detection/DetectionEngine');
const alertEngine        = require('./engine/AlertEngine');
const correlationEngine  = require('./correlation/CorrelationEngine');
const notificationService = require('./notification/NotificationService');
const escalationService  = require('./escalation/EscalationService');

let _initialized = false;
let _rehydrate = null; // in-flight escalation rehydrate started by initialize() (awaited by shutdown())

/**
 * Initialize the complete alerting framework.
 * Idempotent — safe to call multiple times.
 */
async function initialize() {
  if (_initialized) return;
  _initialized = true;

  try {
    // 1. Wire dependencies (before initializing anything that emits)
    alertEngine.registerNotificationService(notificationService);
    alertEngine.registerEscalationService(escalationService);
    escalationService.registerNotificationService(notificationService);

    // 2. Subscribe CorrelationEngine to alert lifecycle events
    alertEngine.on('alert.created', (alert) => {
      correlationEngine.correlate(alert).catch(err =>
        emit('ERROR', 'CORRELATION_ENGINE_ERROR', { error: err.message })
      );
    });

    // 3. Start EscalationService scan loop
    escalationService.start();

    // 4. Re-hydrate escalation timers from DB (picks up alerts from before restart)
    //    Still non-blocking for startup, but the promise is kept: shutdown() lets it settle first, so its alert queries
    //    can never land after the PostgreSQL pools are closed (ER 2026-10-06 — they lazily re-created the reporting
    //    pool, whose idle connections then kept a test process / shutting-down server alive).
    _rehydrate = escalationService.rehydrate().catch(err =>
      emit('WARN', 'ESCALATION_REHYDRATE_FAILED', { error: err.message })
    );

    // 5. Start detection engine (subscribes to eventBus)
    detectionEngine.initialize();

    emit('INFO', 'ALERTING_FRAMEWORK_INITIALIZED', {
      component: 'ALERTING_FRAMEWORK',
      subsystems: ['DETECTION_ENGINE', 'ALERT_ENGINE', 'CORRELATION_ENGINE',
                   'NOTIFICATION_SERVICE', 'ESCALATION_SERVICE'],
    });
  } catch (err) {
    // Non-fatal — alerting is supplemental to core QODIQA functionality
    emit('ERROR', 'ALERTING_FRAMEWORK_INIT_FAILED', { error: err.message });
  }
}

/**
 * Graceful shutdown — stop background timers and event subscriptions.
 * Called from server.js shutdown sequence.
 */
async function shutdown() {
  if (!_initialized) return;
  _initialized = false;

  if (_rehydrate) { const p = _rehydrate; _rehydrate = null; await p; } // never leave start-up DB work in flight

  try {
    escalationService.stop();
    detectionEngine.shutdown();
    emit('INFO', 'ALERTING_FRAMEWORK_SHUTDOWN', {});
  } catch (err) {
    emit('ERROR', 'ALERTING_FRAMEWORK_SHUTDOWN_ERROR', { error: err.message });
  }
}

module.exports = { initialize, shutdown };
