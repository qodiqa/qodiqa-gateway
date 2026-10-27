'use strict';

/**
 * QODIQA Alerting & Notification Framework — Public API
 *
 * Single entry point for all alerting subsystems.
 */

const framework = require('./AlertingFramework');

module.exports = {
  // Lifecycle
  initialize: framework.initialize,
  shutdown:   framework.shutdown,

  // Sub-module access (for testing and advanced usage)
  alertEngine:          require('./engine/AlertEngine'),
  alertStore:           require('./storage/AlertStore'),
  notificationService:  require('./notification/NotificationService'),
  escalationService:    require('./escalation/EscalationService'),
  correlationEngine:    require('./correlation/CorrelationEngine'),
  detectionEngine:      require('./detection/DetectionEngine'),
  anomalyDetector:      require('./detection/AnomalyDetector'),

  // Route factory
  createAlertRouter:    require('./api/alertRoutes').createAlertRouter,

  // Constants
  constants:            require('./constants'),
};
