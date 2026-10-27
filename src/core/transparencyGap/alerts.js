'use strict';

/**
 * Transparency Gap Alert Generator — Component #14
 *
 * Fires structured alerts into the QODIQA alerting framework.
 * Always fire-and-forget: never blocks the calling path, never throws.
 *
 * Alert severity mapping:
 *   Gap CRITICAL → alert CRITICAL
 *   Gap WARNING  → alert HIGH
 *   Gap INFO     → alert INFO (informational, no escalation)
 *
 * Alert type:  OPERATIONAL
 * Alert subtype by gap type:
 *   HASH_CHAIN_BREAK / SEQUENCE_BREAK / CHECKPOINT_DIVERGENCE
 *     → TRANSPARENCY_HASH_CHAIN_BREAK
 *   All others
 *     → TRANSPARENCY_GAP
 */

const { emit } = require('../../../services/logger');

const SOURCE = 'TRANSPARENCY_GAP_ALERTS';

// Map gap severity → alerting framework severity (from constants.SEVERITY)
const _GAP_TO_ALERT_SEVERITY = {
  CRITICAL: 'CRITICAL',
  WARNING:  'HIGH',
  INFO:     'INFO',
};

// Map gap types to alert subtypes (strings — not requiring constants import)
const _CHAIN_INTEGRITY_TYPES = new Set([
  'HASH_CHAIN_BREAK',
  'SEQUENCE_BREAK',
  'CHECKPOINT_DIVERGENCE',
]);

function _alertSubtype(gapType) {
  return _CHAIN_INTEGRITY_TYPES.has(gapType)
    ? 'TRANSPARENCY_HASH_CHAIN_BREAK'
    : 'TRANSPARENCY_GAP';
}

/**
 * Fire an alert for a detected transparency gap.
 * Fire-and-forget: returns a Promise that never rejects.
 *
 * @param {object} gap  — fully classified gap record (includes severity)
 * @returns {Promise<void>}
 */
async function fire(gap) {
  try {
    // Lazy require to avoid circular dependency at module load time.
    const alertEngine = require('../../alerting/engine/AlertEngine');

    const alertSeverity = _GAP_TO_ALERT_SEVERITY[gap.severity] ?? 'HIGH';
    const subtype       = _alertSubtype(gap.gapType);

    await alertEngine.createAlert({
      type:        'OPERATIONAL',
      subtype,
      severity:    alertSeverity,
      sourceEvent: 'TRANSPARENCY_GAP_DETECTED',
      tenantId:    gap.details?.tenantId ?? null,
      description: `Transparency gap detected: ${gap.gapType} in service "${gap.service}"`,
      context: {
        gapId:       gap.gapId,
        gapType:     gap.gapType,
        severity:    gap.severity,
        service:     gap.service,
        artifactId:  gap.artifactId,
        timestamp:   gap.detectedAt,
        details:     gap.details,
      },
    });

    emit('INFO', 'TRANSPARENCY_GAP_ALERTED', {
      source:    SOURCE,
      gapId:     gap.gapId,
      gapType:   gap.gapType,
      severity:  gap.severity,
      service:   gap.service,
      timestamp: gap.detectedAt,
    });
  } catch (err) {
    // Alert failure must never surface to the caller.
    emit('ERROR', 'TRANSPARENCY_GAP_ALERT_FAILED', {
      source:  SOURCE,
      gapId:   gap.gapId,
      gapType: gap.gapType,
      error:   err.message,
    });
  }
}

module.exports = { fire };
