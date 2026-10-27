'use strict';

/**
 * QODIQA Severity Model
 *
 * Defines response expectations, escalation targets, SLA windows, and
 * notification routing for each severity level.
 *
 * This is the authoritative reference for all operational procedures.
 * SOC playbooks and runbooks should defer to these definitions.
 */

const { SEVERITY, CHANNEL, ESCALATION_LEVEL } = require('../constants');

// ── Severity Definitions ──────────────────────────────────────────────────────

const SEVERITY_DEFINITIONS = Object.freeze({

  [SEVERITY.INFO]: {
    label:          'Informational',
    description:    'Normal operational events recorded for audit completeness. No action required.',
    color:          '#6B7280',  // gray
    icon:           'ℹ️',

    // Response expectations
    response: {
      required:     false,
      windowMs:     null,
      expectedAction: 'Record only — review in daily operational summary',
    },

    // Escalation path
    escalation: {
      startLevel:   ESCALATION_LEVEL.L0,
      maxLevel:     ESCALATION_LEVEL.L0,
      steps:        [],
    },

    // Notification targets
    notification: {
      channels:     [],          // INFO alerts are stored only, not dispatched by default
      roles:        [],
      immediate:    false,
    },

    // SLA
    sla: {
      ackWindowMs:  null,
      resWindowMs:  null,
      reportRequired: false,
    },
  },

  [SEVERITY.LOW]: {
    label:          'Low',
    description:    'Minor anomaly or expected degradation. Investigate within business hours.',
    color:          '#3B82F6',  // blue
    icon:           '🔵',

    response: {
      required:     true,
      windowMs:     8 * 3600_000,  // 8 hours
      expectedAction: 'Investigate within business hours; no immediate page required',
    },

    escalation: {
      startLevel:   ESCALATION_LEVEL.L1,
      maxLevel:     ESCALATION_LEVEL.L1,
      steps: [
        {
          afterMs:    4 * 3600_000,   // escalate if no ack in 4 hours
          toLevel:    ESCALATION_LEVEL.L1,
          notifyRoles: ['operator', 'viewer'],
          reason:     'ACK_TIMEOUT',
        },
      ],
    },

    notification: {
      channels:     [CHANNEL.WEBHOOK, CHANNEL.SIEM],
      roles:        ['operator'],
      immediate:    false,
    },

    sla: {
      ackWindowMs:  4 * 3600_000,    // 4 hours to acknowledge
      resWindowMs:  72 * 3600_000,   // 72 hours to resolve
      reportRequired: false,
    },
  },

  [SEVERITY.MEDIUM]: {
    label:          'Medium',
    description:    'Significant event requiring prompt investigation. Notify security team.',
    color:          '#F59E0B',  // amber
    icon:           '🟡',

    response: {
      required:     true,
      windowMs:     2 * 3600_000,
      expectedAction: 'Notify on-call security; investigate within 2 hours; begin incident log',
    },

    escalation: {
      startLevel:   ESCALATION_LEVEL.L1,
      maxLevel:     ESCALATION_LEVEL.L2,
      steps: [
        {
          afterMs:    2 * 3600_000,
          toLevel:    ESCALATION_LEVEL.L2,
          notifyRoles: ['operator', 'compliance'],
          reason:     'ACK_TIMEOUT',
        },
      ],
    },

    notification: {
      channels:     [CHANNEL.SLACK, CHANNEL.WEBHOOK, CHANNEL.SIEM],
      roles:        ['operator', 'compliance'],
      immediate:    true,
    },

    sla: {
      ackWindowMs:  2 * 3600_000,     // 2 hours to acknowledge
      resWindowMs:  24 * 3600_000,    // 24 hours to resolve
      reportRequired: false,
    },
  },

  [SEVERITY.HIGH]: {
    label:          'High',
    description:    'Active security threat or critical operational failure. Page immediately.',
    color:          '#EF4444',  // red
    icon:           '🔴',

    response: {
      required:     true,
      windowMs:     30 * 60_000,     // 30 minutes
      expectedAction: 'Page security on-call immediately; notify compliance team; begin incident response',
    },

    escalation: {
      startLevel:   ESCALATION_LEVEL.L2,
      maxLevel:     ESCALATION_LEVEL.L3,
      steps: [
        {
          afterMs:    30 * 60_000,   // escalate if no ack in 30 mins
          toLevel:    ESCALATION_LEVEL.L2,
          notifyRoles: ['operator', 'compliance', 'admin'],
          reason:     'ACK_TIMEOUT',
        },
        {
          afterMs:    60 * 60_000,   // further escalate if no ack in 1 hour
          toLevel:    ESCALATION_LEVEL.L3,
          notifyRoles: ['admin'],
          reason:     'SUSTAINED_UNACKNOWLEDGED',
        },
      ],
    },

    notification: {
      channels:     [CHANNEL.SLACK, CHANNEL.TEAMS, CHANNEL.PAGERDUTY, CHANNEL.WEBHOOK, CHANNEL.SIEM, CHANNEL.EMAIL],
      roles:        ['operator', 'compliance', 'admin'],
      immediate:    true,
    },

    sla: {
      ackWindowMs:  30 * 60_000,      // 30 minutes to acknowledge
      resWindowMs:  4 * 3600_000,     // 4 hours to resolve
      reportRequired: true,
    },
  },

  [SEVERITY.CRITICAL]: {
    label:          'Critical',
    description:    'Active security incident or catastrophic system failure. All-hands response required.',
    color:          '#7C3AED',  // purple
    icon:           '🚨',

    response: {
      required:     true,
      windowMs:     15 * 60_000,
      expectedAction: 'Immediate all-hands escalation; notify CISO; begin P1 incident bridge; consider traffic isolation',
    },

    escalation: {
      startLevel:   ESCALATION_LEVEL.L3,
      maxLevel:     ESCALATION_LEVEL.L4,
      steps: [
        {
          afterMs:    15 * 60_000,   // escalate at 15 mins if no ack
          toLevel:    ESCALATION_LEVEL.L3,
          notifyRoles: ['admin', 'compliance', 'operator'],
          reason:     'ACK_TIMEOUT',
        },
        {
          afterMs:    30 * 60_000,   // executive escalation at 30 mins
          toLevel:    ESCALATION_LEVEL.L4,
          notifyRoles: ['admin'],
          reason:     'CRITICAL_UNACKNOWLEDGED',
        },
      ],
    },

    notification: {
      channels:     [CHANNEL.SLACK, CHANNEL.TEAMS, CHANNEL.PAGERDUTY, CHANNEL.WEBHOOK, CHANNEL.SIEM, CHANNEL.EMAIL, CHANNEL.SMS],
      roles:        ['admin', 'compliance', 'operator'],
      immediate:    true,
    },

    sla: {
      ackWindowMs:  15 * 60_000,     // 15 minutes to acknowledge
      resWindowMs:  2 * 3600_000,    // 2 hours to resolve
      reportRequired: true,
    },
  },
});

/**
 * Compute the next escalation deadline for an alert.
 *
 * @param {string} severity
 * @param {number} escalationLevel  — Current escalation level
 * @param {number} detectedAt       — Epoch ms when alert was first detected
 * @returns {{ nextLevel: number|null, nextEscalationAt: Date|null, reason: string|null }}
 */
function getNextEscalation(severity, escalationLevel, detectedAt) {
  const def = SEVERITY_DEFINITIONS[severity];
  if (!def) return { nextLevel: null, nextEscalationAt: null, reason: null };

  const steps = def.escalation.steps ?? [];
  for (const step of steps) {
    if (step.toLevel > escalationLevel) {
      return {
        nextLevel:        step.toLevel,
        nextEscalationAt: new Date(detectedAt + step.afterMs),
        reason:           step.reason,
        notifyRoles:      step.notifyRoles,
      };
    }
  }

  return { nextLevel: null, nextEscalationAt: null, reason: null };
}

/**
 * Get notification channels for a given severity.
 * Merges environment-configured channels with severity defaults.
 */
function getNotificationChannels(severity) {
  return SEVERITY_DEFINITIONS[severity]?.notification?.channels ?? [];
}

/**
 * Get notification roles for a given severity.
 */
function getNotificationRoles(severity) {
  return SEVERITY_DEFINITIONS[severity]?.notification?.roles ?? [];
}

/**
 * Is immediate notification required?
 */
function isImmediateNotification(severity) {
  return SEVERITY_DEFINITIONS[severity]?.notification?.immediate === true;
}

/**
 * SLA ack window in milliseconds for a severity level.
 */
function getAckWindow(severity) {
  return SEVERITY_DEFINITIONS[severity]?.sla?.ackWindowMs ?? null;
}

module.exports = {
  SEVERITY_DEFINITIONS,
  getNextEscalation,
  getNotificationChannels,
  getNotificationRoles,
  isImmediateNotification,
  getAckWindow,
};
