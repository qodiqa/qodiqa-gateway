'use strict';

/**
 * QODIQA Notification Service
 *
 * Central dispatcher that routes alerts to configured notification channels
 * based on severity and channel configuration.
 *
 * Responsibilities:
 *   - Resolve which channels to use for each alert severity
 *   - Resolve recipient lists from environment configuration
 *   - Dispatch concurrently to all applicable channels
 *   - Track delivery results in AlertStore
 *   - Apply rate limits per channel
 *   - Provide channel health check aggregate
 */

const { emit } = require('../../../services/logger');
const alertStore = require('../storage/AlertStore');
const {
  SEVERITY, CHANNEL, SEVERITY_DEFINITIONS,
} = require('../constants');
const { getNotificationChannels } = require('../engine/SeverityModel');

const { WebhookChannel }    = require('./channels/WebhookChannel');
const { SlackChannel }      = require('./channels/SlackChannel');
const { TeamsChannel }      = require('./channels/TeamsChannel');
const { SIEMChannel }       = require('./channels/SIEMChannel');
const { EmailChannel }      = require('./channels/EmailChannel');
const { PagerDutyChannel }  = require('./channels/PagerDutyChannel');
const { SMSChannel }        = require('./channels/SMSChannel');

// ── Channel registry ──────────────────────────────────────────────────────────

const _channels = new Map([
  [CHANNEL.WEBHOOK,   new WebhookChannel()],
  [CHANNEL.SLACK,     new SlackChannel()],
  [CHANNEL.TEAMS,     new TeamsChannel()],
  [CHANNEL.SIEM,      new SIEMChannel()],
  [CHANNEL.EMAIL,     new EmailChannel()],
  [CHANNEL.PAGERDUTY, new PagerDutyChannel()],
  [CHANNEL.SMS,       new SMSChannel()],
]);

// ── Recipient resolution ──────────────────────────────────────────────────────

const CHANNEL_RECIPIENTS = {
  [CHANNEL.WEBHOOK]:   process.env.ALERT_WEBHOOK_URL,
  [CHANNEL.SLACK]:     process.env.ALERT_SLACK_WEBHOOK_URL,
  [CHANNEL.TEAMS]:     process.env.ALERT_TEAMS_WEBHOOK_URL,
  [CHANNEL.SIEM]:      process.env.ALERT_SIEM_URL,
  [CHANNEL.EMAIL]:     process.env.ALERT_EMAIL_TO,
  [CHANNEL.PAGERDUTY]: null,  // PagerDuty uses routing key, not URL
  [CHANNEL.SMS]:       process.env.ALERT_SMS_TO,
};

// Which channels are enabled (can be overridden per environment)
function _isChannelEnabled(channelName) {
  // Check explicit disable
  const envKey = `ALERT_${channelName}_ENABLED`;
  if (process.env[envKey] === 'false') return false;

  // Check that the channel has a recipient configured
  const recipient = CHANNEL_RECIPIENTS[channelName];
  if (channelName === CHANNEL.PAGERDUTY) {
    return !!(process.env.ALERT_PAGERDUTY_ROUTING_KEY);
  }
  if (channelName === CHANNEL.SIEM) {
    return !!(process.env.ALERT_SIEM_URL || process.env.ALERT_SIEM_SYSLOG_HOST);
  }
  return !!(recipient);
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/**
 * Send notifications for an alert to all applicable channels.
 * Returns array of delivery results.
 * Never throws — all errors are logged.
 *
 * @param {object} alert  — Saved alert object
 * @returns {Promise<Array<{ channel, sent, error? }>>}
 */
async function notify(alert) {
  const channelsForSeverity = getNotificationChannels(alert.severity);
  const enabledChannels     = channelsForSeverity.filter(_isChannelEnabled);

  if (!enabledChannels.length) {
    return [];
  }

  const deliveries = await Promise.allSettled(
    enabledChannels.map(async (channelName) => {
      const channel   = _channels.get(channelName);
      if (!channel) return { channel: channelName, sent: false, error: 'Not registered' };

      const recipient = CHANNEL_RECIPIENTS[channelName];
      const result    = await channel.deliver(alert, recipient);

      // Record delivery in audit store
      await alertStore.recordNotification(alert.id, {
        channel:      channelName,
        recipient:    recipient ?? channelName,
        status:       result.sent ? 'SENT' : (result.rateLimited ? 'RATE_LIMITED' : 'FAILED'),
        errorMessage: result.error ?? null,
        payloadHash:  result.payloadHash ?? null,
      });

      return { channel: channelName, ...result };
    })
  );

  return deliveries.map(d => d.status === 'fulfilled' ? d.value : {
    channel: 'unknown', sent: false, error: d.reason?.message,
  });
}

/**
 * Send a test notification to a specific channel.
 * Used by the Alert API health check endpoint.
 */
async function testChannel(channelName) {
  const channel = _channels.get(channelName);
  if (!channel) return { ok: false, error: `Unknown channel: ${channelName}` };

  const testAlert = {
    id:          '00000000-test-0000-0000-000000000000',
    type:        'OPERATIONAL',
    subtype:     'TEST',
    severity:    SEVERITY.INFO,
    status:      'OPEN',
    riskScore:   0,
    confidence:  100,
    title:       'QODIQA Alerting Framework — Test Notification',
    description: 'This is a test notification from the QODIQA Alerting Framework.',
    tags:        ['test'],
    detectedAt:  new Date(),
    evidence:    {},
    context:     {},
  };

  return channel.deliver(testAlert, CHANNEL_RECIPIENTS[channelName]);
}

/**
 * Whether at least one notification channel is configured and enabled.
 * Used by server.js's startup validation (MON-3) to warn/fail-fast when
 * CRITICAL alerts would otherwise be detected but delivered to nobody.
 */
function hasAnyChannelConfigured() {
  return Object.values(CHANNEL).some(_isChannelEnabled);
}

/**
 * Names of every currently-enabled channel. Used for the startup readiness
 * log line so operators can see exactly what QODIQA thinks is configured.
 */
function listConfiguredChannels() {
  return Object.values(CHANNEL).filter(_isChannelEnabled);
}

/**
 * Health check across all channels.
 */
async function healthCheck() {
  const results = {};
  await Promise.allSettled(
    [..._channels.entries()].map(async ([name, channel]) => {
      try {
        results[name] = {
          enabled: _isChannelEnabled(name),
          ...(await channel.healthCheck()),
        };
      } catch (err) {
        results[name] = { enabled: false, ok: false, error: err.message };
      }
    })
  );
  return results;
}

/**
 * Escalation-specific notification — direct delivery without suppression.
 * Used by EscalationService to notify at higher escalation levels.
 */
async function notifyEscalation(alert, escalationLevel, roles) {
  emit('INFO', 'ALERT_ESCALATION_NOTIFY', {
    alertId:         alert.id,
    severity:        alert.severity,
    escalationLevel,
    roles:           roles.join(','),
  });

  // For escalation: always use email + pagerduty if configured
  const escalationChannels = [CHANNEL.EMAIL, CHANNEL.PAGERDUTY, CHANNEL.SLACK]
    .filter(_isChannelEnabled);

  return Promise.allSettled(
    escalationChannels.map(channelName => {
      const channel   = _channels.get(channelName);
      const recipient = CHANNEL_RECIPIENTS[channelName];
      return channel?.deliver({
        ...alert,
        title: `[ESCALATION L${escalationLevel}] ${alert.title}`,
      }, recipient);
    })
  );
}

module.exports = {
  notify, testChannel, healthCheck, notifyEscalation,
  hasAnyChannelConfigured, listConfiguredChannels,
};
