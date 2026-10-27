'use strict';

/**
 * MON-3 — coverage for NotificationService's channel-enablement logic:
 * the exact mechanism that makes every channel "disabled by default", and
 * the new hasAnyChannelConfigured()/listConfiguredChannels() helpers that
 * back server.js's startup validation.
 *
 * CHANNEL_RECIPIENTS is computed once at module load from process.env, so
 * each scenario resets the module registry and re-requires with the
 * desired env vars already set — the same reason production env vars are
 * only ever read once at process startup.
 */

const ALERT_ENV_KEYS = [
  'ALERT_WEBHOOK_URL', 'ALERT_WEBHOOK_ENABLED',
  'ALERT_SLACK_WEBHOOK_URL', 'ALERT_SLACK_ENABLED',
  'ALERT_TEAMS_WEBHOOK_URL', 'ALERT_TEAMS_ENABLED',
  'ALERT_SIEM_URL', 'ALERT_SIEM_SYSLOG_HOST', 'ALERT_SIEM_ENABLED',
  'ALERT_EMAIL_TO', 'ALERT_EMAIL_ENABLED',
  'ALERT_PAGERDUTY_ROUTING_KEY', 'ALERT_PAGERDUTY_ENABLED',
  'ALERT_SMS_TO', 'ALERT_SMS_ENABLED',
];

function withEnv(overrides, fn) {
  const saved = {};
  for (const key of ALERT_ENV_KEYS) saved[key] = process.env[key];
  for (const key of ALERT_ENV_KEYS) delete process.env[key];
  Object.assign(process.env, overrides);

  jest.resetModules();
  try {
    const svc = require('../NotificationService');
    return fn(svc);
  } finally {
    for (const key of ALERT_ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    jest.resetModules();
  }
}

describe('NotificationService — channel availability (MON-3)', () => {
  test('hasAnyChannelConfigured() is false with zero env vars set (secure by default)', () => {
    withEnv({}, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(false);
      expect(svc.listConfiguredChannels()).toEqual([]);
    });
  });

  test('Webhook alone enables hasAnyChannelConfigured()', () => {
    withEnv({ ALERT_WEBHOOK_URL: 'https://example.com/hook' }, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(true);
      expect(svc.listConfiguredChannels()).toEqual(['WEBHOOK']);
    });
  });

  test('Slack alone enables hasAnyChannelConfigured()', () => {
    withEnv({ ALERT_SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/x' }, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(true);
      expect(svc.listConfiguredChannels()).toEqual(['SLACK']);
    });
  });

  test('Teams alone enables hasAnyChannelConfigured()', () => {
    withEnv({ ALERT_TEAMS_WEBHOOK_URL: 'https://tenant.webhook.office.com/x' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['TEAMS']);
    });
  });

  test('Email alone (ALERT_EMAIL_TO) enables hasAnyChannelConfigured()', () => {
    withEnv({ ALERT_EMAIL_TO: 'soc@example.com' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['EMAIL']);
    });
  });

  test('PagerDuty is gated on the routing key, not a URL', () => {
    withEnv({ ALERT_PAGERDUTY_ROUTING_KEY: 'abc123' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['PAGERDUTY']);
    });
  });

  test('SMS alone (ALERT_SMS_TO) enables hasAnyChannelConfigured()', () => {
    withEnv({ ALERT_SMS_TO: '+15551234567' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['SMS']);
    });
  });

  test('SIEM is enabled by URL OR syslog host, either alone is sufficient', () => {
    withEnv({ ALERT_SIEM_URL: 'https://siem.example.com/hec' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['SIEM']);
    });
    withEnv({ ALERT_SIEM_SYSLOG_HOST: 'syslog.example.com' }, (svc) => {
      expect(svc.listConfiguredChannels()).toEqual(['SIEM']);
    });
  });

  test('multiple configured channels are all listed', () => {
    withEnv({
      ALERT_WEBHOOK_URL: 'https://example.com/hook',
      ALERT_SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/x',
      ALERT_PAGERDUTY_ROUTING_KEY: 'abc123',
    }, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(true);
      expect(svc.listConfiguredChannels().sort()).toEqual(['PAGERDUTY', 'SLACK', 'WEBHOOK'].sort());
    });
  });

  test('ALERT_<CHANNEL>_ENABLED=false overrides an otherwise-configured recipient', () => {
    withEnv({
      ALERT_WEBHOOK_URL: 'https://example.com/hook',
      ALERT_WEBHOOK_ENABLED: 'false',
    }, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(false);
      expect(svc.listConfiguredChannels()).toEqual([]);
    });
  });

  test('ALERT_<CHANNEL>_ENABLED=false on one channel does not disable others', () => {
    withEnv({
      ALERT_WEBHOOK_URL: 'https://example.com/hook',
      ALERT_WEBHOOK_ENABLED: 'false',
      ALERT_SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/x',
    }, (svc) => {
      expect(svc.hasAnyChannelConfigured()).toBe(true);
      expect(svc.listConfiguredChannels()).toEqual(['SLACK']);
    });
  });
});
