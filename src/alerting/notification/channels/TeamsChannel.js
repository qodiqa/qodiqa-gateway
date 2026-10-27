'use strict';

/**
 * QODIQA Microsoft Teams Notification Channel
 *
 * Delivers Adaptive Card messages to MS Teams via incoming webhooks.
 *
 * Environment:
 *   ALERT_TEAMS_WEBHOOK_URL    — Teams incoming webhook connector URL
 */

const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');

const TEAMS_URL = process.env.ALERT_TEAMS_WEBHOOK_URL;

const TEAMS_COLORS = {
  [SEVERITY.INFO]:     'default',
  [SEVERITY.LOW]:      'accent',
  [SEVERITY.MEDIUM]:   'warning',
  [SEVERITY.HIGH]:     'attention',
  [SEVERITY.CRITICAL]: 'attention',
};

const TEAMS_ICONS = {
  [SEVERITY.INFO]:     'ℹ️',
  [SEVERITY.LOW]:      '🔵',
  [SEVERITY.MEDIUM]:   '⚠️',
  [SEVERITY.HIGH]:     '🔴',
  [SEVERITY.CRITICAL]: '🚨',
};

class TeamsChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'TEAMS',
      maxRetries: 3,
      rateLimit:  60,
      ...opts,
    });
    this._defaultUrl = opts.url ?? TEAMS_URL;
  }

  _format(alert) {
    const icon  = TEAMS_ICONS[alert.severity]  ?? '🔔';
    const color = TEAMS_COLORS[alert.severity] ?? 'default';
    const ts    = new Date(alert.detectedAt).toISOString();

    const facts = [];
    if (alert.type)       facts.push({ name: 'Alert Type',  value: alert.type    });
    if (alert.subtype)    facts.push({ name: 'Subtype',     value: alert.subtype });
    if (alert.riskScore !== undefined) facts.push({ name: 'Risk Score',  value: `${alert.riskScore}/100` });
    if (alert.tenantId)   facts.push({ name: 'Tenant',      value: alert.tenantId });
    if (alert.requestId)  facts.push({ name: 'Request ID',  value: alert.requestId });
    if (alert.publicKeyId)facts.push({ name: 'Key ID',      value: alert.publicKeyId });
    if (alert.clientIp)   facts.push({ name: 'Client IP',   value: alert.clientIp });
    facts.push({ name: 'Detected At', value: ts });
    facts.push({ name: 'Alert ID',    value: alert.id });

    // Adaptive Card format (Teams v2 webhook format)
    const payload = {
      type:        'message',
      attachments: [
        {
          contentType: 'application/vnd.microsoft.card.adaptive',
          content: {
            $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
            type:    'AdaptiveCard',
            version: '1.4',
            body: [
              {
                type: 'Container',
                style: color,
                items: [
                  {
                    type: 'TextBlock',
                    text: `${icon} **QODIQA Security Alert — ${alert.severity}**`,
                    size: 'Medium',
                    weight: 'Bolder',
                    wrap: true,
                  },
                  {
                    type: 'TextBlock',
                    text: alert.title,
                    size: 'Default',
                    weight: 'Bolder',
                    wrap: true,
                  },
                ],
              },
              {
                type: 'TextBlock',
                text: (alert.description ?? '').slice(0, 500),
                wrap: true,
              },
              {
                type:  'FactSet',
                facts: facts,
              },
            ],
            actions: [
              {
                type:  'Action.OpenUrl',
                title: 'View Alert',
                url:   `${process.env.QODIQA_CONSOLE_URL ?? 'https://qodiqa.example.com'}/alerts/${alert.id}`,
              },
            ],
          },
        },
      ],
    };

    return { body: JSON.stringify(payload), contentType: 'application/json' };
  }

  async _send(alert, recipient) {
    const endpoint = recipient ?? this._defaultUrl;
    if (!endpoint) return { ok: false, message: 'No Teams webhook URL configured (ALERT_TEAMS_WEBHOOK_URL)' };

    const { body, contentType } = this._format(alert);
    return _httpPost(endpoint, body, {
      'Content-Type':   contentType,
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent':     'QODIQA-Alerting/1.0',
    }, 10_000);
  }

  async healthCheck() {
    if (!this._defaultUrl) return { ok: false, latencyMs: 0, error: 'ALERT_TEAMS_WEBHOOK_URL not configured' };
    return { ok: true, latencyMs: 0, message: 'Teams webhook URL configured' };
  }
}

module.exports = { TeamsChannel };
