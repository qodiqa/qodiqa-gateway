'use strict';

/**
 * QODIQA Slack Notification Channel
 *
 * Delivers rich Block Kit messages to Slack via incoming webhooks.
 * Severity is visually encoded via color bars and emoji.
 *
 * Environment:
 *   ALERT_SLACK_WEBHOOK_URL      — Slack incoming webhook URL
 *   ALERT_SLACK_CHANNEL          — Override channel (optional, set in Slack webhook config)
 *   ALERT_SLACK_USERNAME         — Bot username (default: QODIQA Security)
 *   ALERT_SLACK_ICON_EMOJI       — Bot icon (default: :shield:)
 */

const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');

const SLACK_URL = process.env.ALERT_SLACK_WEBHOOK_URL;

// Severity → Slack attachment color
const SLACK_COLORS = {
  [SEVERITY.INFO]:     '#6B7280',
  [SEVERITY.LOW]:      '#3B82F6',
  [SEVERITY.MEDIUM]:   '#F59E0B',
  [SEVERITY.HIGH]:     '#EF4444',
  [SEVERITY.CRITICAL]: '#7C3AED',
};

const SEVERITY_EMOJI = {
  [SEVERITY.INFO]:     ':information_source:',
  [SEVERITY.LOW]:      ':large_blue_circle:',
  [SEVERITY.MEDIUM]:   ':warning:',
  [SEVERITY.HIGH]:     ':red_circle:',
  [SEVERITY.CRITICAL]: ':rotating_light:',
};

class SlackChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'SLACK',
      maxRetries: parseInt(process.env.ALERT_SLACK_MAX_RETRIES ?? '3', 10),
      rateLimit:  parseInt(process.env.ALERT_SLACK_RATE_LIMIT  ?? '60', 10),
      ...opts,
    });
    this._defaultUrl = opts.url ?? SLACK_URL;
  }

  _format(alert) {
    const emoji  = SEVERITY_EMOJI[alert.severity] ?? ':bell:';
    const color  = SLACK_COLORS[alert.severity]   ?? '#888888';
    const ts     = new Date(alert.detectedAt).toISOString();
    const fields = [];

    if (alert.type)        fields.push({ title: 'Type',       value: `\`${alert.type}\``,       short: true });
    if (alert.subtype)     fields.push({ title: 'Subtype',    value: `\`${alert.subtype}\``,    short: true });
    if (alert.riskScore !== undefined) fields.push({ title: 'Risk Score', value: `${alert.riskScore}/100`, short: true });
    if (alert.tenantId)    fields.push({ title: 'Tenant',     value: alert.tenantId,             short: true });
    if (alert.requestId)   fields.push({ title: 'Request ID', value: `\`${alert.requestId}\``,  short: false });
    if (alert.publicKeyId) fields.push({ title: 'Key ID',     value: `\`${alert.publicKeyId}\``,short: true });
    if (alert.clientIp)    fields.push({ title: 'Client IP',  value: alert.clientIp,             short: true });

    const payload = {
      username:    process.env.ALERT_SLACK_USERNAME ?? 'QODIQA Security',
      icon_emoji:  process.env.ALERT_SLACK_ICON_EMOJI ?? ':shield:',
      attachments: [
        {
          fallback:   `[${alert.severity}] ${alert.title}`,
          color,
          pretext:    `${emoji} *QODIQA Security Alert — ${alert.severity}*`,
          title:      alert.title,
          text:       alert.description?.slice(0, 2000) ?? '',
          fields,
          footer:     `QODIQA Alerting | Alert ID: ${alert.id}`,
          footer_icon:'https://qodiqa.example.com/favicon.ico',
          ts:         Math.floor(new Date(ts).getTime() / 1000),
          mrkdwn_in:  ['text', 'pretext', 'fields'],
        },
      ],
    };

    if (process.env.ALERT_SLACK_CHANNEL) {
      payload.channel = process.env.ALERT_SLACK_CHANNEL;
    }

    return { body: JSON.stringify(payload), contentType: 'application/json' };
  }

  async _send(alert, recipient) {
    const endpoint = recipient ?? this._defaultUrl;
    if (!endpoint) return { ok: false, message: 'No Slack webhook URL configured (ALERT_SLACK_WEBHOOK_URL)' };

    const { body, contentType } = this._format(alert);
    return _httpPost(endpoint, body, {
      'Content-Type':   contentType,
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent':     'QODIQA-Alerting/1.0',
    }, 10_000);
  }

  async healthCheck() {
    if (!this._defaultUrl) return { ok: false, latencyMs: 0, error: 'ALERT_SLACK_WEBHOOK_URL not configured' };
    return { ok: true, latencyMs: 0, message: 'Webhook URL configured (not tested)' };
  }
}

module.exports = { SlackChannel };
