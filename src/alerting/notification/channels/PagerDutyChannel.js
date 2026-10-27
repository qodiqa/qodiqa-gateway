'use strict';

/**
 * QODIQA PagerDuty Notification Channel
 *
 * Integrates with PagerDuty Events API v2.
 * Manages event lifecycle: trigger → acknowledge → resolve.
 *
 * Environment:
 *   ALERT_PAGERDUTY_ROUTING_KEY  — PagerDuty Integration Key (Events API v2)
 *   ALERT_PAGERDUTY_URL          — Override API URL (default: events.pagerduty.com)
 */

const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');

const PD_ROUTING_KEY = process.env.ALERT_PAGERDUTY_ROUTING_KEY;
const PD_URL         = process.env.ALERT_PAGERDUTY_URL
                     ?? 'https://events.pagerduty.com/v2/enqueue';

const PD_SEVERITY = {
  [SEVERITY.INFO]:     'info',
  [SEVERITY.LOW]:      'info',
  [SEVERITY.MEDIUM]:   'warning',
  [SEVERITY.HIGH]:     'error',
  [SEVERITY.CRITICAL]: 'critical',
};

class PagerDutyChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'PAGERDUTY',
      maxRetries: 3,
      rateLimit:  60,
      ...opts,
    });
    this._routingKey = opts.routingKey ?? PD_ROUTING_KEY;
    this._url        = opts.url        ?? PD_URL;
  }

  _format(alert) {
    const payload = {
      routing_key:  this._routingKey,
      event_action: 'trigger',
      dedup_key:    alert.id,   // PagerDuty uses this to correlate acknowledge/resolve
      payload: {
        summary:     `[${alert.severity}] ${alert.title}`,
        severity:    PD_SEVERITY[alert.severity] ?? 'error',
        source:      'QODIQA Platform',
        timestamp:   new Date(alert.detectedAt).toISOString(),
        component:   alert.component ?? alert.type,
        group:       alert.type,
        class:       alert.subtype,
        custom_details: {
          alert_id:    alert.id,
          type:        alert.type,
          subtype:     alert.subtype,
          risk_score:  alert.riskScore,
          confidence:  alert.confidence,
          tenant_id:   alert.tenantId,
          request_id:  alert.requestId,
          artifact_id: alert.artifactId,
          key_id:      alert.publicKeyId,
          client_ip:   alert.clientIp,
          tags:        (alert.tags ?? []).join(', '),
          description: alert.description?.slice(0, 1000) ?? '',
        },
      },
      links: [
        {
          href:  `${process.env.QODIQA_CONSOLE_URL ?? 'https://qodiqa.example.com'}/alerts/${alert.id}`,
          text:  'View in QODIQA Console',
        },
      ],
    };

    return { body: JSON.stringify(payload), contentType: 'application/json' };
  }

  async _send(alert, recipient) {
    if (!this._routingKey) {
      return { ok: false, message: 'ALERT_PAGERDUTY_ROUTING_KEY not configured' };
    }

    const endpoint = recipient ?? this._url;
    const { body, contentType } = this._format(alert);

    return _httpPost(endpoint, body, {
      'Content-Type':   contentType,
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent':     'QODIQA-Alerting/1.0',
    }, 10_000);
  }

  async healthCheck() {
    if (!this._routingKey) {
      return { ok: false, latencyMs: 0, error: 'ALERT_PAGERDUTY_ROUTING_KEY not configured' };
    }
    return { ok: true, latencyMs: 0, message: 'PagerDuty channel configured' };
  }
}

module.exports = { PagerDutyChannel };
