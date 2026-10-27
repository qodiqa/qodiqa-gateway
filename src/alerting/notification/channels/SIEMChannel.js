'use strict';

/**
 * QODIQA SIEM Integration Channel
 *
 * Delivers alerts in CEF (Common Event Format) via:
 *   1. Syslog UDP/TCP to a configurable SIEM endpoint (Splunk, QRadar, ArcSight)
 *   2. HTTP POST to a SIEM HTTP Event Collector (Splunk HEC, Elastic, etc.)
 *
 * CEF format: Allows universal ingestion by enterprise SIEMs.
 * CEF Version: 0 (ArcSight standard)
 *
 * Environment:
 *   ALERT_SIEM_MODE          — 'syslog' | 'http' (default: 'http')
 *   ALERT_SIEM_URL           — SIEM HEC endpoint URL (http mode)
 *   ALERT_SIEM_TOKEN         — SIEM HEC auth token
 *   ALERT_SIEM_SYSLOG_HOST   — Syslog receiver host
 *   ALERT_SIEM_SYSLOG_PORT   — Syslog receiver port (default 514)
 *   ALERT_SIEM_SYSLOG_PROTO  — 'tcp' | 'udp' (default: udp)
 *   ALERT_SIEM_SOURCE        — Source field (default: qodiqa)
 *   ALERT_SIEM_SOURCETYPE    — Sourcetype field (default: qodiqa:alert)
 */

const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');
const { buildCEFLine, wrapSyslog, sendSyslog } = require('../../../observability/siem/cef');

// CEF severity mapping (0-10 scale)
const CEF_SEVERITY = {
  [SEVERITY.INFO]:     2,
  [SEVERITY.LOW]:      3,
  [SEVERITY.MEDIUM]:   5,
  [SEVERITY.HIGH]:     8,
  [SEVERITY.CRITICAL]: 10,
};

const SIEM_MODE     = process.env.ALERT_SIEM_MODE      ?? 'http';
const SIEM_URL      = process.env.ALERT_SIEM_URL;
const SIEM_TOKEN    = process.env.ALERT_SIEM_TOKEN;
const SYSLOG_HOST   = process.env.ALERT_SIEM_SYSLOG_HOST;
const SYSLOG_PORT   = parseInt(process.env.ALERT_SIEM_SYSLOG_PORT ?? '514', 10);
const SYSLOG_PROTO  = process.env.ALERT_SIEM_SYSLOG_PROTO ?? 'udp';
const SOURCE        = process.env.ALERT_SIEM_SOURCE        ?? 'qodiqa';
const SOURCETYPE    = process.env.ALERT_SIEM_SOURCETYPE    ?? 'qodiqa:alert';

class SIEMChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'SIEM',
      maxRetries: 3,
      rateLimit:  500,  // SIEMs accept high volume
      ...opts,
    });
    this._mode = opts.mode ?? SIEM_MODE;
  }

  _formatCEF(alert) {
    const cefSev  = CEF_SEVERITY[alert.severity] ?? 5;
    const sigId   = `${alert.type}_${alert.subtype}`;

    const ext = {
      rt:          new Date(alert.detectedAt).getTime(),
      src:         alert.clientIp     ?? 'unknown',
      suser:       alert.actorId      ?? alert.tenantId ?? 'unknown',
      requestId:   alert.requestId    ?? '',
      artifactId:  alert.artifactId   ?? '',
      tenantId:    alert.tenantId     ?? '',
      publicKeyId: alert.publicKeyId  ?? '',
      riskScore:   alert.riskScore,
      confidence:  alert.confidence,
      alertId:     alert.id,
      alertType:   alert.type,
      subtype:     alert.subtype,
      msg:         alert.description?.slice(0, 500) ?? '',
    };

    return buildCEFLine({
      deviceVersion: '1.0.0',
      signatureId:   sigId,
      name:          alert.title,
      severity:      cefSev,
      extension:     ext,
    });
  }

  _format(alert) {
    if (this._mode === 'http') {
      // Splunk HEC format
      const body = JSON.stringify({
        time:       new Date(alert.detectedAt).getTime() / 1000,
        source:     SOURCE,
        sourcetype: SOURCETYPE,
        event: {
          id:          alert.id,
          type:        alert.type,
          subtype:     alert.subtype,
          severity:    alert.severity,
          riskScore:   alert.riskScore,
          confidence:  alert.confidence,
          title:       alert.title,
          description: alert.description?.slice(0, 1000),
          tenantId:    alert.tenantId,
          requestId:   alert.requestId,
          artifactId:  alert.artifactId,
          publicKeyId: alert.publicKeyId,
          clientIp:    alert.clientIp,
          detectedAt:  alert.detectedAt,
          cef:         this._formatCEF(alert),
        },
      });
      return { body, contentType: 'application/json' };
    }

    // Syslog: RFC 5424 format with CEF payload
    const cef    = this._formatCEF(alert);
    const syslog = wrapSyslog(cef, { timestamp: new Date(alert.detectedAt) });
    return { body: syslog, contentType: 'text/plain' };
  }

  async _send(alert, recipient) {
    if (this._mode === 'http') {
      const endpoint = recipient ?? SIEM_URL;
      if (!endpoint) return { ok: false, message: 'ALERT_SIEM_URL not configured' };

      const { body, contentType } = this._format(alert);
      const headers = {
        'Content-Type':   contentType,
        'Content-Length': Buffer.byteLength(body).toString(),
        'User-Agent':     'QODIQA-Alerting/1.0',
      };
      if (SIEM_TOKEN) headers['Authorization'] = `Splunk ${SIEM_TOKEN}`;

      return _httpPost(endpoint, body, headers, 10_000);
    }

    // Syslog mode
    const host = recipient ?? SYSLOG_HOST;
    if (!host) return { ok: false, message: 'ALERT_SIEM_SYSLOG_HOST not configured' };

    const { body } = this._format(alert);
    return sendSyslog(body, host, SYSLOG_PORT, SYSLOG_PROTO);
  }

  async healthCheck() {
    if (this._mode === 'http' && !SIEM_URL) {
      return { ok: false, latencyMs: 0, error: 'ALERT_SIEM_URL not configured' };
    }
    if (this._mode === 'syslog' && !SYSLOG_HOST) {
      return { ok: false, latencyMs: 0, error: 'ALERT_SIEM_SYSLOG_HOST not configured' };
    }
    return { ok: true, latencyMs: 0, message: `SIEM channel configured (mode=${this._mode})` };
  }
}

module.exports = { SIEMChannel };
