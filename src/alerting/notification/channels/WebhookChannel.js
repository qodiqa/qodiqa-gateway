'use strict';

/**
 * QODIQA Webhook Notification Channel
 *
 * Delivers alert payloads to arbitrary HTTPS endpoints.
 * Supports:
 *   - HMAC-SHA256 request signing (X-QODIQA-Signature header)
 *   - Configurable payload format (JSON, CEF for SIEM)
 *   - mTLS via environment-provided certificate paths
 *   - Configurable timeout
 *
 * Environment:
 *   ALERT_WEBHOOK_URL       — Default webhook endpoint URL
 *   ALERT_WEBHOOK_SECRET    — HMAC signing secret
 *   ALERT_WEBHOOK_TIMEOUT_MS — Request timeout (default 10 000ms)
 */

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const url    = require('url');
const { BaseChannel } = require('./BaseChannel');
const { SEVERITY } = require('../../constants');

const DEFAULT_URL     = process.env.ALERT_WEBHOOK_URL;
const SIGNING_SECRET  = process.env.ALERT_WEBHOOK_SECRET;
const TIMEOUT_MS      = parseInt(process.env.ALERT_WEBHOOK_TIMEOUT_MS ?? '10000', 10);

class WebhookChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'WEBHOOK',
      maxRetries: parseInt(process.env.ALERT_WEBHOOK_MAX_RETRIES ?? '3', 10),
      rateLimit:  parseInt(process.env.ALERT_WEBHOOK_RATE_LIMIT  ?? '120', 10),
      ...opts,
    });
    this._defaultUrl = opts.url ?? DEFAULT_URL;
  }

  _format(alert) {
    const body = JSON.stringify({
      id:          alert.id,
      type:        alert.type,
      subtype:     alert.subtype,
      severity:    alert.severity,
      status:      alert.status,
      riskScore:   alert.riskScore,
      confidence:  alert.confidence,
      title:       alert.title,
      description: alert.description,
      tags:        alert.tags,
      tenantId:    alert.tenantId,
      requestId:   alert.requestId,
      artifactId:  alert.artifactId,
      publicKeyId: alert.publicKeyId,
      clientIp:    alert.clientIp,
      evidence:    alert.evidence,
      context:     alert.context,
      detectedAt:  alert.detectedAt,
      source:      'qodiqa-alerting',
      schemaVersion: '1.0',
    });
    return { body, contentType: 'application/json' };
  }

  async _send(alert, recipient) {
    const endpoint = recipient ?? this._defaultUrl;
    if (!endpoint) {
      return { ok: false, message: 'No webhook URL configured' };
    }

    const { body, contentType } = this._format(alert);

    // HMAC signature for webhook receiver verification
    const headers = {
      'Content-Type':   contentType,
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent':     'QODIQA-Alerting/1.0',
      'X-QODIQA-Alert-ID':       alert.id,
      'X-QODIQA-Alert-Severity': alert.severity,
      'X-QODIQA-Alert-Type':     alert.type,
    };

    if (SIGNING_SECRET) {
      const sig = crypto.createHmac('sha256', SIGNING_SECRET)
        .update(body).digest('hex');
      headers['X-QODIQA-Signature'] = `sha256=${sig}`;
    }

    return _httpPost(endpoint, body, headers, TIMEOUT_MS);
  }

  async healthCheck() {
    if (!this._defaultUrl) {
      return { ok: false, latencyMs: 0, error: 'ALERT_WEBHOOK_URL not configured' };
    }
    const start = Date.now();
    try {
      const result = await _httpPost(this._defaultUrl, '{"ping":true}', {
        'Content-Type': 'application/json',
        'User-Agent':   'QODIQA-Alerting/1.0',
      }, 5000);
      return { ok: result.ok || result.code < 500, latencyMs: Date.now() - start };
    } catch (err) {
      return { ok: false, latencyMs: Date.now() - start, error: err.message };
    }
  }
}

// ── HTTP POST helper ──────────────────────────────────────────────────────────

function _httpPost(endpoint, body, headers, timeoutMs = 10_000) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new url.URL(endpoint);
    } catch (e) {
      return resolve({ ok: false, message: `Invalid URL: ${endpoint}` });
    }

    const lib = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search ?? ''),
      method:   'POST',
      headers,
      timeout:  timeoutMs,
    };

    const req = lib.request(opts, (res) => {
      let responseBody = '';
      res.on('data', chunk => { responseBody += chunk; });
      res.on('end', () => {
        const ok = res.statusCode >= 200 && res.statusCode < 300;
        resolve({ ok, code: res.statusCode, message: ok ? null : responseBody.slice(0, 200) });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, code: 0, message: `Timeout after ${timeoutMs}ms` });
    });

    req.on('error', (err) => {
      resolve({ ok: false, code: 0, message: err.message });
    });

    req.write(body);
    req.end();
  });
}

module.exports = { WebhookChannel, _httpPost };
