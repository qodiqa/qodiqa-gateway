'use strict';

/**
 * QODIQA SMS Notification Channel
 *
 * Sends SMS alerts via Twilio REST API (or any compatible provider).
 *
 * Environment:
 *   ALERT_SMS_PROVIDER          — 'twilio' | 'webhook' (default: twilio)
 *   ALERT_SMS_FROM              — Sender phone number (+E.164 format)
 *   ALERT_SMS_TO                — Default recipient phone number
 *   ALERT_SMS_TWILIO_ACCOUNT_SID
 *   ALERT_SMS_TWILIO_AUTH_TOKEN
 *   ALERT_SMS_WEBHOOK_URL       — Generic SMS gateway webhook URL
 */

const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');

const SMS_PROVIDER  = process.env.ALERT_SMS_PROVIDER  ?? 'twilio';
const SMS_FROM      = process.env.ALERT_SMS_FROM;
const DEFAULT_SMS_TO = process.env.ALERT_SMS_TO;

class SMSChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'SMS',
      maxRetries: 3,
      rateLimit:  10,   // conservative — SMS is expensive and rate-limited
      ...opts,
    });
  }

  _format(alert) {
    // SMS must be brief — 160 chars for GSM7 encoding
    const prefix = {
      [SEVERITY.CRITICAL]: '🚨 CRITICAL: ',
      [SEVERITY.HIGH]:     '🔴 HIGH: ',
      [SEVERITY.MEDIUM]:   '⚠️ MEDIUM: ',
      [SEVERITY.LOW]:      '🔵 LOW: ',
      [SEVERITY.INFO]:     'ℹ️ INFO: ',
    }[alert.severity] ?? '';

    let msg = `${prefix}${alert.title}`;
    const suffix = ` | ID: ${alert.id.slice(0, 8)}`;
    const maxBody = 160 - suffix.length;

    if (msg.length > maxBody) {
      msg = msg.slice(0, maxBody - 3) + '...';
    }
    msg += suffix;

    return { body: msg };
  }

  async _send(alert, recipient) {
    const to = recipient ?? DEFAULT_SMS_TO;
    if (!to) return { ok: false, message: 'No SMS recipient configured (ALERT_SMS_TO)' };

    const { body: message } = this._format(alert);

    if (SMS_PROVIDER === 'twilio') {
      return _sendViaTwilio(to, message);
    }

    // Generic webhook fallback
    const url = process.env.ALERT_SMS_WEBHOOK_URL;
    if (!url) return { ok: false, message: 'No SMS provider configured' };

    const payload = JSON.stringify({ to, from: SMS_FROM, message });
    return _httpPost(url, payload, {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(payload).toString(),
    }, 10_000);
  }

  async healthCheck() {
    if (SMS_PROVIDER === 'twilio') {
      const sid   = process.env.ALERT_SMS_TWILIO_ACCOUNT_SID;
      const token = process.env.ALERT_SMS_TWILIO_AUTH_TOKEN;
      if (!sid || !token) return { ok: false, latencyMs: 0, error: 'Twilio credentials not configured' };
    }
    if (!DEFAULT_SMS_TO) return { ok: false, latencyMs: 0, error: 'ALERT_SMS_TO not configured' };
    return { ok: true, latencyMs: 0, message: `SMS channel configured (provider=${SMS_PROVIDER})` };
  }
}

async function _sendViaTwilio(to, message) {
  const sid   = process.env.ALERT_SMS_TWILIO_ACCOUNT_SID;
  const token = process.env.ALERT_SMS_TWILIO_AUTH_TOKEN;
  const from  = SMS_FROM;

  if (!sid || !token || !from) {
    return { ok: false, message: 'Twilio credentials incomplete (SID, AUTH_TOKEN, FROM required)' };
  }

  const body = new URLSearchParams({ To: to, From: from, Body: message }).toString();
  const auth = Buffer.from(`${sid}:${token}`).toString('base64');

  return _httpPost(
    `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`,
    body,
    {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Authorization': `Basic ${auth}`,
      'User-Agent':    'QODIQA-Alerting/1.0',
    },
    15_000
  );
}

module.exports = { SMSChannel };
