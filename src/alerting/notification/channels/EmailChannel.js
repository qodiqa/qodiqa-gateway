'use strict';

/**
 * QODIQA Email Notification Channel
 *
 * Delivers HTML/text alert emails via:
 *   - HTTP API (SendGrid, Mailgun, AWS SES — configurable via ALERT_EMAIL_PROVIDER)
 *   - Direct SMTP using Node.js built-in net/tls modules (no external dependencies)
 *
 * Environment:
 *   ALERT_EMAIL_PROVIDER      — 'sendgrid' | 'mailgun' | 'smtp' (default: smtp)
 *   ALERT_EMAIL_FROM          — Sender address
 *   ALERT_EMAIL_TO            — Default recipient (comma-separated for multiple)
 *
 *   SendGrid:
 *     ALERT_EMAIL_SENDGRID_API_KEY
 *
 *   Mailgun:
 *     ALERT_EMAIL_MAILGUN_API_KEY
 *     ALERT_EMAIL_MAILGUN_DOMAIN
 *
 *   SMTP:
 *     ALERT_EMAIL_SMTP_HOST                     — SMTP server host
 *     ALERT_EMAIL_SMTP_PORT                     — SMTP port (default 587)
 *     ALERT_EMAIL_SMTP_USER                     — SMTP username
 *     ALERT_EMAIL_SMTP_PASS                     — SMTP password
 *     ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED  — 'false' to accept a
 *                                                  self-signed/internal-CA
 *                                                  relay certificate during
 *                                                  STARTTLS (default: true —
 *                                                  verify like any other
 *                                                  outbound TLS connection)
 *     ALERT_EMAIL_TRUSTED_RELAY_ONLY            — 'true' to permit SMTP AUTH
 *                                                  over plaintext when the
 *                                                  relay does not advertise
 *                                                  STARTTLS. Only for relays
 *                                                  reachable exclusively over
 *                                                  a trusted internal network
 *                                                  (see docs/operations/
 *                                                  notification-setup.md).
 *                                                  Default: unset — refuse.
 *
 * Credential safety: SMTP AUTH LOGIN transmits the mailbox
 * username and password base64-encoded, not encrypted — base64 is trivially
 * reversible, so those bytes are plaintext on the wire. STARTTLS is
 * negotiated (and the socket upgraded to TLS) immediately after EHLO and
 * *before* AUTH LOGIN is ever issued, so credentials only travel encrypted.
 * If the relay does not advertise STARTTLS in its EHLO response, AUTH is
 * refused outright unless the operator has explicitly opted into
 * ALERT_EMAIL_TRUSTED_RELAY_ONLY=true for a relay reachable only over a
 * network they trust (e.g. a same-VPC internal relay with no public route).
 * Internet-facing deployments should use the SendGrid/Mailgun HTTPS
 * providers instead — see docs/operations/notification-setup.md.
 */

const net    = require('net');
const tls    = require('tls');
const https  = require('https');
const { BaseChannel } = require('./BaseChannel');
const { _httpPost }   = require('./WebhookChannel');
const { SEVERITY }    = require('../../constants');

const EMAIL_PROVIDER = process.env.ALERT_EMAIL_PROVIDER ?? 'smtp';
const FROM_ADDRESS   = process.env.ALERT_EMAIL_FROM     ?? 'security@qodiqa.example.com';
const DEFAULT_TO     = process.env.ALERT_EMAIL_TO;

const SEVERITY_SUBJECT_PREFIX = {
  [SEVERITY.INFO]:     '[INFO]',
  [SEVERITY.LOW]:      '[LOW]',
  [SEVERITY.MEDIUM]:   '[MEDIUM] ⚠️',
  [SEVERITY.HIGH]:     '[HIGH] 🔴',
  [SEVERITY.CRITICAL]: '[CRITICAL] 🚨 IMMEDIATE ACTION REQUIRED',
};

class EmailChannel extends BaseChannel {
  constructor(opts = {}) {
    super({
      name:       'EMAIL',
      maxRetries: 3,
      rateLimit:  30,   // conservative rate limit for email
      ...opts,
    });
  }

  _format(alert) {
    const subject = `${SEVERITY_SUBJECT_PREFIX[alert.severity] ?? '[ALERT]'} ${alert.title}`;
    const ts      = new Date(alert.detectedAt).toISOString();

    const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>QODIQA Security Alert</title></head>
<body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px">
<div style="max-width:700px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden">
  <div style="background:${_severityBg(alert.severity)};padding:20px;color:#fff">
    <h1 style="margin:0;font-size:20px">🛡️ QODIQA Security Alert</h1>
    <p style="margin:5px 0 0;opacity:.85;font-size:14px">Severity: ${alert.severity} | Risk Score: ${alert.riskScore}/100</p>
  </div>
  <div style="padding:24px">
    <h2 style="color:#1a1a2e;margin-top:0">${_esc(alert.title)}</h2>
    <p style="color:#444;line-height:1.6">${_esc(alert.description ?? '').slice(0, 1000)}</p>
    <table style="width:100%;border-collapse:collapse;margin-top:16px">
      <tr><td style="padding:8px;background:#f8f8f8;font-weight:bold;width:140px">Alert ID</td><td style="padding:8px">${_esc(alert.id)}</td></tr>
      <tr><td style="padding:8px;font-weight:bold">Type</td><td style="padding:8px">${_esc(alert.type)}</td></tr>
      <tr><td style="padding:8px;background:#f8f8f8;font-weight:bold">Subtype</td><td style="padding:8px;background:#f8f8f8">${_esc(alert.subtype)}</td></tr>
      <tr><td style="padding:8px;font-weight:bold">Detected At</td><td style="padding:8px">${ts}</td></tr>
      ${alert.tenantId    ? `<tr><td style="padding:8px;background:#f8f8f8;font-weight:bold">Tenant</td><td style="padding:8px;background:#f8f8f8">${_esc(alert.tenantId)}</td></tr>` : ''}
      ${alert.requestId   ? `<tr><td style="padding:8px;font-weight:bold">Request ID</td><td style="padding:8px">${_esc(alert.requestId)}</td></tr>` : ''}
      ${alert.publicKeyId ? `<tr><td style="padding:8px;background:#f8f8f8;font-weight:bold">Key ID</td><td style="padding:8px;background:#f8f8f8">${_esc(alert.publicKeyId)}</td></tr>` : ''}
      ${alert.clientIp    ? `<tr><td style="padding:8px;font-weight:bold">Client IP</td><td style="padding:8px">${_esc(alert.clientIp)}</td></tr>` : ''}
    </table>
    <div style="margin-top:24px;padding:16px;background:#fff8f0;border-left:4px solid ${_severityBg(alert.severity)};border-radius:0 4px 4px 0">
      <p style="margin:0;font-weight:bold">Response Required</p>
      <p style="margin:4px 0 0;font-size:13px;color:#555">
        View and acknowledge this alert in the QODIQA Security Console.
      </p>
    </div>
  </div>
  <div style="padding:12px 24px;background:#f0f0f0;font-size:12px;color:#888;text-align:center">
    QODIQA Security Platform | This alert was generated automatically. Do not reply to this email.
  </div>
</div>
</body>
</html>`;

    const text = [
      `QODIQA SECURITY ALERT — ${alert.severity}`,
      `${'='.repeat(50)}`,
      `Title:       ${alert.title}`,
      `Type:        ${alert.type} / ${alert.subtype}`,
      `Risk Score:  ${alert.riskScore}/100`,
      `Detected:    ${ts}`,
      alert.tenantId    ? `Tenant:      ${alert.tenantId}` : '',
      alert.requestId   ? `Request ID:  ${alert.requestId}` : '',
      alert.publicKeyId ? `Key ID:      ${alert.publicKeyId}` : '',
      alert.clientIp    ? `Client IP:   ${alert.clientIp}` : '',
      ``,
      alert.description ?? '',
      ``,
      `Alert ID: ${alert.id}`,
    ].filter(Boolean).join('\n');

    return { subject, html, text };
  }

  async _send(alert, recipient) {
    const to = recipient ?? DEFAULT_TO;
    if (!to) return { ok: false, message: 'No email recipient configured (ALERT_EMAIL_TO)' };

    const { subject, html, text } = this._format(alert);

    switch (EMAIL_PROVIDER) {
      case 'sendgrid': return _sendViaSendGrid(to, subject, html, text);
      case 'mailgun':  return _sendViaMailgun(to, subject, html, text);
      case 'smtp':
      default:         return _sendViaSMTP(to, subject, html, text);
    }
  }

  async healthCheck() {
    if (!DEFAULT_TO) return { ok: false, latencyMs: 0, error: 'ALERT_EMAIL_TO not configured' };
    return { ok: true, latencyMs: 0, message: `Email channel configured (provider=${EMAIL_PROVIDER})` };
  }
}

// ── SendGrid ──────────────────────────────────────────────────────────────────

async function _sendViaSendGrid(to, subject, html, text) {
  const apiKey = process.env.ALERT_EMAIL_SENDGRID_API_KEY;
  if (!apiKey) return { ok: false, message: 'ALERT_EMAIL_SENDGRID_API_KEY not set' };

  const body = JSON.stringify({
    personalizations: [{ to: to.split(',').map(e => ({ email: e.trim() })) }],
    from:             { email: FROM_ADDRESS },
    subject,
    content: [
      { type: 'text/plain', value: text },
      { type: 'text/html',  value: html },
    ],
  });

  return _httpPost('https://api.sendgrid.com/v3/mail/send', body, {
    'Content-Type':  'application/json',
    'Authorization': `Bearer ${apiKey}`,
  }, 15_000);
}

// ── Mailgun ───────────────────────────────────────────────────────────────────

async function _sendViaMailgun(to, subject, html, text) {
  const apiKey = process.env.ALERT_EMAIL_MAILGUN_API_KEY;
  const domain = process.env.ALERT_EMAIL_MAILGUN_DOMAIN;
  if (!apiKey || !domain) return { ok: false, message: 'Mailgun credentials not configured' };

  const body = new URLSearchParams({ from: FROM_ADDRESS, to, subject, html, text }).toString();
  const auth = Buffer.from(`api:${apiKey}`).toString('base64');

  return _httpPost(`https://api.mailgun.net/v3/${domain}/messages`, body, {
    'Content-Type':  'application/x-www-form-urlencoded',
    'Authorization': `Basic ${auth}`,
  }, 15_000);
}

// ── Minimal SMTP client (no external dependencies) ────────────────────────────
//
// State machine:
//   CONNECT -> EHLO -> [STARTTLS -> EHLO (post-TLS)] -> [AUTH -> AUTH_USER ->
//   AUTH_PASS] -> MAIL -> RCPT -> DATA -> BODY -> QUIT
//
// STARTTLS, when the relay advertises it in its EHLO capability list, is
// always negotiated before anything else — including the plaintext-only MAIL
// FROM path used when no credentials are configured — so message content is
// protected whenever the relay supports it. AUTH LOGIN is additionally
// gated: it is only ever issued once the socket has been upgraded to TLS.
// If the relay doesn't advertise STARTTLS and credentials are configured,
// the transport refuses to send them in plaintext unless the operator has
// explicitly opted into ALERT_EMAIL_TRUSTED_RELAY_ONLY=true (see module
// header). This mirrors the existing REDIS_TLS_REJECT_UNAUTHORIZED pattern:
// secure by default, with a single explicit, documented escape hatch.

function _envBool(name, defaultVal) {
  const raw = process.env[name];
  if (!raw || !raw.trim()) return defaultVal;
  return raw.trim() === 'true';
}

function _sendViaSMTP(to, subject, html, text) {
  const host                  = process.env.ALERT_EMAIL_SMTP_HOST ?? 'localhost';
  const port                  = parseInt(process.env.ALERT_EMAIL_SMTP_PORT ?? '587', 10);
  const user                  = process.env.ALERT_EMAIL_SMTP_USER;
  const pass                  = process.env.ALERT_EMAIL_SMTP_PASS;
  const requiresAuth          = Boolean(user && pass);
  const trustedRelayOnly      = _envBool('ALERT_EMAIL_TRUSTED_RELAY_ONLY', false);
  const tlsRejectUnauthorized = _envBool('ALERT_EMAIL_SMTP_TLS_REJECT_UNAUTHORIZED', true);

  return new Promise((resolve) => {
    let socket   = new net.Socket();
    let state    = 'CONNECT';
    let buffer   = '';
    let settled  = false;
    let ehloCaps = new Set();
    let isSecure = false;

    const boundary = `----=_Part_${Date.now()}`;
    const mimeBody = [
      `From: ${FROM_ADDRESS}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      `MIME-Version: 1.0`,
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
      ``,
      `--${boundary}`,
      `Content-Type: text/plain; charset=utf-8`,
      ``,
      text,
      `--${boundary}`,
      `Content-Type: text/html; charset=utf-8`,
      ``,
      html,
      `--${boundary}--`,
    ].join('\r\n');

    const cmd = (c) => socket.write(c + '\r\n');

    function finish(result) {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* already closed */ }
      resolve(result);
    }

    function bindTransportEvents(s) {
      s.setTimeout(15_000);
      s.on('timeout', () => finish({ ok: false, message: 'SMTP timeout' }));
      s.on('error',   (err) => finish({ ok: false, message: `SMTP transport error: ${err.message}` }));
    }

    // Upgrades the plaintext socket to TLS in place. Must run to completion
    // (secureConnect) before any further SMTP command is written — the
    // caller only transitions state after this resolves via the 'EHLO'
    // re-issue inside the connect callback below.
    function upgradeToTls() {
      const plainSocket = socket;
      plainSocket.removeListener('data', onData);
      buffer = '';  // discard any unterminated plaintext-phase remainder

      const tlsSocket = tls.connect({
        socket: plainSocket,
        // SNI (servername) is only meaningful for hostnames — RFC 6066
        // forbids IP literals there, and Node deprecation-warns on it.
        ...(net.isIP(host) === 0 ? { servername: host } : {}),
        rejectUnauthorized: tlsRejectUnauthorized,
      }, () => {
        socket   = tlsSocket;
        ehloCaps = new Set();
        isSecure = true;
        state    = 'EHLO';
        cmd('EHLO qodiqa.example.com');
      });

      bindTransportEvents(tlsSocket);
      tlsSocket.on('data', onData);
    }

    let rcptList = null; let rcptIdx = 0; const rcptAccepted = []; const rcptRejected = [];

    function onData(chunk) {
      buffer += chunk.toString();
      const lines = buffer.split('\r\n');
      buffer = lines.pop();  // keep incomplete line

      for (const line of lines) {
        const code            = parseInt(line.slice(0, 3), 10);
        const isContinuation  = line[3] === '-';

        // Capture every EHLO capability line (continuation or final) so
        // STARTTLS support can be detected regardless of where it appears
        // in the multi-line response.
        if (state === 'EHLO' && Number.isInteger(code)) {
          const capability = line.slice(4).trim().split(' ')[0].toUpperCase();
          if (capability) ehloCaps.add(capability);
        }

        if (isContinuation) continue;

        switch (state) {
          case 'CONNECT':
            if (code === 220) { state = 'EHLO'; cmd('EHLO qodiqa.example.com'); }
            else { finish({ ok: false, message: `SMTP: expected 220, got ${line}` }); }
            break;

          case 'EHLO':
            if (code !== 250) {
              finish({ ok: false, message: `SMTP EHLO failed: ${line}` });
              break;
            }
            if (!isSecure && ehloCaps.has('STARTTLS')) {
              // Not yet upgraded, and the relay offers it — always take it,
              // even when no AUTH is coming, so message content benefits too.
              state = 'STARTTLS';
              cmd('STARTTLS');
            } else if (!isSecure && requiresAuth && !trustedRelayOnly) {
              // Plaintext channel, credentials configured, no explicit opt-in
              // to trust this relay unencrypted — refuse rather than leak
              // AUTH LOGIN credentials on the wire.
              finish({
                ok: false,
                message: 'SMTP: relay does not advertise STARTTLS — refusing to send ' +
                  'AUTH LOGIN credentials in plaintext. Set ' +
                  'ALERT_EMAIL_TRUSTED_RELAY_ONLY=true only for a relay reachable ' +
                  'exclusively over a trusted internal network, or switch ' +
                  'ALERT_EMAIL_PROVIDER to sendgrid/mailgun for Internet-facing delivery.',
              });
            } else if (requiresAuth) {
              state = 'AUTH';
              cmd('AUTH LOGIN');
            } else {
              state = 'MAIL';
              cmd(`MAIL FROM:<${FROM_ADDRESS}>`);
            }
            break;

          case 'STARTTLS':
            if (code === 220) { upgradeToTls(); }
            else { finish({ ok: false, message: `SMTP STARTTLS failed: ${line}` }); }
            break;

          case 'AUTH':
            if (code === 334) { state = 'AUTH_USER'; cmd(Buffer.from(user).toString('base64')); }
            else { finish({ ok: false, message: `SMTP AUTH LOGIN failed: ${line}` }); }
            break;
          case 'AUTH_USER':
            if (code === 334) { state = 'AUTH_PASS'; cmd(Buffer.from(pass).toString('base64')); }
            else { finish({ ok: false, message: `SMTP AUTH LOGIN failed: ${line}` }); }
            break;
          case 'AUTH_PASS':
            if (code === 235) { state = 'MAIL'; cmd(`MAIL FROM:<${FROM_ADDRESS}>`); }
            else { finish({ ok: false, message: `SMTP auth failed: ${line}` }); }
            break;
          case 'MAIL':
            if (code === 250) {
              state = 'RCPT';
              // only recipients[0] used to get an RCPT TO — a comma-separated ALERT_EMAIL_TO delivered to the
              // first address only. Every address is now offered to the relay in turn.
              rcptList = to.split(',').map(e => e.trim()).filter(Boolean);
              rcptIdx = 0;
              cmd(`RCPT TO:<${rcptList[0]}>`);
            } else { finish({ ok: false, message: `SMTP MAIL FROM failed: ${line}` }); }
            break;
          case 'RCPT':
            if (code === 250 || code === 251) rcptAccepted.push(rcptList[rcptIdx]);
            else rcptRejected.push({ address: rcptList[rcptIdx], response: line });
            rcptIdx++;
            if (rcptIdx < rcptList.length) { cmd(`RCPT TO:<${rcptList[rcptIdx]}>`); break; }
            if (rcptAccepted.length > 0) { state = 'DATA'; cmd('DATA'); }
            else { finish({ ok: false, message: `SMTP RCPT failed for every recipient: ${rcptRejected.map(r => r.response).join(' | ')}` }); }
            break;
          case 'DATA':
            if (code === 354) { state = 'BODY'; cmd(mimeBody + '\r\n.'); }
            else { finish({ ok: false, message: `SMTP DATA failed: ${line}` }); }
            break;
          case 'BODY':
            if (code === 250) { state = 'QUIT'; cmd('QUIT'); }
            else { finish({ ok: false, message: `SMTP message submission failed: ${line}` }); }
            break;
          case 'QUIT':
            finish(rcptRejected.length ? { ok: true, rejectedRecipients: rcptRejected.map(r => r.address) } : { ok: true });
            break;
        }
      }
    }

    bindTransportEvents(socket);
    socket.on('data', onData);
    socket.connect(port, host, () => {});
  });
}

function _esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function _severityBg(severity) {
  const map = { INFO: '#6B7280', LOW: '#3B82F6', MEDIUM: '#D97706', HIGH: '#DC2626', CRITICAL: '#7C3AED' };
  return map[severity] ?? '#374151';
}

module.exports = { EmailChannel };
