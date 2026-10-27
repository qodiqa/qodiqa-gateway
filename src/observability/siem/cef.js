'use strict';

/**
 * Shared CEF (Common Event Format) builder and syslog transport —.
 *
 * Extracted from src/alerting/notification/channels/SIEMChannel.js so the
 * alert-scoped CEF/syslog exporter and the bulk audit-stream SIEM exporter
 * (src/observability/logShipping/destinations/siem.js) share one
 * implementation of CEF line construction, RFC 5424 syslog wrapping, and
 * the UDP/TCP syslog send. Neither consumer duplicates this logic.
 *
 * CEF format: CEF:Version|Device Vendor|Device Product|Device Version|
 *             Signature ID|Name|Severity|Extension
 * CEF Version: 0 (ArcSight standard)
 */

const dgram = require('dgram');
const net   = require('net');

// ── CEF line construction ───────────────────────────────────────────────────

/**
 * Build a single CEF:0 line.
 *
 * @param {object} fields
 * @param {string} [fields.deviceVendor='QODIQA']
 * @param {string} [fields.deviceProduct='QODIQA Platform']
 * @param {string} fields.deviceVersion
 * @param {string} fields.signatureId
 * @param {string} fields.name
 * @param {number} fields.severity      — CEF severity, 0-10
 * @param {object} fields.extension     — key → value extension fields
 * @returns {string}
 */
function buildCEFLine({
  deviceVendor  = 'QODIQA',
  deviceProduct = 'QODIQA Platform',
  deviceVersion,
  signatureId,
  name,
  severity,
  extension = {},
}) {
  const nameEsc = cefEscapeHeader(name);
  const extStr = Object.entries(extension)
    .filter(([, v]) => v !== '' && v !== null && v !== undefined)
    .map(([k, v]) => `${k}=${cefEscapeExtensionValue(String(v))}`)
    .join(' ');

  return `CEF:0|${deviceVendor}|${deviceProduct}|${deviceVersion}|${signatureId}|${nameEsc}|${severity}|${extStr}`;
}

function cefEscapeHeader(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|');
}

function cefEscapeExtensionValue(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

// ── RFC 5424 syslog wrapping ─────────────────────────────────────────────────

/**
 * Wrap a CEF (or any) message body in an RFC 5424 syslog envelope.
 *
 * @param {string} body
 * @param {object} [opts]
 * @param {number} [opts.facility=1]  — syslog facility (1 = user-level)
 * @param {number} [opts.severity=4]  — syslog severity (4 = warning)
 * @param {string} [opts.host='qodiqa']
 * @param {string} [opts.appName='QODIQA']
 * @param {Date}   [opts.timestamp]
 * @returns {string}
 */
function wrapSyslog(body, { facility = 1, severity = 4, host = 'qodiqa', appName = 'QODIQA', timestamp } = {}) {
  const pri = facility * 8 + severity;
  const ts  = (timestamp instanceof Date ? timestamp : new Date()).toISOString();
  return `<${pri}>1 ${ts} ${host} ${appName} - - - ${body}`;
}

// ── Syslog UDP/TCP sender ────────────────────────────────────────────────────

/**
 * Send a pre-formatted syslog line over UDP or TCP.
 * Never throws — resolves { ok, message? } in all cases.
 *
 * @param {string} message
 * @param {string} host
 * @param {number} port
 * @param {'udp'|'tcp'} proto
 * @returns {Promise<{ok: boolean, message?: string}>}
 */
function sendSyslog(message, host, port, proto) {
  return new Promise((resolve) => {
    const buf = Buffer.from(message + '\n', 'utf8');

    if (proto === 'tcp') {
      const socket = new net.Socket();
      socket.setTimeout(5000);
      socket.connect(port, host, () => {
        socket.write(buf, () => {
          socket.destroy();
          resolve({ ok: true });
        });
      });
      socket.on('error', (err) => resolve({ ok: false, message: err.message }));
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ ok: false, message: 'TCP syslog timeout' });
      });
    } else {
      // UDP (fire and forget — no delivery guarantee by design, matching real syslog)
      const client = dgram.createSocket('udp4');
      client.send(buf, port, host, (err) => {
        client.close();
        resolve(err ? { ok: false, message: err.message } : { ok: true });
      });
    }
  });
}

module.exports = {
  buildCEFLine,
  wrapSyslog,
  sendSyslog,
  cefEscapeHeader,
  cefEscapeExtensionValue,
};
