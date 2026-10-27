'use strict';

// SIEM destination adapter (CEF/syslog) — remediation.
//
// Ships the complete normalized audit/log event stream to a generic
// enterprise SIEM (Splunk, QRadar, ArcSight, etc.) as CEF, via either:
//   1. Syslog UDP/TCP  (mode: 'syslog')
//   2. HTTP POST to a SIEM HTTP Event Collector, CEF embedded in JSON (mode: 'http')
//
// This is the bulk-export counterpart to
// src/alerting/notification/channels/SIEMChannel.js, which formats only
// alert objects. Both share CEF construction and syslog transport via
// src/observability/siem/cef.js — no duplicated formatting/transport logic.
//
// Error classification mirrors the other destinations: network errors and
// 429/5xx are retryable; syslog UDP has no delivery guarantee by design
// (matches SIEMChannel's existing semantics) — a retry on syslog UDP/TCP
// may resend an already-delivered line; this is an accepted, documented
// limitation of fire-and-forget syslog transport, not a queue defect.

const { httpsPost: defaultHttpsPost }                = require('../_transport');
const { buildCEFLine, sendSyslog: defaultSendSyslog, wrapSyslog } = require('../../siem/cef');

// Maps the operational logger's severity levels (see services/logger.js) to
// CEF's 0-10 severity scale — distinct from SEVERITY (alert severity) used
// by SIEMChannel.js, since these are raw audit/log events, not alerts.
const LOG_LEVEL_CEF_SEVERITY = {
  INFO:     2,
  WARN:     5,
  ERROR:    8,
  CRITICAL: 10,
  FATAL:    10,
};

function _formatEventCEF(event) {
  const severity = LOG_LEVEL_CEF_SEVERITY[event.severity] ?? 3;
  const ext = {
    rt:         new Date(event.timestamp).getTime(),
    requestId:  event.requestId  || '',
    traceId:    event.traceId    || '',
    tenantId:   event.tenantId   || '',
    tenantSlug: event.tenantSlug || '',
    cat:        event.eventType  || 'LOG',
    msg:        (event.message || '').slice(0, 500),
  };

  return buildCEFLine({
    deviceVersion: '1.0.0',
    signatureId:   event.eventType || 'AUDIT_EVENT',
    name:          event.eventType || 'Audit Event',
    severity,
    extension:     ext,
  });
}

/**
 * Create the SIEM (CEF/syslog) destination adapter.
 *
 * @param {object} config        — log ship config (config.siem: mode, url, token, syslogHost/Port/Proto)
 * @param {object} [deps]
 * @param {Function} [deps.httpsPost]   — HTTP POST implementation (http mode)
 * @param {Function} [deps.sendSyslog]  — syslog send implementation (syslog mode)
 * @returns {{ name: string, send: Function }}
 */
function createSiemDestination(config, { httpsPost = defaultHttpsPost, sendSyslog = defaultSendSyslog } = {}) {
  const { mode, url, token, syslogHost, syslogPort, syslogProto } = config.siem;

  return {
    name: 'siem',

    async send(events) {
      if (mode === 'syslog') {
        for (const event of events) {
          const cef  = _formatEventCEF(event);
          const line = wrapSyslog(cef, { host: config.service || 'qodiqa', appName: 'QODIQA' });
          const result = await sendSyslog(line, syslogHost, syslogPort, syslogProto);
          if (!result.ok) {
            const err = new Error(result.message || 'SIEM syslog delivery failed');
            err.retryable = true;
            throw err;
          }
        }
        return;
      }

      // HTTP mode: HEC-style batch, one JSON object per line, CEF embedded.
      const body = events.map(event => JSON.stringify({
        time:  Math.floor(new Date(event.timestamp).getTime() / 1000),
        event: { ...event, cef: _formatEventCEF(event) },
      })).join('\n');

      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Splunk ${token}`;

      let result;
      try {
        result = await httpsPost(url, headers, body);
      } catch (err) {
        err.retryable = true;
        throw err;
      }

      if (result.status >= 400) {
        const err = new Error(`SIEM HTTP endpoint returned HTTP ${result.status}`);
        err.status    = result.status;
        err.retryable = result.status === 429 || result.status >= 500;
        throw err;
      }
    },
  };
}

module.exports = { createSiemDestination, _formatEventCEF };
