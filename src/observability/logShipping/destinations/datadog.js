'use strict';

// Datadog destination adapter — Component #24
//
// Ships log events to the Datadog Logs Intake API.
// Reference: https://docs.datadoghq.com/api/latest/logs/#send-logs
//
// Endpoint: POST https://http-intake.logs.{site}/api/v2/logs
// Auth:     DD-API-KEY header
// Format:   JSON array of log objects
//
// Datadog-specific field mapping:
//   QODIQA schema → Datadog
//   severity      → status (TRACE/DEBUG/INFO/WARN/ERROR/CRITICAL)
//   message       → message
//   service       → service
//   eventType     → ddsource (tagging)

const { httpsPost: defaultHttpsPost } = require('../_transport');

const LEVEL_MAP = {
  TRACE:    'trace',
  DEBUG:    'debug',
  INFO:     'info',
  WARN:     'warn',
  WARNING:  'warn',
  ERROR:    'error',
  CRITICAL: 'critical',
};

function _toDatadogEvent(event) {
  return {
    message:   event.message,
    status:    LEVEL_MAP[event.severity?.toUpperCase()] || 'info',
    service:   event.service,
    ddsource:  event.eventType,
    ddtags:    [
      `env:${event.environment}`,
      event.tenantId   ? `tenant_id:${event.tenantId}`     : null,
      event.tenantSlug ? `tenant_slug:${event.tenantSlug}` : null,
    ].filter(Boolean).join(','),
    timestamp: event.timestamp,
    requestId: event.requestId,
    traceId:   event.traceId,
    tenantId:  event.tenantId,
    ...event.metadata,
  };
}

/**
 * Create the Datadog destination adapter.
 *
 * @param {object} config       — log ship config (config.datadog must have apiKey and site)
 * @param {object} [deps]
 * @param {Function} [deps.httpsPost]
 * @returns {{ name: string, send: Function }}
 */
function createDatadogDestination(config, { httpsPost = defaultHttpsPost } = {}) {
  const { apiKey, site } = config.datadog;
  const url = `https://http-intake.logs.${site}/api/v2/logs`;

  return {
    name: 'datadog',

    async send(events) {
      const payload = JSON.stringify(events.map(_toDatadogEvent));

      let result;
      try {
        result = await httpsPost(
          url,
          {
            'Content-Type': 'application/json',
            'DD-API-KEY':   apiKey,
          },
          payload,
        );
      } catch (err) {
        err.retryable = true;
        throw err;
      }

      if (result.status >= 400) {
        const err = new Error(`Datadog returned HTTP ${result.status}`);
        err.status    = result.status;
        // 401/403: auth failure — non-retryable; 429/5xx: retryable
        err.retryable = result.status === 429 || result.status >= 500;
        throw err;
      }
    },
  };
}

module.exports = { createDatadogDestination };
