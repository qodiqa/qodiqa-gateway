'use strict';

// configuration for the optional metrics OTLP export bridge.
// Follows the exact convention already established by
// src/observability/tracing/config.js: disabled unless explicitly enabled,
// HTTPS-only endpoint, defensive parsing with safe fallbacks for every
// numeric value (a malformed env var can never throw during startup).
//
// Deliberately REUSES QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT and
// QODIQA_OTEL_SERVICE_NAME from the tracing config — one collector target,
// one service identity, whether an operator enables traces, metrics, or
// both. Metrics get their OWN enable flag (QODIQA_OTEL_METRICS_ENABLED)
// since a site may reasonably want one signal without the other.

const { emit } = require('../../../services/logger');

const MIN_EXPORT_INTERVAL_MS = 5_000; // floor: never hammer a collector faster than this

function loadMetricsExportConfig() {
  const enabled = process.env.QODIQA_OTEL_METRICS_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  const serviceName = (process.env.QODIQA_OTEL_SERVICE_NAME || 'qodiqa').trim();
  const endpoint    = (process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT || '').trim();
  const environment = (process.env.NODE_ENV || 'development').trim();

  const exportIntervalMs = (() => {
    const v = parseInt(process.env.QODIQA_OTEL_METRICS_EXPORT_INTERVAL_MS, 10);
    return Number.isFinite(v) && v >= MIN_EXPORT_INTERVAL_MS ? v : 60_000;
  })();

  const valid = Boolean(endpoint && endpoint.startsWith('https://'));

  if (!valid) {
    emit('ERROR', 'METRICS_EXPORT_CONFIG_INVALID', {
      message: 'QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT must be a valid HTTPS URL when metrics export is enabled',
      hint:    'Example: QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.company.com',
    });
  }

  return Object.freeze({ enabled, valid, serviceName, endpoint, environment, exportIntervalMs });
}

module.exports = { loadMetricsExportConfig, MIN_EXPORT_INTERVAL_MS };
