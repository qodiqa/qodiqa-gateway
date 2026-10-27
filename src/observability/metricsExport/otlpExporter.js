'use strict';

// OTLP HTTP metrics exporter — ships a metrics snapshot to an OpenTelemetry
// Collector or compatible endpoint using the OTLP/HTTP JSON format.
//
// POST /v1/metrics  →  Content-Type: application/json
// Body: OTLP ResourceMetrics JSON (protobuf JSON mapping)
//
// Mirrors src/observability/tracing/exporters/otlp.js exactly (same
// transport, same error classification) — the metrics signal reuses the
// identical, already-tested pattern rather than inventing a new one.
//
// Error classification (same policy as log shipping destinations and the
// trace exporter):
//   Retryable:     429, 502, 503, 504, network errors
//   Non-retryable: 400, 401, 403, other 4xx

const { httpsPost: defaultHttpsPost } = require('../logShipping/_transport');

/**
 * Create an OTLP HTTP metrics exporter.
 *
 * @param {{ endpoint, serviceName, environment }} config
 * @param {{ httpsPost? }}                         [deps]
 */
function createOtlpMetricsExporter(config, { httpsPost = defaultHttpsPost } = {}) {
  const endpoint = config.endpoint.replace(/\/$/, '') + '/v1/metrics';

  /**
   * Export a snapshot of metric instances (each exposing toOtlpMetric()).
   * Throws (retryable or non-retryable) on HTTP error.
   * Throws retryable on network error.
   *
   * @param {Array<{toOtlpMetric: Function}>} metricInstances
   */
  async function exportMetrics(metricInstances) {
    if (!metricInstances || metricInstances.length === 0) return;

    const nowNano = String(Date.now() * 1e6);
    const otlpMetrics = [];
    for (const m of metricInstances) {
      try {
        if (typeof m.toOtlpMetric === 'function') {
          otlpMetrics.push(m.toOtlpMetric(nowNano, nowNano));
        }
      } catch { /* one malformed metric must never block the rest of the export */ }
    }
    if (otlpMetrics.length === 0) return;

    const payload = {
      resourceMetrics: [{
        resource: {
          attributes: [
            { key: 'service.name',           value: { stringValue: config.serviceName || 'qodiqa' } },
            { key: 'deployment.environment', value: { stringValue: config.environment || 'development' } },
          ],
        },
        scopeMetrics: [{
          scope:   { name: 'qodiqa-metrics', version: '1.0.0' },
          metrics: otlpMetrics,
        }],
      }],
    };

    const body    = JSON.stringify(payload);
    const headers = { 'Content-Type': 'application/json' };

    let result;
    try {
      result = await httpsPost(endpoint, headers, body);
    } catch (err) {
      err.retryable = true;
      throw err;
    }

    if (result.status === 429 || result.status >= 500) {
      const err = new Error(`OTLP metrics export failed: HTTP ${result.status}`);
      err.retryable = true;
      throw err;
    }

    if (result.status >= 400) {
      const err = new Error(`OTLP metrics export failed: HTTP ${result.status}`);
      err.retryable = false;
      throw err;
    }
  }

  return { exportMetrics, name: 'otlp' };
}

module.exports = { createOtlpMetricsExporter };
