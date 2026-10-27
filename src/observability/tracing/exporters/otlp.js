'use strict';

// OTLP HTTP exporter — ships finished spans to an OpenTelemetry Collector or
// compatible endpoint using the OTLP/HTTP JSON format.
//
// POST /v1/traces  →  Content-Type: application/json
// Body: OTLP ResourceSpans JSON (protobuf JSON mapping, hex IDs)
//
// Error classification (same policy as log shipping destinations):
//   Retryable:     429, 502, 503, 504, network errors
//   Non-retryable: 400, 401, 403, other 4xx

const { httpsPost: defaultHttpsPost } = require('../../logShipping/_transport');

/**
 * Create an OTLP HTTP exporter.
 *
 * @param {{ endpoint, serviceName, environment }} config
 * @param {{ httpsPost? }}                         [deps]
 */
function createOtlpExporter(config, { httpsPost = defaultHttpsPost } = {}) {
  const endpoint = config.endpoint.replace(/\/$/, '') + '/v1/traces';

  /**
   * Export an array of finished Span objects.
   * Throws (retryable or non-retryable) on HTTP error.
   * Throws retryable on network error.
   *
   * @param {Span[]} spans
   */
  async function exportSpans(spans) {
    if (!spans || spans.length === 0) return;

    const payload = {
      resourceSpans: [{
        resource: {
          attributes: [
            { key: 'service.name',            value: { stringValue: config.serviceName  || 'qodiqa'      } },
            { key: 'deployment.environment',  value: { stringValue: config.environment  || 'development' } },
          ],
        },
        scopeSpans: [{
          scope:  { name: 'qodiqa-tracer', version: '1.0.0' },
          spans:  spans.map(s => s.toOtlp()),
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
      const err = new Error(`OTLP export failed: HTTP ${result.status}`);
      err.retryable = true;
      throw err;
    }

    if (result.status >= 400) {
      const err = new Error(`OTLP export failed: HTTP ${result.status}`);
      err.retryable = false;
      throw err;
    }
  }

  return { exportSpans, name: 'otlp' };
}

module.exports = { createOtlpExporter };
