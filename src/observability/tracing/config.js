'use strict';

const { emit } = require('../../../services/logger');

function loadTracingConfig() {
  const enabled = process.env.QODIQA_OTEL_ENABLED === 'true';
  if (!enabled) return Object.freeze({ enabled: false, valid: false });

  const serviceName = (process.env.QODIQA_OTEL_SERVICE_NAME || 'qodiqa').trim();
  const endpoint    = (process.env.QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT || '').trim();
  const environment = (process.env.NODE_ENV || 'development').trim();

  const sampleRate = (() => {
    const v = parseFloat(process.env.QODIQA_OTEL_SAMPLE_RATE);
    return !isNaN(v) && v >= 0 && v <= 1 ? v : 1.0;
  })();

  const maxRetries = (() => {
    const v = parseInt(process.env.QODIQA_OTEL_MAX_RETRIES, 10);
    return Number.isFinite(v) && v >= 0 ? v : 3;
  })();

  const batchSize = (() => {
    const v = parseInt(process.env.QODIQA_OTEL_BATCH_SIZE, 10);
    return Number.isFinite(v) && v > 0 ? v : 100;
  })();

  const flushIntervalMs = (() => {
    const v = parseInt(process.env.QODIQA_OTEL_FLUSH_INTERVAL_MS, 10);
    return Number.isFinite(v) && v >= 0 ? v : 5000;
  })();

  const valid = Boolean(endpoint && endpoint.startsWith('https://'));

  if (!valid) {
    emit('ERROR', 'TRACING_CONFIG_INVALID', {
      message: 'QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT must be a valid HTTPS URL when tracing is enabled',
      hint:    'Example: QODIQA_OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.company.com',
    });
  }

  return Object.freeze({ enabled, valid, serviceName, endpoint, environment, sampleRate, maxRetries, batchSize, flushIntervalMs });
}

module.exports = { loadTracingConfig };
