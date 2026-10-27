'use strict';

const { loadTracingConfig }            = require('./config');
const { createTracer }                  = require('./tracer');
const { createOtlpExporter }            = require('./exporters/otlp');
const { createRequestTracingMiddleware } = require('./middleware');

// ── No-op span ────────────────────────────────────────────────────────────────

function _noopSpan() {
  return {
    name: '', traceId: '', spanId: '', parentSpanId: null, sampled: false,
    get startMs()  { return 0; },
    get endMs()    { return null; },
    get status()   { return { code: 0 }; },
    get finished() { return false; },
    setAttributes() {},
    setStatus()    {},
    recordException() {},
    end()          {},
    toOtlp()       { return {}; },
  };
}

const _NOOP_METRICS = Object.freeze({
  traces_created_total:    0,
  spans_created_total:     0,
  spans_exported_total:    0,
  spans_failed_total:      0,
  trace_export_latency_ms: null,
});

const _NOOP_HEALTH = Object.freeze({
  component:   'opentelemetry',
  status:      'disabled',
  exporter:    'noop',
  lastExport:  null,
  lastFailure: null,
  queuedSpans: 0,
});

const _NOOP = Object.freeze({
  tracer: Object.freeze({
    startSpan:       () => _noopSpan(),
    startActiveSpan: (name, opts, fn) => {
      if (typeof opts === 'function') { fn = opts; }
      return fn(_noopSpan());
    },
    currentSpan:  () => null,
    inject:       (h) => h || {},
    extract:      () => null,
    forceFlush:   async () => {},
    shutdown:     async () => {},
    getHealth:    () => Object.assign({}, _NOOP_HEALTH),
    getMetrics:   () => Object.assign({}, _NOOP_METRICS),
  }),
  requestMiddleware: (req, res, next) => next(),
  getHealth:  () => Object.assign({}, _NOOP_HEALTH),
  getMetrics: () => Object.assign({}, _NOOP_METRICS),
  shutdown:   async () => {},
});

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Initialise the tracing subsystem.
 *
 * Returns a no-op subsystem when tracing is disabled or misconfigured,
 * so callers never need to guard on the return value.
 *
 * @param {object}  [config]          — result of loadTracingConfig(); loaded from env if omitted
 * @param {object}  [deps]
 * @param {object}  [deps.exporter]   — override the OTLP exporter (for testing)
 * @param {Function}[deps.httpsPost]  — override the HTTP transport (for testing)
 * @returns {{ tracer, requestMiddleware, getHealth, getMetrics, shutdown }}
 */
function initTracing(config, deps = {}) {
  if (!config) config = loadTracingConfig();
  if (!config.enabled || !config.valid) return _NOOP;

  const exporter  = deps.exporter || createOtlpExporter(config, { httpsPost: deps.httpsPost });
  const tracer    = createTracer(config, { exporter });
  const requestMiddleware = createRequestTracingMiddleware(tracer);

  return {
    tracer,
    requestMiddleware,
    getHealth:  () => tracer.getHealth(),
    getMetrics: () => tracer.getMetrics(),
    shutdown:   () => tracer.shutdown(),
  };
}

module.exports = { initTracing, loadTracingConfig };
