'use strict';

// Express middleware that creates a root server span for every inbound request.
//
// Behaviour:
//   1. If the request carries a valid W3C traceparent header, the existing trace
//      is continued (traceId preserved, parentSpanId set to the incoming spanId).
//   2. Otherwise a new traceId is generated.
//   3. The span is activated in AsyncLocalStorage so that any code downstream
//      (route handlers, service calls) can create child spans without explicit
//      context passing.
//   4. req.traceId, req.spanId, and req.rootSpan are attached for downstream use.
//   5. A traceparent response header is set so clients can correlate requests.
//   6. The span is ended on res 'finish' — never throws.

const { generateTraceId, formatTraceparent, runWithContext } = require('./context');
const { createSpan, SPAN_KIND_SERVER }                        = require('./span');

/**
 * @param {ReturnType<import('./tracer').createTracer>} tracer
 * @returns {Function} Express middleware
 */
// the root span used to carry the RAW request URL, query string included, so an
// enabled OTLP exporter shipped query VALUES (identifiers, filters, anything a client puts there) to the tracing
// backend. The span now records the path plus the query parameter NAMES only, each value replaced by "<redacted>".
// The default exporter is noop, so nothing left the process before either; this closes it for an enabled exporter.
function safeHttpUrl(url) {
  if (typeof url !== 'string' || url === '') return '';
  const q = url.indexOf('?');
  if (q < 0) return url;
  const names = url.slice(q + 1).split('&').filter(Boolean).map((kv) => {
    const name = kv.split('=')[0];
    let decoded = name; try { decoded = decodeURIComponent(name); } catch { /* keep as sent */ }
    return `${encodeURIComponent(decoded)}=<redacted>`;
  });
  return names.length ? `${url.slice(0, q)}?${names.join('&')}` : url.slice(0, q);
}

function createRequestTracingMiddleware(tracer) {
  return function tracingMiddleware(req, res, next) {
    try {
      const incoming     = tracer.extract(req.headers);
      const traceId      = incoming ? incoming.traceId      : generateTraceId();
      const parentSpanId = incoming ? incoming.parentSpanId : null;

      // Propagate sampling decision from upstream; default to true for root spans
      // a ROOT request is sampled according to QODIQA_OTEL_SAMPLE_RATE (was hard-coded `true`, so a rate of 0
      // still exported every HTTP span); an upstream decision (traceparent flags) is still honoured.
      const sampled = incoming !== null ? incoming.sampled : (typeof tracer.shouldSample === 'function' ? tracer.shouldSample(traceId) : true);

      const span = tracer.startSpan(`HTTP ${req.method}`, {
        traceId,
        parentSpanId,
        sampled,
        kind: SPAN_KIND_SERVER,
        attributes: {
          'http.method':         req.method  || '',
          'http.url':            safeHttpUrl(req.url),
          'http.host':           (req.headers && (req.headers.host || '')) || '',
          'qodiqa.request_id':   req.requestId || '',
          'qodiqa.tenant_id':    req.tenantId  || '',
        },
      });

      req.traceId  = span.traceId;
      req.spanId   = span.spanId;
      req.rootSpan = span;

      res.setHeader('traceparent', formatTraceparent({ traceId: span.traceId, spanId: span.spanId, sampled }));

      res.on('finish', () => {
        try {
          span.setAttributes({ 'http.status_code': String(res.statusCode) });
          if (res.statusCode >= 500) span.setStatus('error', `HTTP ${res.statusCode}`);
          else                       span.setStatus('ok');
          span.end();
        } catch { /* failure isolation */ }
      });

      const ctx = { traceId: span.traceId, spanId: span.spanId, sampled, span };
      runWithContext(ctx, next);
    } catch {
      // Tracing must never break the request — fall through unconditionally
      next();
    }
  };
}

module.exports = { createRequestTracingMiddleware };
