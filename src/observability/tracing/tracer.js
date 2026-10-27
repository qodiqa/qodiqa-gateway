'use strict';

// Core tracer: span creation, context inheritance, batched export.
//
// Design invariants:
//   • startSpan() is synchronous — never blocks the caller.
//   • Finished spans are buffered and exported asynchronously in batches.
//   • Export failures are swallowed — they never propagate to callers.
//   • The sampler decides once per root span; child spans inherit parent's decision.
//   • Unsampled spans are created normally but never enqueued for export.

const {
  generateTraceId,
  generateSpanId,
  parseTraceparent,
  formatTraceparent,
  currentContext,
  runWithContext,
} = require('./context');

const { createSpan, SPAN_KIND_INTERNAL } = require('./span');
const { createSampler }                   = require('./sampler');
const { _NOOP_EXPORTER }                  = require('./exporters/noop');

/**
 * Create a tracer instance.
 *
 * @param {{ sampleRate, batchSize, serviceName, environment }} config
 * @param {{ exporter? }}                                       [deps]
 */
function createTracer(config, deps = {}) {
  const sampler  = createSampler(config.sampleRate);
  const exporter = deps.exporter || _NOOP_EXPORTER;

  const _state = {
    pendingSpans:  [],
    tracesCreated: 0,
    spansCreated:  0,
    exported:      0,
    failed:        0,
    lastExport:    null,
    lastFailure:   null,
  };

  const batchSize = config.batchSize || 100;

  // spans were exported only when `batchSize` accumulated or at shutdown, so a quiet instance held
  // its spans indefinitely. A periodic flush (unref'd — never keeps the process alive) bounds export latency; skipped for the
  // no-op exporter. QODIQA_OTEL_FLUSH_INTERVAL_MS (default 5000, 0 disables).
  const flushIntervalMs = Number.isFinite(config.flushIntervalMs) ? config.flushIntervalMs : 5000;
  let _flushTimer = null;

  // ── Export pipeline ─────────────────────────────────────────────────────────

  async function _flush() {
    if (_state.pendingSpans.length === 0) return;
    const batch = _state.pendingSpans.splice(0, batchSize);
    try {
      await exporter.exportSpans(batch);
      _state.exported  += batch.length;
      _state.lastExport = new Date().toISOString();
    } catch {
      _state.failed      += batch.length;
      _state.lastFailure  = new Date().toISOString();
      // Failure isolation — never rethrow
    }
  }

  function _enqueue(span) {
    if (!span.sampled) return;
    _state.pendingSpans.push(span);
    if (_state.pendingSpans.length >= batchSize) {
      _flush().catch(() => {});
    }
  }

  if (flushIntervalMs > 0 && exporter !== _NOOP_EXPORTER) {
    _flushTimer = setInterval(() => { _flush().catch(() => {}); }, flushIntervalMs);
    if (_flushTimer.unref) _flushTimer.unref();
  }

  // ── Span creation ───────────────────────────────────────────────────────────

  /**
   * Create a new span. Does NOT activate it in the AsyncLocalStorage context.
   * The caller is responsible for ending the span.
   *
   * @param {string} name
   * @param {{ traceId?, parentSpanId?, sampled?, kind?, attributes? }} [opts]
   * @returns {Span}
   */
  function startSpan(name, opts = {}) {
    const ctx = currentContext();

    const traceId = opts.traceId || (ctx && ctx.traceId) || generateTraceId();

    // Root span if no parent and no active context
    const isRootSpan   = !opts.parentSpanId && !ctx;
    const parentSpanId = opts.parentSpanId || (ctx && ctx.spanId) || null;
    const spanId       = generateSpanId();

    // Sampling: inherit from active context, opts, or decide freshly for root spans
    const sampled = opts.sampled !== undefined
      ? opts.sampled
      : (ctx ? ctx.sampled : sampler.shouldSample(traceId));

    _state.spansCreated++;
    if (isRootSpan) _state.tracesCreated++;

    const span = createSpan({
      name, traceId, spanId, parentSpanId, sampled,
      kind:       opts.kind       || SPAN_KIND_INTERNAL,
      attributes: opts.attributes || {},
    });

    // Wrap end() so finished spans are automatically enqueued
    const _origEnd = span.end.bind(span);
    span.end = (endTime) => {
      _origEnd(endTime);
      _enqueue(span);
    };

    return span;
  }

  /**
   * Create a span and make it the active span for the duration of fn.
   * Child spans created inside fn automatically inherit traceId and parentSpanId.
   *
   * @param {string}   name
   * @param {object}   [opts]
   * @param {Function} fn     — receives (span) — responsible for ending the span
   * @returns the return value of fn (may be a Promise)
   */
  function startActiveSpan(name, opts, fn) {
    if (typeof opts === 'function') { fn = opts; opts = {}; }
    const span = startSpan(name, opts);
    const ctx  = { traceId: span.traceId, spanId: span.spanId, sampled: span.sampled, span };
    return runWithContext(ctx, () => fn(span));
  }

  // ── Context accessors ───────────────────────────────────────────────────────

  /** @returns {Span|null} */
  function currentSpan() {
    const ctx = currentContext();
    return ctx ? ctx.span || null : null;
  }

  /**
   * Inject W3C traceparent into a headers object using the active context.
   * Returns headers unchanged if there is no active context.
   */
  function inject(headers) {
    const ctx = currentContext();
    if (!ctx) return headers || {};
    return Object.assign({}, headers || {}, {
      traceparent: formatTraceparent({ traceId: ctx.traceId, spanId: ctx.spanId, sampled: ctx.sampled }),
    });
  }

  /**
   * Extract incoming W3C trace context from request headers.
   * @returns {{ traceId, parentSpanId, sampled }|null}
   */
  function extract(headers) {
    const h = (headers && (headers.traceparent || headers['traceparent'])) || null;
    return parseTraceparent(h);
  }

  // ── Lifecycle ───────────────────────────────────────────────────────────────

  /** Flush all buffered spans. Returns when export completes (or fails silently). */
  async function forceFlush() {
    await _flush();
  }

  /** Flush and release resources. */
  async function shutdown() {
    if (_flushTimer) { clearInterval(_flushTimer); _flushTimer = null; }
    await _flush();
  }

  // ── Observability ───────────────────────────────────────────────────────────

  function getMetrics() {
    return {
      traces_created_total:    _state.tracesCreated,
      spans_created_total:     _state.spansCreated,
      spans_exported_total:    _state.exported,
      spans_failed_total:      _state.failed,
      trace_export_latency_ms: null,
    };
  }

  function getHealth() {
    let status = 'unknown';
    if (_state.lastExport  && !_state.lastFailure)                            status = 'healthy';
    else if (!_state.lastExport  && _state.lastFailure)                       status = 'degraded';
    else if (_state.lastExport   && _state.lastFailure)
      status = _state.lastExport >= _state.lastFailure ? 'healthy' : 'degraded';

    return {
      component:   'opentelemetry',
      status,
      exporter:    exporter.name,
      lastExport:  _state.lastExport,
      lastFailure: _state.lastFailure,
      queuedSpans: _state.pendingSpans.length,
    };
  }

  /** Head-sampling decision for a NEW root trace (audit 4.4: the HTTP middleware used to hard-code `true`). */
  function shouldSample(traceId) { return sampler.shouldSample(traceId); }

  return { startSpan, startActiveSpan, currentSpan, inject, extract, forceFlush, shutdown, getHealth, getMetrics, shouldSample };
}

module.exports = { createTracer };
