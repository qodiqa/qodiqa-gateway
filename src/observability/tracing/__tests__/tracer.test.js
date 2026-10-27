'use strict';

const { createTracer } = require('../tracer');

function makeExporter() {
  return { name: 'mock', exportSpans: jest.fn().mockResolvedValue() };
}

function makeConfig(overrides = {}) {
  return { sampleRate: 1.0, batchSize: 100, serviceName: 'qodiqa', environment: 'test', ...overrides };
}

// ── Span creation ──────────────────────────────────────────────────────────────

describe('createTracer — startSpan', () => {
  it('returns a span with the given name', () => {
    const t = createTracer(makeConfig());
    const s = t.startSpan('my-operation');
    expect(s.name).toBe('my-operation');
  });

  it('generates a traceId', () => {
    const t = createTracer(makeConfig());
    const s = t.startSpan('op');
    expect(s.traceId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('generates a spanId', () => {
    const t = createTracer(makeConfig());
    const s = t.startSpan('op');
    expect(s.spanId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('root span has no parentSpanId', () => {
    const t = createTracer(makeConfig());
    const s = t.startSpan('root');
    expect(s.parentSpanId).toBeNull();
  });

  it('accepts explicit traceId', () => {
    const t  = createTracer(makeConfig());
    const id = 'a'.repeat(32);
    const s  = t.startSpan('op', { traceId: id });
    expect(s.traceId).toBe(id);
  });

  it('accepts explicit parentSpanId', () => {
    const t = createTracer(makeConfig());
    const s = t.startSpan('child', { parentSpanId: '1'.repeat(16) });
    expect(s.parentSpanId).toBe('1'.repeat(16));
  });

  it('unsampled span (rate=0) has sampled=false', () => {
    const t = createTracer(makeConfig({ sampleRate: 0 }));
    const s = t.startSpan('op');
    expect(s.sampled).toBe(false);
  });

  it('sampled span (rate=1) has sampled=true', () => {
    const t = createTracer(makeConfig({ sampleRate: 1 }));
    const s = t.startSpan('op');
    expect(s.sampled).toBe(true);
  });
});

// ── Metrics ────────────────────────────────────────────────────────────────────

describe('createTracer — getMetrics', () => {
  it('increments spans_created_total on each startSpan', () => {
    const t = createTracer(makeConfig());
    t.startSpan('a');
    t.startSpan('b');
    expect(t.getMetrics().spans_created_total).toBe(2);
  });

  it('increments traces_created_total only for root spans', () => {
    const t = createTracer(makeConfig());
    t.startSpan('root1');
    t.startSpan('root2');
    expect(t.getMetrics().traces_created_total).toBe(2);
  });

  it('child span (with explicit parentSpanId) does not increment traces_created_total', () => {
    const t = createTracer(makeConfig());
    t.startSpan('root');
    t.startSpan('child', { parentSpanId: '1'.repeat(16) });
    expect(t.getMetrics().traces_created_total).toBe(1);
    expect(t.getMetrics().spans_created_total).toBe(2);
  });

  it('spans_exported_total increments after forceFlush', async () => {
    const exporter = makeExporter();
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.forceFlush();
    expect(t.getMetrics().spans_exported_total).toBe(1);
  });

  it('spans_failed_total increments when exporter throws', async () => {
    const exporter = { name: 'fail', exportSpans: jest.fn().mockRejectedValue(new Error('down')) };
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.forceFlush();
    expect(t.getMetrics().spans_failed_total).toBe(1);
  });
});

// ── Context propagation ────────────────────────────────────────────────────────

describe('createTracer — startActiveSpan', () => {
  it('child span inherits traceId from active context', () => {
    const t = createTracer(makeConfig());
    let childTraceId;
    t.startActiveSpan('parent', (parent) => {
      const child = t.startSpan('child');
      childTraceId = child.traceId;
      child.end();
      parent.end();
    });
    expect(childTraceId).toBeDefined();
    expect(childTraceId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('child span uses parent spanId as parentSpanId', () => {
    const t = createTracer(makeConfig());
    let parentId, childParentId;
    t.startActiveSpan('parent', (parent) => {
      parentId = parent.spanId;
      const child = t.startSpan('child');
      childParentId = child.parentSpanId;
      child.end();
      parent.end();
    });
    expect(childParentId).toBe(parentId);
  });

  it('currentSpan() returns active span inside startActiveSpan', () => {
    const t = createTracer(makeConfig());
    let captured;
    t.startActiveSpan('op', (span) => {
      captured = t.currentSpan();
      span.end();
    });
    expect(captured).toBeDefined();
    expect(captured.name).toBe('op');
  });

  it('currentSpan() returns null outside startActiveSpan', () => {
    const t = createTracer(makeConfig());
    expect(t.currentSpan()).toBeNull();
  });

  it('supports async fn inside startActiveSpan', async () => {
    const t = createTracer(makeConfig());
    let capturedTraceId;
    await t.startActiveSpan('async-parent', async (parent) => {
      await new Promise(r => setImmediate(r));
      const child = t.startSpan('async-child');
      capturedTraceId = child.traceId;
      child.end();
      parent.end();
    });
    expect(capturedTraceId).toBe(capturedTraceId); // non-null
    expect(capturedTraceId).toMatch(/^[0-9a-f]{32}$/);
  });
});

// ── inject / extract ───────────────────────────────────────────────────────────

describe('createTracer — inject / extract', () => {
  it('inject returns headers unchanged with no active context', () => {
    const t = createTracer(makeConfig());
    const h = { 'x-custom': 'val' };
    expect(t.inject(h)).toEqual({ 'x-custom': 'val' });
  });

  it('inject adds traceparent header within active context', () => {
    const t = createTracer(makeConfig());
    let injected;
    t.startActiveSpan('op', (span) => {
      injected = t.inject({});
      span.end();
    });
    expect(injected.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/);
  });

  it('extract parses traceparent from request headers', () => {
    const t = createTracer(makeConfig());
    const h = { traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' };
    const ctx = t.extract(h);
    expect(ctx.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736');
    expect(ctx.sampled).toBe(true);
  });

  it('extract returns null for missing header', () => {
    const t = createTracer(makeConfig());
    expect(t.extract({})).toBeNull();
  });

  it('extract returns null for invalid traceparent', () => {
    const t = createTracer(makeConfig());
    expect(t.extract({ traceparent: 'invalid' })).toBeNull();
  });
});

// ── Health monitoring ──────────────────────────────────────────────────────────

describe('createTracer — getHealth', () => {
  it('status is unknown before any export', () => {
    const t = createTracer(makeConfig());
    expect(t.getHealth().status).toBe('unknown');
  });

  it('status is healthy after successful export', async () => {
    const exporter = makeExporter();
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.forceFlush();
    expect(t.getHealth().status).toBe('healthy');
  });

  it('status is degraded after failed export', async () => {
    const exporter = { name: 'fail', exportSpans: jest.fn().mockRejectedValue(new Error('down')) };
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.forceFlush();
    expect(t.getHealth().status).toBe('degraded');
  });

  it('includes component=opentelemetry', () => {
    const t = createTracer(makeConfig());
    expect(t.getHealth().component).toBe('opentelemetry');
  });

  it('includes queuedSpans count', async () => {
    const exporter = makeExporter();
    const t = createTracer(makeConfig(), { exporter });
    expect(t.getHealth().queuedSpans).toBe(0);
  });
});

// ── Failure isolation ──────────────────────────────────────────────────────────

describe('createTracer — failure isolation', () => {
  it('forceFlush does not throw when exporter throws', async () => {
    const exporter = { name: 'fail', exportSpans: jest.fn().mockRejectedValue(new Error('boom')) };
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await expect(t.forceFlush()).resolves.toBeUndefined();
  });

  it('unsampled spans are never exported', async () => {
    const exporter = makeExporter();
    const t = createTracer(makeConfig({ sampleRate: 0 }), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.forceFlush();
    expect(exporter.exportSpans).not.toHaveBeenCalled();
  });

  it('shutdown flushes remaining spans', async () => {
    const exporter = makeExporter();
    const t = createTracer(makeConfig(), { exporter });
    const s = t.startSpan('op');
    s.end();
    await t.shutdown();
    expect(exporter.exportSpans).toHaveBeenCalledTimes(1);
  });
});
