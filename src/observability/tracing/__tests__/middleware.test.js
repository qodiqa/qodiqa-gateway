'use strict';

const { createRequestTracingMiddleware } = require('../middleware');
const { createTracer }                   = require('../tracer');
const { parseTraceparent }               = require('../context');

function makeTracer(overrides = {}) {
  return createTracer({ sampleRate: 1.0, batchSize: 100, serviceName: 'qodiqa', environment: 'test', ...overrides });
}

function makeReq(overrides = {}) {
  return {
    method:    'GET',
    url:       '/api/test',
    headers:   {},
    requestId: 'req_abc',
    tenantId:  '',
    ...overrides,
  };
}

function makeRes() {
  const handlers = {};
  return {
    statusCode: 200,
    setHeader: jest.fn(),
    on(event, fn) { handlers[event] = fn; },
    _emit(event) { if (handlers[event]) handlers[event](); },
  };
}

// ── Span creation ──────────────────────────────────────────────────────────────

describe('createRequestTracingMiddleware — span creation', () => {
  it('attaches traceId to req', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.traceId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('attaches spanId to req', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.spanId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('attaches rootSpan to req', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.rootSpan).toBeDefined();
    expect(req.rootSpan.name).toBe('HTTP GET');
  });

  it('sets traceparent response header', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(res.setHeader).toHaveBeenCalledWith('traceparent', expect.stringMatching(/^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/));
  });

  it('span name includes HTTP method', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq({ method: 'POST' });
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.rootSpan.name).toBe('HTTP POST');
  });
});

// ── Context propagation ────────────────────────────────────────────────────────

describe('createRequestTracingMiddleware — context propagation', () => {
  it('continues existing trace from valid traceparent header', () => {
    const existingTraceId = '4bf92f3577b34da6a3ce929d0e0e4736';
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq({
      headers: { traceparent: `00-${existingTraceId}-00f067aa0ba902b7-01` },
    });
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.traceId).toBe(existingTraceId);
  });

  it('generates new traceId when no traceparent header', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.traceId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('sets parentSpanId from incoming traceparent', () => {
    const incomingSpanId = '00f067aa0ba902b7';
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq({
      headers: { traceparent: `00-4bf92f3577b34da6a3ce929d0e0e4736-${incomingSpanId}-01` },
    });
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.rootSpan.parentSpanId).toBe(incomingSpanId);
  });

  it('child spans created in next() inherit the request traceId', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    let childTraceId;
    mw(req, res, () => {
      const child = t.startSpan('child');
      childTraceId = child.traceId;
      child.end();
    });
    expect(childTraceId).toBe(req.traceId);
  });
});

// ── Span completion on finish ──────────────────────────────────────────────────

describe('createRequestTracingMiddleware — span lifecycle', () => {
  it('span is not finished before res.finish', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    expect(req.rootSpan.finished).toBe(false);
  });

  it('span is finished after res finish event', () => {
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    mw(req, res, () => {});
    res._emit('finish');
    expect(req.rootSpan.finished).toBe(true);
  });

  it('span has ok status for 2xx responses', () => {
    const { STATUS_OK } = require('../span');
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    res.statusCode = 200;
    mw(req, res, () => {});
    res._emit('finish');
    expect(req.rootSpan.status.code).toBe(STATUS_OK);
  });

  it('span has error status for 5xx responses', () => {
    const { STATUS_ERROR } = require('../span');
    const t   = makeTracer();
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    res.statusCode = 500;
    mw(req, res, () => {});
    res._emit('finish');
    expect(req.rootSpan.status.code).toBe(STATUS_ERROR);
  });
});

// ── Failure isolation ──────────────────────────────────────────────────────────

describe('createRequestTracingMiddleware — failure isolation', () => {
  it('calls next() even if tracer.extract throws', () => {
    const t   = makeTracer();
    t.extract = () => { throw new Error('oops'); };
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    const next = jest.fn();
    mw(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('calls next() even if tracer.startSpan throws', () => {
    const t   = makeTracer();
    t.startSpan = () => { throw new Error('oops'); };
    const mw  = createRequestTracingMiddleware(t);
    const req = makeReq();
    const res = makeRes();
    const next = jest.fn();
    mw(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});

// ── initTracing — integration smoke test ──────────────────────────────────────

describe('initTracing — no-op when disabled', () => {
  it('requestMiddleware calls next() immediately', () => {
    const { initTracing } = require('../index');
    const sys  = initTracing({ enabled: false, valid: false });
    const next = jest.fn();
    sys.requestMiddleware({}, {}, next);
    expect(next).toHaveBeenCalled();
  });

  it('getHealth returns disabled status', () => {
    const { initTracing } = require('../index');
    const sys = initTracing({ enabled: false, valid: false });
    expect(sys.getHealth().status).toBe('disabled');
  });

  it('getMetrics returns zero counts', () => {
    const { initTracing } = require('../index');
    const sys = initTracing({ enabled: false, valid: false });
    expect(sys.getMetrics().spans_created_total).toBe(0);
  });

  it('tracer.startSpan returns a no-op span that does not throw', () => {
    const { initTracing } = require('../index');
    const sys  = initTracing({ enabled: false, valid: false });
    const span = sys.tracer.startSpan('op');
    expect(() => { span.setAttributes({ a: 'b' }); span.end(); }).not.toThrow();
  });
});

describe('initTracing — enabled with mock exporter', () => {
  it('returns a functional tracer', async () => {
    const { initTracing } = require('../index');
    const exporter = { name: 'mock', exportSpans: jest.fn().mockResolvedValue() };
    const sys = initTracing(
      { enabled: true, valid: true, sampleRate: 1.0, batchSize: 100, serviceName: 'qodiqa', environment: 'test' },
      { exporter },
    );
    const span = sys.tracer.startSpan('test-op');
    span.end();
    await sys.shutdown();
    expect(exporter.exportSpans).toHaveBeenCalledTimes(1);
  });
});

// the exported root span never carries query-string VALUES.
describe('http.url in the exported root span', () => {
  const urlOf = (url) => {
    const req = makeReq({ url });
    createRequestTracingMiddleware(makeTracer())(req, makeRes(), () => {});
    const otlp = req.rootSpan.toOtlp();
    const a = otlp.attributes.find((x) => x.key === 'http.url');
    return { value: a && a.value.stringValue, exported: JSON.stringify(otlp) };
  };

  it('a path without a query string is recorded unchanged', () => {
    expect(urlOf('/v1/transparency/roots').value).toBe('/v1/transparency/roots');
  });

  it('query parameter NAMES are kept, every VALUE is redacted, and no value appears anywhere in the exported span', () => {
    const r = urlOf('/v1/transparency/roots?pageSize=pagesizeQXZ&tenantId=acme-secret-tenant&token=sk_live_should_never_leave');
    expect(r.value).toBe('/v1/transparency/roots?pageSize=<redacted>&tenantId=<redacted>&token=<redacted>');
    for (const v of ['pagesizeQXZ', 'acme-secret-tenant', 'sk_live_should_never_leave']) expect(r.exported).not.toContain(v);
  });

  it('edge cases: bare flag, empty query, percent-encoded names, malformed encoding', () => {
    expect(urlOf('/x?debug').value).toBe('/x?debug=<redacted>');
    expect(urlOf('/x?').value).toBe('/x');
    expect(urlOf('/x?a%20b=1').value).toBe('/x?a%20b=<redacted>');
    expect(urlOf('/x?%E0%A4%A=1').value).toBe('/x?%25E0%25A4%25A=<redacted>');
  });
});
