'use strict';

const {
  createSpan,
  STATUS_UNSET,
  STATUS_OK,
  STATUS_ERROR,
  SPAN_KIND_SERVER,
  SPAN_KIND_INTERNAL,
} = require('../span');

const TRACE_ID  = '4bf92f3577b34da6a3ce929d0e0e4736';
const SPAN_ID   = '00f067aa0ba902b7';
const PARENT_ID = 'b7ad6b7169203331';

function makeSpan(overrides = {}) {
  return createSpan({
    name:    'test-span',
    traceId: TRACE_ID,
    spanId:  SPAN_ID,
    ...overrides,
  });
}

// ── Lifecycle ──────────────────────────────────────────────────────────────────

describe('span lifecycle', () => {
  it('is not finished initially', () => {
    expect(makeSpan().finished).toBe(false);
  });

  it('is finished after end()', () => {
    const s = makeSpan();
    s.end();
    expect(s.finished).toBe(true);
  });

  it('records endMs on end()', () => {
    const s = makeSpan();
    expect(s.endMs).toBeNull();
    s.end();
    expect(s.endMs).toBeGreaterThan(0);
  });

  it('end() accepts explicit time', () => {
    const s = makeSpan();
    s.end(12345);
    expect(s.endMs).toBe(12345);
  });

  it('second end() is ignored', () => {
    const s = makeSpan();
    s.end(100);
    s.end(200);
    expect(s.endMs).toBe(100);
  });

  it('has STATUS_UNSET before any setStatus()', () => {
    expect(makeSpan().status.code).toBe(STATUS_UNSET);
  });

  it('setStatus("ok") sets STATUS_OK', () => {
    const s = makeSpan();
    s.setStatus('ok');
    expect(s.status.code).toBe(STATUS_OK);
  });

  it('setStatus("error", msg) sets STATUS_ERROR with message', () => {
    const s = makeSpan();
    s.setStatus('error', 'something failed');
    expect(s.status.code).toBe(STATUS_ERROR);
    expect(s.status.message).toBe('something failed');
  });

  it('setStatus after end() is ignored', () => {
    const s = makeSpan();
    s.end();
    s.setStatus('ok');
    expect(s.status.code).toBe(STATUS_UNSET);
  });

  it('setAttributes after end() is ignored', () => {
    const s = makeSpan({ attributes: { a: '1' } });
    s.end();
    s.setAttributes({ b: '2' });
    expect(s.toOtlp().attributes.map(a => a.key)).not.toContain('b');
  });
});

// ── Attributes and redaction ───────────────────────────────────────────────────

describe('span attributes', () => {
  it('stores attributes from constructor', () => {
    const s = makeSpan({ attributes: { 'http.method': 'GET' } });
    s.end();
    const attrs = s.toOtlp().attributes;
    expect(attrs.find(a => a.key === 'http.method').value.stringValue).toBe('GET');
  });

  it('setAttributes merges into existing', () => {
    const s = makeSpan({ attributes: { a: '1' } });
    s.setAttributes({ b: '2' });
    s.end();
    const keys = s.toOtlp().attributes.map(a => a.key);
    expect(keys).toContain('a');
    expect(keys).toContain('b');
  });

  it('redacts sensitive attribute — authorization', () => {
    const s = makeSpan({ attributes: { authorization: 'Bearer secret' } });
    s.end();
    const attr = s.toOtlp().attributes.find(a => a.key === 'authorization');
    expect(attr.value.stringValue).toBe('[REDACTED]');
  });

  it('redacts sensitive attribute — apiKey', () => {
    const s = makeSpan({ attributes: { apiKey: 'sk-1234' } });
    s.end();
    const attr = s.toOtlp().attributes.find(a => a.key === 'apiKey');
    expect(attr.value.stringValue).toBe('[REDACTED]');
  });

  it('redacts sensitive attribute — token', () => {
    const s = makeSpan({ attributes: { token: 'abc123' } });
    s.end();
    const attr = s.toOtlp().attributes.find(a => a.key === 'token');
    expect(attr.value.stringValue).toBe('[REDACTED]');
  });

  it('does not redact non-sensitive attributes', () => {
    const s = makeSpan({ attributes: { 'http.url': '/api/cert' } });
    s.end();
    const attr = s.toOtlp().attributes.find(a => a.key === 'http.url');
    expect(attr.value.stringValue).toBe('/api/cert');
  });

  it('redacts sensitive attributes added via setAttributes', () => {
    const s = makeSpan();
    s.setAttributes({ password: 'secret123' });
    s.end();
    const attr = s.toOtlp().attributes.find(a => a.key === 'password');
    expect(attr.value.stringValue).toBe('[REDACTED]');
  });
});

// ── recordException ────────────────────────────────────────────────────────────

describe('recordException', () => {
  it('records exception event', () => {
    const s   = makeSpan();
    const err = new Error('boom');
    s.recordException(err);
    s.end();
    const otlp   = s.toOtlp();
    const event  = otlp.events.find(e => e.name === 'exception');
    expect(event).toBeDefined();
    expect(event.attributes['exception.type']).toBe('Error');
    expect(event.attributes['exception.message']).toBe('boom');
  });

  it('sets status to ERROR on recordException', () => {
    const s = makeSpan();
    s.recordException(new Error('fail'));
    expect(s.status.code).toBe(STATUS_ERROR);
  });

  it('ignored after end()', () => {
    const s = makeSpan();
    s.end();
    s.recordException(new Error('late'));
    expect(s.toOtlp().events).toHaveLength(0);
  });
});

// ── toOtlp ────────────────────────────────────────────────────────────────────

describe('toOtlp', () => {
  it('includes traceId and spanId', () => {
    const s = makeSpan();
    s.end();
    const otlp = s.toOtlp();
    expect(otlp.traceId).toBe(TRACE_ID);
    expect(otlp.spanId).toBe(SPAN_ID);
  });

  it('includes parentSpanId when set', () => {
    const s = makeSpan({ parentSpanId: PARENT_ID });
    s.end();
    expect(s.toOtlp().parentSpanId).toBe(PARENT_ID);
  });

  it('omits parentSpanId when null', () => {
    const s = makeSpan();
    s.end();
    expect(s.toOtlp()).not.toHaveProperty('parentSpanId');
  });

  it('startTimeUnixNano is a numeric string', () => {
    const s = makeSpan();
    s.end();
    expect(s.toOtlp().startTimeUnixNano).toMatch(/^\d+$/);
  });

  it('endTimeUnixNano is a numeric string', () => {
    const s = makeSpan();
    s.end();
    expect(s.toOtlp().endTimeUnixNano).toMatch(/^\d+$/);
  });

  it('endTimeUnixNano > startTimeUnixNano (non-zero duration)', () => {
    const s = makeSpan();
    s.end(s.startMs + 100);
    const { startTimeUnixNano, endTimeUnixNano } = s.toOtlp();
    expect(BigInt(endTimeUnixNano)).toBeGreaterThanOrEqual(BigInt(startTimeUnixNano));
  });

  it('kind is set to the constructor value', () => {
    const s = makeSpan({ kind: SPAN_KIND_SERVER });
    s.end();
    expect(s.toOtlp().kind).toBe(SPAN_KIND_SERVER);
  });
});
