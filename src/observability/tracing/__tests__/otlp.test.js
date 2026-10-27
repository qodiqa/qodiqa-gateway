'use strict';

const { createOtlpExporter } = require('../exporters/otlp');
const { createSpan }          = require('../span');

const BASE_CONFIG = {
  endpoint:    'https://otel.company.com',
  serviceName: 'qodiqa',
  environment: 'test',
};

function makeFinishedSpan(overrides = {}) {
  const span = createSpan({
    name:    'test-op',
    traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
    spanId:  '00f067aa0ba902b7',
    ...overrides,
  });
  span.end();
  return span;
}

// ── HTTP request ───────────────────────────────────────────────────────────────

describe('createOtlpExporter — HTTP POST', () => {
  it('POSTs to /v1/traces under the configured endpoint', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);
    const [url] = httpPost.mock.calls[0];
    expect(url).toBe('https://otel.company.com/v1/traces');
  });

  it('strips trailing slash from endpoint before appending path', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpExporter({ ...BASE_CONFIG, endpoint: 'https://otel.company.com/' }, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);
    const [url] = httpPost.mock.calls[0];
    expect(url).not.toContain('//v1');
    expect(url).toBe('https://otel.company.com/v1/traces');
  });

  it('sends Content-Type: application/json', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);
    const [, headers] = httpPost.mock.calls[0];
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('does nothing when called with empty array', async () => {
    const httpPost = jest.fn();
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([]);
    expect(httpPost).not.toHaveBeenCalled();
  });
});

// ── Payload format ─────────────────────────────────────────────────────────────

describe('createOtlpExporter — OTLP JSON payload', () => {
  it('wraps spans in resourceSpans/scopeSpans OTLP envelope', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);

    const payload = JSON.parse(capturedBody);
    expect(payload).toHaveProperty('resourceSpans');
    expect(Array.isArray(payload.resourceSpans)).toBe(true);
    expect(payload.resourceSpans[0]).toHaveProperty('scopeSpans');
    expect(payload.resourceSpans[0].scopeSpans[0]).toHaveProperty('spans');
  });

  it('includes service.name in resource attributes', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);

    const payload = JSON.parse(capturedBody);
    const resourceAttrs = payload.resourceSpans[0].resource.attributes;
    const svcAttr = resourceAttrs.find(a => a.key === 'service.name');
    expect(svcAttr.value.stringValue).toBe('qodiqa');
  });

  it('includes deployment.environment in resource attributes', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan()]);

    const payload = JSON.parse(capturedBody);
    const resourceAttrs = payload.resourceSpans[0].resource.attributes;
    const envAttr = resourceAttrs.find(a => a.key === 'deployment.environment');
    expect(envAttr.value.stringValue).toBe('test');
  });

  it('exports all spans in the batch', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportSpans([makeFinishedSpan(), makeFinishedSpan()]);

    const payload = JSON.parse(capturedBody);
    expect(payload.resourceSpans[0].scopeSpans[0].spans).toHaveLength(2);
  });

  it('exporter name is "otlp"', () => {
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: jest.fn() });
    expect(exp.name).toBe('otlp');
  });
});

// ── Error handling ─────────────────────────────────────────────────────────────

describe('createOtlpExporter — error handling', () => {
  it('throws retryable error on HTTP 503', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 503, body: '' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).rejects.toMatchObject({ retryable: true });
  });

  it('throws retryable error on HTTP 429', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 429, body: '' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).rejects.toMatchObject({ retryable: true });
  });

  it('throws non-retryable error on HTTP 400', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 400, body: '' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).rejects.toMatchObject({ retryable: false });
  });

  it('throws non-retryable error on HTTP 401', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 401, body: '' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).rejects.toMatchObject({ retryable: false });
  });

  it('wraps network error as retryable', async () => {
    const httpPost = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).rejects.toMatchObject({ retryable: true });
  });

  it('resolves without throwing on HTTP 200', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportSpans([makeFinishedSpan()])).resolves.toBeUndefined();
  });
});
