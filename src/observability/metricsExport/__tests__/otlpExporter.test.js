'use strict';

const { createOtlpMetricsExporter } = require('../otlpExporter');

const BASE_CONFIG = {
  endpoint:    'https://otel.company.com',
  serviceName: 'qodiqa',
  environment: 'test',
};

function makeCounter(value, labels) {
  return {
    toOtlpMetric: (startNano, nowNano) => ({
      name: 'qodiqa_test_total',
      description: 'test counter',
      unit: '',
      sum: {
        dataPoints: [{ attributes: [], startTimeUnixNano: startNano, timeUnixNano: nowNano, asDouble: value }],
        aggregationTemporality: 2,
        isMonotonic: true,
      },
    }),
  };
}

describe('createOtlpMetricsExporter — HTTP POST', () => {
  it('POSTs to /v1/metrics under the configured endpoint', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const [url] = httpPost.mock.calls[0];
    expect(url).toBe('https://otel.company.com/v1/metrics');
  });

  it('strips trailing slash from endpoint before appending path', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter({ ...BASE_CONFIG, endpoint: 'https://otel.company.com/' }, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const [url] = httpPost.mock.calls[0];
    expect(url).not.toContain('//v1');
    expect(url).toBe('https://otel.company.com/v1/metrics');
  });

  it('sends Content-Type: application/json', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const [, headers] = httpPost.mock.calls[0];
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('does nothing (no HTTP call) when called with an empty array', async () => {
    const httpPost = jest.fn();
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics([]);
    expect(httpPost).not.toHaveBeenCalled();
  });

  it('does nothing when called with undefined', async () => {
    const httpPost = jest.fn();
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics(undefined);
    expect(httpPost).not.toHaveBeenCalled();
  });

  it('wraps metrics in resourceMetrics/scopeMetrics OTLP envelope', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const [, , body] = httpPost.mock.calls[0];
    const payload = JSON.parse(body);
    expect(payload.resourceMetrics).toHaveLength(1);
    expect(payload.resourceMetrics[0].scopeMetrics).toHaveLength(1);
    expect(payload.resourceMetrics[0].scopeMetrics[0].metrics).toHaveLength(1);
    expect(payload.resourceMetrics[0].scopeMetrics[0].metrics[0].name).toBe('qodiqa_test_total');
  });

  it('includes service.name in resource attributes', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter({ ...BASE_CONFIG, serviceName: 'my-svc' }, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const payload = JSON.parse(httpPost.mock.calls[0][2]);
    const attr = payload.resourceMetrics[0].resource.attributes.find(a => a.key === 'service.name');
    expect(attr.value.stringValue).toBe('my-svc');
  });

  it('includes deployment.environment in resource attributes', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter({ ...BASE_CONFIG, environment: 'production' }, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1)]);
    const payload = JSON.parse(httpPost.mock.calls[0][2]);
    const attr = payload.resourceMetrics[0].resource.attributes.find(a => a.key === 'deployment.environment');
    expect(attr.value.stringValue).toBe('production');
  });

  it('exports all metric instances passed in one batch', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await exp.exportMetrics([makeCounter(1), makeCounter(2), makeCounter(3)]);
    const payload = JSON.parse(httpPost.mock.calls[0][2]);
    expect(payload.resourceMetrics[0].scopeMetrics[0].metrics).toHaveLength(3);
  });

  it('a metric instance whose toOtlpMetric() throws is skipped, not fatal to the batch', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    const broken = { toOtlpMetric: () => { throw new Error('boom'); } };
    await expect(exp.exportMetrics([makeCounter(1), broken, makeCounter(2)])).resolves.toBeUndefined();
    const payload = JSON.parse(httpPost.mock.calls[0][2]);
    expect(payload.resourceMetrics[0].scopeMetrics[0].metrics).toHaveLength(2);
  });

  it('a metric instance missing toOtlpMetric() entirely is skipped, not fatal', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1), {}])).resolves.toBeUndefined();
    const payload = JSON.parse(httpPost.mock.calls[0][2]);
    expect(payload.resourceMetrics[0].scopeMetrics[0].metrics).toHaveLength(1);
  });

  it('exporter name is "otlp"', () => {
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: jest.fn() });
    expect(exp.name).toBe('otlp');
  });
});

describe('createOtlpMetricsExporter — error classification', () => {
  it('throws retryable error on HTTP 503', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 503, body: '' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).rejects.toMatchObject({ retryable: true });
  });

  it('throws retryable error on HTTP 429', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 429, body: '' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).rejects.toMatchObject({ retryable: true });
  });

  it('throws non-retryable error on HTTP 400', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 400, body: '' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).rejects.toMatchObject({ retryable: false });
  });

  it('throws non-retryable error on HTTP 401', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 401, body: '' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).rejects.toMatchObject({ retryable: false });
  });

  it('wraps network error as retryable', async () => {
    const httpPost = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).rejects.toMatchObject({ retryable: true });
  });

  it('resolves without throwing on HTTP 200', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '' });
    const exp = createOtlpMetricsExporter(BASE_CONFIG, { httpsPost: httpPost });
    await expect(exp.exportMetrics([makeCounter(1)])).resolves.toBeUndefined();
  });
});
