'use strict';

const { createDatadogDestination } = require('../destinations/datadog');

const BASE_CONFIG = {
  datadog: {
    enabled: true,
    valid:   true,
    apiKey:  'dd-test-api-key',
    site:    'datadoghq.com',
  },
};

const SAMPLE_EVENT = {
  timestamp:   '2026-06-24T00:00:00.000Z',
  service:     'qodiqa',
  environment: 'test',
  eventType:   'CERT_COMPLETE',
  severity:    'INFO',
  message:     'Certification completed',
  tenantId:    'tenant-001',
  tenantSlug:  'acme',
  metadata:    {},
};

describe('Datadog destination adapter', () => {
  it('POSTs to the Datadog logs intake endpoint', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 202, body: '{}' });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    expect(httpPost).toHaveBeenCalledWith(
      'https://http-intake.logs.datadoghq.com/api/v2/logs',
      expect.objectContaining({ 'DD-API-KEY': 'dd-test-api-key' }),
      expect.any(String),
    );
  });

  it('uses custom site from config', async () => {
    const config = { datadog: { ...BASE_CONFIG.datadog, site: 'datadoghq.eu' } };
    const httpPost = jest.fn().mockResolvedValue({ status: 202, body: '{}' });
    const dest = createDatadogDestination(config, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const [url] = httpPost.mock.calls[0];
    expect(url).toContain('datadoghq.eu');
  });

  it('sends JSON array body', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 202, body: '{}' });
    });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const parsed = JSON.parse(capturedBody);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(1);
  });

  it('maps severity to Datadog status field', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 202, body: '{}' });
    });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([{ ...SAMPLE_EVENT, severity: 'WARN' }]);

    const [event] = JSON.parse(capturedBody);
    expect(event.status).toBe('warn');
  });

  it('includes tenant tags in ddtags', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 202, body: '{}' });
    });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const [event] = JSON.parse(capturedBody);
    expect(event.ddtags).toContain('tenant_id:tenant-001');
    expect(event.ddtags).toContain('tenant_slug:acme');
  });

  it('throws retryable error on HTTP 429', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 429, body: '' });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('throws non-retryable error on HTTP 403 (invalid API key)', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 403, body: '' });
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: false });
  });

  it('wraps network error as retryable', async () => {
    const httpPost = jest.fn().mockRejectedValue(new Error('ETIMEDOUT'));
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('destination name is "datadog"', () => {
    const dest = createDatadogDestination(BASE_CONFIG, { httpsPost: jest.fn() });
    expect(dest.name).toBe('datadog');
  });
});
