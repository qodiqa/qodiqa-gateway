'use strict';

const { createSplunkDestination } = require('../destinations/splunk');

const BASE_CONFIG = {
  splunk: {
    enabled: true,
    valid:   true,
    url:     'https://splunk.company.com:8088',
    token:   'splunk-hec-token',
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
  metadata:    {},
};

describe('Splunk HEC destination adapter', () => {
  it('POSTs to the Splunk HEC /services/collector/event endpoint', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const [url] = httpPost.mock.calls[0];
    expect(url).toBe('https://splunk.company.com:8088/services/collector/event');
  });

  it('sends Authorization: Splunk <token> header', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const [, headers] = httpPost.mock.calls[0];
    expect(headers['Authorization']).toBe('Splunk splunk-hec-token');
  });

  it('strips trailing slash from base URL', async () => {
    const config = { splunk: { ...BASE_CONFIG.splunk, url: 'https://splunk.company.com:8088/' } };
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '{}' });
    const dest = createSplunkDestination(config, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const [url] = httpPost.mock.calls[0];
    expect(url).not.toContain('//services');
  });

  it('sends HEC-formatted NDJSON body', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const parsed = JSON.parse(capturedBody);
    expect(parsed).toHaveProperty('time');
    expect(parsed).toHaveProperty('event');
    expect(parsed).toHaveProperty('sourcetype', '_json');
  });

  it('sets HEC time as Unix epoch seconds', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const { time } = JSON.parse(capturedBody);
    expect(typeof time).toBe('number');
    expect(time).toBe(Math.floor(new Date(SAMPLE_EVENT.timestamp).getTime() / 1000));
  });

  it('sends multiple events as newline-delimited HEC objects', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT, { ...SAMPLE_EVENT, eventType: 'CERT_STARTED' }]);

    const lines = capturedBody.split('\n');
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it('throws retryable error on HTTP 503', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 503, body: '' });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('throws non-retryable error on HTTP 401 (invalid token)', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 401, body: '' });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: false });
  });

  it('wraps network error as retryable', async () => {
    const httpPost = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('destination name is "splunk"', () => {
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: jest.fn() });
    expect(dest.name).toBe('splunk');
  });
});

// ── #6: schema='cim' ───────────────────────────────────────────────────

describe('Splunk HEC destination adapter — schema="cim"', () => {
  const CIM_CONFIG = { splunk: { ...BASE_CONFIG.splunk, schema: 'cim' } };

  it('is backward compatible by default — omitting schema still sends the raw event and sourcetype "_json"', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = createSplunkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const parsed = JSON.parse(capturedBody);
    expect(parsed.sourcetype).toBe('_json');
    expect(parsed.event).toMatchObject({ eventType: 'CERT_COMPLETE' });
  });

  it('maps each event to CIM (Alerts model) shape and sourcetype "qodiqa:cim" when schema="cim"', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = createSplunkDestination(CIM_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const parsed = JSON.parse(capturedBody);
    expect(parsed.sourcetype).toBe('qodiqa:cim');
    expect(parsed.event).toMatchObject({
      signature: 'CERT_COMPLETE',
      severity:  'informational',
      tenant:    'tenant-001',
      vendor_product: 'QODIQA Platform',
    });
  });

  it('a mapping-function failure falls back to the raw event and increments the mapping-error metric, never breaking delivery', async () => {
    jest.resetModules();
    jest.doMock('../../siem/cimMapper', () => ({
      mapToCim: jest.fn(() => { throw new Error('mapping exploded'); }),
    }));
    const mockInc = jest.fn();
    jest.doMock('../../metrics', () => ({
      logShipSchemaMappingErrorsTotal: { inc: mockInc },
    }));
    const { createSplunkDestination: freshCreate } = require('../destinations/splunk');

    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_u, _h, b) => {
      capturedBody = b;
      return Promise.resolve({ status: 200, body: '{}' });
    });
    const dest = freshCreate(CIM_CONFIG, { httpsPost: httpPost });

    await expect(dest.send([SAMPLE_EVENT])).resolves.toBeUndefined();
    const parsed = JSON.parse(capturedBody);
    expect(parsed.event).toMatchObject({ eventType: 'CERT_COMPLETE' }); // raw fallback
    expect(mockInc).toHaveBeenCalledWith({ destination: 'splunk', schema: 'cim' });

    jest.dontMock('../../siem/cimMapper');
    jest.dontMock('../../metrics');
  });
});
