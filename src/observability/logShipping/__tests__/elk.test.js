'use strict';

const { createElkDestination } = require('../destinations/elk');

const BASE_CONFIG = {
  elk: { enabled: true, valid: true, url: 'https://logstash.company.com' },
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

describe('ELK destination adapter', () => {
  it('POSTs to the configured URL', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: '' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    expect(httpPost).toHaveBeenCalledWith(
      'https://logstash.company.com',
      expect.objectContaining({ 'Content-Type': 'application/x-ndjson' }),
      expect.any(String),
    );
  });

  it('sends NDJSON-formatted body', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_url, _headers, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '' });
    });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT, { ...SAMPLE_EVENT, eventType: 'CERT_STARTED' }]);

    const lines = capturedBody.split('\n');
    expect(lines).toHaveLength(2);
    expect(() => JSON.parse(lines[0])).not.toThrow();
    expect(() => JSON.parse(lines[1])).not.toThrow();
  });

  it('does not throw on HTTP 200', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 200, body: 'ok' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).resolves.toBeUndefined();
  });

  it('throws retryable error on HTTP 429', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 429, body: 'rate limited' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('throws retryable error on HTTP 503', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 503, body: 'unavailable' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('throws non-retryable error on HTTP 400', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 400, body: 'bad request' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: false });
  });

  it('throws non-retryable error on HTTP 401', async () => {
    const httpPost = jest.fn().mockResolvedValue({ status: 401, body: 'unauthorized' });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: false });
  });

  it('wraps network error as retryable', async () => {
    const networkErr = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });
    const httpPost = jest.fn().mockRejectedValue(networkErr);
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    await expect(dest.send([SAMPLE_EVENT])).rejects.toMatchObject({ retryable: true });
  });

  it('destination name is "elk"', () => {
    const httpPost = jest.fn();
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });
    expect(dest.name).toBe('elk');
  });
});

// ── #6: schema='ecs' ──────────────────────────────────────────────────

describe('ELK destination adapter — schema="ecs"', () => {
  const ECS_CONFIG = { elk: { ...BASE_CONFIG.elk, schema: 'ecs' } };

  it('is backward compatible by default — omitting schema still sends the raw event unchanged', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_url, _headers, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '' });
    });
    const dest = createElkDestination(BASE_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    expect(JSON.parse(capturedBody)).toEqual(SAMPLE_EVENT);
  });

  it('maps each event to ECS shape when schema="ecs"', async () => {
    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_url, _headers, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '' });
    });
    const dest = createElkDestination(ECS_CONFIG, { httpsPost: httpPost });

    await dest.send([SAMPLE_EVENT]);

    const mapped = JSON.parse(capturedBody);
    expect(mapped).toMatchObject({
      '@timestamp': SAMPLE_EVENT.timestamp,
      ecs: { version: '8.11' },
      event: expect.objectContaining({ action: 'cert_complete' }),
      qodiqa: expect.objectContaining({ event_type: 'CERT_COMPLETE', tenant: { id: 'tenant-001', slug: null } }),
    });
  });

  it('a mapping-function failure falls back to the raw event and increments the mapping-error metric, never breaking delivery', async () => {
    jest.resetModules();
    jest.doMock('../../siem/ecsMapper', () => ({
      mapToEcs: jest.fn(() => { throw new Error('mapping exploded'); }),
    }));
    const mockInc = jest.fn();
    jest.doMock('../../metrics', () => ({
      logShipSchemaMappingErrorsTotal: { inc: mockInc },
    }));
    const { createElkDestination: freshCreate } = require('../destinations/elk');

    let capturedBody;
    const httpPost = jest.fn().mockImplementation((_url, _headers, body) => {
      capturedBody = body;
      return Promise.resolve({ status: 200, body: '' });
    });
    const dest = freshCreate(ECS_CONFIG, { httpsPost: httpPost });

    await expect(dest.send([SAMPLE_EVENT])).resolves.toBeUndefined();
    expect(JSON.parse(capturedBody)).toEqual(SAMPLE_EVENT);
    expect(mockInc).toHaveBeenCalledWith({ destination: 'elk', schema: 'ecs' });

    jest.dontMock('../../siem/ecsMapper');
    jest.dontMock('../../metrics');
  });
});
