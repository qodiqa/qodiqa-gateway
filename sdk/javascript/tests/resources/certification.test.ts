import { MockServer } from '../mock-server';
import { QodiqaClient, AuthenticationError } from '../../src/index';
import type { ApiResponse, CertificationRecord, BatchRecord, Artifact } from '../../src/types';

const VALID_API_KEY = 'ok_' + 'c'.repeat(64);

const MOCK_ARTIFACT: Artifact = {
  expiry: Date.now() + 300_000,
  payload: {
    requestId: 'req-cert',
    requestHash: 'h1',
    policyHash: 'h2',
    tenantId: 't1',
  },
  publicKeyId: 'key-1',
  timestamp: Date.now(),
  signature: 'sig-cert',
};

const MOCK_CERT_RECORD: CertificationRecord = {
  id: 'cert-001',
  status: 'PASSED',
  score: 98,
  controls: ['ctrl-1', 'ctrl-2'],
  summary: { passed: 10, failed: 0 },
  createdAt: '2024-01-01T00:00:00.000Z',
};

const MOCK_BATCH_RECORD: BatchRecord = {
  batchId: 'batch-001',
  status: 'completed',
  total: 5,
  completed: 5,
  failed: 0,
  createdAt: '2024-01-01T00:00:00.000Z',
};

function mockApiResponse<T>(data: T): ApiResponse<T> {
  return {
    status: 'success',
    timestamp: new Date().toISOString(),
    requestId: 'req-cert-test',
    data,
  };
}

describe('CertificationResource', () => {
  let server: MockServer;
  let baseUrl: string;

  beforeAll(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.reset();
  });

  function makeClient(withApiKey = false) {
    return new QodiqaClient({
      baseUrl,
      timeout: 5000,
      maxRetries: 0,
      ...(withApiKey ? { apiKey: VALID_API_KEY } : {}),
    });
  }

  describe('evaluate()', () => {
    it('returns certification record on success', async () => {
      server.mock('POST', '/v1/certification/evaluate', {
        status: 200,
        body: mockApiResponse(MOCK_CERT_RECORD),
      });

      // the server mounts /v1/certification/evaluate on the admin router — the ops key is required.
      const client = makeClient(true);
      const res = await client.certification.evaluate({ artifact: MOCK_ARTIFACT });
      expect(res.data.id).toBe('cert-001');
      expect(res.data.score).toBe(98);
      expect(server.getCallLog()[0]!.headers['authorization']).toMatch(/^Bearer ok_/);
    });

    it('throws AuthenticationError without apiKey', async () => {
      await expect(makeClient(false).certification.evaluate({ artifact: MOCK_ARTIFACT })).rejects.toBeInstanceOf(AuthenticationError);
    });
  });

  describe('get()', () => {
    it('retrieves a certification record by id', async () => {
      server.mock('GET', '/v1/certification/:id', {
        status: 200,
        body: mockApiResponse(MOCK_CERT_RECORD),
      });

      const client = makeClient();
      const res = await client.certification.get('cert-001');
      expect(res.data.id).toBe('cert-001');
      expect(res.data.status).toBe('PASSED');
    });

    it('throws on empty id', async () => {
      const client = makeClient();
      await expect(client.certification.get('')).rejects.toThrow();
    });
  });

  describe('getSummary()', () => {
    it('retrieves a summary', async () => {
      server.mock('GET', '/v1/certification/:id/summary', {
        status: 200,
        body: mockApiResponse({ passed: 10, failed: 0 }),
      });

      const client = makeClient();
      const res = await client.certification.getSummary('cert-001');
      expect(res).toBeDefined();
    });
  });

  describe('submitBatch() — ops protected', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(
        client.certification.submitBatch({ items: [{ artifact: MOCK_ARTIFACT }] }),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('submits a batch with ops key', async () => {
      server.mock('POST', '/v1/certifications/batch', {
        status: 200,
        body: mockApiResponse(MOCK_BATCH_RECORD),
      });

      const client = makeClient(true);
      const res = await client.certification.submitBatch({
        items: [{ artifact: MOCK_ARTIFACT }],
      });
      expect(res.data.batchId).toBe('batch-001');
      expect(res.data.status).toBe('completed');
    });
  });

  describe('getBatch()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(
        client.certification.getBatch('batch-001'),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('returns batch record with ops key', async () => {
      server.mock('GET', '/v1/certifications/batch/:batchId', {
        status: 200,
        body: mockApiResponse(MOCK_BATCH_RECORD),
      });

      const client = makeClient(true);
      const res = await client.certification.getBatch('batch-001');
      expect(res.data.batchId).toBe('batch-001');
      expect(res.data.total).toBe(5);
    });
  });

  describe('getBatchResults()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(
        client.certification.getBatchResults('batch-001'),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });
  });

  describe('cancelBatch()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(
        client.certification.cancelBatch('batch-001'),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });
  });
});
