import { MockServer } from '../mock-server';
import {
  QodiqaClient,
  AuthenticationError,
  NotFoundError,
} from '../../src/index';
import type { Artifact, AttestationRecord, ApiResponse, PaginatedResponse } from '../../src/types';

const VALID_API_KEY = 'ok_' + 'a'.repeat(64);

const MOCK_ARTIFACT: Artifact = {
  expiry: Date.now() + 300_000,
  payload: {
    requestId: 'req-attest',
    requestHash: 'h1',
    policyHash: 'h2',
    tenantId: 't1',
  },
  publicKeyId: 'key-1',
  timestamp: Date.now(),
  signature: 'sig-1',
};

const MOCK_RECORD: AttestationRecord = {
  attestationId: 'att-001',
  status: 'VALID',
  artifact: MOCK_ARTIFACT,
  evidence: { chain: [], verificationResult: true },
  summary: { score: 100 },
};

function mockApiResponse<T>(data: T): ApiResponse<T> {
  return {
    status: 'success',
    timestamp: new Date().toISOString(),
    requestId: 'req-test',
    data,
  };
}

describe('AttestationResource', () => {
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

  // -------------------------------------------------------------------------
  // verify()
  // -------------------------------------------------------------------------

  describe('verify()', () => {
    it('returns attestation record on success', async () => {
      server.mock('POST', '/v1/attestation/verify', {
        status: 200,
        body: mockApiResponse(MOCK_RECORD),
      });

      const client = makeClient();
      const res = await client.attestation.verify({ artifact: MOCK_ARTIFACT });
      expect(res.data.attestationId).toBe('att-001');
      expect(res.data.status).toBe('VALID');
    });
  });

  // -------------------------------------------------------------------------
  // get()
  // -------------------------------------------------------------------------

  describe('get()', () => {
    it('returns attestation record by id', async () => {
      server.mock('GET', '/v1/attestation/:id', {
        status: 200,
        body: mockApiResponse(MOCK_RECORD),
      });

      const client = makeClient();
      const res = await client.attestation.get('att-001');
      expect(res.data.attestationId).toBe('att-001');
    });

    it('throws on empty id', async () => {
      const client = makeClient();
      await expect(client.attestation.get('')).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // export() — ops protected
  // -------------------------------------------------------------------------

  describe('export()', () => {
    it('returns the attestation record on success', async () => {
      server.mock('GET', '/v1/attestation/:id/export', {
        status: 200,
        body: mockApiResponse(MOCK_RECORD),
      });

      const client = makeClient(true);
      const res = await client.attestation.export('att-001');
      expect(res.data.attestationId).toBe('att-001');
      expect(res.data.status).toBe('VALID');
    });

    it('sends the ops Authorization header', async () => {
      server.mock('GET', '/v1/attestation/:id/export', {
        status: 200,
        body: mockApiResponse(MOCK_RECORD),
      });

      const client = makeClient(true);
      await client.attestation.export('att-001');

      const log = server.getCallLog();
      expect(log[0]!.headers['authorization']).toBe(`Bearer ${VALID_API_KEY}`);
    });

    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.attestation.export('att-001')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('throws on empty id', async () => {
      const client = makeClient(true);
      await expect(client.attestation.export('')).rejects.toThrow();
    });

    it('propagates a 404 as NotFoundError', async () => {
      server.mock('GET', '/v1/attestation/:id/export', {
        status: 404,
        body: {
          status: 'error',
          reason: 'NOT_FOUND',
          message: 'Attestation not found: att-missing',
          requestId: 'req-404',
        },
      });

      const client = makeClient(true);
      await expect(client.attestation.export('att-missing')).rejects.toBeInstanceOf(
        NotFoundError,
      );
    });
  });

  // -------------------------------------------------------------------------
  // list() — ops protected
  // -------------------------------------------------------------------------

  describe('list()', () => {
    it('returns paginated attestation records with ops key', async () => {
      const paginatedData: PaginatedResponse<AttestationRecord> = {
        records: [MOCK_RECORD],
        page: 1,
        pageSize: 50,
        total: 1,
        hasMore: false,
      };

      server.mock('GET', '/v1/attestation/admin/history', {
        status: 200,
        body: mockApiResponse(paginatedData),
      });

      const client = makeClient(true);
      const res = await client.attestation.list({ page: 1, pageSize: 50 });
      expect(res.data.records).toHaveLength(1);
      expect(res.data.total).toBe(1);
    });

    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.attestation.list()).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });
  });

  // -------------------------------------------------------------------------
  // stats() — ops protected
  // -------------------------------------------------------------------------

  describe('stats()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.attestation.stats()).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('returns stats with ops key', async () => {
      server.mock('GET', '/v1/attestation/admin/stats', {
        status: 200,
        body: mockApiResponse({ total: 100, valid: 95, invalid: 5 }),
      });

      const client = makeClient(true);
      const res = await client.attestation.stats();
      expect(res).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // getEvidence() — ops protected
  // -------------------------------------------------------------------------

  describe('getEvidence()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.attestation.getEvidence('att-001')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('returns evidence package with ops key', async () => {
      server.mock('GET', '/v1/attestation/:id/evidence', {
        status: 200,
        body: mockApiResponse({ package: 'data' }),
      });

      const client = makeClient(true);
      const res = await client.attestation.getEvidence('att-001');
      expect(res).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // verifyEvidence() and verifyChain()
  // -------------------------------------------------------------------------

  describe('verifyEvidence()', () => {
    it('calls POST /v1/attestation/evidence/verify', async () => {
      server.mock('POST', '/v1/attestation/evidence/verify', {
        status: 200,
        body: mockApiResponse({ verified: true }),
      });

      const client = makeClient();
      const res = await client.attestation.verifyEvidence({
        artifact: MOCK_ARTIFACT,
      });
      expect(res).toBeDefined();
    });
  });

  describe('verifyChain()', () => {
    it('calls POST /v1/attestation/chain/verify', async () => {
      server.mock('POST', '/v1/attestation/chain/verify', {
        status: 200,
        body: mockApiResponse({ chainValid: true }),
      });

      // admin router + MANAGE_ATTESTATIONS server-side — the ops key is required.
      const client = makeClient(true);
      const res = await client.attestation.verifyChain({ artifact: MOCK_ARTIFACT });
      expect(res).toBeDefined();
      expect(server.getCallLog()[0]!.headers['authorization']).toMatch(/^Bearer ok_/);
    });

    it('throws AuthenticationError without apiKey', async () => {
      await expect(makeClient(false).attestation.verifyChain({ evidenceIds: ['e1'] })).rejects.toBeInstanceOf(AuthenticationError);
    });
  });
});
