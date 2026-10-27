import { MockServer } from '../mock-server';
import { QodiqaClient, ValidationError } from '../../src/index';
import type { VerifyRequest, Artifact } from '../../src/types';

const MOCK_ARTIFACT: Artifact = {
  expiry: Date.now() + 300_000,
  payload: {
    requestId: 'req-001',
    requestHash: 'hash-abc',
    policyHash: 'hash-def',
    tenantId: 'tenant-1',
  },
  publicKeyId: 'key-1',
  timestamp: Date.now(),
  signature: 'sig-xyz',
};

const ARTIFACT_B64 = Buffer.from(JSON.stringify(MOCK_ARTIFACT)).toString('base64');

const MOCK_REQUEST: VerifyRequest = {
  artifact: MOCK_ARTIFACT,
  request: {
    method: 'POST',
    path: '/ai/chat',
    body: { prompt: 'hello' },
  },
};

describe('VerifyResource', () => {
  let server: MockServer;
  let baseUrl: string;
  let client: QodiqaClient;

  beforeAll(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.reset();
    client = new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 0 });
  });

  // -------------------------------------------------------------------------
  // verify()
  // -------------------------------------------------------------------------

  describe('verify()', () => {
    it('returns EXECUTE decision on valid artifact', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: {
          decision: 'EXECUTE',
          reason: 'OK',
          details: {},
          requestId: 'req-v1',
          artifactId: 'art-001',
          keyId: 'key-1',
        },
      });

      const res = await client.verify.verify(ARTIFACT_B64, MOCK_REQUEST);
      expect(res.decision).toBe('EXECUTE');
      expect(res.artifactId).toBe('art-001');
    });

    it('does not attach an x-qodiqa-artifact header', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'r' },
      });

      await client.verify.verify(ARTIFACT_B64, MOCK_REQUEST);
      const log = server.getCallLog();
      expect(log[0]!.headers['x-qodiqa-artifact']).toBeUndefined();
    });

    it('sends the full request body', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'r' },
      });

      await client.verify.verify(ARTIFACT_B64, MOCK_REQUEST);
      const log = server.getCallLog();
      const body = log[0]!.body as { artifact: Artifact; request: unknown };
      expect(body.artifact).toBeDefined();
      expect(body.request).toBeDefined();
    });

    it('returns BLOCK decision', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: {
          decision: 'BLOCK',
          reason: 'EXPIRED_ARTIFACT',
          details: { expiry: 0 },
          requestId: 'req-v2',
        },
      });

      const res = await client.verify.verify(ARTIFACT_B64, MOCK_REQUEST);
      expect(res.decision).toBe('BLOCK');
      expect(res.reason).toBe('EXPIRED_ARTIFACT');
    });

    it('throws when artifact is empty', async () => {
      await expect(
        client.verify.verify('', MOCK_REQUEST),
      ).rejects.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // verifyV2()
  // -------------------------------------------------------------------------

  describe('verifyV2()', () => {
    it('calls POST /verify/v2 and returns EXECUTE decision', async () => {
      server.mock('POST', '/verify/v2', {
        status: 200,
        body: {
          decision: 'EXECUTE',
          reason: 'ALL_CHECKS_PASSED',
          details: {},
          requestId: 'req-v2-1',
          artifactId: 'art-002',
          keyId: 'key-1',
        },
      });

      const res = await client.verify.verifyV2(MOCK_REQUEST);
      expect(res.decision).toBe('EXECUTE');
      expect(res.artifactId).toBe('art-002');

      const log = server.getCallLog();
      expect(log[0]!.path).toBe('/verify/v2');
    });

    it('does not attach an x-qodiqa-artifact header', async () => {
      server.mock('POST', '/verify/v2', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'r' },
      });

      await client.verify.verifyV2(MOCK_REQUEST);
      const log = server.getCallLog();
      expect(log[0]!.headers['x-qodiqa-artifact']).toBeUndefined();
    });

    it('sends the full request body', async () => {
      server.mock('POST', '/verify/v2', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'r' },
      });

      await client.verify.verifyV2(MOCK_REQUEST);
      const log = server.getCallLog();
      const body = log[0]!.body as { artifact: Artifact; request: unknown };
      expect(body.artifact).toBeDefined();
      expect(body.request).toBeDefined();
    });

    it('returns BLOCK decision', async () => {
      server.mock('POST', '/verify/v2', {
        status: 200,
        body: {
          decision: 'BLOCK',
          reason: 'EXPIRED_ARTIFACT',
          details: { expiry: 0 },
          requestId: 'req-v2-2',
        },
      });

      const res = await client.verify.verifyV2(MOCK_REQUEST);
      expect(res.decision).toBe('BLOCK');
      expect(res.reason).toBe('EXPIRED_ARTIFACT');
    });

    it('returns 400 ValidationError on bad body', async () => {
      server.mock('POST', '/verify/v2', {
        status: 400,
        body: {
          decision: 'BLOCK',
          reason: 'VALIDATION_ERROR',
          details: { message: 'Missing artifact field' },
          requestId: 'v2-err',
        },
      });

      await expect(client.verify.verifyV2(MOCK_REQUEST)).rejects.toBeInstanceOf(
        ValidationError,
      );
    });
  });

  // -------------------------------------------------------------------------
  // dryRun()
  // -------------------------------------------------------------------------

  describe('dryRun()', () => {
    it('returns EXECUTE decision without setting artifact header', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'dry-1' },
      });

      const res = await client.verify.dryRun(MOCK_REQUEST);
      expect(res.decision).toBe('EXECUTE');

      const log = server.getCallLog();
      expect(log[0]!.headers['x-qodiqa-artifact']).toBeUndefined();
    });

    it('sends the full request body', async () => {
      server.mock('POST', '/verify', {
        status: 200,
        body: { decision: 'EXECUTE', reason: 'OK', details: {}, requestId: 'dry-2' },
      });

      await client.verify.dryRun(MOCK_REQUEST);
      const log = server.getCallLog();
      const body = log[0]!.body as { artifact: Artifact; request: unknown };
      expect(body.artifact).toBeDefined();
      expect(body.request).toBeDefined();
    });

    it('returns 400 ValidationError on bad body', async () => {
      server.mock('POST', '/verify', {
        status: 400,
        body: {
          decision: 'BLOCK',
          reason: 'VALIDATION_ERROR',
          details: { message: 'Missing artifact field' },
          requestId: 'dry-err',
        },
      });

      await expect(client.verify.dryRun(MOCK_REQUEST)).rejects.toBeInstanceOf(
        ValidationError,
      );
    });
  });
});
