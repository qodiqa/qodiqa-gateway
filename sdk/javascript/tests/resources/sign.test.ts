import { MockServer } from '../mock-server';
import { QodiqaClient, AuthenticationError, ValidationError } from '../../src/index';
import type { SignResponse, Artifact } from '../../src/types';

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

const MOCK_SIGN_RESPONSE: SignResponse = {
  artifactId: 'art-001',
  artifact: MOCK_ARTIFACT,
  meta: {
    keyId: 'key-1',
    expiresAt: Date.now() + 300_000,
    tenantId: 'tenant-1',
  },
  requestId: 'req-sign-001',
};

describe('SignResource', () => {
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

  function makeClient(withSignToken = true) {
    return new QodiqaClient({
      baseUrl,
      timeout: 5000,
      maxRetries: 0,
      ...(withSignToken ? { signToken: 'test-sign-token' } : {}),
    });
  }

  describe('sign()', () => {
    it('returns a signed artifact on success', async () => {
      server.mock('POST', '/sign', {
        status: 200,
        body: MOCK_SIGN_RESPONSE,
      });

      const client = makeClient(true);
      const res = await client.sign.sign({
        request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hello' } },
      });

      expect(res.artifactId).toBe('art-001');
      expect(res.artifact.publicKeyId).toBe('key-1');
      expect(res.meta.keyId).toBe('key-1');
      expect(res.meta.tenantId).toBe('tenant-1');
      expect(res.requestId).toBe('req-sign-001');
    });

    it('sends Authorization: Bearer header (TRUST-1 — per-identity signing API key)', async () => {
      server.mock('POST', '/sign', { status: 200, body: MOCK_SIGN_RESPONSE });

      const client = makeClient(true);
      await client.sign.sign({
        request: { method: 'POST', path: '/ai/chat', body: {} },
      });

      const log = server.getCallLog();
      expect(log[0]!.headers['authorization']).toBe('Bearer test-sign-token');
    });

    it('throws AuthenticationError when signToken is not configured', async () => {
      const client = makeClient(false);
      await expect(
        client.sign.sign({
          request: { method: 'GET', path: '/test', body: {} },
        }),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('throws ValidationError when request.method is empty', async () => {
      const client = makeClient(true);
      await expect(
        client.sign.sign({
          request: { method: '' as 'GET', path: '/test', body: {} },
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    });

    it('throws ValidationError when request.path is empty', async () => {
      const client = makeClient(true);
      await expect(
        client.sign.sign({
          request: { method: 'POST', path: '', body: {} },
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    });

    it('forwards optional payload and ttl', async () => {
      server.mock('POST', '/sign', { status: 200, body: MOCK_SIGN_RESPONSE });

      const client = makeClient(true);
      await client.sign.sign({
        request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } },
        payload: { userId: 'user-1', sessionId: 'sess-1' },
        ttl: 60_000,
      });

      const log = server.getCallLog();
      const body = log[0]!.body as { payload: Record<string, unknown>; ttl: number };
      expect(body.payload?.userId).toBe('user-1');
      expect(body.ttl).toBe(60_000);
    });

    it('attaches x-qodiqa-artifact header when artifactHeader is provided', async () => {
      server.mock('POST', '/sign', { status: 200, body: MOCK_SIGN_RESPONSE });

      const existingArtifact = Buffer.from(JSON.stringify(MOCK_ARTIFACT)).toString('base64');
      const client = makeClient(true);

      await client.sign.sign(
        { request: { method: 'POST', path: '/ai/chat', body: {} } },
        existingArtifact,
      );

      const log = server.getCallLog();
      expect(log[0]!.headers['x-qodiqa-artifact']).toBe(existingArtifact);
    });

    it('does not attach x-qodiqa-artifact header when no artifactHeader is provided', async () => {
      server.mock('POST', '/sign', { status: 200, body: MOCK_SIGN_RESPONSE });

      const client = makeClient(true);
      await client.sign.sign({
        request: { method: 'POST', path: '/ai/chat', body: {} },
      });

      const log = server.getCallLog();
      expect(log[0]!.headers['x-qodiqa-artifact']).toBeUndefined();
    });

    it('returns 401 AuthenticationError from server', async () => {
      server.mock('POST', '/sign', {
        status: 401,
        body: {
          decision: 'BLOCK',
          reason: 'UNAUTHORIZED',
          details: { message: 'Invalid sign token' },
          requestId: 'r1',
        },
      });

      const client = makeClient(true);
      await expect(
        client.sign.sign({ request: { method: 'POST', path: '/ai/chat', body: {} } }),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });
  });
});
