import { MockServer } from './mock-server';
import {
  QodiqaClient,
  ValidationError,
  AuthenticationError,
} from '../src/index';

describe('QodiqaClient', () => {
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
    client = new QodiqaClient({
      baseUrl,
      timeout: 5000,
      maxRetries: 0,
    });
  });

  // -------------------------------------------------------------------------
  // Instantiation
  // -------------------------------------------------------------------------

  describe('instantiation', () => {
    it('creates a client with default config', () => {
      const c = new QodiqaClient();
      expect(c).toBeInstanceOf(QodiqaClient);
    });

    it('creates a client with full config', () => {
      const c = new QodiqaClient({
        apiKey: 'ok_' + 'a'.repeat(64),
        signToken: 'my-sign-token',
        baseUrl: 'http://localhost:3000',
        timeout: 10_000,
        maxRetries: 3,
        defaultHeaders: { 'x-custom': 'value' },
        userAgent: 'test-agent/1.0',
      });
      expect(c).toBeInstanceOf(QodiqaClient);
    });

    it('exposes all resource instances', () => {
      const c = new QodiqaClient({ baseUrl });
      expect(c.sign).toBeDefined();
      expect(c.chat).toBeDefined();
      expect(c.verify).toBeDefined();
      expect(c.portal).toBeDefined();
      expect(c.attestation).toBeDefined();
      expect(c.transparency).toBeDefined();
      expect(c.evidence).toBeDefined();
      expect(c.certification).toBeDefined();
      expect(c.webhooks).toBeDefined();
    });

    it('throws ValidationError for invalid baseUrl', () => {
      expect(() => new QodiqaClient({ baseUrl: 'not-a-url' })).toThrow(
        ValidationError,
      );
    });

    it('throws ValidationError for malformed apiKey', () => {
      expect(
        () => new QodiqaClient({ baseUrl, apiKey: 'bad-key' }),
      ).toThrow(ValidationError);
    });

    it('throws ValidationError for non-ok_ apiKey prefix', () => {
      expect(
        () =>
          new QodiqaClient({
            baseUrl,
            apiKey: 'sk_' + 'f'.repeat(64),
          }),
      ).toThrow(ValidationError);
    });

    it('throws ValidationError for apiKey with wrong hex length', () => {
      expect(
        () =>
          new QodiqaClient({
            baseUrl,
            apiKey: 'ok_' + 'a'.repeat(63), // one too short
          }),
      ).toThrow(ValidationError);
    });

    it('throws ValidationError for non-positive timeout', () => {
      expect(() => new QodiqaClient({ baseUrl, timeout: 0 })).toThrow(
        ValidationError,
      );
    });

    it('throws ValidationError for negative maxRetries', () => {
      expect(() => new QodiqaClient({ baseUrl, maxRetries: -1 })).toThrow(
        ValidationError,
      );
    });
  });

  // -------------------------------------------------------------------------
  // healthCheck
  // -------------------------------------------------------------------------

  describe('healthCheck()', () => {
    it('returns health response on 200', async () => {
      server.mock('GET', '/health', {
        status: 200,
        body: { status: 'ok', uptime: 12345 },
      });

      const result = await client.healthCheck();
      expect(result.status).toBe('ok');
      expect(result.uptime).toBe(12345);
    });
  });

  // -------------------------------------------------------------------------
  // readinessCheck
  // -------------------------------------------------------------------------

  describe('readinessCheck()', () => {
    it('returns readiness response on 200', async () => {
      server.mock('GET', '/ready', {
        status: 200,
        body: {
          ready: true,
          components: {
            nonceStore: true,
            anomalyStore: true,
            rateLimitStore: true,
          },
        },
      });

      const result = await client.readinessCheck();
      expect(result.ready).toBe(true);
      expect(result.components.nonceStore).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // getPublicKeys
  // -------------------------------------------------------------------------

  describe('getPublicKeys()', () => {
    it('returns keys list, unwrapped from the server envelope', async () => {
      // Real server response is enveloped ({status,timestamp,requestId,data}) —
      // confirmed live during's SDK-accuracy sweep. getPublicKeys()
      // unwraps `.data` internally so callers can use `keys.keys` directly.
      server.mock('GET', '/public-keys', {
        status: 200,
        body: {
          status: 'success',
          timestamp: '2024-01-01T00:00:00.000Z',
          requestId: 'req-keys-1',
          data: {
            keys: [
              {
                keyId: 'key-1',
                algorithm: 'RS256',
                publicKey: 'MIIBIj...',
                status: 'active',
              },
            ],
          },
        },
      });

      const result = await client.getPublicKeys();
      expect(result.keys).toHaveLength(1);
      expect(result.keys[0]!.keyId).toBe('key-1');
    });
  });

  // -------------------------------------------------------------------------
  // getAuditChain
  // -------------------------------------------------------------------------

  describe('getAuditChain()', () => {
    it('returns audit chain for a given artifactId', async () => {
      // /audit/:artifactId is ops-gated server-side (adminStack('READ_AUDIT'))
      // — confirmed live during's SDK-accuracy sweep. Requires apiKey.
      const opsClient = new QodiqaClient({
        baseUrl,
        timeout: 5000,
        maxRetries: 0,
        apiKey: 'ok_' + 'a'.repeat(64),
      });
      // the route replies with the standard success envelope (src/api/routes/audit.js success()).
      server.mock('GET', '/audit/:artifactId', {
        status: 200,
        body: {
          status: 'success',
          timestamp: '2024-01-01T00:00:00.000Z',
          requestId: 'req-001',
          data: {
            artifactId: 'art-abc',
            decision: 'EXECUTE',
            reason: 'OK',
            timestamp: '2024-01-01T00:00:00.000Z',
            chain: [],
          },
        },
      });

      const result = await opsClient.getAuditChain('art-abc');
      expect(result.data.artifactId).toBe('art-abc');
      expect(result.data.decision).toBe('EXECUTE');
    });

    it('throws AuthenticationError without apiKey', async () => {
      await expect(client.getAuditChain('art-abc')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('throws on empty artifactId', async () => {
      await expect(client.getAuditChain('')).rejects.toThrow(ValidationError);
    });
  });
});
