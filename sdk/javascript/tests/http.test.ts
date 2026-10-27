import { MockServer } from './mock-server';
import { HttpClient } from '../src/http';
import { resolveConfig } from '../src/config';
import {
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ServerError,
  ValidationError,
  VerificationError,
  TimeoutError,
} from '../src/errors';

function makeClient(baseUrl: string, overrides: Record<string, unknown> = {}) {
  const config = resolveConfig({ baseUrl, timeout: 5000, maxRetries: 0, ...overrides });
  return new HttpClient(config);
}

describe('HttpClient', () => {
  let server: MockServer;
  let baseUrl: string;
  let client: HttpClient;

  beforeAll(async () => {
    server = new MockServer();
    baseUrl = await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.reset();
    client = makeClient(baseUrl);
  });

  // -------------------------------------------------------------------------
  // HTTP methods
  // -------------------------------------------------------------------------

  describe('GET', () => {
    it('performs a GET request and returns parsed body', async () => {
      server.mock('GET', '/test', { status: 200, body: { hello: 'world' } });
      const res = await client.get<{ hello: string }>('/test');
      expect(res.hello).toBe('world');
    });
  });

  describe('POST', () => {
    it('serialises the body as JSON', async () => {
      server.mock('POST', '/test', { status: 200, body: { ok: true } });
      await client.post('/test', { name: 'qodiqa' });
      const log = server.getCallLog();
      expect(log[0]!.body).toEqual({ name: 'qodiqa' });
    });

    it('sends Content-Type: application/json', async () => {
      server.mock('POST', '/test', { status: 200, body: {} });
      await client.post('/test', {});
      const log = server.getCallLog();
      expect(log[0]!.headers['content-type']).toContain('application/json');
    });
  });

  describe('PUT', () => {
    it('performs a PUT request', async () => {
      server.mock('PUT', '/resource/1', { status: 200, body: { updated: true } });
      const res = await client.put<{ updated: boolean }>('/resource/1', { x: 1 });
      expect(res.updated).toBe(true);
    });
  });

  describe('PATCH', () => {
    it('performs a PATCH request', async () => {
      server.mock('PATCH', '/resource/1', { status: 200, body: { patched: true } });
      const res = await client.patch<{ patched: boolean }>('/resource/1', { y: 2 });
      expect(res.patched).toBe(true);
    });
  });

  describe('DELETE', () => {
    it('performs a DELETE request', async () => {
      server.mock('DELETE', '/resource/1', { status: 200, body: { deleted: true } });
      const res = await client.delete<{ deleted: boolean }>('/resource/1');
      expect(res.deleted).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // Query string building
  // -------------------------------------------------------------------------

  describe('query string', () => {
    it('appends query parameters to the URL', async () => {
      server.mock('GET', '/items', { status: 200, body: {} });
      await client.get('/items', { query: { page: 2, pageSize: 25 } });
      const log = server.getCallLog();
      expect(log[0]!.path).toContain('page=2');
      expect(log[0]!.path).toContain('pageSize=25');
    });

    it('omits undefined query parameters', async () => {
      server.mock('GET', '/items', { status: 200, body: {} });
      await client.get('/items', { query: { page: 1, filter: undefined } });
      const log = server.getCallLog();
      expect(log[0]!.path).not.toContain('filter');
    });
  });

  // -------------------------------------------------------------------------
  // Error response parsing
  // -------------------------------------------------------------------------

  describe('error mapping', () => {
    it('401 → AuthenticationError', async () => {
      server.mock('GET', '/protected', {
        status: 401,
        body: {
          decision: 'BLOCK',
          reason: 'UNAUTHORIZED',
          details: { message: 'Invalid token' },
          requestId: 'req-1',
        },
      });
      await expect(client.get('/protected')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('403 → AuthorizationError', async () => {
      server.mock('GET', '/admin', {
        status: 403,
        body: {
          decision: 'BLOCK',
          reason: 'FORBIDDEN',
          details: { message: 'Forbidden' },
          requestId: 'req-2',
        },
      });
      await expect(client.get('/admin')).rejects.toBeInstanceOf(
        AuthorizationError,
      );
    });

    it('404 → NotFoundError', async () => {
      server.mock('GET', '/missing', {
        status: 404,
        body: {
          decision: 'BLOCK',
          reason: 'NOT_FOUND',
          details: { message: 'Not found' },
          requestId: 'req-3',
        },
      });
      await expect(client.get('/missing')).rejects.toBeInstanceOf(NotFoundError);
    });

    it('429 → RateLimitError', async () => {
      server.mock('GET', '/slow', {
        status: 429,
        body: {
          decision: 'BLOCK',
          reason: 'RATE_LIMITED',
          details: { message: 'Too many requests' },
          requestId: 'req-4',
        },
        headers: { 'Retry-After': '30' },
      });
      const err = await client.get('/slow').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RateLimitError);
    });

    it('500 → ServerError', async () => {
      server.mock('GET', '/broken', {
        status: 500,
        body: {
          decision: 'BLOCK',
          reason: 'INTERNAL_ERROR',
          details: { message: 'Something went wrong' },
          requestId: 'req-5',
        },
      });
      await expect(client.get('/broken')).rejects.toBeInstanceOf(ServerError);
    });

    it('400 → ValidationError', async () => {
      server.mock('POST', '/validate', {
        status: 400,
        body: {
          decision: 'BLOCK',
          reason: 'VALIDATION_ERROR',
          details: { message: 'Bad request body' },
          requestId: 'req-6',
        },
      });
      await expect(client.post('/validate', {})).rejects.toBeInstanceOf(
        ValidationError,
      );
    });

    it('attaches requestId from response body to error', async () => {
      server.mock('GET', '/err', {
        status: 404,
        body: {
          decision: 'BLOCK',
          reason: 'NOT_FOUND',
          details: { message: 'Gone' },
          requestId: 'my-req-id',
        },
      });
      const err = await client.get('/err').catch((e: unknown) => e);
      expect((err as NotFoundError).requestId).toBe('my-req-id');
    });

    // D26-7: MANAGEMENT_ERROR envelope ({status:'error', error:{code,message,
    // details}}, used by the management/admin/observability surface — webhooks,
    // attestation, certification, transparency, RBAC, audit) — previously never
    // read at all, silently dropping the real message and falling back to the
    // generic "HTTP {status}" text. Confirmed live during against a real
    // /v1/webhooks 400.
    it('D26-7: MANAGEMENT_ERROR envelope — surfaces error.code/error.message, not the generic fallback', async () => {
      server.mock('POST', '/v1/webhooks', {
        status: 400,
        body: {
          status: 'error',
          timestamp: '2026-08-13T00:00:00.000Z',
          requestId: 'req-mgmt-1',
          error: {
            code: 'INVALID_PARAM',
            message: 'tenantId query parameter is required',
            details: { field: 'tenantId' },
          },
        },
      });
      const err = await client.post('/v1/webhooks', {}).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ValidationError);
      // A caller reading err.message gets the real server text, not a generic
      // "HTTP 400" fallback — this is what "readable by an SDK caller" means,
      // not merely present somewhere on the wire.
      expect((err as ValidationError).message).toBe('tenantId query parameter is required');
      expect((err as ValidationError).requestId).toBe('req-mgmt-1');
      expect((err as ValidationError).details).toEqual({ field: 'tenantId' });
    });

    it('D26-7: MANAGEMENT_ERROR 401 still correctly classifies AuthenticationError via error.code', async () => {
      server.mock('GET', '/audit/art-1', {
        status: 401,
        body: {
          status: 'error',
          requestId: 'req-mgmt-2',
          error: { code: 'UNAUTHORIZED', message: 'Missing authentication credentials' },
        },
      });
      const err = await client.get('/audit/art-1').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthenticationError);
      expect((err as AuthenticationError).message).toBe('Missing authentication credentials');
    });

    // (SDK half): the factory used to check status===403 before checking
    // reason code, so a real REQUEST_MISMATCH (or any of the other 7
    // VerificationError reasons) at HTTP 403 — which is how the server always
    // sends them, per src/errors/catalog.js — was masked as AuthorizationError.
    it('REQUEST_MISMATCH reason at HTTP 403 → VerificationError, not AuthorizationError', async () => {
      server.mock('POST', '/ai/chat', {
        status: 403,
        body: {
          decision: 'BLOCK',
          reason: 'REQUEST_MISMATCH',
          details: { issue: 'requestHash does not match actual request' },
          requestId: 'req-vf-1',
        },
      });
      const err = await client.post('/ai/chat', {}).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VerificationError);
      expect(err).not.toBeInstanceOf(AuthorizationError);
    });

    it('all 8 documented VerificationError reasons at HTTP 403 classify correctly', async () => {
      const reasons = [
        'INVALID_SIGNATURE', 'INVALID_ARTIFACT', 'KEY_NOT_FOUND', 'EXPIRED',
        'FUTURE_TIMESTAMP', 'TIME_SKEW_EXCEEDED', 'REQUEST_MISMATCH', 'REPLAY_DETECTED',
      ];
      for (const reason of reasons) {
        server.reset();
        server.mock('POST', '/ai/chat', {
          status: 403,
          body: { decision: 'BLOCK', reason, details: {}, requestId: 'req' },
        });
        const err = await client.post('/ai/chat', {}).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(VerificationError);
      }
    });

    // No misclassification introduced: a genuine 403 that is NOT one of the 8
    // VerificationError reasons (e.g. a real authorization failure, reason
    // FORBIDDEN, or unset/unmapped) still correctly throws AuthorizationError.
    it('a genuine 403 authorization failure (reason FORBIDDEN) still → AuthorizationError, not VerificationError', async () => {
      server.mock('GET', '/v1/admin/restricted', {
        status: 403,
        body: { decision: 'BLOCK', reason: 'FORBIDDEN', details: {}, requestId: 'req-authz' },
      });
      const err = await client.get('/v1/admin/restricted').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthorizationError);
      expect(err).not.toBeInstanceOf(VerificationError);
    });

    it('a 403 with no reason at all still → AuthorizationError (status-only fallback preserved)', async () => {
      server.mock('GET', '/v1/admin/other', {
        status: 403,
        body: { message: 'Forbidden' },
      });
      const err = await client.get('/v1/admin/other').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthorizationError);
    });

    it('a genuine 401 authentication failure is unaffected by the reorder', async () => {
      server.mock('GET', '/v1/admin/x', {
        status: 401,
        body: { decision: 'BLOCK', reason: 'UNAUTHORIZED', details: {}, requestId: 'req-auth' },
      });
      const err = await client.get('/v1/admin/x').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AuthenticationError);
      expect(err).not.toBeInstanceOf(VerificationError);
    });
  });

  // -------------------------------------------------------------------------
  // Timeout handling
  // -------------------------------------------------------------------------

  describe('timeout', () => {
    it('throws TimeoutError when request exceeds timeout', async () => {
      // Register a route that doesn't respond immediately by using a deliberately
      // short timeout and a server that delays response.
      const slowServer = new MockServer();

      // Override handleRequest to introduce delay
      const slowUrl = await slowServer.start();
      // We register a normal mock but configure the client with 1ms timeout
      slowServer.mock('GET', '/slow', {
        status: 200,
        body: { ok: true },
      });

      const fastFailClient = makeClient(slowUrl, { timeout: 1, maxRetries: 0 });
      await expect(fastFailClient.get('/slow')).rejects.toBeInstanceOf(TimeoutError);
      await slowServer.stop();
    });
  });

  // -------------------------------------------------------------------------
  // Response unwrapping
  // -------------------------------------------------------------------------

  describe('response unwrapping', () => {
    it('returns the raw body as-is (no automatic unwrapping)', async () => {
      const envelope = {
        status: 'success',
        timestamp: '2024-01-01T00:00:00Z',
        requestId: 'req-7',
        data: { id: 'item-1' },
      };
      server.mock('GET', '/wrapped', { status: 200, body: envelope });
      const result = await client.get<typeof envelope>('/wrapped');
      expect(result.status).toBe('success');
      expect(result.data).toEqual({ id: 'item-1' });
    });
  });

  // -------------------------------------------------------------------------
  // Custom headers
  // -------------------------------------------------------------------------

  describe('headers', () => {
    it('merges defaultHeaders into every request', async () => {
      server.mock('GET', '/h', { status: 200, body: {} });
      const c = makeClient(baseUrl, { defaultHeaders: { 'x-tenant': 'tenant-1' } });
      await c.get('/h');
      const log = server.getCallLog();
      expect(log[0]!.headers['x-tenant']).toBe('tenant-1');
    });

    it('per-request headers override defaults', async () => {
      server.mock('GET', '/h2', { status: 200, body: {} });
      const c = makeClient(baseUrl, {
        defaultHeaders: { 'x-custom': 'default-val' },
      });
      await c.get('/h2', { headers: { 'x-custom': 'override-val' } });
      const log = server.getCallLog();
      expect(log[0]!.headers['x-custom']).toBe('override-val');
    });
  });
});
