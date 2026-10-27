import { MockServer } from '../mock-server';
import { QodiqaClient, AuthenticationError } from '../../src/index';
import type {
  ApiResponse,
  WebhookEndpoint,
  WebhookRecord,
  WebhookCreateResult,
  WebhookListResponse,
} from '../../src/types';

const VALID_API_KEY = 'ok_' + 'd'.repeat(64);

// Real server response shape (snake_case, nested under `endpoint`) — confirmed
// live during's SDK-accuracy sweep.
const MOCK_ENDPOINT: WebhookEndpoint = {
  id: 'wh-001',
  tenant_id: 'tenant-1',
  url: 'https://example.com/webhook',
  enabled: true,
  event_types: ['attestation.completed', 'certification.evaluated'],
  description: 'Main webhook',
  created_by: 'admin',
  created_at: '2024-01-01T00:00:00.000Z',
  updated_at: '2024-01-01T00:00:00.000Z',
};

const MOCK_CREATE_RESULT: WebhookCreateResult = {
  endpoint: MOCK_ENDPOINT,
  secret: 'whsec_abc123',
  notice: 'The secret is returned once only and cannot be retrieved again. Store it securely.',
};

const MOCK_RECORD: WebhookRecord = { endpoint: MOCK_ENDPOINT };

function mockApiResponse<T>(data: T): ApiResponse<T> {
  return {
    status: 'success',
    timestamp: new Date().toISOString(),
    requestId: 'req-webhook-test',
    data,
  };
}

describe('WebhooksResource', () => {
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

  describe('create() — ops protected', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(
        client.webhooks.create({
          tenantId: 'tenant-1',
          url: 'https://example.com/wh',
          eventTypes: ['attestation.completed'],
        }),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('creates a webhook with ops key', async () => {
      server.mock('POST', '/v1/webhooks', {
        status: 200,
        body: mockApiResponse(MOCK_CREATE_RESULT),
      });

      const client = makeClient(true);
      const res = await client.webhooks.create({
        tenantId: 'tenant-1',
        url: 'https://example.com/webhook',
        eventTypes: ['attestation.completed'],
        description: 'Main webhook',
      });
      expect(res.data.endpoint.id).toBe('wh-001');
      expect(res.data.endpoint.enabled).toBe(true);
      expect(res.data.secret).toBe('whsec_abc123');
    });

    it('sends Authorization header', async () => {
      server.mock('POST', '/v1/webhooks', {
        status: 200,
        body: mockApiResponse(MOCK_CREATE_RESULT),
      });

      const client = makeClient(true);
      await client.webhooks.create({
        tenantId: 't1',
        url: 'https://example.com/wh',
        eventTypes: ['event.type'],
      });
      const log = server.getCallLog();
      expect(log[0]!.headers['authorization']).toMatch(/^Bearer ok_/);
    });
  });

  describe('list() — ops protected', () => {
    it('throws ValidationError without tenantId', async () => {
      const client = makeClient(true);
      await expect(client.webhooks.list('')).rejects.toThrow();
    });

    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.webhooks.list('tenant-1')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('returns paginated webhook list with ops key', async () => {
      // Real array key is `endpoints`, not the generic PaginatedResponse's
      // `entries` — confirmed live during's SDK-accuracy sweep.
      const paginated: WebhookListResponse = {
        endpoints: [MOCK_ENDPOINT],
        page: 1,
        pageSize: 50,
        total: 1,
        totalItems: 1,
        totalPages: 1,
        hasNextPage: false,
        hasPreviousPage: false,
      };
      server.mock('GET', '/v1/webhooks', {
        status: 200,
        body: mockApiResponse(paginated),
      });

      const client = makeClient(true);
      const res = await client.webhooks.list('tenant-1');
      expect(res.data.endpoints).toHaveLength(1);
      expect(res.data.endpoints[0]!.id).toBe('wh-001');
    });

    it('sends tenantId as a query parameter', async () => {
      server.mock('GET', '/v1/webhooks', {
        status: 200,
        body: mockApiResponse({
          endpoints: [], page: 1, pageSize: 50, total: 0,
          totalItems: 0, totalPages: 0, hasNextPage: false, hasPreviousPage: false,
        } satisfies WebhookListResponse),
      });

      const client = makeClient(true);
      await client.webhooks.list('tenant-1');
      const log = server.getCallLog();
      expect(log[0]!.path).toContain('tenantId=tenant-1');
    });
  });

  describe('get()', () => {
    it('throws AuthenticationError without apiKey', async () => {
      const client = makeClient(false);
      await expect(client.webhooks.get('wh-001', 'tenant-1')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('returns webhook record with ops key', async () => {
      server.mock('GET', '/v1/webhooks/:id', {
        status: 200,
        body: mockApiResponse(MOCK_RECORD),
      });

      const client = makeClient(true);
      const res = await client.webhooks.get('wh-001', 'tenant-1');
      expect(res.data.endpoint.id).toBe('wh-001');
    });

    it('throws on empty id', async () => {
      const client = makeClient(true);
      await expect(client.webhooks.get('', 'tenant-1')).rejects.toThrow();
    });
  });

  describe('update()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(
        client.webhooks.update('wh-001', { enabled: false }, 'tenant-1'),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('updates a webhook with ops key', async () => {
      const updated: WebhookRecord = {
        endpoint: { ...MOCK_ENDPOINT, enabled: false },
      };
      server.mock('PATCH', '/v1/webhooks/:id', {
        status: 200,
        body: mockApiResponse(updated),
      });

      const client = makeClient(true);
      const res = await client.webhooks.update('wh-001', { enabled: false }, 'tenant-1');
      expect(res.data.endpoint.enabled).toBe(false);
    });
  });

  describe('delete()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(client.webhooks.delete('wh-001', 'tenant-1')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });

    it('deletes a webhook with ops key', async () => {
      server.mock('DELETE', '/v1/webhooks/:id', {
        status: 200,
        body: mockApiResponse(null),
      });

      const client = makeClient(true);
      const res = await client.webhooks.delete('wh-001', 'tenant-1');
      expect(res).toBeDefined();
    });
  });

  describe('test()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(client.webhooks.test('wh-001', 'tenant-1')).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });
  });

  describe('getDeliveries()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(
        client.webhooks.getDeliveries('wh-001', 'tenant-1'),
      ).rejects.toBeInstanceOf(AuthenticationError);
    });
  });

  describe('metrics()', () => {
    it('requires ops api key', async () => {
      const client = makeClient(false);
      await expect(client.webhooks.metrics()).rejects.toBeInstanceOf(
        AuthenticationError,
      );
    });
  });
});
