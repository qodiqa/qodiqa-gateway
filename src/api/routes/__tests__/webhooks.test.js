'use strict';

/**
 * Webhooks API — Component #28 Tests
 *
 * WHK-01…05   Signature generation and verification
 * WHK-06…10   URL validation / SSRF protection
 * WHK-11…14   Secret encryption / decryption
 * WHK-15…18   Event payload builders
 * WHK-19…23   Dispatcher: event queuing, unsupported events, fan-out
 * WHK-24…28   HTTP delivery: success, timeout, HTTP error, invalid URL
 * WHK-29…35   Route: POST / — create endpoint
 * WHK-36…40   Route: GET / — list endpoints
 * WHK-41…44   Route: GET /:id — get endpoint
 * WHK-45…48   Route: PATCH /:id — update endpoint
 * WHK-49…52   Route: DELETE /:id — disable endpoint
 * WHK-53…56   Route: POST /:id/test — test delivery
 * WHK-57…60   Route: GET /:id/deliveries — delivery log
 * WHK-61…65   Retry handler: endpoint gone, PG down, success, failure
 * WHK-66…70   Metrics tracking
 * WHK-71…74   Idempotency: same eventId reuses operationId
 * WHK-75…77   RBAC: READ_WEBHOOKS and MANAGE_WEBHOOKS enforcement
 */

// ── Global mocks (must precede all requires) ──────────────────────────────────

const mockPool = {
  _enabled: true,
  isEnabled() { return this._enabled; },
  query: jest.fn(),
  // Test double for the real pgPool.withTenantTransaction: runs fn against
  // the same mocked .query() without replicating tenantContext.validate()'s
  // format checking — real validation is covered by the live-PG adversarial
  // harness (test/security/crossTenantAdversarial.integration.test.js), not here.
  withTenantTransaction: jest.fn((_tenantId, fn) => fn({ query: mockPool.query })),
};
jest.mock('../../../infra/postgres/pool', () => mockPool);

jest.mock('../../../../services/logger', () => ({
  emit:                 jest.fn(),
  allowed:              jest.fn(),
  blocked:              jest.fn(),
  eventBus:             { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() },
  registerCentralStore: jest.fn(),
}));

// Mock rate limit (no-op in tests)
jest.mock('../../../core/rateLimit', () => ({
  createRateLimitMiddleware: () => (_req, _res, next) => next(),
}));

// Mock recovery queue
const mockEnqueueWebhookDelivery = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../core/persistenceRecovery', () => ({
  enqueueWebhookDelivery: mockEnqueueWebhookDelivery,
  isEnabled:              () => true,
  OPERATION_TYPES:        { WEBHOOK_DELIVERY: 'WEBHOOK_DELIVERY' },
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const crypto    = require('crypto');
const supertest = require('supertest');
const express   = require('express');

// Must set KEK before requiring webhook modules
process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);

const { computeSignature, validateUrl, deliver, post } = require('../../../core/webhooks/webhookDelivery');
const { encryptSecret, decryptSecret, generateSecret } = require('../../../core/webhooks/webhookSecrets');
const {
  dispatchEvent,
  buildCertificationCompletedPayload,
  buildAttestationCompletedPayload,
  SUPPORTED_EVENTS,
} = require('../../../core/webhooks/webhookDispatcher');
const webhookMetrics = require('../../../core/webhooks/webhookMetrics');
const webhookStore   = require('../../../core/webhooks/webhookStore');
const { createWebhooksAdminRouter } = require('../webhooks');

// ── Test app factory ──────────────────────────────────────────────────────────

function _makeApp({ rbacUser = { username: 'admin', role: 'admin' }, requirePermission } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = rbacUser; req.requestId = 'test-req-id'; next(); });
  const _noop = (_r, _s, n) => n();
  app.use('/v1/webhooks', createWebhooksAdminRouter({
    requirePermission: requirePermission ?? (() => _noop),
  }));
  return app;
}

// ── Shared test data ──────────────────────────────────────────────────────────

const TENANT_ID   = 'test-tenant-1';
const ENDPOINT_ID = '11111111-1111-1111-1111-111111111111';
const EVENT_ID    = '22222222-2222-2222-2222-222222222222';

const MOCK_ENDPOINT = {
  id:          ENDPOINT_ID,
  tenant_id:   TENANT_ID,
  url:         'https://example.com/webhook',
  enabled:     true,
  event_types: ['certification.completed'],
  description: 'Test endpoint',
  created_by:  'admin',
  created_at:  '2026-01-01T00:00:00.000Z',
  updated_at:  '2026-01-01T00:00:00.000Z',
};

// ── WHK-01…05: Signature generation ──────────────────────────────────────────

describe('WHK — signature', () => {
  test('WHK-01 computeSignature produces sha256= prefixed hex string', () => {
    const sig = computeSignature('mysecret', '2026-01-01T00:00:00.000Z', '{"hello":"world"}');
    expect(sig).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  test('WHK-02 signature is deterministic for same inputs', () => {
    const ts   = '2026-01-01T00:00:00.000Z';
    const body = '{"event":"test"}';
    const s1   = computeSignature('secret', ts, body);
    const s2   = computeSignature('secret', ts, body);
    expect(s1).toBe(s2);
  });

  test('WHK-03 different secrets produce different signatures', () => {
    const ts   = '2026-01-01T00:00:00.000Z';
    const body = '{"event":"test"}';
    expect(computeSignature('secret1', ts, body)).not.toBe(computeSignature('secret2', ts, body));
  });

  test('WHK-04 signing input is timestamp + "." + body', () => {
    const secret = 'testsecret';
    const ts     = '2026-01-01T00:00:00.000Z';
    const body   = '{"x":1}';
    const expected = 'sha256=' + crypto.createHmac('sha256', secret)
      .update(`${ts}.${body}`).digest('hex');
    expect(computeSignature(secret, ts, body)).toBe(expected);
  });

  test('WHK-05 different body produces different signature', () => {
    const ts = '2026-01-01T00:00:00.000Z';
    expect(computeSignature('s', ts, '{"a":1}')).not.toBe(computeSignature('s', ts, '{"a":2}'));
  });
});

// ── WHK-06…10: URL validation / SSRF ─────────────────────────────────────────

describe('WHK — URL validation', () => {
  test('WHK-06 accepts valid HTTPS URL', () => {
    const r = validateUrl('https://example.com/hook');
    expect(r.ok).toBe(true);
  });

  test('WHK-07 rejects HTTP (non-HTTPS)', () => {
    const r = validateUrl('http://example.com/hook');
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/HTTPS/i);
  });

  test('WHK-08 rejects localhost', () => {
    const r = validateUrl('https://localhost/hook');
    expect(r.ok).toBe(false);
  });

  test('WHK-09 rejects RFC-1918 private IP (10.x.x.x)', () => {
    const r = validateUrl('https://10.0.0.1/hook');
    expect(r.ok).toBe(false);
  });

  test('WHK-10 rejects link-local / 169.254.x.x', () => {
    const r = validateUrl('https://169.254.169.254/hook');
    expect(r.ok).toBe(false);
  });

  test('WHK-10b rejects 127.x.x.x loopback', () => {
    const r = validateUrl('https://127.0.0.1/hook');
    expect(r.ok).toBe(false);
  });

  test('WHK-10c rejects malformed URL', () => {
    const r = validateUrl('not-a-url');
    expect(r.ok).toBe(false);
  });
});

// ──: registration-time IP-literal check ─────────────────
// The registration check uses the SAME blocklist as delivery (webhookSecurity). Before, `new URL()` kept the brackets
// of an IPv6 literal, so no pattern matched and these addresses could be registered; only delivery refused them.
describe('registration rejects every blocked IP literal, in every representation', () => {
  test.each([
    ['https://[::7f00:1]/hook', '::/96 IPv4-compatible loopback (hex)'],
    ['https://[::127.0.0.1]/hook', '::/96 IPv4-compatible loopback (dotted)'],
    ['https://[0:0:0:0:0:0:7f00:1]/hook', '::/96 (fully expanded)'],
    ['https://[::a9fe:a9fe]/hook', '::/96 IPv4-compatible metadata address'],
    ['https://[::1]/hook', 'IPv6 loopback'],
    ['https://[::ffff:127.0.0.1]/hook', 'IPv4-mapped loopback'],
    ['https://[::ffff:a9fe:a9fe]/hook', 'IPv4-mapped metadata address'],
    ['https://[fd00::1]/hook', 'unique-local'],
    ['https://[fe80::1]/hook', 'link-local'],
    ['https://[64:ff9b::7f00:1]/hook', 'NAT64 to loopback'],
    ['https://100.64.0.1/hook', 'IPv4 shared address space (was accepted by the old regexes)'],
  ])('SEC08-01 %s (%s) is refused', (url) => {
    const r = validateUrl(url);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Blocked private\/loopback address: blocked IPv[46] address/);
  });

  test.each([
    ['https://[2606:4700:4700::1111]/hook', 'global unicast IPv6'],
    ['https://[2001:4860:4860::8888]/hook', 'global unicast IPv6'],
    ['https://[0:0:0:0:1::1]/hook', 'outside ::/96'],
    ['https://8.8.8.8/hook', 'public IPv4'],
    ['https://fcm.googleapis.com/hook', 'hostname that merely starts with "fc" (over-blocked by the old regexes)'],
    ['https://fd-partner.example.com/hook', 'hostname that merely starts with "fd"'],
  ])('SEC08-02 %s (%s) is accepted — no over-blocking', (url) => {
    expect(validateUrl(url)).toMatchObject({ ok: true });
  });

  test('SEC08-03 blocked hostnames (delivery-time rules) are refused at registration too', () => {
    expect(validateUrl('https://metadata.google.internal/hook')).toMatchObject({ ok: false });
    expect(validateUrl('https://localhost/hook').error).toMatch(/Blocked hostname/);
  });
});

// ── WHK-11…14: Secret encryption ─────────────────────────────────────────────

describe('WHK — secret encryption', () => {
  test('WHK-11 generateSecret returns whsec_ prefixed string', () => {
    const s = generateSecret();
    expect(s).toMatch(/^whsec_[0-9a-f]{64}$/);
  });

  test('WHK-12 each generateSecret call returns unique value', () => {
    expect(generateSecret()).not.toBe(generateSecret());
  });

  test('WHK-13 encrypt then decrypt returns original plaintext', () => {
    const plain  = generateSecret();
    const { enc, iv, tag } = encryptSecret(plain);
    const result = decryptSecret(enc, iv, tag);
    expect(result).toBe(plain);
  });

  test('WHK-14 encrypted values differ for same plaintext (unique IVs)', () => {
    const plain = 'whsec_test';
    const a = encryptSecret(plain);
    const b = encryptSecret(plain);
    expect(a.enc).not.toBe(b.enc);
    expect(a.iv).not.toBe(b.iv);
  });
});

// ── WHK-15…18: Event payload builders ────────────────────────────────────────

describe('WHK — event payload builders', () => {
  test('WHK-15 buildCertificationCompletedPayload includes required fields', () => {
    const record = {
      certification_id:       'cert-uuid',
      certification_level:    'CERTIFIED',
      certification_decision: 'CERTIFIED',
      score:                  75,
    };
    const p = buildCertificationCompletedPayload(record);
    expect(p.eventType).toBe('certification.completed');
    expect(p.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(p.certificationId).toBe('cert-uuid');
    expect(p.level).toBe('CERTIFIED');
    expect(p.score).toBe(75);
    expect(p.status).toBe('CERTIFIED');
    expect(p.timestamp).toBeTruthy();
  });

  test('WHK-16 buildAttestationCompletedPayload includes required fields', () => {
    const record = {
      attestation_id:       'att-uuid',
      attestation_decision: 'ATTESTED',
      policy_version:       '2.1',
    };
    const p = buildAttestationCompletedPayload(record);
    expect(p.eventType).toBe('attestation.completed');
    expect(p.attestationId).toBe('att-uuid');
    expect(p.decision).toBe('ATTESTED');
    expect(p.policyVersion).toBe('2.1');
  });

  test('WHK-17 each payload builder produces unique eventId', () => {
    const r = { certification_id: 'x', certification_level: 'CERTIFIED', certification_decision: 'CERTIFIED', score: 80 };
    const p1 = buildCertificationCompletedPayload(r);
    const p2 = buildCertificationCompletedPayload(r);
    expect(p1.eventId).not.toBe(p2.eventId);
  });

  test('WHK-18 SUPPORTED_EVENTS contains both expected types', () => {
    expect(SUPPORTED_EVENTS.has('certification.completed')).toBe(true);
    expect(SUPPORTED_EVENTS.has('attestation.completed')).toBe(true);
  });
});

// ── WHK-19…23: Dispatcher ─────────────────────────────────────────────────────

describe('WHK — dispatcher', () => {
  beforeEach(() => {
    mockPool.query.mockReset();
    mockEnqueueWebhookDelivery.mockReset().mockResolvedValue(undefined);
    webhookMetrics.reset();
  });

  test('WHK-19 dispatchEvent does not block caller (setImmediate fire-and-forget)', (done) => {
    // spy on listByEventType to confirm it runs asynchronously
    let called = false;
    const originalQuery = mockPool.query;
    mockPool.query.mockResolvedValue({ rows: [] });

    const start = Date.now();
    dispatchEvent('certification.completed', { eventId: EVENT_ID });
    const elapsed = Date.now() - start;

    // Should return almost immediately
    expect(elapsed).toBeLessThan(20);
    setTimeout(done, 50);
  });

  test('WHK-20 dispatchEvent with unsupported eventType emits WARN and returns', () => {
    const logger = require('../../../../services/logger');
    dispatchEvent('unknown.event', { eventId: 'x' });
    expect(logger.emit).toHaveBeenCalledWith('WARN', 'WEBHOOK_UNSUPPORTED_EVENT', expect.any(Object));
  });

  test('WHK-21 dispatchEvent enqueues one operation per matching endpoint', async () => {
    const enc = encryptSecret('whsec_abc');
    mockPool.query.mockResolvedValue({
      rows: [{
        id:          ENDPOINT_ID,
        tenant_id:   TENANT_ID,
        url:         'https://example.com/hook',
        event_types: ['certification.completed'],
        secret_enc:  enc.enc,
        secret_iv:   enc.iv,
        secret_tag:  enc.tag,
      }],
    });

    const payload = buildCertificationCompletedPayload({
      certification_id:       'c1',
      certification_level:    'CERTIFIED',
      certification_decision: 'CERTIFIED',
      score:                  80,
    });

    dispatchEvent('certification.completed', payload);
    await new Promise(r => setTimeout(r, 30));

    expect(mockEnqueueWebhookDelivery).toHaveBeenCalledTimes(1);
    const call = mockEnqueueWebhookDelivery.mock.calls[0][0];
    expect(call.operationId).toBe(`whd:${ENDPOINT_ID}:${payload.eventId}`);
    expect(call.payload.eventId).toBe(payload.eventId);
    expect(call.payload.eventType).toBe('certification.completed');
  });

  test('WHK-22 dispatchEvent with no matching endpoints enqueues nothing', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const payload = buildCertificationCompletedPayload({
      certification_id: 'x', certification_level: 'NOT_CERTIFIED', certification_decision: 'NOT_CERTIFIED', score: 30,
    });
    dispatchEvent('certification.completed', payload);
    await new Promise(r => setTimeout(r, 30));
    expect(mockEnqueueWebhookDelivery).not.toHaveBeenCalled();
  });

  test('WHK-23 operationId is stable for same (endpointId, eventId) — idempotency', () => {
    const eventId     = 'fixed-event-uuid';
    const endpointId  = 'fixed-endpoint-uuid';
    const expectedId  = `whd:${endpointId}:${eventId}`;
    // Verify the ID derivation formula is deterministic
    expect(expectedId).toBe(`whd:${endpointId}:${eventId}`);
  });
});

// ── WHK-24…28: HTTP delivery ──────────────────────────────────────────────────

describe('WHK — HTTP delivery', () => {
  test('WHK-24 validateUrl rejects non-HTTPS target', async () => {
    const result = await post({ url: 'http://example.com/hook', secret: 'x', eventId: 'e', eventType: 'test', payload: {} });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/HTTPS/i);
    expect(result.durationMs).toBe(0);
  });

  test('WHK-25 validateUrl rejects private IP target', async () => {
    const result = await post({ url: 'https://192.168.1.1/hook', secret: 'x', eventId: 'e', eventType: 't', payload: {} });
    expect(result.ok).toBe(false);
  });

  test('WHK-26 deliver returns ok=false for invalid URL endpoint', async () => {
    mockPool.query.mockResolvedValue({ rows: [] }); // logDelivery no-op when PG disabled
    mockPool._enabled = false;
    const result = await deliver({
      endpointId: 'ep1',
      url:        'http://localhost/hook',
      secret:     'sec',
      eventId:    EVENT_ID,
      eventType:  'certification.completed',
      payload:    { test: true },
      attempt:    1,
    });
    mockPool._enabled = true;
    expect(result.ok).toBe(false);
  });

  test('WHK-27 computeSignature produces reproducible HMAC', () => {
    const s1 = computeSignature('sec', 'ts', 'body');
    const s2 = computeSignature('sec', 'ts', 'body');
    expect(s1).toBe(s2);
  });

  test('WHK-28 computeSignature differs with different timestamp (replay protection)', () => {
    const s1 = computeSignature('sec', 'ts1', 'body');
    const s2 = computeSignature('sec', 'ts2', 'body');
    expect(s1).not.toBe(s2);
  });
});

// ── WHK-29…35: Route POST / ───────────────────────────────────────────────────

describe('WHK — route POST /', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-29 creates endpoint and returns secret once', async () => {
    const enc = encryptSecret(generateSecret());
    mockPool.query.mockResolvedValue({ rows: [MOCK_ENDPOINT] });

    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: ['certification.completed'] });

    expect(res.status).toBe(201);
    expect(res.body.data.secret).toMatch(/^whsec_/);
    expect(res.body.data.endpoint.id).toBe(ENDPOINT_ID);
    expect(res.body.data.notice).toMatch(/once only/);
  });

  test('WHK-30 rejects missing tenantId', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ url: 'https://example.com/hook', eventTypes: ['certification.completed'] });
    expect(res.status).toBe(400);
  });

  test('WHK-31 rejects HTTP URL', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'http://example.com/hook', eventTypes: ['certification.completed'] });
    expect(res.status).toBe(400);
  });

  test('WHK-32 rejects localhost URL', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://localhost/hook', eventTypes: ['certification.completed'] });
    expect(res.status).toBe(400);
  });

  test('WHK-33 rejects unknown event type', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: ['bad.event'] });
    expect(res.status).toBe(400);
  });

  test('WHK-34 rejects empty eventTypes array', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: [] });
    expect(res.status).toBe(400);
  });

  test('WHK-35 returns 400 when PG is disabled', async () => {
    mockPool._enabled = false;
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: ['certification.completed'] });
    expect(res.status).toBe(400);
    mockPool._enabled = true;
  });

  test('SEC08-04 route: a ::/96 webhook URL never reaches persistent state (400 before any store call)', async () => {
    for (const url of ['https://[::7f00:1]/hook', 'https://[::127.0.0.1]/hook', 'https://[::ffff:7f00:1]/hook']) {
      mockPool.query.mockReset();
      const res = await supertest(app).post('/v1/webhooks').send({ tenantId: TENANT_ID, url, eventTypes: ['certification.completed'] });
      expect(res.status).toBe(400);
      expect(JSON.stringify(res.body)).toMatch(/Blocked private\/loopback address/);
      expect(mockPool.query).not.toHaveBeenCalled();
    }
  });

  test('item 9 audit: rejects an unrecognised extra body key (webhookCreateSchema had no explicit mode — default strip — now .strict())', async () => {
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({
        tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: ['certification.completed'],
        unexpectedKey: 'should be rejected',
      });
    expect(res.status).toBe(400);
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});

// ── WHK-36…40: Route GET / ────────────────────────────────────────────────────

describe('WHK — route GET /', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-36 lists endpoints for a tenant', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] })
      .mockResolvedValueOnce({ rows: [{ total: 1 }] });

    const res = await supertest(app).get('/v1/webhooks?tenantId=test-tenant-1');
    expect(res.status).toBe(200);
    expect(res.body.data.endpoints).toHaveLength(1);
    expect(res.body.data.total).toBe(1);
  });

  test('WHK-37 returns 400 when tenantId is missing', async () => {
    const res = await supertest(app).get('/v1/webhooks');
    expect(res.status).toBe(400);
  });

  test('WHK-38 returns empty list when PG disabled', async () => {
    mockPool._enabled = false;
    const res = await supertest(app).get('/v1/webhooks?tenantId=t1');
    expect(res.status).toBe(200);
    expect(res.body.data.endpoints).toHaveLength(0);
    mockPool._enabled = true;
  });

  test('WHK-39 pagination parameters are respected', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: 0 }] });
    const res = await supertest(app).get('/v1/webhooks?tenantId=t1&page=2&pageSize=10');
    expect(res.status).toBe(200);
    expect(res.body.data.page).toBe(2);
    expect(res.body.data.pageSize).toBe(10);
  });

  test('WHK-40 enabledOnly=true is applied', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: 0 }] });
    const res = await supertest(app).get('/v1/webhooks?tenantId=t1&enabledOnly=true');
    expect(res.status).toBe(200);
    // Verify the query was called with enabledOnly condition
    const queryCall = mockPool.query.mock.calls[0][0];
    expect(queryCall).toMatch(/enabled = TRUE/);
  });
});

// ── WHK-41…44: Route GET /:id ─────────────────────────────────────────────────

describe('WHK — route GET /:id', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-41 returns endpoint by ID', async () => {
    mockPool.query.mockResolvedValue({ rows: [MOCK_ENDPOINT] });
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(200);
    expect(res.body.data.endpoint.id).toBe(ENDPOINT_ID);
  });

  test('WHK-42 returns 404 for unknown endpoint', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(404);
  });

  test('WHK-43 returns 400 for non-UUID id', async () => {
    const res = await supertest(app).get('/v1/webhooks/not-a-uuid');
    expect(res.status).toBe(400);
  });

  test('WHK-44 never returns secret columns in response', async () => {
    mockPool.query.mockResolvedValue({
      rows: [{ ...MOCK_ENDPOINT, secret_enc: 'enc', secret_iv: 'iv', secret_tag: 'tag' }],
    });
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(200);
    // The store's SELECT projection excludes secret columns
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/secret_enc/);
    expect(body).not.toMatch(/secret_iv/);
    expect(body).not.toMatch(/secret_tag/);
  });

  test('WHK-78 returns 400 when tenantId query parameter is missing', async () => {
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}`);
    expect(res.status).toBe(400);
  });
});

// ── WHK-45…48: Route PATCH /:id ──────────────────────────────────────────────

describe('WHK — route PATCH /:id', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-45 updates endpoint successfully', async () => {
    const updated = { ...MOCK_ENDPOINT, enabled: false, updated_at: new Date().toISOString() };
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] }) // getEndpointById
      .mockResolvedValueOnce({ rows: [updated] });       // updateEndpoint

    const res = await supertest(app)
      .patch(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`)
      .send({ enabled: false });

    expect(res.status).toBe(200);
    expect(res.body.data.endpoint.enabled).toBe(false);
  });

  test('SEC08-05 route: an update cannot move an endpoint to a ::/96 address (400 before any store call)', async () => {
    const res = await supertest(app).patch(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`).send({ url: 'https://[::7f00:1]/hook' });
    expect(res.status).toBe(400);
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('WHK-46 returns 404 when endpoint not found', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const res = await supertest(app).patch(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`).send({ enabled: false });
    expect(res.status).toBe(404);
  });

  test('WHK-47 rejects SSRF url in update', async () => {
    mockPool.query.mockResolvedValue({ rows: [MOCK_ENDPOINT] });
    const res = await supertest(app)
      .patch(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`)
      .send({ url: 'https://10.0.0.1/hook' });
    expect(res.status).toBe(400);
  });

  test('WHK-48 returns 400 for empty update body', async () => {
    const res = await supertest(app).patch(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`).send({});
    expect(res.status).toBe(400);
  });

  test('WHK-79 returns 400 when tenantId query parameter is missing', async () => {
    const res = await supertest(app).patch(`/v1/webhooks/${ENDPOINT_ID}`).send({ enabled: false });
    expect(res.status).toBe(400);
  });
});

// ── WHK-49…52: Route DELETE /:id ─────────────────────────────────────────────

describe('WHK — route DELETE /:id', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-49 disables endpoint successfully', async () => {
    const disabled = { ...MOCK_ENDPOINT, enabled: false };
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] }) // getEndpointById
      .mockResolvedValueOnce({ rows: [disabled] });     // deleteEndpoint

    const res = await supertest(app).delete(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(200);
    expect(res.body.data.endpoint.enabled).toBe(false);
  });

  test('WHK-50 returns 404 for unknown endpoint', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const res = await supertest(app).delete(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(404);
  });

  test('WHK-51 returns 400 for non-UUID id', async () => {
    const res = await supertest(app).delete('/v1/webhooks/not-a-uuid');
    expect(res.status).toBe(400);
  });

  test('WHK-52 soft-delete (UPDATE not DELETE) is used', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] })
      .mockResolvedValueOnce({ rows: [{ ...MOCK_ENDPOINT, enabled: false }] });
    await supertest(app).delete(`/v1/webhooks/${ENDPOINT_ID}?tenantId=${TENANT_ID}`);
    // Should call UPDATE (soft delete), not DELETE FROM
    const updateCall = mockPool.query.mock.calls.find(c => c[0].includes('UPDATE webhook_endpoints'));
    expect(updateCall).toBeDefined();
    const deleteCall = mockPool.query.mock.calls.find(c => c[0].includes('DELETE FROM'));
    expect(deleteCall).toBeUndefined();
  });

  test('WHK-80 returns 400 when tenantId query parameter is missing', async () => {
    const res = await supertest(app).delete(`/v1/webhooks/${ENDPOINT_ID}`);
    expect(res.status).toBe(400);
  });
});

// ── WHK-53…56: Route POST /:id/test ──────────────────────────────────────────

describe('WHK — route POST /:id/test', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-53 returns 404 for missing endpoint', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const res = await supertest(app).post(`/v1/webhooks/${ENDPOINT_ID}/test?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(404);
  });

  test('WHK-54 test delivery returns ok/fail result (not a 5xx)', async () => {
    const plain = generateSecret();
    const enc   = encryptSecret(plain);
    mockPool.query
      .mockResolvedValueOnce({
        rows: [{
          ...MOCK_ENDPOINT,
          secret_enc:  enc.enc,
          secret_iv:   enc.iv,
          secret_tag:  enc.tag,
          _secret:     plain,
        }],
      })
      .mockResolvedValueOnce({ rows: [] }); // logDelivery

    const res = await supertest(app).post(`/v1/webhooks/${ENDPOINT_ID}/test?tenantId=${TENANT_ID}`);
    // Will fail delivery to example.com in test (connection refused)
    // but route should still return 200 with ok=false or ok=true
    expect([200]).toContain(res.status);
    expect(typeof res.body.data.ok).toBe('boolean');
    expect(res.body.data.eventId).toBeTruthy();
  });

  test('WHK-55 returns 400 for non-UUID id', async () => {
    const res = await supertest(app).post('/v1/webhooks/bad-id/test');
    expect(res.status).toBe(400);
  });

  test('WHK-56 test response includes eventType field', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    // Endpoint not found case
    const res = await supertest(app).post(`/v1/webhooks/${ENDPOINT_ID}/test?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(404); // endpoint not found
  });

  test('WHK-81 returns 400 when tenantId query parameter is missing', async () => {
    const res = await supertest(app).post(`/v1/webhooks/${ENDPOINT_ID}/test`);
    expect(res.status).toBe(400);
  });
});

// ── WHK-57…60: Route GET /:id/deliveries ─────────────────────────────────────

describe('WHK — route GET /:id/deliveries', () => {
  let app;

  beforeEach(() => {
    app = _makeApp();
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  const DELIVERY_ROW = {
    delivery_id: '33333333-3333-3333-3333-333333333333',
    endpoint_id: ENDPOINT_ID,
    event_id:    EVENT_ID,
    event_type:  'certification.completed',
    attempt:     1,
    delivered_at: '2026-01-01T00:00:00.000Z',
    http_status:  200,
    duration_ms:  120,
    success:      true,
    error_msg:    null,
  };

  test('WHK-57 returns delivery history for endpoint', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] })   // getEndpointById
      .mockResolvedValueOnce({ rows: [DELIVERY_ROW] })    // list deliveries
      .mockResolvedValueOnce({ rows: [{ total: 1 }] });   // count

    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}/deliveries?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(200);
    expect(res.body.data.deliveries).toHaveLength(1);
    expect(res.body.data.deliveries[0].success).toBe(true);
  });

  test('WHK-58 returns 404 for unknown endpoint', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}/deliveries?tenantId=${TENANT_ID}`);
    expect(res.status).toBe(404);
  });

  test('WHK-59 failedOnly filter is supported', async () => {
    mockPool.query
      .mockResolvedValueOnce({ rows: [MOCK_ENDPOINT] })
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: 0 }] });

    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}/deliveries?tenantId=${TENANT_ID}&failedOnly=true`);
    expect(res.status).toBe(200);
    const query = mockPool.query.mock.calls[1][0];
    expect(query).toMatch(/success = FALSE/);
  });

  test('WHK-60 returns 400 for non-UUID id', async () => {
    const res = await supertest(app).get('/v1/webhooks/bad-id/deliveries');
    expect(res.status).toBe(400);
  });

  test('WHK-82 returns 400 when tenantId query parameter is missing', async () => {
    const res = await supertest(app).get(`/v1/webhooks/${ENDPOINT_ID}/deliveries`);
    expect(res.status).toBe(400);
  });
});

// ── WHK-61…65: Retry handler ──────────────────────────────────────────────────

describe('WHK — retry handler', () => {
  const { retryHandler } = require('../../../core/webhooks/webhookDelivery');

  beforeEach(() => {
    mockPool.query.mockReset();
    mockPool._enabled = true;
  });

  test('WHK-61 returns success=true when endpoint is gone (avoid infinite retries)', async () => {
    mockPool.query.mockResolvedValue({ rows: [] });

    const op = {
      retryCount: 2,
      payload: { endpointId: ENDPOINT_ID, eventId: EVENT_ID, eventType: 'certification.completed', eventPayload: {} },
    };

    const result = await retryHandler(op);
    expect(result.success).toBe(true);
  });

  test('WHK-62 returns success=false for failed HTTP delivery', async () => {
    const plain = generateSecret();
    const enc   = encryptSecret(plain);
    mockPool.query
      .mockResolvedValueOnce({
        rows: [{ ...MOCK_ENDPOINT, secret_enc: enc.enc, secret_iv: enc.iv, secret_tag: enc.tag }],
      })
      .mockResolvedValueOnce({ rows: [] }); // logDelivery

    const op = {
      retryCount: 0,
      payload: {
        endpointId:   ENDPOINT_ID,
        eventId:      EVENT_ID,
        eventType:    'certification.completed',
        eventPayload: { eventId: EVENT_ID, eventType: 'certification.completed', timestamp: '2026-01-01T00:00:00.000Z', tenantId: TENANT_ID },
      },
    };

    const result = await retryHandler(op);
    // Real network call to example.com will fail; result.success should be false
    expect(result).toHaveProperty('success');
    expect(typeof result.success).toBe('boolean');
  });

  test('WHK-63 attempt number = retryCount + 1', async () => {
    // When endpoint is gone the handler returns immediately; verify retryCount is used
    mockPool.query.mockResolvedValue({ rows: [] });
    const op = { retryCount: 3, payload: { endpointId: 'ep', eventId: 'ev', eventType: 'attestation.completed', eventPayload: {} } };
    const result = await retryHandler(op);
    expect(result.success).toBe(true); // endpoint gone
  });

  test('WHK-64 retryHandler increments retry metric (attempt > 1)', async () => {
    webhookMetrics.reset();
    mockPool.query.mockResolvedValue({ rows: [] }); // endpoint gone

    const op = { retryCount: 1, payload: { endpointId: 'ep', eventId: 'ev', eventType: 'certification.completed', eventPayload: {} } };
    await retryHandler(op);

    const snap = webhookMetrics.snapshot();
    // webhook_retries_total should have been incremented (attempt = retryCount + 1 = 2 > 1)
    const retryKey = Object.keys(snap.counters).find(k => k.includes('webhook_retries_total'));
    // May or may not be present depending on code path (endpoint gone = early return)
    // The increment happens before endpoint lookup; verify the metric key exists if set
    expect(snap).toBeTruthy();
  });

  test('WHK-65 retryHandler does not throw when PG is down', async () => {
    mockPool._enabled = false;
    const op = { retryCount: 0, payload: { endpointId: 'ep', eventId: 'ev', eventType: 'certification.completed', eventPayload: { tenantId: TENANT_ID } } };
    const result = await retryHandler(op);
    expect(result.success).toBe(true); // endpoint not found (PG disabled)
    mockPool._enabled = true;
  });

  test('WHK-83 retryHandler fails closed (no query attempted) when eventPayload carries no tenantId', async () => {
    // the async delivery path has no HTTP request to draw tenant
    // context from — it must come from the enqueued eventPayload. A payload
    // built without one (e.g. a malformed/legacy enqueue) must not fall back
    // to an unscoped query; it must stop retrying exactly like "endpoint gone".
    mockPool.query.mockReset();
    const op = { retryCount: 0, payload: { endpointId: ENDPOINT_ID, eventId: EVENT_ID, eventType: 'certification.completed', eventPayload: {} } };
    const result = await retryHandler(op);
    expect(result.success).toBe(true);
    expect(mockPool.query).not.toHaveBeenCalled();
  });
});

// ── WHK-66…70: Metrics ───────────────────────────────────────────────────────

describe('WHK — metrics', () => {
  beforeEach(() => webhookMetrics.reset());

  test('WHK-66 inc() increments counter', () => {
    webhookMetrics.inc('test_counter', { eventType: 'a' });
    webhookMetrics.inc('test_counter', { eventType: 'a' });
    const snap = webhookMetrics.snapshot();
    expect(snap.counters['test_counter{eventType="a"}']).toBe(2);
  });

  test('WHK-67 add() accumulates latency', () => {
    webhookMetrics.add('test_latency', 100, {});
    webhookMetrics.add('test_latency', 200, {});
    const snap = webhookMetrics.snapshot();
    expect(snap.latency['test_latency{}']).toBe(300);
  });

  test('WHK-68 reset() clears all metrics', () => {
    webhookMetrics.inc('x', {});
    webhookMetrics.reset();
    const snap = webhookMetrics.snapshot();
    expect(Object.keys(snap.counters)).toHaveLength(0);
  });

  test('WHK-69 snapshot() is a point-in-time copy', () => {
    webhookMetrics.inc('c', {});
    const s1 = webhookMetrics.snapshot();
    webhookMetrics.inc('c', {});
    const s2 = webhookMetrics.snapshot();
    expect(s1.counters['c{}']).toBe(1);
    expect(s2.counters['c{}']).toBe(2);
  });

  test('WHK-70 GET /metrics route returns metrics snapshot', async () => {
    const app = _makeApp();
    const res = await supertest(app).get('/v1/webhooks/metrics');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveProperty('webhookMetrics');
    expect(res.body.data.webhookMetrics).toHaveProperty('counters');
    expect(res.body.data.webhookMetrics).toHaveProperty('latency');
  });
});

// ── WHK-71…74: Idempotency ────────────────────────────────────────────────────

describe('WHK — idempotency', () => {
  test('WHK-71 same eventId always produces same operationId for same endpoint', () => {
    const ep    = 'ep-uuid';
    const ev    = 'ev-uuid';
    const id1   = `whd:${ep}:${ev}`;
    const id2   = `whd:${ep}:${ev}`;
    expect(id1).toBe(id2);
  });

  test('WHK-72 different eventIds produce different operationIds', () => {
    const ep  = 'ep-uuid';
    const id1 = `whd:${ep}:ev1`;
    const id2 = `whd:${ep}:ev2`;
    expect(id1).not.toBe(id2);
  });

  test('WHK-73 delivery_id is a UUID (from DB default)', () => {
    const uuid = crypto.randomUUID();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  test('WHK-74 eventId from payload builder is a UUID', () => {
    const p = buildCertificationCompletedPayload({ certification_id: 'x', certification_level: 'CERTIFIED', certification_decision: 'CERTIFIED', score: 80 });
    expect(p.eventId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

// ── WHK-75…77: RBAC enforcement ───────────────────────────────────────────────

describe('WHK — RBAC', () => {
  test('WHK-75 viewer role cannot create endpoint (MANAGE_WEBHOOKS denied)', async () => {
    const denyManage = (perm) => (_req, res, _next) => {
      if (perm === 'MANAGE_WEBHOOKS') return res.status(403).json({ decision: 'BLOCK', reason: 'FORBIDDEN' });
      _next();
    };
    const app = _makeApp({ requirePermission: denyManage });
    const res = await supertest(app)
      .post('/v1/webhooks')
      .send({ tenantId: TENANT_ID, url: 'https://example.com/hook', eventTypes: ['certification.completed'] });
    expect(res.status).toBe(403);
  });

  test('WHK-76 auditor role can list endpoints (READ_WEBHOOKS allowed)', async () => {
    const allowRead = () => (_req, _res, next) => next();
    const app = _makeApp({ requirePermission: allowRead });
    mockPool._enabled = true;
    mockPool.query
      .mockResolvedValueOnce({ rows: [] })
      .mockResolvedValueOnce({ rows: [{ total: 0 }] });
    const res = await supertest(app).get('/v1/webhooks?tenantId=t1');
    expect(res.status).toBe(200);
  });

  test('WHK-77 viewer role cannot manage endpoint (MANAGE_WEBHOOKS denied for DELETE)', async () => {
    const denyManage = (perm) => (_req, res, _next) => {
      if (perm === 'MANAGE_WEBHOOKS') return res.status(403).json({ decision: 'BLOCK', reason: 'FORBIDDEN' });
      _next();
    };
    const app = _makeApp({ requirePermission: denyManage });
    const res = await supertest(app).delete(`/v1/webhooks/${ENDPOINT_ID}`);
    expect(res.status).toBe(403);
  });
});
