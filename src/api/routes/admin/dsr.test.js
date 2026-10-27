'use strict';

/**
 * GDPR Data Subject Rights Administration API — route test suite.
 *
 * Mocks core/dsr/DataSubjectRightsService entirely — the underlying business
 * logic (identity verification, approval gating, anonymization, restriction,
 * export checksums) is covered by src/core/dsr/__tests__/*.test.js and
 * src/core/consent/consent.test.js. This suite covers: request validation,
 * RBAC gating (READ_DSR / MANAGE_DSR, using the real permission matrix),
 * response envelope shape, and error->HTTP status mapping.
 */

const mockService = {
  createRequest:   jest.fn(),
  verifyIdentity:  jest.fn(),
  approve:         jest.fn(),
  rectify:         jest.fn(),
  erase:           jest.fn(),
  restrict:        jest.fn(),
  liftRestriction: jest.fn(),
  generateExport:  jest.fn(),
  getRequest:      jest.fn(),
  listRequests:    jest.fn(),
  listEvents:      jest.fn(),
};

jest.mock('../../../core/dsr/DataSubjectRightsService', () => mockService);

const request = require('supertest');
const express = require('express');
const { isPermitted } = require('../../../core/rbac/roles');
const { createDsrRouter } = require('./dsr');

// ── Test app — mirrors the real requirePermission(permission) contract
//    (curried middleware, 403 FORBIDDEN, checks req.rbacUser.role against
//    the real permission matrix) without pulling in the full ops-auth stack. ──

function makeApp({ role = 'admin', withPermissionCheck = true } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.rbacUser = { id: 'u1', username: 'tester', role }; next(); });

  const requirePermission = withPermissionCheck
    ? (permission) => (req, res, next) => {
        if (!isPermitted(req.rbacUser?.role, permission)) {
          return res.status(403).json({ error: 'FORBIDDEN', message: 'Insufficient permissions' });
        }
        next();
      }
    : undefined;

  app.use('/v1/admin/dsr', createDsrRouter({ requirePermission }));
  return app;
}

const UUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';

beforeEach(() => jest.clearAllMocks());

describe('RBAC gating', () => {
  test('viewer role can GET (READ_DSR) but not POST (MANAGE_DSR)', async () => {
    const app = makeApp({ role: 'viewer' });
    mockService.listRequests.mockResolvedValue({ requests: [], total: 0 });

    await request(app).get('/v1/admin/dsr').expect(403);
  });

  test('auditor role (has READ_DSR, not MANAGE_DSR) can list but not create', async () => {
    const app = makeApp({ role: 'auditor' });
    mockService.listRequests.mockResolvedValue({ requests: [], total: 0 });

    await request(app).get('/v1/admin/dsr').expect(200);
    await request(app).post('/v1/admin/dsr').send({ requestType: 'ERASURE', actorId: 'a1' }).expect(403);
  });

  test('compliance role (has MANAGE_DSR) can create requests', async () => {
    const app = makeApp({ role: 'compliance' });
    mockService.createRequest.mockResolvedValue({ id: UUID, status: 'RECEIVED' });

    await request(app)
      .post('/v1/admin/dsr')
      .send({ requestType: 'ERASURE', actorId: 'actor-1' })
      .expect(201);
  });

  test('no requirePermission wired (undefined) falls open to _noop, matching every other admin router', async () => {
    const app = makeApp({ role: 'viewer', withPermissionCheck: false });
    mockService.listRequests.mockResolvedValue({ requests: [], total: 0 });
    await request(app).get('/v1/admin/dsr').expect(200);
  });
});

describe('GET /v1/admin/dsr', () => {
  test('lists requests with the success envelope', async () => {
    const app = makeApp();
    mockService.listRequests.mockResolvedValue({ requests: [{ id: UUID }], total: 1 });

    const res = await request(app).get('/v1/admin/dsr').expect(200);
    expect(res.body.status).toBe('success');
    expect(res.body.data.requests).toHaveLength(1);
  });

  test('rejects an invalid status filter', async () => {
    const app = makeApp();
    const res = await request(app).get('/v1/admin/dsr?status=NOT_A_STATUS').expect(400);
    expect(res.body.error.code).toBe('INVALID_QUERY');
  });
});

describe('GET /v1/admin/dsr/:id', () => {
  test('404s when the request does not exist', async () => {
    const app = makeApp();
    mockService.getRequest.mockResolvedValue(null);
    const res = await request(app).get(`/v1/admin/dsr/${UUID}`).expect(404);
    expect(res.body.error.code).toBe('DSR_REQUEST_NOT_FOUND');
  });

  test('returns request + event trail', async () => {
    const app = makeApp();
    mockService.getRequest.mockResolvedValue({ id: UUID, status: 'COMPLETED' });
    mockService.listEvents.mockResolvedValue([{ event_type: 'DSR_REQUEST_RECEIVED' }]);

    const res = await request(app).get(`/v1/admin/dsr/${UUID}`).expect(200);
    expect(res.body.data.request.id).toBe(UUID);
    expect(res.body.data.events).toHaveLength(1);
  });

  test('rejects a non-UUID id', async () => {
    const app = makeApp();
    await request(app).get('/v1/admin/dsr/not-a-uuid').expect(400);
  });
});

describe('POST /v1/admin/dsr — create', () => {
  test('rejects a missing actorId', async () => {
    const app = makeApp();
    const res = await request(app).post('/v1/admin/dsr').send({ requestType: 'ERASURE' }).expect(400);
    expect(res.body.error.code).toBe('INVALID_BODY');
  });

  test('rejects an unknown requestType', async () => {
    const app = makeApp();
    await request(app).post('/v1/admin/dsr').send({ requestType: 'DESTROY_EVERYTHING', actorId: 'a1' }).expect(400);
  });

  test('defaults requestedBy to the authenticated rbacUser', async () => {
    const app = makeApp();
    mockService.createRequest.mockResolvedValue({ id: UUID });

    await request(app).post('/v1/admin/dsr').send({ requestType: 'PORTABILITY', actorId: 'actor-1' }).expect(201);
    expect(mockService.createRequest).toHaveBeenCalledWith(expect.objectContaining({ requested_by: 'tester' }));
  });

  test('item 9 audit: rejects an unrecognised extra body key (dsrCreateRequestSchema was .passthrough(), now .strict())', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/v1/admin/dsr')
      .send({ requestType: 'PORTABILITY', actorId: 'actor-1', unexpectedKey: 'should be rejected' })
      .expect(400);
    expect(res.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: null,
      error:     { code: 'INVALID_BODY', message: expect.any(String) },
    });
    expect(mockService.createRequest).not.toHaveBeenCalled();
  });
});

describe('full lifecycle happy path (mocked service)', () => {
  test('verify-identity -> approve -> rectify', async () => {
    const app = makeApp();
    mockService.verifyIdentity.mockResolvedValue({ id: UUID, status: 'IDENTITY_VERIFIED' });
    mockService.approve.mockResolvedValue({ id: UUID, status: 'APPROVED' });
    mockService.rectify.mockResolvedValue({ id: UUID, status: 'COMPLETED' });

    await request(app)
      .post(`/v1/admin/dsr/${UUID}/verify-identity`)
      .send({ method: 'OPERATOR_ATTESTATION', result: 'VERIFIED' })
      .expect(200);

    await request(app).post(`/v1/admin/dsr/${UUID}/approve`).send({}).expect(200);

    const res = await request(app)
      .post(`/v1/admin/dsr/${UUID}/rectify`)
      .send({ consentId: UUID, fields: { subject_name: 'New Name' } })
      .expect(200);
    expect(res.body.data.status).toBe('COMPLETED');
  });

  test('(D5-A): erase always pseudonymizes — pseudonymizeActorId is accepted for compatibility and ignored', async () => {
    const app = makeApp();
    mockService.erase.mockResolvedValue({ id: UUID, status: 'COMPLETED' });

    await request(app)
      .post(`/v1/admin/dsr/${UUID}/erase`)
      .send({ pseudonymizeActorId: false })
      .expect(200);
    expect(mockService.erase).toHaveBeenCalledWith({ requestId: UUID, tenantId: null, erasedBy: 'tester' });
  });

  test('restrict then lift', async () => {
    const app = makeApp();
    mockService.restrict.mockResolvedValue({ id: UUID, status: 'COMPLETED' });
    mockService.liftRestriction.mockResolvedValue({ id: UUID, status: 'COMPLETED' });

    await request(app).post(`/v1/admin/dsr/${UUID}/restrict`).send({ reason: 'subject request' }).expect(200);
    await request(app).post(`/v1/admin/dsr/${UUID}/lift`).send({}).expect(200);
  });

  test('export returns the payload and checksum inline', async () => {
    const app = makeApp();
    mockService.generateExport.mockResolvedValue({ payload: '{"ok":true}', format: 'JSON', checksum: 'abc', sizeBytes: 12 });

    const res = await request(app).post(`/v1/admin/dsr/${UUID}/export`).send({ format: 'JSON' }).expect(200);
    expect(res.body.data.checksum).toBe('abc');
    expect(res.body.data.payload).toBe('{"ok":true}');
  });
});

describe('error -> HTTP status mapping', () => {
  test('gate failure ("not approved for execution") maps to 409', async () => {
    const app = makeApp();
    mockService.rectify.mockRejectedValue(new Error('DSR request req-1 is not approved for execution (status=RECEIVED)'));

    const res = await request(app)
      .post(`/v1/admin/dsr/${UUID}/rectify`)
      .send({ consentId: UUID, fields: { subject_name: 'X' } })
      .expect(409);
    expect(res.body.error.code).toBe('DSR_GATE_FAILED');
  });

  test('not-found error maps to 404', async () => {
    const app = makeApp();
    mockService.erase.mockRejectedValue(new Error('DSR request not found: req-1'));

    const res = await request(app).post(`/v1/admin/dsr/${UUID}/erase`).send({}).expect(404);
    expect(res.body.error.code).toBe('DSR_REQUEST_NOT_FOUND');
  });

  test('unclassified failure routes through the centralized handler: 500, sanitized envelope, byte-exact', async () => {
    const app = makeApp();
    mockService.restrict.mockRejectedValue(new Error('unexpected db error'));

    const res = await request(app).post(`/v1/admin/dsr/${UUID}/restrict`).send({}).expect(500);
    expect(res.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: null,
      error:     { code: 'DSR_OPERATION_FAILED', message: 'An unexpected error occurred' },
    });
  });

  test('unclassified failure never leaks err.message, driver/SQL internals, or a stack trace to the client', async () => {
    const app = makeApp();
    const sensitive = new Error(
      'connection to 10.0.0.7:5432 failed: password authentication failed for user "qodiqa_app" ' +
      'at Object.query (/src/core/dsr/DSRStore.js:184:11)',
    );
    mockService.rectify.mockRejectedValue(sensitive);

    const res = await request(app)
      .post(`/v1/admin/dsr/${UUID}/rectify`)
      .send({ consentId: UUID, fields: { subject_name: 'X' } })
      .expect(500);

    const raw = JSON.stringify(res.body);
    expect(raw).not.toContain('10.0.0.7');
    expect(raw).not.toContain('password authentication failed');
    expect(raw).not.toContain('DSRStore.js');
    expect(raw).not.toContain('qodiqa_app');
    expect(res.body.error.message).toBe('An unexpected error occurred');
    expect(res.body.error.stack).toBeUndefined();
  });

  test('gate-failure and not-found classifications still surface their deliberate, safe domain message (unchanged)', async () => {
    const app = makeApp();
    mockService.erase.mockRejectedValue(new Error('DSR request not found: some-id'));
    const res = await request(app).post(`/v1/admin/dsr/${UUID}/erase`).send({}).expect(404);
    expect(res.body.error.message).toBe('DSR request not found: some-id');
  });
});

describe('405 catch-all', () => {
  test('unsupported method under the mount is rejected', async () => {
    const app = makeApp();
    await request(app).delete(`/v1/admin/dsr/${UUID}`).expect(405);
  });
});

// ── operator identities come from the session only ─────────
describe('D10: DSR identities and lifecycle refusals', () => {
  test.each([
    ['post', '', { requestType: 'ERASURE', actorId: 'subject-1', requestedBy: 'someone-else' }, 'createRequest', 'requested_by'],
    ['post', '/verify-identity', { method: 'OPERATOR_ATTESTATION', result: 'VERIFIED', verifiedBy: 'someone-else' }, 'verifyIdentity', 'verifiedBy'],
    ['post', '/approve', { approvedBy: 'someone-else' }, 'approve', 'approvedBy'],
    ['post', '/erase', { erasedBy: 'someone-else' }, 'erase', 'erasedBy'],
    ['post', '/restrict', { restrictedBy: 'someone-else' }, 'restrict', 'restrictedBy'],
  ])('%s %s: a body identity is ignored — the authenticated operator is recorded', async (method, suffix, body, fn, field) => {
    const app = makeApp();
    mockService[fn].mockResolvedValue({ id: UUID, status: 'OK' });
    const url = suffix ? `/v1/admin/dsr/${UUID}${suffix}` : '/v1/admin/dsr';
    const res = await request(app)[method](url).send(body);
    expect(res.status).toBeLessThan(300);
    expect(mockService[fn].mock.calls[0][0][field]).toBe('tester');
  });

  test('approve by the requester or identity verifier → 403 DSR_SELF_APPROVAL_FORBIDDEN', async () => {
    const app = makeApp();
    mockService.approve.mockRejectedValue(Object.assign(new Error('the requester (tester) may not approve their own request'),
      { code: 'DSR_SELF_APPROVAL_FORBIDDEN', statusCode: 403 }));
    const res = await request(app).post(`/v1/admin/dsr/${UUID}/approve`).send({});
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('DSR_SELF_APPROVAL_FORBIDDEN');
  });

  test('a disallowed status transition (e.g. re-approving a COMPLETED request) → 409 DSR_INVALID_TRANSITION', async () => {
    const app = makeApp();
    mockService.approve.mockRejectedValue(Object.assign(new Error('status transition COMPLETED → APPROVED is not allowed'),
      { code: 'DSR_INVALID_TRANSITION', statusCode: 409 }));
    const res = await request(app).post(`/v1/admin/dsr/${UUID}/approve`).send({});
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('DSR_INVALID_TRANSITION');
  });
});
