'use strict';

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));

const { createPortalSessionMiddleware } = require('../portalAuth');

function mockReqRes(headers = {}) {
  const req = { headers, requestId: 'req-1', clientIp: '127.0.0.1', path: '/tenant-portal/api/me', method: 'GET' };
  const res = {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  return { req, res };
}

// tenantId added — a real store record always carries it (tenantPortalUserStore.findOrCreateByIdpSubject), and
// the middleware now binds the token's tenant to it; the earlier fixture omitted the field only because nothing read it.
const VALID_USER = { id: 'pu_1', tenantId: 'acme', email: 'a@acme.example', idpSubject: 'sub-1', role: 'tenant', enabled: true };

describe('createPortalSessionMiddleware', () => {
  test('throws if verifySessionToken or getPortalUserById is missing', () => {
    expect(() => createPortalSessionMiddleware({})).toThrow(/verifySessionToken/);
    expect(() => createPortalSessionMiddleware({ verifySessionToken: () => {} })).toThrow(/getPortalUserById/);
  });

  test('missing Authorization header -> 401, next() not called', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn(),
      getPortalUserById:  jest.fn(),
    });
    const { req, res } = mockReqRes({});
    mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect(req.rbacUser).toBeUndefined();
  });

  test('invalid/expired token (verifySessionToken returns null) -> 401', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue(null),
      getPortalUserById:  jest.fn(),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_bad.deadbeef' });
    mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('valid token but unknown/deleted portal user -> 401', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }),
      getPortalUserById:  jest.fn().mockReturnValue(null),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('valid token but DISABLED portal user -> 401', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }),
      getPortalUserById:  jest.fn().mockReturnValue({ ...VALID_USER, enabled: false }),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('valid token + enabled user -> req.rbacUser and req.tenantContext set, next() called', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }),
      getPortalUserById:  jest.fn().mockReturnValue(VALID_USER),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    mw(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.rbacUser).toEqual({ id: 'pu_1', username: 'a@acme.example', role: 'tenant', enabled: true });
    expect(req.tenantContext).toEqual({ tenantId: 'acme' });
    expect(Object.isFrozen(req.rbacUser)).toBe(true);
    expect(Object.isFrozen(req.tenantContext)).toBe(true);
  });

  test('a forged X-Tenant-ID header has NO EFFECT — req.tenantContext still comes from the token', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }),
      getPortalUserById:  jest.fn().mockReturnValue(VALID_USER),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y', 'x-tenant-id': 'globex' });
    mw(req, res, next);
    expect(req.tenantContext).toEqual({ tenantId: 'acme' });
  });

  test('role is re-read from the STORE record, not trusted from the verified token alone', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      // Token claims role='tenant', but the store record (source of truth
      // for role) says something else — the store wins.
      verifySessionToken: jest.fn().mockReturnValue({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }),
      getPortalUserById:  jest.fn().mockReturnValue({ ...VALID_USER, role: 'tenant' }),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    mw(req, res, next);
    expect(req.rbacUser.role).toBe('tenant');
  });

  test('verifySessionToken throwing is treated as a failure, not a crash — 401, never 500', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockImplementation(() => { throw new Error('boom'); }),
      getPortalUserById:  jest.fn(),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    expect(() => mw(req, res, next)).not.toThrow();
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('a non-Bearer Authorization scheme is rejected', () => {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn(),
      getPortalUserById:  jest.fn(),
    });
    const { req, res } = mockReqRes({ authorization: 'Basic dXNlcjpwYXNz' });
    mw(req, res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });
});

// ── server-side revocation ────────────────────────────────────
describe('createPortalSessionMiddleware — session revocation', () => {
  function run(claims, user) {
    const next = jest.fn();
    const mw = createPortalSessionMiddleware({
      verifySessionToken: jest.fn().mockReturnValue(claims),
      getPortalUserById:  jest.fn().mockReturnValue(user),
    });
    const { req, res } = mockReqRes({ authorization: 'Bearer pt_x.y' });
    mw(req, res, next);
    return { next, req, res };
  }
  const CLAIMS = { portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant', sessionVersion: 0 };

  test('DD095-M1 token version below the record version (revoked) -> 401, next() not called', () => {
    const { next, res, req } = run(CLAIMS, { ...VALID_USER, sessionVersion: 1 });
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
    expect(req.rbacUser).toBeUndefined();
  });

  test('DD095-M2 token minted at the current version -> accepted; req.portalSession carries it', () => {
    const { next, req } = run({ ...CLAIMS, sessionVersion: 3 }, { ...VALID_USER, sessionVersion: 3 });
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.portalSession).toEqual({ portalUserId: 'pu_1', sessionVersion: 3 });
  });

  test('DD095-M3 a token version AHEAD of the record is refused too (never accepted on mismatch)', () => {
    const { next, res } = run({ ...CLAIMS, sessionVersion: 2 }, { ...VALID_USER, sessionVersion: 1 });
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('DD095-M4 old-format token (no sessionVersion claim) + never-revoked record -> still accepted', () => {
    const { next } = run({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }, VALID_USER);
    expect(next).toHaveBeenCalledTimes(1);
  });

  test('DD095-M5 old-format token after the user was revoked once -> 401', () => {
    const { next, res } = run({ portalUserId: 'pu_1', tenantId: 'acme', role: 'tenant' }, { ...VALID_USER, sessionVersion: 1 });
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('DD095-M6 role changed on the record since the token was minted -> 401 (session ends, not silently re-scoped)', () => {
    const { next, res } = run(CLAIMS, { ...VALID_USER, role: 'viewer' });
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('DD095-M7 tenant changed on the record since the token was minted -> 401', () => {
    const { next, res } = run(CLAIMS, { ...VALID_USER, tenantId: 'globex' });
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('DD095-M8 the denial reason is logged as SESSION_REVOKED', () => {
    const { emit } = require('../../../services/logger');
    emit.mockClear();
    run(CLAIMS, { ...VALID_USER, sessionVersion: 5 });
    const denied = emit.mock.calls.find(([, code]) => code === 'PORTAL_AUTH_DENIED');
    expect(denied[2].reason).toBe('SESSION_REVOKED');
  });
});
