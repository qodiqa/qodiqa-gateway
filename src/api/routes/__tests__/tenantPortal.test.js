'use strict';

/**
 * Tenant Portal route integration tests —.
 *
 * Uses the REAL createPortalSessionMiddleware + REAL portalSessionToken +
 * REAL rbacResolve/requirePermission (src/core/rbac/authorize.js) — the
 * exact chain server/startup.js wires in production — so these tests prove
 * the actual authorization/tenant-isolation integration, not a stand-in.
 * Only the data-layer modules the route file requires directly
 * (tenantRegistry, portalUserStore, consentRegistry, tenantKeyManager,
 * oidcClient) are mocked, since those own their own dedicated test files.
 */

const request = require('supertest');
const express = require('express');

const SECRET = 'd'.repeat(64);

function freshApp(overrides = {}) {
  jest.resetModules();
  process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;

  const mockTenants = overrides.tenants || {
    acme:   { tenantId: 'acme', tenantName: 'Acme Corp', status: 'active' },
    globex: { tenantId: 'globex', tenantName: 'Globex Inc', status: 'active' },
  };
  jest.doMock('../../../core/tenancy/tenantRegistry', () => ({
    getTenant: jest.fn((id) => mockTenants[id] || null),
    assertActiveTenant: jest.fn((id) => {
      const t = mockTenants[id];
      if (!t) return { valid: false, reason: 'TENANT_UNKNOWN' };
      if (t.status !== 'active') return { valid: false, reason: 'TENANT_INACTIVE' };
      return { valid: true, tenant: t };
    }),
  }));

  const mockUsers = new Map(); // id -> record
  jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({
    findOrCreateByIdpSubject: jest.fn(({ tenantId }) => {
      const id = `pu_${tenantId}`;
      const rec = mockUsers.get(id) || { id, tenantId, role: 'tenant', enabled: true, email: `u@${tenantId}.example`, idpSubject: 'sub' };
      mockUsers.set(id, rec);
      return rec;
    }),
    getById: jest.fn((id) => mockUsers.get(id) || null),
    // same contract as the real store (increment from the stored value; null when unknown).
    revokeSessions: jest.fn((id) => {
      if (overrides.revokeFails) return Promise.reject(Object.assign(new Error('stale'), { code: 'CONTROL_PLANE_STALE' }));
      const r = mockUsers.get(id);
      if (!r) return null;
      const n = { ...r, sessionVersion: (Number.isSafeInteger(r.sessionVersion) ? r.sessionVersion : 0) + 1 };
      mockUsers.set(id, n);
      return n;
    }),
  }));

  const mockConsent = overrides.consentByTenant || {};
  jest.doMock('../../../core/consent', () => ({
    list: jest.fn(async ({ tenant_id }) => ({
      records: mockConsent[tenant_id] || [],
      total: (mockConsent[tenant_id] || []).length,
    })),
  }));

  const mockKeyStatus = overrides.keyStatusByTenant || {};
  jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({
    getTenantKeyStatus: jest.fn((tenantId) => mockKeyStatus[tenantId] || {
      clientId: tenantId, status: 'HEALTHY', issues: [], activeKey: null, keyCount: 0, activeKeyCount: 0,
    }),
  }));

  jest.doMock('../../../core/portal/oidcClient', () => ({
    buildAuthorizationUrl: jest.fn(async () => 'https://idp.example.com/authorize?mock=1'),
    exchangeCode: jest.fn(),
  }));

  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

  const { createTenantPortalRouter } = require('../tenantPortal');
  const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
  const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
  const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
  const { mintSessionToken } = require('../../../../services/portal/portalSessionToken');

  const portalUserStore = require('../../../core/portal/tenantPortalUserStore');
  const portalSessionAuth = createPortalSessionMiddleware({
    verifySessionToken: require('../../../../services/portal/portalSessionToken').verifySessionToken,
    getPortalUserById:  portalUserStore.getById,
  });
  const rbacResolve = createRbacResolveMiddleware({});
  const requirePermission = createRequirePermission({ isPermitted, isValidPermission });

  const router = createTenantPortalRouter({
    requirePermission,
    portalSessionAuth,
    rbacResolve,
    rateLimit: (req, res, next) => next(),
  });

  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
  app.use('/tenant-portal', router);

  // Seed a portal user directly so tests can mint a matching token without
  // driving the full OIDC callback flow (that flow is covered separately).
  function seedUser(tenantId, overridesRec = {}) {
    const id = `pu_${tenantId}`;
    const rec = { id, tenantId, role: 'tenant', enabled: true, email: `u@${tenantId}.example`, idpSubject: 'sub', ...overridesRec };
    mockUsers.set(id, rec);
    return rec;
  }

  function tokenFor(tenantId, recOverrides = {}) {
    const rec = seedUser(tenantId, recOverrides);
    return mintSessionToken({ portalUserId: rec.id, tenantId: rec.tenantId, role: rec.role, sessionVersion: rec.sessionVersion });
  }

  return { app, tokenFor, seedUser, mockUsers };
}

afterEach(() => {
  delete process.env.QODIQA_PORTAL_SESSION_SECRET;
  delete process.env.NODE_ENV_ORIGINAL;
  jest.dontMock('../../../core/tenancy/tenantRegistry');
  jest.dontMock('../../../core/portal/tenantPortalUserStore');
  jest.dontMock('../../../core/consent');
  jest.dontMock('../../../../services/artifact/tenantKeyManager');
  jest.dontMock('../../../core/portal/oidcClient');
  jest.dontMock('../../../../services/logger');
});

describe('authentication', () => {
  test('GET /tenant-portal/api/me without a token -> 401', async () => {
    const { app } = freshApp();
    const r = await request(app).get('/tenant-portal/api/me');
    expect(r.status).toBe(401);
  });

  test('GET /tenant-portal/api/me with an invalid token -> 401', async () => {
    const { app } = freshApp();
    const r = await request(app).get('/tenant-portal/api/me').set('Authorization', 'Bearer pt_garbage.deadbeef');
    expect(r.status).toBe(401);
  });

  test('GET /tenant-portal/api/me with an EXPIRED token -> 401', async () => {
    const { app, tokenFor } = freshApp();
    process.env.QODIQA_PORTAL_SESSION_TTL_MS = '1';
    const token = tokenFor('acme');
    delete process.env.QODIQA_PORTAL_SESSION_TTL_MS;
    await new Promise((r) => setTimeout(r, 20));
    const r = await request(app).get('/tenant-portal/api/me').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(401);
  });

  test('GET /tenant-portal/api/me for a DISABLED portal user -> 401', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme', { enabled: false });
    const r = await request(app).get('/tenant-portal/api/me').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(401);
  });

  test('a valid token authenticates successfully', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    const r = await request(app).get('/tenant-portal/api/me').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(200);
    expect(r.body.data.tenantId).toBe('acme');
  });

  // logout now ends the session SERVER-SIDE, so it authenticates the session it ends. this
  // test asserted the opposite ("succeeds without requiring re-authentication (stateless token)") — an
  // unauthenticated no-op 200; the server-side revocation itself is proven in the describe block below.
  test('POST /tenant-portal/logout WITHOUT a token -> 401', async () => {
    const { app } = freshApp();
    const r = await request(app).post('/tenant-portal/logout');
    expect(r.status).toBe(401);
  });
});

// -- server-side revocation through the real middleware + real tokens --
describe('portal session revocation', () => {
  const crypto = require('crypto');
  const me = (app, token) => request(app).get('/tenant-portal/api/me').set('Authorization', `Bearer ${token}`);
  const mintFor = (rec, sessionVersion) => require('../../../../services/portal/portalSessionToken')
    .mintSessionToken({ portalUserId: rec.id, tenantId: rec.tenantId, role: rec.role, sessionVersion });

  test('DD095-R1 self-service logout revokes the session server-side: the SAME token is refused immediately', async () => {
    const { app, tokenFor } = freshApp();
    const token = tokenFor('acme');
    expect((await me(app, token)).status).toBe(200);
    const out = await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${token}`);
    expect(out.status).toBe(200);
    expect(out.body.data).toEqual({ loggedOut: true, sessionsRevoked: true });
    expect((await me(app, token)).status).toBe(401);
  });

  test('DD095-R2 logout ends every session of that user (all tabs/devices), and only that user', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const tokenA1 = tokenFor('acme');
    const tokenA2 = mintFor(mockUsers.get('pu_acme'));
    const tokenB = tokenFor('globex');
    await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${tokenA1}`).expect(200);
    expect((await me(app, tokenA2)).status).toBe(401);
    expect((await me(app, tokenB)).status).toBe(200); // other users unaffected
  });

  test('DD095-R3 a fresh login after revocation (token at the new version) works; the old token stays dead', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const old = tokenFor('acme');
    await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${old}`).expect(200);
    const r = mockUsers.get('pu_acme');
    const fresh = mintFor(r, r.sessionVersion);
    expect((await me(app, fresh)).status).toBe(200);
    expect((await me(app, old)).status).toBe(401);
  });

  test('DD095-R4 logout with an already-revoked or invalid token -> 401 (no second revoke)', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const token = tokenFor('acme');
    await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${token}`).expect(200);
    expect((await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${token}`)).status).toBe(401);
    expect((await request(app).post('/tenant-portal/logout').set('Authorization', 'Bearer pt_garbage.deadbeef')).status).toBe(401);
    expect(mockUsers.get('pu_acme').sessionVersion).toBe(1);
  });

  test('DD095-R5 logout cannot revoke someone else: a body naming another user/tenant is ignored', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const tokenA = tokenFor('acme');
    tokenFor('globex');
    await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${tokenA}`)
      .send({ portalUserId: 'pu_globex', tenantId: 'globex' }).expect(200);
    expect(mockUsers.get('pu_globex').sessionVersion).toBeUndefined();
    expect(mockUsers.get('pu_acme').sessionVersion).toBe(1);
  });

  test('DD095-R6 a refused revoke write fails closed: 503, and the client is not told the session ended', async () => {
    const { app, tokenFor } = freshApp({ revokeFails: true });
    const token = tokenFor('acme');
    const r = await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(503);
    expect(r.body.data).toBeUndefined();
  });

  test('DD095-R7 an operator revoke (version bumped on the record) kills an outstanding token immediately', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const token = tokenFor('acme');
    expect((await me(app, token)).status).toBe(200);
    mockUsers.set('pu_acme', { ...mockUsers.get('pu_acme'), sessionVersion: 1 });
    expect((await me(app, token)).status).toBe(401);
  });

  test('DD095-R8 disabling kills the session; re-enabling (version bumped by the disable) does not revive it', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const token = tokenFor('acme');
    mockUsers.set('pu_acme', { ...mockUsers.get('pu_acme'), enabled: false, sessionVersion: 1 });
    expect((await me(app, token)).status).toBe(401);
    mockUsers.set('pu_acme', { ...mockUsers.get('pu_acme'), enabled: true });
    expect((await me(app, token)).status).toBe(401);
  });

  test('DD095-R9 a role change on the record kills the session', async () => {
    const { app, tokenFor, mockUsers } = freshApp();
    const token = tokenFor('acme');
    mockUsers.set('pu_acme', { ...mockUsers.get('pu_acme'), role: 'viewer' });
    expect((await me(app, token)).status).toBe(401);
  });

  test('DD095-R10 an OLD-FORMAT token (minted, no sv) is still accepted until expiry or revocation', async () => {
    const { app, seedUser, mockUsers } = freshApp();
    seedUser('acme');
    const now = Date.now();
    const encoded = Buffer.from(JSON.stringify({ sub: 'pu_acme', tenantId: 'acme', role: 'tenant', issuedAt: now, expiresAt: now + 60_000 })).toString('base64url');
    const sig = crypto.createHmac('sha256', Buffer.from(SECRET, 'utf8')).update(encoded, 'utf8').digest('hex');
    const legacy = `pt_${encoded}.${sig}`;
    expect((await me(app, legacy)).status).toBe(200);
    mockUsers.set('pu_acme', { ...mockUsers.get('pu_acme'), sessionVersion: 1 });
    expect((await me(app, legacy)).status).toBe(401);
  });
});

describe('tenant isolation (mandatory negative tests)', () => {
  test('tenant A cannot access tenant B consent data — DENIED', async () => {
    const { app, tokenFor } = freshApp({
      consentByTenant: {
        acme:   [{ id: 'c-acme-1', actor_id: 'user1', action: 'chat', state: 'granted', version: 1, granted_at: '2026-01-01' }],
        globex: [{ id: 'c-globex-1', actor_id: 'user2', action: 'chat', state: 'granted', version: 1, granted_at: '2026-01-01' }],
      },
    });
    const tokenA = tokenFor('acme');
    const r = await request(app).get('/tenant-portal/api/consent').set('Authorization', `Bearer ${tokenA}`);
    expect(r.status).toBe(200);
    const ids = r.body.data.records.map((rec) => rec.id);
    expect(ids).toContain('c-acme-1');
    expect(ids).not.toContain('c-globex-1');
  });

  test('changing the URL/query tenant id has no effect — server-derived tenant always wins', async () => {
    const { app, tokenFor } = freshApp({
      consentByTenant: {
        acme:   [{ id: 'c-acme-1', actor_id: 'user1', action: 'chat', state: 'granted', version: 1, granted_at: '2026-01-01' }],
        globex: [{ id: 'c-globex-1', actor_id: 'user2', action: 'chat', state: 'granted', version: 1, granted_at: '2026-01-01' }],
      },
    });
    const tokenA = tokenFor('acme');
    const r = await request(app)
      .get('/tenant-portal/api/consent?tenantId=globex&tenant_id=globex')
      .set('Authorization', `Bearer ${tokenA}`);
    expect(r.status).toBe(200);
    const ids = r.body.data.records.map((rec) => rec.id);
    expect(ids).toEqual(['c-acme-1']);
  });

  test('forged X-Tenant-ID header is IGNORED — response still reflects the token\'s own tenant', async () => {
    const { app, tokenFor } = freshApp();
    const tokenA = tokenFor('acme');
    const r = await request(app)
      .get('/tenant-portal/api/me')
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Tenant-ID', 'globex');
    expect(r.status).toBe(200);
    expect(r.body.data.tenantId).toBe('acme'); // NOT globex
  });

  test('a request-body tenant override on a POST-shaped attempt has no effect (logout ignores any body)', async () => {
    // logout is authenticated now, so the attempt carries tenant A's token; the body names tenant B.
    const { app, tokenFor, mockUsers } = freshApp();
    const tokenA = tokenFor('acme');
    tokenFor('globex');
    const r = await request(app).post('/tenant-portal/logout').set('Authorization', `Bearer ${tokenA}`).send({ tenantId: 'globex', role: 'admin' });
    expect(r.status).toBe(200);
    expect(mockUsers.get('pu_globex').sessionVersion).toBeUndefined(); // tenant B untouched — body never consulted
  });

  test('keys endpoint is tenant-scoped: tenant A only ever sees ITS OWN key status, never tenant B\'s', async () => {
    const { app, tokenFor } = freshApp({
      keyStatusByTenant: {
        acme:   { clientId: 'acme', status: 'HEALTHY', issues: [], activeKey: { keyId: 'acme:key_v1' }, keyCount: 1, activeKeyCount: 1 },
        globex: { clientId: 'globex', status: 'CRITICAL', issues: ['NO_ACTIVE_KEY'], activeKey: null, keyCount: 0, activeKeyCount: 0 },
      },
    });
    const tokenA = tokenFor('acme');
    const r = await request(app).get('/tenant-portal/api/keys').set('Authorization', `Bearer ${tokenA}`);
    expect(r.status).toBe(200);
    expect(r.body.data.clientId).toBe('acme');
    expect(r.body.data.activeKey.keyId).toBe('acme:key_v1');
  });

  test('a token minted for tenant B, presented alongside an attempt to read tenant A via query params, still only returns tenant B\'s own data', async () => {
    const { app, tokenFor } = freshApp({
      keyStatusByTenant: {
        acme:   { clientId: 'acme', status: 'HEALTHY', issues: [], activeKey: { keyId: 'acme:key_v1' }, keyCount: 1, activeKeyCount: 1 },
        globex: { clientId: 'globex', status: 'CRITICAL', issues: ['NO_ACTIVE_KEY'], activeKey: null, keyCount: 0, activeKeyCount: 0 },
      },
    });
    const tokenB = tokenFor('globex');
    const r = await request(app).get('/tenant-portal/api/keys?tenantId=acme').set('Authorization', `Bearer ${tokenB}`);
    expect(r.status).toBe(200);
    expect(r.body.data.clientId).toBe('globex');
  });
});

describe('key material safety', () => {
  test('the keys response never contains private/encrypted key fields', async () => {
    const { app, tokenFor } = freshApp({
      keyStatusByTenant: {
        acme: {
          clientId: 'acme', status: 'HEALTHY', issues: [],
          activeKey: { keyId: 'acme:key_v1', version: 1, createdAt: '2026-01-01', expiresAt: '2026-07-01', rotationDeadline: '2026-04-01', daysUntilExpiry: 10, daysUntilRotation: 5 },
          keyCount: 1, activeKeyCount: 1,
        },
      },
    });
    const token = tokenFor('acme');
    const r = await request(app).get('/tenant-portal/api/keys').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(200);
    const serialized = JSON.stringify(r.body);
    for (const forbidden of ['encryptedPrivateKeyDer', 'privateKeyDer', 'publicKeyDer', 'privDer', '_privDer', 'authTag']) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});

describe('RBAC integration (reuses the existing permission matrix, no second authz system)', () => {
  test('a portal session with role != tenant is rejected by the SAME requirePermission() every admin route uses', async () => {
    const { app, tokenFor, seedUser } = freshApp();
    // Simulate a corrupted/forged store record claiming an unrecognised role
    // — isPermitted() must fail closed for any role not in the permission
    // matrix for READ_TENANT_IDENTITY (which is [TENANT, ADMIN] only).
    const rec = seedUser('acme', { role: 'auditor' });
    const { mintSessionToken } = require('../../../../services/portal/portalSessionToken');
    const token = mintSessionToken({ portalUserId: rec.id, tenantId: rec.tenantId, role: 'auditor' });
    const r = await request(app).get('/tenant-portal/api/me').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBe(403);
  });
});

describe('dev-login route (non-production stub)', () => {
  test('dev-login is refused (404) when QODIQA_PORTAL_DEV_AUTH_ENABLED is not set', async () => {
    const { app } = freshApp();
    const savedEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';
    try {
      const r = await request(app).get('/tenant-portal/dev-login?tenantId=acme');
      expect(r.status).toBe(404);
    } finally {
      process.env.NODE_ENV = savedEnv;
    }
  });

  test('dev-login is refused (404) in production even if QODIQA_PORTAL_DEV_AUTH_ENABLED=true', async () => {
    const { app } = freshApp();
    const savedEnv = process.env.NODE_ENV;
    const savedFlag = process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED;
    process.env.NODE_ENV = 'production';
    process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED = 'true';
    try {
      const r = await request(app).get('/tenant-portal/dev-login?tenantId=acme');
      expect(r.status).toBe(404);
    } finally {
      process.env.NODE_ENV = savedEnv;
      if (savedFlag === undefined) delete process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED;
      else process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED = savedFlag;
    }
  });

  test('dev-login works when explicitly enabled outside production, and only for a real active tenant', async () => {
    const { app } = freshApp();
    const savedEnv = process.env.NODE_ENV;
    const savedFlag = process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED;
    process.env.NODE_ENV = 'development';
    process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED = 'true';
    try {
      const bad = await request(app).get('/tenant-portal/dev-login?tenantId=does-not-exist');
      expect(bad.status).toBe(400);

      const ok = await request(app).get('/tenant-portal/dev-login?tenantId=acme');
      expect(ok.status).toBe(302);
      expect(ok.headers.location).toMatch(/^\/tenant-portal\.html#token=/);
    } finally {
      process.env.NODE_ENV = savedEnv;
      if (savedFlag === undefined) delete process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED;
      else process.env.QODIQA_PORTAL_DEV_AUTH_ENABLED = savedFlag;
    }
  });
});

describe('OIDC callback (successful SSO authentication)', () => {
  test('a valid callback with matching state/claims JIT-provisions a portal user and redirects with a session token', async () => {
    jest.resetModules();
    process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
    const { mintFlowState } = require('../../../../services/portal/oidcFlowState');
    const flowState = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });

    jest.doMock('../../../core/tenancy/tenantRegistry', () => ({
      getTenant: jest.fn(),
      assertActiveTenant: jest.fn((id) => id === 'acme'
        ? { valid: true, tenant: { tenantId: 'acme', tenantName: 'Acme Corp', status: 'active' } }
        : { valid: false, reason: 'TENANT_UNKNOWN' }),
    }));
    const created = [];
    jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({
      findOrCreateByIdpSubject: jest.fn((fields) => {
        created.push(fields);
        return { id: 'pu_1', tenantId: fields.tenantId, role: 'tenant', enabled: true, email: fields.email, idpSubject: fields.idpSubject };
      }),
      getById: jest.fn(),
    }));
    jest.doMock('../../../core/portal/oidcClient', () => ({
      buildAuthorizationUrl: jest.fn(),
      exchangeCode: jest.fn(async () => ({
        claims: { sub: 'idp-user-1', iss: 'https://idp.example.com', email: 'real@acme.example', tenant_id: 'acme' },
      })),
    }));
    jest.doMock('../../../core/consent', () => ({ list: jest.fn() }));
    jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn() }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const { createTenantPortalRouter } = require('../tenantPortal');
    const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
    const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
    const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
    const { verifySessionToken } = require('../../../../services/portal/portalSessionToken');
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');

    const router = createTenantPortalRouter({
      requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
      portalSessionAuth: createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }),
      rbacResolve: createRbacResolveMiddleware({}),
      rateLimit: (req, res, next) => next(),
    });
    const app = express();
    app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
    app.use('/tenant-portal', router);

    const r = await request(app).get('/tenant-portal/callback').query({ code: 'auth-code-1', state: flowState });
    expect(r.status).toBe(302);
    expect(r.headers.location).toMatch(/^\/tenant-portal\.html#token=pt_/);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({ idpIssuer: 'https://idp.example.com', idpSubject: 'idp-user-1', tenantId: 'acme', email: 'real@acme.example' });

    jest.dontMock('../../../core/tenancy/tenantRegistry');
    jest.dontMock('../../../core/portal/tenantPortalUserStore');
    jest.dontMock('../../../core/portal/oidcClient');
    jest.dontMock('../../../core/consent');
    jest.dontMock('../../../../services/artifact/tenantKeyManager');
    jest.dontMock('../../../../services/logger');
  });

  test('a callback whose OIDC tenant claim maps to an UNKNOWN tenant is rejected — no JIT provisioning occurs', async () => {
    jest.resetModules();
    process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
    const { mintFlowState } = require('../../../../services/portal/oidcFlowState');
    const flowState = mintFlowState({ nonce: 'n1', codeVerifier: 'cv1' });

    jest.doMock('../../../core/tenancy/tenantRegistry', () => ({
      getTenant: jest.fn(),
      assertActiveTenant: jest.fn(() => ({ valid: false, reason: 'TENANT_UNKNOWN' })),
    }));
    const findOrCreate = jest.fn();
    jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({ findOrCreateByIdpSubject: findOrCreate, getById: jest.fn() }));
    jest.doMock('../../../core/portal/oidcClient', () => ({
      buildAuthorizationUrl: jest.fn(),
      exchangeCode: jest.fn(async () => ({
        claims: { sub: 'idp-user-1', iss: 'https://idp.example.com', email: 'x@example.com', tenant_id: 'no-such-tenant' },
      })),
    }));
    jest.doMock('../../../core/consent', () => ({ list: jest.fn() }));
    jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn() }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const { createTenantPortalRouter } = require('../tenantPortal');
    const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
    const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
    const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
    const { verifySessionToken } = require('../../../../services/portal/portalSessionToken');
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');

    const router = createTenantPortalRouter({
      requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
      portalSessionAuth: createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }),
      rbacResolve: createRbacResolveMiddleware({}),
      rateLimit: (req, res, next) => next(),
    });
    const app = express();
    app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
    app.use('/tenant-portal', router);

    const r = await request(app).get('/tenant-portal/callback').query({ code: 'auth-code-1', state: flowState });
    expect(r.status).toBe(302);
    expect(r.headers.location).toBe('/tenant-login.html?error=tenant_not_provisioned');
    expect(findOrCreate).not.toHaveBeenCalled();

    jest.dontMock('../../../core/tenancy/tenantRegistry');
    jest.dontMock('../../../core/portal/tenantPortalUserStore');
    jest.dontMock('../../../core/portal/oidcClient');
    jest.dontMock('../../../core/consent');
    jest.dontMock('../../../../services/artifact/tenantKeyManager');
    jest.dontMock('../../../../services/logger');
  });

  test('a callback with a FORGED/mismatched state parameter is rejected before any code exchange is attempted', async () => {
    jest.resetModules();
    process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
    const exchangeCode = jest.fn();
    jest.doMock('../../../core/portal/oidcClient', () => ({ buildAuthorizationUrl: jest.fn(), exchangeCode }));
    jest.doMock('../../../core/tenancy/tenantRegistry', () => ({ getTenant: jest.fn(), assertActiveTenant: jest.fn() }));
    jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({ findOrCreateByIdpSubject: jest.fn(), getById: jest.fn() }));
    jest.doMock('../../../core/consent', () => ({ list: jest.fn() }));
    jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn() }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const { createTenantPortalRouter } = require('../tenantPortal');
    const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
    const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
    const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
    const { verifySessionToken } = require('../../../../services/portal/portalSessionToken');
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');

    const router = createTenantPortalRouter({
      requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
      portalSessionAuth: createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }),
      rbacResolve: createRbacResolveMiddleware({}),
      rateLimit: (req, res, next) => next(),
    });
    const app = express();
    app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
    app.use('/tenant-portal', router);

    const r = await request(app).get('/tenant-portal/callback').query({ code: 'auth-code-1', state: 'forged.deadbeef' });
    expect(r.status).toBe(302);
    expect(r.headers.location).toBe('/tenant-login.html?error=invalid_request');
    expect(exchangeCode).not.toHaveBeenCalled();

    jest.dontMock('../../../core/portal/oidcClient');
    jest.dontMock('../../../core/tenancy/tenantRegistry');
    jest.dontMock('../../../core/portal/tenantPortalUserStore');
    jest.dontMock('../../../core/consent');
    jest.dontMock('../../../../services/artifact/tenantKeyManager');
    jest.dontMock('../../../../services/logger');
  });
});

describe('login redirect safety', () => {
  test('GET /tenant-portal/login redirects to the IdP authorization URL', async () => {
    const { app } = freshApp();
    const r = await request(app).get('/tenant-portal/login');
    expect(r.status).toBe(302);
    expect(r.headers.location).toContain('idp.example.com');
  });

  test('the error redirect target is always the fixed local login page — never open to request input', async () => {
    // Force buildAuthorizationUrl to throw so the error path is exercised.
    jest.resetModules();
    process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
    jest.doMock('../../../core/portal/oidcClient', () => ({
      buildAuthorizationUrl: jest.fn(async () => { throw new Error('discovery failed: connection refused'); }),
      exchangeCode: jest.fn(),
    }));
    jest.doMock('../../../core/tenancy/tenantRegistry', () => ({ getTenant: jest.fn(), assertActiveTenant: jest.fn() }));
    jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({ findOrCreateByIdpSubject: jest.fn(), getById: jest.fn() }));
    jest.doMock('../../../core/consent', () => ({ list: jest.fn() }));
    jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn() }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const { createTenantPortalRouter } = require('../tenantPortal');
    const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
    const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
    const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');

    const router = createTenantPortalRouter({
      requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
      portalSessionAuth: createPortalSessionMiddleware({
        verifySessionToken: require('../../../../services/portal/portalSessionToken').verifySessionToken,
        getPortalUserById: portalUserStore.getById,
      }),
      rbacResolve: createRbacResolveMiddleware({}),
      rateLimit: (req, res, next) => next(),
    });
    const app = express();
    app.use('/tenant-portal', router);

    const r = await request(app).get('/tenant-portal/login');
    expect(r.status).toBe(302);
    expect(r.headers.location).toBe('/tenant-login.html?error=login_unavailable');
    // Never leak the underlying error text into the redirect target.
    expect(r.headers.location).not.toContain('connection refused');

    jest.dontMock('../../../core/portal/oidcClient');
    jest.dontMock('../../../core/tenancy/tenantRegistry');
    jest.dontMock('../../../core/portal/tenantPortalUserStore');
    jest.dontMock('../../../core/consent');
    jest.dontMock('../../../../services/artifact/tenantKeyManager');
    jest.dontMock('../../../../services/logger');
  });
});

describe('error safety', () => {
  test('a data-layer exception on /api/consent never leaks a stack trace or raw error message to the client', async () => {
    jest.resetModules();
    process.env.QODIQA_PORTAL_SESSION_SECRET = SECRET;
    jest.doMock('../../../core/tenancy/tenantRegistry', () => ({
      getTenant: jest.fn(() => ({ tenantId: 'acme', tenantName: 'Acme Corp', status: 'active' })),
      assertActiveTenant: jest.fn(() => ({ valid: true, tenant: { tenantId: 'acme' } })),
    }));
    jest.doMock('../../../core/portal/tenantPortalUserStore', () => ({
      findOrCreateByIdpSubject: jest.fn(),
      getById: jest.fn(() => ({ id: 'pu_acme', tenantId: 'acme', role: 'tenant', enabled: true, email: 'u@acme.example' })),
    }));
    jest.doMock('../../../core/consent', () => ({
      list: jest.fn(async () => { throw new Error('relation "consent_records" does not exist at /some/internal/path.js:42'); }),
    }));
    jest.doMock('../../../../services/artifact/tenantKeyManager', () => ({ getTenantKeyStatus: jest.fn() }));
    jest.doMock('../../../core/portal/oidcClient', () => ({ buildAuthorizationUrl: jest.fn(), exchangeCode: jest.fn() }));
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const { createTenantPortalRouter } = require('../tenantPortal');
    const { createPortalSessionMiddleware } = require('../../../middleware/portalAuth');
    const { createRbacResolveMiddleware, createRequirePermission } = require('../../../middleware/rbac');
    const { isPermitted, isValidPermission } = require('../../../core/rbac/authorize');
    const { mintSessionToken, verifySessionToken } = require('../../../../services/portal/portalSessionToken');
    const portalUserStore = require('../../../core/portal/tenantPortalUserStore');

    const router = createTenantPortalRouter({
      requirePermission: createRequirePermission({ isPermitted, isValidPermission }),
      portalSessionAuth: createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }),
      rbacResolve: createRbacResolveMiddleware({}),
      rateLimit: (req, res, next) => next(),
    });
    const app = express();
    app.use((req, res, next) => { req.requestId = 'test-req'; res.locals.requestId = 'test-req'; next(); });
    app.use('/tenant-portal', router);

    const token = mintSessionToken({ portalUserId: 'pu_acme', tenantId: 'acme', role: 'tenant' });
    const r = await request(app).get('/tenant-portal/api/consent').set('Authorization', `Bearer ${token}`);
    expect(r.status).toBeGreaterThanOrEqual(400);
    const serialized = JSON.stringify(r.body);
    expect(serialized).not.toContain('consent_records');
    expect(serialized).not.toContain('/some/internal/path.js');

    jest.dontMock('../../../core/tenancy/tenantRegistry');
    jest.dontMock('../../../core/portal/tenantPortalUserStore');
    jest.dontMock('../../../core/consent');
    jest.dontMock('../../../../services/artifact/tenantKeyManager');
    jest.dontMock('../../../core/portal/oidcClient');
    jest.dontMock('../../../../services/logger');
  });
});
