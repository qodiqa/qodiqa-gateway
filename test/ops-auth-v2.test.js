'use strict';

/**
 * Ops Authentication v2 — per-operator API key tests.
 *
 * Covers:
 * issueApiKey returns a plaintext key with ok_ prefix
 * resolveOperatorKey finds the operator by their key
 * resolveOperatorKey returns null for unknown key
 * resolveOperatorKey returns null for empty/null input
 * revokeApiKey makes the key immediately invalid
 * revokeApiKey throws NO_API_KEY when user has no active key
 * issueApiKey rotation — old key invalid, new key valid
 * issueApiKey throws NOT_FOUND for unknown user
 * resolveOperatorKey returns null for disabled user (check at middleware level)
 * opsAuth — valid API key → 200, req.rbacUser attached
 * opsAuth — revoked API key → 401
 * opsAuth — wrong key → 401
 * opsAuth — missing credential → 401
 * opsAuth — disabled operator key → 401
 * opsAuth — shared token still works (migration path)
 * opsAuth — invalid shared token → 401
 * opsAuth — req.rbacUser has correct id, username, role
 * opsAuth — req.operatorAuthMethod is 'api-key' for key auth
 * opsAuth — req.operatorAuthMethod is 'shared-token' for legacy auth
 * rbac resolve — skips header lookup when rbacUser already set by opsAuth
 * rbac resolve — rejects shared-token auth regardless of X-Ops-Actor header
 * rbacAdmin POST /users/:id/api-key issues a key (MANAGE_USERS)
 * rbacAdmin POST /users/:id/api-key requires MANAGE_USERS permission
 * rbacAdmin DELETE /users/:id/api-key revokes a key
 * rbacAdmin GET /users returns hasApiKey field
 * rbacAdmin GET /users never exposes apiKeyHash
 * deleteUser removes the key from the index
 * key hash is not exposed in any API response
 * resolveOperatorKey does not return user when disabled (extra guard in opsAuth)
 */

const os      = require('os');
const path    = require('path');
const request = require('supertest');
const express = require('express');

// ── Test isolation ────────────────────────────────────────────────────────────
// Redirect the RBAC store to a temp file so tests never touch data/rbac-users.json

const RBAC_TEST_PATH = path.join(os.tmpdir(), `rbac-oa-test-${process.pid}.json`);

beforeAll(() => {
  process.env.QODIQA_RBAC_STORE_PATH = RBAC_TEST_PATH;
});

afterAll(() => {
  delete process.env.QODIQA_RBAC_STORE_PATH;
  try { require('fs').unlinkSync(RBAC_TEST_PATH); } catch (_) {}
});

// Require after setting env so the store picks up the test path.
const store = require('../src/core/rbac/store');
const { createOpsAuthMiddleware } = require('../src/middleware/opsAuth');
const { createRbacResolveMiddleware, createRequirePermission: _createRequirePermission } = require('../src/middleware/rbac');
const { isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission } = require('../src/core/rbac/authorize');
const createRbacAdminRouter = require('../src/api/routes/rbacAdmin');

// createRequirePermission() now requires isPermitted/isValidPermission to be
// injected (src/middleware/rbac.js no longer reaches into src/core directly —
// see .dependency-cruiser.js's no-middleware-to-core rule). This wrapper
// supplies the real core/rbac/authorize.js implementation so every existing
// call site below keeps working unchanged.
function createRequirePermission(opts) {
  return _createRequirePermission({ isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission, ...opts });
}

beforeEach(() => {
  store._reset();
  // Also remove the disk file so _ensureLoaded() can't reload stale state
  try { require('fs').unlinkSync(RBAC_TEST_PATH); } catch (_) {}
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeOpsApp({ token = null, rbacStoreArg = store } = {}) {
  const app = express();
  app.use(express.json());
  const opsConfig = { token };
  app.use(createOpsAuthMiddleware(opsConfig, rbacStoreArg));
  app.get('/ping', (req, res) => res.json({
    ok:             true,
    rbacUser:       req.rbacUser ?? null,
    authMethod:     req.operatorAuthMethod ?? null,
  }));
  return app;
}

function makeRbacApp({ rbacStoreArg = store } = {}) {
  const app = express();
  app.use(express.json());
  // Simulate opsAuth always passing (shared token)
  app.use(createOpsAuthMiddleware({ token: 'test-shared-token' }, rbacStoreArg));
  app.use(createRbacResolveMiddleware({ store: rbacStoreArg, enabled: true }));
  const requirePermission = createRequirePermission({ enabled: true });
  app.use('/rbac', createRbacAdminRouter({ store: rbacStoreArg, requirePermission }));
  return app;
}

function createAdminWithKey() {
  const user = store.createUser({ username: 'alice', role: 'admin', createdBy: 'test' });
  const { plaintext } = store.issueApiKey(user.id, { issuedBy: 'test' });
  return { user, plaintext };
}

// ── … store key management ──────────────────────────────────────

describe('store.js — API key management', () => {
  test('issueApiKey returns a plaintext key with ok_ prefix', () => {
    const user = store.createUser({ username: 'bob', role: 'auditor', createdBy: 'test' });
    const { plaintext, issuedAt } = store.issueApiKey(user.id, { issuedBy: 'test' });
    expect(plaintext).toMatch(/^ok_[0-9a-f]{64}$/);
    expect(issuedAt).toBeTruthy();
  });

  test('resolveOperatorKey finds the operator by their plaintext key', () => {
    const user = store.createUser({ username: 'carol', role: 'operator', createdBy: 'test' });
    const { plaintext } = store.issueApiKey(user.id, { issuedBy: 'test' });
    const resolved = store.resolveOperatorKey(plaintext);
    expect(resolved).not.toBeNull();
    expect(resolved.id).toBe(user.id);
    expect(resolved.username).toBe('carol');
  });

  test('resolveOperatorKey returns null for an unknown key', () => {
    const fake = 'ok_' + 'a'.repeat(64);
    expect(store.resolveOperatorKey(fake)).toBeNull();
  });

  test('resolveOperatorKey returns null for empty or null input', () => {
    expect(store.resolveOperatorKey('')).toBeNull();
    expect(store.resolveOperatorKey(null)).toBeNull();
    expect(store.resolveOperatorKey(undefined)).toBeNull();
  });

  test('revokeApiKey makes the key immediately invalid', () => {
    const user = store.createUser({ username: 'dave', role: 'viewer', createdBy: 'test' });
    const { plaintext } = store.issueApiKey(user.id, { issuedBy: 'test' });
    store.revokeApiKey(user.id, { revokedBy: 'test' });
    expect(store.resolveOperatorKey(plaintext)).toBeNull();
  });

  test('revokeApiKey throws NO_API_KEY when user has no active key', () => {
    const user = store.createUser({ username: 'eve', role: 'viewer', createdBy: 'test' });
    expect(() => store.revokeApiKey(user.id)).toThrow(
      expect.objectContaining({ code: 'NO_API_KEY' }),
    );
  });

  // rotation gives the previous key a bounded
  // grace (QODIQA_API_KEY_ROTATION_GRACE_HOURS, default 24 h) so clients can
  // cut over; with grace 0 the earlier behaviour (old key dead at rotation) holds.
  // Expiry of the grace window: src/core/security/__tests__/apiKeyLifecycle.test.js.
  test('issueApiKey rotation — old key only within the rotation grace, new key valid', () => {
    const user = store.createUser({ username: 'frank', role: 'auditor', createdBy: 'test' });
    const { plaintext: oldKey } = store.issueApiKey(user.id, { issuedBy: 'test' });
    const { plaintext: newKey } = store.issueApiKey(user.id, { issuedBy: 'test' });
    expect(store.resolveOperatorKeyDetailed(oldKey)).toMatchObject({ status: 'grace', via: 'previous' });
    expect(store.resolveOperatorKey(newKey)).not.toBeNull();
  });

  test('issueApiKey rotation with QODIQA_API_KEY_ROTATION_GRACE_HOURS=0 — old key invalid immediately', () => {
    const saved = process.env.QODIQA_API_KEY_ROTATION_GRACE_HOURS;
    process.env.QODIQA_API_KEY_ROTATION_GRACE_HOURS = '0';
    try {
      const user = store.createUser({ username: 'frank-b', role: 'auditor', createdBy: 'test' });
      const { plaintext: oldKey } = store.issueApiKey(user.id, { issuedBy: 'test' });
      const { plaintext: newKey } = store.issueApiKey(user.id, { issuedBy: 'test' });
      expect(store.resolveOperatorKey(oldKey)).toBeNull();
      expect(store.resolveOperatorKey(newKey)).not.toBeNull();
    } finally {
      if (saved === undefined) delete process.env.QODIQA_API_KEY_ROTATION_GRACE_HOURS; else process.env.QODIQA_API_KEY_ROTATION_GRACE_HOURS = saved;
    }
  });

  test('issueApiKey throws NOT_FOUND for unknown userId', () => {
    expect(() => store.issueApiKey('non-existent-id')).toThrow(
      expect.objectContaining({ code: 'NOT_FOUND' }),
    );
  });

  test('deleteUser removes the key from the index', () => {
    // Create a second admin so we can delete the first
    store.createUser({ username: 'admin2', role: 'admin', createdBy: 'test' });
    const user = store.createUser({ username: 'temp-op', role: 'operator', createdBy: 'test' });
    const { plaintext } = store.issueApiKey(user.id, { issuedBy: 'test' });
    store.deleteUser(user.id, { deletedBy: 'test' });
    expect(store.resolveOperatorKey(plaintext)).toBeNull();
  });
});

// ── … opsAuth middleware ────────────────────────────────────────

describe('createOpsAuthMiddleware — API key authentication', () => {
  test('valid API key → 200, req.rbacUser attached', async () => {
    const { user, plaintext } = createAdminWithKey();
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.status).toBe(200);
    expect(res.body.rbacUser.id).toBe(user.id);
    expect(res.body.rbacUser.username).toBe('alice');
  });

  test('revoked API key → 401', async () => {
    const { user, plaintext } = createAdminWithKey();
    store.revokeApiKey(user.id, { revokedBy: 'test' });
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.status).toBe(401);
  });

  test('wrong key → 401', async () => {
    createAdminWithKey(); // ensure at least one key exists
    const fakeKey = 'ok_' + 'b'.repeat(64);
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${fakeKey}`);
    expect(res.status).toBe(401);
  });

  test('missing credential → 401', async () => {
    const app = makeOpsApp();
    const res = await request(app).get('/ping'); // no auth header
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
  });

  test('disabled operator key → 401', async () => {
    const { user, plaintext } = createAdminWithKey();
    // Create second admin so we can disable alice
    store.createUser({ username: 'admin2', role: 'admin', createdBy: 'test' });
    store.updateUser(user.id, { enabled: false, updatedBy: 'test' });
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.status).toBe(401);
  });

  test('shared token still works (migration path)', async () => {
    const app = makeOpsApp({ token: 'legacy-shared-secret-1234' });
    const res = await request(app)
      .get('/ping')
      .set('X-Ops-Token', 'legacy-shared-secret-1234');
    expect(res.status).toBe(200);
    expect(res.body.authMethod).toBe('shared-token');
  });

  test('invalid shared token → 401', async () => {
    const app = makeOpsApp({ token: 'correct-shared-token-here' });
    const res = await request(app)
      .get('/ping')
      .set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(401);
  });

  test('req.rbacUser has correct id, username, role from key auth', async () => {
    const user = store.createUser({ username: 'grace', role: 'auditor', createdBy: 'test' });
    const { plaintext } = store.issueApiKey(user.id, { issuedBy: 'test' });
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.body.rbacUser).toMatchObject({
      id:       user.id,
      username: 'grace',
      role:     'auditor',
      enabled:  true,
    });
  });

  test('req.operatorAuthMethod is "api-key" for key authentication', async () => {
    const { plaintext } = createAdminWithKey();
    const app = makeOpsApp();
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.body.authMethod).toBe('api-key');
  });

  test('req.operatorAuthMethod is "shared-token" for legacy authentication', async () => {
    const app = makeOpsApp({ token: 'legacy-token-for-test' });
    const res = await request(app)
      .get('/ping')
      .set('Authorization', 'Bearer legacy-token-for-test');
    expect(res.body.authMethod).toBe('shared-token');
  });

  test('API key takes priority over shared token when both present', async () => {
    const { plaintext } = createAdminWithKey();
    // Both API key AND shared token are configured
    const app = makeOpsApp({ token: 'some-shared-token' });
    const res = await request(app).get('/ping').set('Authorization', `Bearer ${plaintext}`);
    expect(res.status).toBe(200);
    // Authenticated via API key, not shared token
    expect(res.body.authMethod).toBe('api-key');
    expect(res.body.rbacUser).not.toBeNull();
  });
});

// ── … rbac resolve middleware ────────────────────────────────────

describe('createRbacResolveMiddleware — identity forwarding', () => {
  test('rbac resolve skips X-Ops-Actor when rbacUser already set by opsAuth', async () => {
    const { user, plaintext } = createAdminWithKey();
    // Build app: opsAuth (with API key support) + rbac resolve + protected route
    const app = express();
    app.use(express.json());
    app.use(createOpsAuthMiddleware({ token: null }, store));
    app.use(createRbacResolveMiddleware({ store, enabled: true }));
    app.get('/me', (req, res) => res.json({ username: req.rbacUser?.username ?? null }));

    // No X-Ops-Actor header — rbac resolve would normally return 403
    const res = await request(app).get('/me').set('Authorization', `Bearer ${plaintext}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe('alice');
  });

  test('rbac resolve rejects shared-token auth regardless of X-Ops-Actor header', async () => {
    // Shared-token auth does NOT set req.rbacUser (no per-operator key resolved).
    // X-Ops-Actor header must not be consulted — shared-token auth is always
    // rejected at the RBAC layer when RBAC is enabled.
    const aliceUser = store.createUser({ username: 'alice-oa21', role: 'admin', createdBy: 'test' });
    void aliceUser;

    const app = express();
    app.use(express.json());
    app.use(createOpsAuthMiddleware({ token: 'shared-secret' }, store));
    app.use(createRbacResolveMiddleware({ store, enabled: true }));
    app.get('/me', (req, res) => res.json({ username: req.rbacUser?.username ?? null }));

    // With X-Ops-Actor pointing at a valid admin — must still be rejected
    const withHeader = await request(app)
      .get('/me')
      .set('Authorization', 'Bearer shared-secret')
      .set('X-Ops-Actor', 'alice-oa21');
    expect(withHeader.status).toBe(403);

    // Without X-Ops-Actor — also rejected
    const withoutHeader = await request(app)
      .get('/me')
      .set('Authorization', 'Bearer shared-secret');
    expect(withoutHeader.status).toBe(403);
  });
});

// ── … rbacAdmin key management routes ────────────────────────────

describe('rbacAdmin — key management routes', () => {
  function makeAdminRbacApp() {
    // Full rbac app where the "caller" is alice (admin with key)
    const { user: adminUser, plaintext: adminKey } = createAdminWithKey();
    const app = express();
    app.use(express.json());
    app.use(createOpsAuthMiddleware({ token: null }, store));
    app.use(createRbacResolveMiddleware({ store, enabled: true }));
    const requirePermission = createRequirePermission({ enabled: true });
    app.use('/rbac', createRbacAdminRouter({ store, requirePermission }));
    return { app, adminUser, adminKey };
  }

  test('POST /users/:id/api-key issues a key (MANAGE_USERS)', async () => {
    const { app, adminKey } = makeAdminRbacApp();
    const target = store.createUser({ username: 'helen', role: 'viewer', createdBy: 'test' });
    const res = await request(app)
      .post(`/rbac/users/${target.id}/api-key`)
      .set('Authorization', `Bearer ${adminKey}`);
    expect(res.status).toBe(201);
    expect(res.body.data.apiKey).toMatch(/^ok_[0-9a-f]{64}$/);
    expect(res.body.data.message).toContain('will not be displayed again');
    // Key must actually work
    expect(store.resolveOperatorKey(res.body.data.apiKey)).not.toBeNull();
  });

  test('POST /users/:id/api-key requires MANAGE_USERS (viewer cannot issue)', async () => {
    const { app, adminKey } = makeAdminRbacApp();
    // Create a viewer user with their own key to call the endpoint
    const viewer = store.createUser({ username: 'ivy', role: 'viewer', createdBy: 'test' });
    const { plaintext: viewerKey } = store.issueApiKey(viewer.id, { issuedBy: 'test' });
    const target = store.createUser({ username: 'jay', role: 'viewer', createdBy: 'test' });

    const res = await request(app)
      .post(`/rbac/users/${target.id}/api-key`)
      .set('Authorization', `Bearer ${viewerKey}`);
    expect(res.status).toBe(403);
    void adminKey; // admin key not used here
  });

  test('DELETE /users/:id/api-key revokes a key immediately', async () => {
    const { app, adminKey } = makeAdminRbacApp();
    const target = store.createUser({ username: 'kate', role: 'auditor', createdBy: 'test' });
    const { plaintext } = store.issueApiKey(target.id, { issuedBy: 'test' });
    expect(store.resolveOperatorKey(plaintext)).not.toBeNull();

    const res = await request(app)
      .delete(`/rbac/users/${target.id}/api-key`)
      .set('Authorization', `Bearer ${adminKey}`);
    expect(res.status).toBe(200);
    expect(res.body.data.revoked).toBe(true);
    expect(store.resolveOperatorKey(plaintext)).toBeNull();
  });

  test('GET /users response includes hasApiKey field', async () => {
    const { app, adminKey, adminUser } = makeAdminRbacApp();
    const res = await request(app)
      .get('/rbac/users')
      .set('Authorization', `Bearer ${adminKey}`);
    expect(res.status).toBe(200);
    const alice = res.body.data.users.find(u => u.id === adminUser.id);
    expect(alice).toBeDefined();
    expect(typeof alice.hasApiKey).toBe('boolean');
    expect(alice.hasApiKey).toBe(true); // alice has a key (we just issued it)
  });

  test('GET /users never exposes apiKeyHash', async () => {
    const { app, adminKey } = makeAdminRbacApp();
    const res = await request(app)
      .get('/rbac/users')
      .set('Authorization', `Bearer ${adminKey}`);
    expect(res.status).toBe(200);
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('apiKeyHash');
  });

  test('key hash is not exposed in any API response', async () => {
    const { app, adminKey } = makeAdminRbacApp();
    const target = store.createUser({ username: 'leo', role: 'viewer', createdBy: 'test' });
    const issueRes = await request(app)
      .post(`/rbac/users/${target.id}/api-key`)
      .set('Authorization', `Bearer ${adminKey}`);
    expect(issueRes.status).toBe(201);
    const issueBody = JSON.stringify(issueRes.body);
    expect(issueBody).not.toContain('apiKeyHash');

    const getRes = await request(app)
      .get(`/rbac/users/${target.id}`)
      .set('Authorization', `Bearer ${adminKey}`);
    const getBody = JSON.stringify(getRes.body);
    expect(getBody).not.toContain('apiKeyHash');
  });
});
