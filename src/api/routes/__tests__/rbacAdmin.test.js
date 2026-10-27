'use strict';

/**
 * RBAC System — test suite
 *
 * RB-01…RB-10   Role definitions and permission matrix
 * RB-11…RB-20   User store CRUD
 * RB-21…RB-30   RBAC resolve middleware
 * RB-31…RB-42   requirePermission middleware
 * RB-43…RB-55   /rbac admin API routes
 * RB-56…RB-62   Bootstrap admin
 * RB-63…RB-68   Fail-closed scenarios
 * RB-69…RB-74   Regression guards: no disabled mode, no synthetic admin,
 *                no configuration can ever grant implicit administrative
 * access
 * RB-75…RB-80   Evidence package requestor context (Req 7)
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../../core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const request  = require('supertest');
const express  = require('express');
const os       = require('os');
const fs       = require('fs');
const path     = require('path');
const { randomUUID } = require('crypto');

const { ROLES, PERMISSIONS, isValidRole, isValidPermission, isPermitted, permissionsForRole } =
  require('../../../core/rbac/roles');
const { RbacStoreError, _reset: resetStore } = require('../../../core/rbac/store');
const { CustomRoleStoreError, _reset: resetCustomRoleStore } = require('../../../core/rbac/customRoleStore');
const { createRbacResolveMiddleware, createRequirePermission: _createRequirePermission } = require('../../../middleware/rbac');
const { isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission } = require('../../../core/rbac/authorize');
const createRbacAdminRouter = require('../rbacAdmin');

// createRequirePermission() now requires isPermitted/isValidPermission to be
// injected (src/middleware/rbac.js no longer reaches into src/core directly —
// see .dependency-cruiser.js's no-middleware-to-core rule). This wrapper
// supplies the real core/rbac/authorize.js implementation so every existing
// call site below (createRequirePermission(), createRequirePermission({...}))
// keeps working unchanged.
function createRequirePermission(opts) {
  return _createRequirePermission({ isPermitted: _rbacIsPermitted, isValidPermission: _rbacIsValidPermission, ...opts });
}

// ── Store factory (isolated per test) ────────────────────────────────────────

function makeIsolatedStore() {
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rbac-test-'));
  const tmpPath = path.join(tmpDir, 'rbac-users.json');
  process.env.QODIQA_RBAC_STORE_PATH = tmpPath;
  resetStore();

  // Re-require to get fresh module state with new path
  // (We use the same module singleton but _reset() cleared the cache)
  const store = require('../../../core/rbac/store');
  return store;
}

function makeIsolatedCustomRoleStore() {
  const tmpDir  = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-rbac-role-test-'));
  const tmpPath = path.join(tmpDir, 'rbac-custom-roles.json');
  process.env.QODIQA_RBAC_CUSTOM_ROLE_STORE_PATH = tmpPath;
  resetCustomRoleStore();

  const customRoleStore = require('../../../core/rbac/customRoleStore');
  return customRoleStore;
}

// ── Test-only pre-auth middleware ─────────────────────────────────────────────
//
// In production, req.rbacUser is populated by createOpsAuthMiddleware (via a
// per-operator API key lookup).  For unit tests that exercise RBAC logic — not
// the auth flow — we simulate that by reading a test-internal header
// (x-test-actor) and performing the same store lookup that opsAuth would do.
//
// This header is ONLY consumed by this test middleware.  Production code reads
// it nowhere.

function makePreAuthMiddleware(store) {
  return function testPreAuth(req, _res, next) {
    const name = req.headers['x-test-actor'];
    if (typeof name === 'string' && name.trim()) {
      const u = store.getUserByUsername(name.trim());
      if (u && u.enabled) {
        req.rbacUser = Object.freeze({
          id:       u.id,
          username: u.username,
          role:     u.role,
          enabled:  u.enabled,
        });
      }
    }
    next();
  };
}

// ── App factory ───────────────────────────────────────────────────────────────

function makeApp() {
  const store           = makeIsolatedStore();
  const customRoleStore = makeIsolatedCustomRoleStore();
  const resolve = createRbacResolveMiddleware({ store });
  const rp      = createRequirePermission();
  const router  = createRbacAdminRouter({ store, customRoleStore, requirePermission: rp });

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = `test-${Date.now()}`; next(); });
  app.use(makePreAuthMiddleware(store));   // simulates opsAuth API key resolution
  app.use('/rbac', resolve, router);
  return { app, store, customRoleStore, rp };
}

// testActorHeader — returns a header object consumed by makePreAuthMiddleware.
// Production code never reads x-test-actor.
function testActorHeader(username) {
  return { 'x-test-actor': username };
}

// ─────────────────────────────────────────────────────────────────────────────
// RB-01…RB-10  Role definitions and permission matrix
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-01…RB-10  Role definitions and permission matrix', () => {
  test('RB-01  exactly six canonical roles', () => {
    // 5 -> 6, adding 'tenant' — see roles.js's
    // ROLES.TENANT comment for why it's a distinct identity class (the
    // tenant self-service portal's one role) rather than a sixth
    // console-operator tier.
    expect(Object.values(ROLES)).toHaveLength(6);
    expect(Object.values(ROLES)).toContain('admin');
    expect(Object.values(ROLES)).toContain('auditor');
    expect(Object.values(ROLES)).toContain('compliance');
    expect(Object.values(ROLES)).toContain('operator');
    expect(Object.values(ROLES)).toContain('viewer');
    expect(Object.values(ROLES)).toContain('tenant');
  });

  test('RB-02  isValidRole accepts all canonical roles', () => {
    for (const role of Object.values(ROLES)) {
      expect(isValidRole(role)).toBe(true);
    }
  });

  test('RB-03  isValidRole rejects non-canonical strings', () => {
    expect(isValidRole('superadmin')).toBe(false);
    expect(isValidRole('')).toBe(false);
    expect(isValidRole(null)).toBe(false);
    expect(isValidRole(undefined)).toBe(false);
    expect(isValidRole(42)).toBe(false);
  });

  test('RB-04  isValidPermission accepts all defined permissions', () => {
    for (const perm of Object.keys(PERMISSIONS)) {
      expect(isValidPermission(perm)).toBe(true);
    }
  });

  test('RB-05  isValidPermission rejects unknown strings', () => {
    expect(isValidPermission('HACK_EVERYTHING')).toBe(false);
    expect(isValidPermission('')).toBe(false);
    expect(isValidPermission(null)).toBe(false);
  });

  test('RB-06  Admin is permitted everything', () => {
    for (const perm of Object.keys(PERMISSIONS)) {
      expect(isPermitted(ROLES.ADMIN, perm)).toBe(true);
    }
  });

  test('RB-07  Viewer is only permitted VIEW_DASHBOARD', () => {
    const viewerPerms = permissionsForRole(ROLES.VIEWER);
    expect(viewerPerms).toContain('VIEW_DASHBOARD');
    // Viewer must NOT have any admin or audit permissions
    expect(isPermitted(ROLES.VIEWER, 'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.VIEWER, 'READ_AUDIT')).toBe(false);
    expect(isPermitted(ROLES.VIEWER, 'MANAGE_POLICIES')).toBe(false);
    expect(isPermitted(ROLES.VIEWER, 'MANAGE_KEYS')).toBe(false);
  });

  test('RB-08  Auditor cannot modify policies or keys', () => {
    expect(isPermitted(ROLES.AUDITOR, 'MANAGE_POLICIES')).toBe(false);
    expect(isPermitted(ROLES.AUDITOR, 'MANAGE_KEYS')).toBe(false);
    expect(isPermitted(ROLES.AUDITOR, 'MANAGE_USERS')).toBe(false);
  });

  test('RB-09  Operator can generate evidence but not manage keys', () => {
    expect(isPermitted(ROLES.OPERATOR, 'GENERATE_EVIDENCE')).toBe(true);
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_KEYS')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_POLICIES')).toBe(false);
  });

  test('RB-10  isPermitted fails closed on invalid input', () => {
    expect(isPermitted(null, 'READ_AUDIT')).toBe(false);
    expect(isPermitted('admin', null)).toBe(false);
    expect(isPermitted(undefined, undefined)).toBe(false);
    expect(isPermitted('admin', 'DOES_NOT_EXIST')).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-11…RB-20  User store CRUD
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-11…RB-20  User store CRUD', () => {
  let store;
  beforeEach(() => { store = makeIsolatedStore(); });

  test('RB-11  createUser succeeds with valid inputs', () => {
    const user = store.createUser({ username: 'alice', role: 'auditor', createdBy: 'test' });
    expect(user.id).toBeTruthy();
    expect(user.username).toBe('alice');
    expect(user.role).toBe('auditor');
    expect(user.enabled).toBe(true);
    expect(user.createdAt).toBeTruthy();
    expect(user.createdBy).toBe('test');
  });

  test('RB-12  createUser rejects invalid username', () => {
    expect(() => store.createUser({ username: 'x', role: 'auditor' }))
      .toThrow(RbacStoreError);
    expect(() => store.createUser({ username: 'x', role: 'auditor' }))
      .toThrow(expect.objectContaining({ code: 'INVALID_USERNAME' }));
  });

  test('RB-13  createUser rejects invalid role', () => {
    expect(() => store.createUser({ username: 'alice', role: 'supergod' }))
      .toThrow(expect.objectContaining({ code: 'INVALID_ROLE' }));
  });

  test('RB-14  createUser rejects duplicate username (case-insensitive)', () => {
    store.createUser({ username: 'Alice', role: 'auditor' });
    expect(() => store.createUser({ username: 'alice', role: 'operator' }))
      .toThrow(expect.objectContaining({ code: 'USERNAME_TAKEN' }));
  });

  test('RB-15  getUser returns null for unknown ID', () => {
    expect(store.getUser('does-not-exist')).toBeNull();
  });

  test('RB-16  getUserByUsername finds user case-insensitively', () => {
    store.createUser({ username: 'Bob', role: 'operator' });
    const u = store.getUserByUsername('bob');
    expect(u).not.toBeNull();
    expect(u.username).toBe('Bob');
  });

  test('RB-17  updateUser changes role', () => {
    const user = store.createUser({ username: 'charlie', role: 'viewer' });
    const updated = store.updateUser(user.id, { role: 'operator', updatedBy: 'admin' });
    expect(updated.role).toBe('operator');
    expect(updated.updatedBy).toBe('admin');
  });

  test('RB-18  updateUser protects last admin from demotion', () => {
    const admin = store.createUser({ username: 'sole-admin', role: 'admin' });
    expect(() => store.updateUser(admin.id, { role: 'viewer' }))
      .toThrow(expect.objectContaining({ code: 'LAST_ADMIN' }));
    expect(() => store.updateUser(admin.id, { enabled: false }))
      .toThrow(expect.objectContaining({ code: 'LAST_ADMIN' }));
  });

  test('RB-19  deleteUser removes user; deleteUser protects last admin', () => {
    const u1 = store.createUser({ username: 'admin1', role: 'admin' });
    const u2 = store.createUser({ username: 'admin2', role: 'admin' });
    store.deleteUser(u1.id);
    expect(store.getUser(u1.id)).toBeNull();
    // Now only one admin — cannot delete
    expect(() => store.deleteUser(u2.id)).toThrow(expect.objectContaining({ code: 'LAST_ADMIN' }));
  });

  test('RB-20  listUsers returns all users sorted by createdAt', () => {
    store.createUser({ username: 'first', role: 'viewer' });
    store.createUser({ username: 'second', role: 'viewer' });
    const list = store.listUsers();
    expect(list.length).toBe(2);
    expect(list[0].username).toBe('first');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-21…RB-30  RBAC resolve middleware
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-21…RB-30  RBAC resolve middleware', () => {
  function makeResolveApp() {
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    app.use(makePreAuthMiddleware(store));   // simulates opsAuth: sets req.rbacUser from store
    app.use(resolve);
    app.get('/test', (req, res) => {
      res.json({ rbacUser: req.rbacUser ?? null });
    });
    return { app, store };
  }

  test('RB-21  resolve passes through when req.rbacUser is set by pre-auth', async () => {
    const { app, store } = makeResolveApp();
    const user = store.createUser({ username: 'alice', role: 'auditor' });
    const r = await request(app).get('/test').set(testActorHeader('alice'));
    expect(r.status).toBe(200);
    expect(r.body.rbacUser.username).toBe('alice');
    expect(r.body.rbacUser.role).toBe('auditor');
    expect(r.body.rbacUser.id).toBe(user.id);
  });

  test('RB-22  resolve returns 403 when no authenticated identity', async () => {
    const { app } = makeResolveApp();
    const r = await request(app).get('/test');  // no pre-auth header
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
  });

  test('RB-23  resolve returns 403 when pre-auth cannot resolve user (unknown username)', async () => {
    const { app } = makeResolveApp();
    const r = await request(app).get('/test').set(testActorHeader('ghost'));
    expect(r.status).toBe(403);
  });

  test('RB-24  resolve returns 403 for disabled user (pre-auth skips disabled accounts)', async () => {
    const { app, store } = makeResolveApp();
    const admin = store.createUser({ username: 'admin1', role: 'admin' });
    store.createUser({ username: 'admin2', role: 'admin' });
    store.updateUser(admin.id, { enabled: false, updatedBy: 'test' });

    const r = await request(app).get('/test').set(testActorHeader('admin1'));
    expect(r.status).toBe(403);
  });

  test('RB-25  resolve NEVER attaches a synthetic admin — no configuration can produce one', async () => {
    // Regression guard for the removed vulnerability (formerly: RBAC-disabled
    // mode attached a synthetic admin identity to every request). No such
    // mode exists any more — passing any legacy-shaped option is a no-op.
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store, enabled: false });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    app.use(resolve); // deliberately no pre-auth — no identity is ever set
    app.get('/test', (req, res) => res.json({ rbacUser: req.rbacUser ?? null }));

    const r = await request(app).get('/test');
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
  });

  test('RB-26  resolve requires a real credential — no request passes through without one', async () => {
    const { app } = makeResolveApp();
    const r = await request(app).get('/test'); // no credential of any kind
    expect(r.status).toBe(403);
  });

  test('RB-27  X-Ops-Actor header is ignored — does not establish identity', async () => {
    const { app, store } = makeResolveApp();
    store.createUser({ username: 'alice', role: 'admin' });
    // X-Ops-Actor header alone (without going through pre-auth / opsAuth) → 403
    const r = await request(app).get('/test').set({ 'X-Ops-Actor': 'alice' });
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
  });

  test('RB-28  X-Ops-Actor with any value is ignored', async () => {
    const { app } = makeResolveApp();
    const r = await request(app).get('/test').set({ 'X-Ops-Actor': 'a'.repeat(200) });
    expect(r.status).toBe(403);
  });

  test('RB-29  rbacUser is frozen (immutable)', async () => {
    const { app, store } = makeResolveApp();
    store.createUser({ username: 'bob', role: 'operator' });
    let capturedUser;
    app.get('/capture', (req, res) => {
      capturedUser = req.rbacUser;
      res.json({ ok: true });
    });
    await request(app).get('/capture').set(testActorHeader('bob'));
    expect(() => { capturedUser.role = 'admin'; }).toThrow();
  });

  test('RB-30  resolve returns 403 (not 500) when no identity is present', async () => {
    // rbacResolve no longer calls getUserByUsername — it only inspects req.rbacUser.
    // Any request that reaches rbacResolve without an authenticated identity gets 403.
    const resolve = createRbacResolveMiddleware({ store: {} });
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'x'; next(); });
    app.use(resolve);
    app.get('/t', (_req, res) => res.json({ ok: true }));
    const r = await request(app).get('/t');  // no pre-auth, no rbacUser
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-31…RB-42  requirePermission middleware
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-31…RB-42  requirePermission middleware', () => {
  function makePermApp() {
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store });
    const rp      = createRequirePermission();
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    app.use(makePreAuthMiddleware(store));   // simulates opsAuth
    app.use(resolve);

    // Add test routes
    app.get('/audit',    rp('READ_AUDIT'),       (_, res) => res.json({ ok: true }));
    app.get('/evidence', rp('GENERATE_EVIDENCE'), (_, res) => res.json({ ok: true }));
    app.get('/keys',     rp('MANAGE_KEYS'),       (_, res) => res.json({ ok: true }));
    app.get('/dash',     rp('VIEW_DASHBOARD'),    (_, res) => res.json({ ok: true }));
    app.get('/users',    rp('MANAGE_USERS'),      (_, res) => res.json({ ok: true }));
    return { app, store };
  }

  async function getAs(app, route, username) {
    return request(app).get(route).set(testActorHeader(username));
  }

  test('RB-31  Admin can access all routes', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'superadmin', role: 'admin' });
    for (const route of ['/audit', '/evidence', '/keys', '/dash', '/users']) {
      const r = await getAs(app, route, 'superadmin');
      expect(r.status).toBe(200);
    }
  });

  test('RB-32  Auditor can read audit and generate evidence but not manage keys', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'audrey', role: 'auditor' });
    expect((await getAs(app, '/audit',    'audrey')).status).toBe(200);
    expect((await getAs(app, '/evidence', 'audrey')).status).toBe(200);
    expect((await getAs(app, '/keys',     'audrey')).status).toBe(403);
    expect((await getAs(app, '/users',    'audrey')).status).toBe(403);
  });

  test('RB-33  Compliance can generate evidence but not manage keys or users', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'comp', role: 'compliance' });
    expect((await getAs(app, '/evidence', 'comp')).status).toBe(200);
    expect((await getAs(app, '/audit',    'comp')).status).toBe(200);
    expect((await getAs(app, '/keys',     'comp')).status).toBe(403);
    expect((await getAs(app, '/users',    'comp')).status).toBe(403);
  });

  test('RB-34  Operator can generate evidence and view dashboard but not audit or keys', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'ops', role: 'operator' });
    expect((await getAs(app, '/evidence', 'ops')).status).toBe(200);
    expect((await getAs(app, '/dash',     'ops')).status).toBe(200);
    expect((await getAs(app, '/audit',    'ops')).status).toBe(403);
    expect((await getAs(app, '/keys',     'ops')).status).toBe(403);
  });

  test('RB-35  Viewer can only access dashboard', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'lurker', role: 'viewer' });
    expect((await getAs(app, '/dash',     'lurker')).status).toBe(200);
    expect((await getAs(app, '/audit',    'lurker')).status).toBe(403);
    expect((await getAs(app, '/evidence', 'lurker')).status).toBe(403);
    expect((await getAs(app, '/keys',     'lurker')).status).toBe(403);
    expect((await getAs(app, '/users',    'lurker')).status).toBe(403);
  });

  test('RB-36  Permission denied returns 403 with FORBIDDEN error', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'viewer', role: 'viewer' });
    const r = await getAs(app, '/keys', 'viewer');
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
    expect(r.body.error.message).toBe('Insufficient permissions');
  });

  test('RB-37  403 response must not leak user role or internal details', async () => {
    const { app, store } = makePermApp();
    store.createUser({ username: 'leaker', role: 'viewer' });
    const r = await getAs(app, '/audit', 'leaker');
    expect(r.status).toBe(403);
    const body = JSON.stringify(r.body);
    expect(body).not.toContain('viewer');
    expect(body).not.toContain('rbacUser');
  });

  test('RB-38  requirePermission throws at setup time for unknown permission', () => {
    const rp = createRequirePermission();
    expect(() => rp('NOT_A_REAL_PERM')).toThrow('unknown permission');
  });

  test('RB-39  requirePermission denies when rbacUser not set (no resolve middleware)', async () => {
    const rp  = createRequirePermission();
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    // No resolve middleware — rbacUser will be undefined
    app.get('/secret', rp('READ_AUDIT'), (_, res) => res.json({ ok: true }));
    const r = await request(app).get('/secret');
    expect(r.status).toBe(403);
  });

  test('RB-40  no permission check ever passes through without an explicit RBAC assignment', async () => {
    // Regression guard for the removed vulnerability (formerly: "RBAC
    // disabled" made every requirePermission() check a no-op). Every route
    // below now requires a real user record with a role that is actually
    // permitted — an unauthenticated caller is denied on every one of them.
    const { app } = makePermApp();
    for (const route of ['/audit', '/evidence', '/keys', '/dash', '/users']) {
      const r = await request(app).get(route); // no actor header
      expect(r.status).toBe(403);
    }
  });

  test('RB-41  an authentication header is always required — there is no unauthenticated pass-through', async () => {
    const { app } = makePermApp();
    const r = await request(app).get('/audit');
    expect(r.status).toBe(403);
  });

  test('RB-42  Multiple permission checks compose correctly', async () => {
    // Route that requires two sequential permission checks
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store });
    const rp      = createRequirePermission();
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    app.use(makePreAuthMiddleware(store));
    app.use(resolve);
    app.get('/both', rp('READ_AUDIT'), rp('GENERATE_EVIDENCE'), (_, res) => res.json({ ok: true }));

    store.createUser({ username: 'admin', role: 'admin' });
    store.createUser({ username: 'auditor', role: 'auditor' });
    store.createUser({ username: 'operator', role: 'operator' });

    // Admin has both
    expect((await request(app).get('/both').set(testActorHeader('admin'))).status).toBe(200);
    // Auditor has both
    expect((await request(app).get('/both').set(testActorHeader('auditor'))).status).toBe(200);
    // Operator has GENERATE_EVIDENCE but not READ_AUDIT — fails first check
    expect((await request(app).get('/both').set(testActorHeader('operator'))).status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-43…RB-55  /rbac admin API routes
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-43…RB-55  /rbac admin API routes', () => {
  let app, store;

  beforeEach(() => {
    ({ app, store } = makeApp());
    // Create an admin user so we can hit protected routes
    store.createUser({ username: 'admin', role: 'admin' });
  });

  async function adminGet(path)       { return request(app).get(path).set(testActorHeader('admin')); }
  async function adminPost(path, body){ return request(app).post(path).set(testActorHeader('admin')).send(body); }
  async function adminPut(path, body) { return request(app).put(path).set(testActorHeader('admin')).send(body); }
  async function adminDel(path)       { return request(app).delete(path).set(testActorHeader('admin')); }

  test('RB-43  GET /rbac/roles returns role definitions', async () => {
    const r = await adminGet('/rbac/roles');
    expect(r.status).toBe(200);
    const { roles } = r.body.data;
    // 5 -> 6, adding the 'tenant' role.
    expect(roles.length).toBe(6);
    const adminRole = roles.find(r => r.id === 'admin');
    expect(adminRole.permissions.length).toBeGreaterThan(0);
  });

  test('RB-44  GET /rbac/permissions returns full matrix', async () => {
    const r = await adminGet('/rbac/permissions');
    expect(r.status).toBe(200);
    const { matrix } = r.body.data;
    expect(matrix.length).toBeGreaterThan(0);
    const readAudit = matrix.find(m => m.permission === 'READ_AUDIT');
    expect(readAudit.allowedRoles).toContain('admin');
    expect(readAudit.allowedRoles).toContain('auditor');
  });

  test('RB-45  GET /rbac/users lists all users', async () => {
    store.createUser({ username: 'alice', role: 'auditor' });
    const r = await adminGet('/rbac/users');
    expect(r.status).toBe(200);
    expect(r.body.data.total).toBeGreaterThanOrEqual(2); // admin + alice
  });

  test('RB-46  POST /rbac/users creates user and returns 201', async () => {
    const r = await adminPost('/rbac/users', { username: 'newbie', role: 'viewer' });
    expect(r.status).toBe(201);
    expect(r.body.data.user.username).toBe('newbie');
    expect(r.body.data.user.role).toBe('viewer');
    expect(r.body.data.user.id).toBeTruthy();
  });

  test('RB-47  POST /rbac/users rejects missing fields', async () => {
    const r = await adminPost('/rbac/users', { username: 'missing-role' });
    // API-9 remediation: schema-validation failures now return 400, not 422.
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('MISSING_FIELDS');
  });

  test('RB-48  POST /rbac/users rejects invalid role', async () => {
    const r = await adminPost('/rbac/users', { username: 'joker', role: 'superadmin' });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('INVALID_ROLE');
  });

  test('item 9 audit: POST /rbac/users rejects an unrecognised extra body key (createUserSchema was .passthrough(), now .strict())', async () => {
    const r = await adminPost('/rbac/users', { username: 'newbie2', role: 'viewer', unexpectedKey: 'nope' });
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('MISSING_FIELDS');
  });

  test('RB-49  POST /rbac/users returns 409 on duplicate username', async () => {
    await adminPost('/rbac/users', { username: 'dup', role: 'viewer' });
    const r = await adminPost('/rbac/users', { username: 'dup', role: 'operator' });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('USERNAME_TAKEN');
  });

  test('RB-50  GET /rbac/users/:id returns user', async () => {
    const created = (await adminPost('/rbac/users', { username: 'charlie', role: 'operator' })).body.data.user;
    const r = await adminGet(`/rbac/users/${created.id}`);
    expect(r.status).toBe(200);
    expect(r.body.data.user.username).toBe('charlie');
  });

  test('RB-51  GET /rbac/users/:id returns 404 for unknown user', async () => {
    const r = await adminGet('/rbac/users/does-not-exist');
    expect(r.status).toBe(404);
  });

  test('RB-52  PUT /rbac/users/:id updates user role', async () => {
    const created = (await adminPost('/rbac/users', { username: 'changeme', role: 'viewer' })).body.data.user;
    const r = await adminPut(`/rbac/users/${created.id}`, { role: 'operator' });
    expect(r.status).toBe(200);
    expect(r.body.data.user.role).toBe('operator');
  });

  test('RB-53  DELETE /rbac/users/:id removes user', async () => {
    // Create a second admin so we can delete users without hitting LAST_ADMIN
    const created = (await adminPost('/rbac/users', { username: 'todelete', role: 'viewer' })).body.data.user;
    const r = await adminDel(`/rbac/users/${created.id}`);
    expect(r.status).toBe(200);
    expect(r.body.data.deleted).toBe(true);
    // Verify gone
    const get = await adminGet(`/rbac/users/${created.id}`);
    expect(get.status).toBe(404);
  });

  test('RB-54  GET /rbac/users/:id/permissions lists effective permissions', async () => {
    const created = (await adminPost('/rbac/users', { username: 'auditor2', role: 'auditor' })).body.data.user;
    const r = await adminGet(`/rbac/users/${created.id}/permissions`);
    expect(r.status).toBe(200);
    expect(r.body.data.permissions).toContain('READ_AUDIT');
    expect(r.body.data.permissions).toContain('GENERATE_EVIDENCE');
    expect(r.body.data.permissions).not.toContain('MANAGE_KEYS');
  });

  test('RB-55  Non-admin (viewer) cannot access /rbac/users', async () => {
    store.createUser({ username: 'lowperm', role: 'viewer' });
    const r = await request(app).get('/rbac/users').set(testActorHeader('lowperm'));
    expect(r.status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-56…RB-62  Bootstrap admin
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-56…RB-62  Bootstrap admin', () => {
  test('RB-56  bootstrapAdmin creates admin when store is empty', () => {
    const store = makeIsolatedStore();
    const admin = store.bootstrapAdmin();
    expect(admin).not.toBeNull();
    expect(admin.role).toBe('admin');
    expect(admin.enabled).toBe(true);
  });

  test('RB-57  bootstrapAdmin is idempotent when admin already exists', () => {
    const store = makeIsolatedStore();
    store.bootstrapAdmin();
    const second = store.bootstrapAdmin();
    expect(second).toBeNull();  // already existed, no new user created
    expect(store.listUsers().filter(u => u.role === 'admin').length).toBe(1);
  });

  test('RB-58  bootstrap respects QODIQA_RBAC_BOOTSTRAP_ADMIN_ID env var', () => {
    const store = makeIsolatedStore();
    const savedId = process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_ID;
    try {
      process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_ID       = 'custom-admin-id';
      process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_USERNAME = 'customadmin';
      const admin = store.bootstrapAdmin();
      expect(admin.id).toBe('custom-admin-id');
      expect(admin.username).toBe('customadmin');
    } finally {
      process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_ID = savedId || '';
      delete process.env.QODIQA_RBAC_BOOTSTRAP_ADMIN_USERNAME;
    }
  });

  test('RB-59  bootstrapAdmin is marked as BOOTSTRAP creator', () => {
    const store = makeIsolatedStore();
    const admin = store.bootstrapAdmin();
    expect(admin.createdBy).toBe('BOOTSTRAP');
  });

  test('RB-60  after bootstrap, admin can be looked up by username', () => {
    const store = makeIsolatedStore();
    store.bootstrapAdmin();
    const found = store.getUserByUsername('admin');
    expect(found).not.toBeNull();
    expect(found.role).toBe('admin');
  });

  test('RB-61  bootstrapAdmin does NOT create extra users when non-admin users exist', () => {
    const store = makeIsolatedStore();
    store.createUser({ username: 'operator', role: 'operator' });
    const admin = store.bootstrapAdmin();  // no admin yet, should create
    expect(admin).not.toBeNull();
    expect(store.listUsers().length).toBe(2);  // operator + bootstrap-admin
  });

  test('RB-62  bootstrapAdmin skips when a manual admin already exists', () => {
    const store = makeIsolatedStore();
    store.createUser({ username: 'manualadmin', role: 'admin' });
    const result = store.bootstrapAdmin();
    expect(result).toBeNull();
    expect(store.listUsers().filter(u => u.role === 'admin').length).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-63…RB-68  Fail-closed scenarios
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-63…RB-68  Fail-closed scenarios', () => {
  test('RB-63  missing authentication returns 403 (not 500) when RBAC enabled', async () => {
    const { app, store } = makeApp();
    store.createUser({ username: 'admin', role: 'admin' });
    const r = await request(app).get('/rbac/roles');  // no pre-auth, no rbacUser
    expect(r.status).toBe(403);
  });

  test('RB-64  unresolvable pre-auth username returns 403 (not 500)', async () => {
    const { app } = makeApp();
    const r = await request(app).get('/rbac/roles').set(testActorHeader('ghost'));
    expect(r.status).toBe(403);
  });

  test('RB-65  disabled user returns 403', async () => {
    const { app, store } = makeApp();
    // Create two admins so we can disable one
    store.createUser({ username: 'admin', role: 'admin' });
    const disabled = store.createUser({ username: 'disabled-admin', role: 'admin' });
    store.createUser({ username: 'admin2', role: 'admin' });
    store.updateUser(disabled.id, { enabled: false, updatedBy: 'test' });

    const r = await request(app).get('/rbac/roles').set(testActorHeader('disabled-admin'));
    expect(r.status).toBe(403);
  });

  test('RB-66  store.updateUser throws NOT_FOUND for unknown user ID', () => {
    const store = makeIsolatedStore();
    expect(() => store.updateUser('nonexistent', { role: 'viewer' }))
      .toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  test('RB-67  store.deleteUser throws NOT_FOUND for unknown user ID', () => {
    const store = makeIsolatedStore();
    expect(() => store.deleteUser('nonexistent'))
      .toThrow(expect.objectContaining({ code: 'NOT_FOUND' }));
  });

  test('RB-68  requirePermission with no rbacUser returns 403, not 500', async () => {
    const rp  = createRequirePermission();
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'test'; next(); });
    // Deliberately skip resolve middleware so req.rbacUser is undefined
    app.get('/protected', rp('READ_AUDIT'), (_, res) => res.json({ ok: true }));

    const r = await request(app).get('/protected');
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe('FORBIDDEN');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-69…RB-74  Regression guards: fail-closed is unconditional
//
// remediation: QODIQA_RBAC_ENABLED=false (or unset) used to attach a
// synthetic admin identity (SYNTHETIC_ADMIN, role="admin", synthetic:true) to
// every request and turn every requirePermission() check into a no-op — a
// fail-OPEN default that granted full administrative access to any
// authenticated caller with no RBAC assignment at all. That code path has
// been deleted from src/middleware/rbac.js entirely; these tests assert it
// cannot be reconstructed through any input, including the legacy
// `{ enabled: false }` option shape (accepted for call-site compatibility,
// but no longer read for any security decision).
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-69…RB-74  Regression guards: fail-closed is unconditional', () => {
  test('RB-69  resolve NEVER attaches an admin identity — passing the legacy option is a no-op', async () => {
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store, enabled: false });
    const app = express();
    app.use(express.json());
    app.use((req, _r, next) => { req.requestId = 'x'; next(); });
    app.use(resolve);
    app.get('/t', (req, res) => res.json({ user: req.rbacUser ?? null }));
    const r = await request(app).get('/t');
    expect(r.status).toBe(403);
    expect(r.body.user).toBeUndefined();
  });

  test('RB-70  requirePermission still denies — passing the legacy option is a no-op', async () => {
    const rp  = createRequirePermission({ enabled: false });
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = 'x'; next(); });
    // MANAGE_KEYS requires admin role — no rbacUser is set here at all
    app.get('/keys', rp('MANAGE_KEYS'), (_, res) => res.json({ ok: true }));
    const r = await request(app).get('/keys');
    expect(r.status).toBe(403);
  });

  test('RB-71  an identity header is always required — no request bypasses authentication', async () => {
    const { app } = makeApp();
    const r = await request(app).get('/rbac/roles');
    expect(r.status).toBe(403);
  });

  test('RB-72  POST /rbac/users requires MANAGE_USERS — an unauthenticated caller is denied', async () => {
    const { app } = makeApp();
    const r = await request(app)
      .post('/rbac/users')
      .send({ username: 'noauth-user', role: 'viewer' });
    expect(r.status).toBe(403);
  });

  test('RB-73  an admin route only succeeds for a real, explicitly-assigned admin user', async () => {
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store });
    const rp      = createRequirePermission();
    const app = express();
    app.use(express.json());
    app.use((req, _r, next) => { req.requestId = 'x'; next(); });
    app.use(makePreAuthMiddleware(store));
    app.use(resolve);
    app.get('/any', rp('MANAGE_KEYS'), (_, res) => res.json({ ok: true }));

    // No identity at all → denied
    expect((await request(app).get('/any')).status).toBe(403);

    // A real, persisted admin user → allowed. This is the ONLY way to reach
    // this route: an explicit RBAC assignment, never a default or fallback.
    store.createUser({ username: 'real-admin', role: 'admin' });
    expect((await request(app).get('/any').set(testActorHeader('real-admin'))).status).toBe(200);
  });

  test('RB-74  createRequirePermission always throws on unknown permission, regardless of any option passed', () => {
    // Permission-name validation is unconditional — it never depended on the
    // removed enabled/disabled distinction, and still doesn't.
    const rpNoArgs  = createRequirePermission();
    const rpLegacyArg = createRequirePermission({ enabled: false });
    expect(() => rpNoArgs('INVALID_PERM')).toThrow('unknown permission');
    expect(() => rpLegacyArg('INVALID_PERM')).toThrow('unknown permission');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-75…RB-80  Evidence package requestor context (Req 7)
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-75…RB-80  Evidence package requestor context', () => {
  const { generateEvidencePackage } = require('../../../core/evidence/generator');
  const { append } = require('../../../core/audit/audit-log.js');
  const { getActiveKey } = require('../../../../services/artifact/keyStore');
  const { computePolicyHash } = require('../../../../services/policyHash');
  const { signArtifact } = require('../../../validation/signArtifact');
  const crypto = require('crypto');

  let KEY;
  const TEST_POLICIES = [
    { id: 'p1', type: 'REQUIRE_CONSENT', priority: 1, enabled: true, config: {} },
  ];

  beforeAll(() => { KEY = getActiveKey('default'); });

  function appendTestAllow(artifactId) {
    const artifact   = signArtifact({ payload: { x: 1 }, timestamp: Date.now(), expiry: Date.now() + 60000, publicKeyId: KEY.keyId }, KEY.privDer);
    const inputHash  = crypto.createHash('sha256').update(JSON.stringify(artifact.payload)).digest('hex');
    const policyHash = computePolicyHash(TEST_POLICIES);
    return append({
      artifactId,
      inputHash,
      decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:          Buffer.from(artifact.signature, 'base64').toString('hex'),
      requestHash:        crypto.createHash('sha256').update('req').digest('hex'),
      policyHash,
      verificationResult: true,
      executionContext:   { stage: 'ENFORCE', reason: 'ALL_CHECKS_PASSED', publicKeyId: KEY.keyId },
    });
  }

  test('RB-75  evidence package includes requestor section', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    const requestor = { id: 'user-123', username: 'alice', role: 'auditor' };
    const result = await generateEvidencePackage(artifactId, TEST_POLICIES, requestor);
    expect(result.found).toBe(true);
    expect(result.package.sections.requestor).toBeDefined();
    expect(result.package.sections.requestor.userId).toBe('user-123');
    expect(result.package.sections.requestor.username).toBe('alice');
    expect(result.package.sections.requestor.role).toBe('auditor');
  });

  test('RB-76  requestor authorization result is AUTHORIZED when user provided', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    const result = await generateEvidencePackage(artifactId, TEST_POLICIES, { id: 'u1', username: 'bob', role: 'compliance' });
    expect(result.package.sections.requestor.authorizationResult).toBe('AUTHORIZED');
  });

  test('RB-77  requestor section shows UNKNOWN when no requestor provided', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    const result = await generateEvidencePackage(artifactId, TEST_POLICIES, null);
    expect(result.package.sections.requestor.authorizationResult).toBe('UNKNOWN');
    expect(result.package.sections.requestor.userId).toBeNull();
  });

  test('RB-78  requestor section is included in package integrity seal', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    const requestor = { id: 'req1', username: 'carol', role: 'operator' };
    const pkg1 = await generateEvidencePackage(artifactId, TEST_POLICIES, requestor);
    // The package hash should be non-null and a SHA-256 hex string
    expect(pkg1.package.integrity.packageHash).toMatch(/^[a-f0-9]{64}$/);
  });

  test('RB-79  synthetic RBAC user (disabled mode) appears in requestor section', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    // Synthetic admin from disabled RBAC mode
    const syntheticUser = { id: '_service', username: 'service-account', role: 'admin', synthetic: true };
    const result = await generateEvidencePackage(artifactId, TEST_POLICIES, syntheticUser);
    expect(result.package.sections.requestor.role).toBe('admin');
    expect(result.package.sections.requestor.username).toBe('service-account');
  });

  test('RB-80  requestor section has generatedAt timestamp', async () => {
    const artifactId = randomUUID();
    await appendTestAllow(artifactId);
    const before = new Date().toISOString();
    const result = await generateEvidencePackage(artifactId, TEST_POLICIES, { id: 'x', username: 'eve', role: 'auditor' });
    expect(result.package.sections.requestor.generatedAt).toBeTruthy();
    expect(result.package.sections.requestor.generatedAt >= before).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-81…RB-110  Permission completeness, MANAGE_CONSENT, and batch RBAC
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-81…RB-110  Permission completeness, MANAGE_CONSENT, and batch RBAC', () => {

  // ── Permission matrix integrity ─────────────────────────────────────────────

  test('RB-81  PERMISSION_SET has no duplicate keys', () => {
    const keys = Object.keys(PERMISSIONS);
    expect(new Set(keys).size).toBe(keys.length);
  });

  test('RB-82  every permission has at least one allowed role', () => {
    for (const [perm, roles] of Object.entries(PERMISSIONS)) {
      expect(roles.length).toBeGreaterThan(0);
      // roles must all be valid canonical role strings
      for (const role of roles) {
        expect(isValidRole(role)).toBe(true);
      }
    }
  });

  test('RB-83  admin is permitted every defined permission', () => {
    for (const perm of Object.keys(PERMISSIONS)) {
      expect(isPermitted(ROLES.ADMIN, perm)).toBe(true);
    }
  });

  // ── MANAGE_CONSENT ──────────────────────────────────────────────────────────

  test('RB-84  MANAGE_CONSENT is defined in the permission matrix', () => {
    expect(isValidPermission('MANAGE_CONSENT')).toBe(true);
  });

  test('RB-85  only admin has MANAGE_CONSENT', () => {
    expect(isPermitted(ROLES.ADMIN,      'MANAGE_CONSENT')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR,   'MANAGE_CONSENT')).toBe(false);
    expect(isPermitted(ROLES.VIEWER,     'MANAGE_CONSENT')).toBe(false);
  });

  // ── SUBMIT_BATCH_CERTIFICATION ──────────────────────────────────────────────

  test('RB-86  SUBMIT_BATCH_CERTIFICATION is defined in the permission matrix', () => {
    expect(isValidPermission('SUBMIT_BATCH_CERTIFICATION')).toBe(true);
  });

  test('RB-87  admin and operator have SUBMIT_BATCH_CERTIFICATION; others do not', () => {
    expect(isPermitted(ROLES.ADMIN,      'SUBMIT_BATCH_CERTIFICATION')).toBe(true);
    expect(isPermitted(ROLES.OPERATOR,   'SUBMIT_BATCH_CERTIFICATION')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'SUBMIT_BATCH_CERTIFICATION')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'SUBMIT_BATCH_CERTIFICATION')).toBe(false);
    expect(isPermitted(ROLES.VIEWER,     'SUBMIT_BATCH_CERTIFICATION')).toBe(false);
  });

  // ── CANCEL_BATCH_CERTIFICATION ──────────────────────────────────────────────

  test('RB-88  CANCEL_BATCH_CERTIFICATION is defined in the permission matrix', () => {
    expect(isValidPermission('CANCEL_BATCH_CERTIFICATION')).toBe(true);
  });

  test('RB-89  admin and operator have CANCEL_BATCH_CERTIFICATION; others do not', () => {
    expect(isPermitted(ROLES.ADMIN,      'CANCEL_BATCH_CERTIFICATION')).toBe(true);
    expect(isPermitted(ROLES.OPERATOR,   'CANCEL_BATCH_CERTIFICATION')).toBe(true);
    expect(isPermitted(ROLES.AUDITOR,    'CANCEL_BATCH_CERTIFICATION')).toBe(false);
    expect(isPermitted(ROLES.COMPLIANCE, 'CANCEL_BATCH_CERTIFICATION')).toBe(false);
    expect(isPermitted(ROLES.VIEWER,     'CANCEL_BATCH_CERTIFICATION')).toBe(false);
  });

  // ── READ_CERTIFICATIONS scope ───────────────────────────────────────────────

  test('RB-90  operator has READ_CERTIFICATIONS for batch status monitoring', () => {
    expect(isPermitted(ROLES.OPERATOR, 'READ_CERTIFICATIONS')).toBe(true);
  });

  test('RB-91  operator cannot export certifications (export is audit/compliance only)', () => {
    expect(isPermitted(ROLES.OPERATOR, 'EXPORT_CERTIFICATIONS')).toBe(false);
  });

  // ── Viewer privilege scope ──────────────────────────────────────────────────

  test('RB-92  viewer has exactly one permission (VIEW_DASHBOARD)', () => {
    const viewerPerms = permissionsForRole(ROLES.VIEWER);
    expect(viewerPerms).toHaveLength(1);
    expect(viewerPerms[0]).toBe('VIEW_DASHBOARD');
  });

  // ── Compliance privilege scope ──────────────────────────────────────────────

  test('RB-93  compliance has MANAGE_RETENTION but no other MANAGE_* permission', () => {
    const compliancePerms = permissionsForRole(ROLES.COMPLIANCE);
    const managePerms = compliancePerms.filter(p => p.startsWith('MANAGE_'));
    expect(managePerms).toContain('MANAGE_RETENTION');
    expect(managePerms).not.toContain('MANAGE_USERS');
    expect(managePerms).not.toContain('MANAGE_KEYS');
    expect(managePerms).not.toContain('MANAGE_POLICIES');
    expect(managePerms).not.toContain('MANAGE_CONSENT');
    expect(managePerms).not.toContain('MANAGE_WEBHOOKS');
    expect(managePerms).not.toContain('SUBMIT_BATCH_CERTIFICATION');
    expect(managePerms).not.toContain('CANCEL_BATCH_CERTIFICATION');
  });

  // ── requirePermission factory — regression guards ───────────────────────────
  // These confirm that requirePermission no longer throws at creation time for
  // the three permissions that were previously undefined in the matrix.

  test('RB-94  requirePermission does not throw for MANAGE_CONSENT', () => {
    const rp = createRequirePermission();
    expect(() => rp('MANAGE_CONSENT')).not.toThrow();
  });

  test('RB-95  requirePermission does not throw for SUBMIT_BATCH_CERTIFICATION', () => {
    const rp = createRequirePermission();
    expect(() => rp('SUBMIT_BATCH_CERTIFICATION')).not.toThrow();
  });

  test('RB-96  requirePermission does not throw for CANCEL_BATCH_CERTIFICATION', () => {
    const rp = createRequirePermission();
    expect(() => rp('CANCEL_BATCH_CERTIFICATION')).not.toThrow();
  });

  // ── Privilege escalation guards ─────────────────────────────────────────────

  test('RB-97  operator cannot access MANAGE_CONSENT (privilege boundary)', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_CONSENT')).toBe(false);
  });

  test('RB-98  auditor cannot submit batch certifications (privilege boundary)', () => {
    expect(isPermitted(ROLES.AUDITOR, 'SUBMIT_BATCH_CERTIFICATION')).toBe(false);
    expect(isPermitted(ROLES.AUDITOR, 'CANCEL_BATCH_CERTIFICATION')).toBe(false);
  });

  test('RB-99  operator cannot access user management (privilege boundary)', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_USERS')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR, 'READ_USERS')).toBe(false);
  });

  test('RB-100  operator cannot manage policies, keys, or webhooks', () => {
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_POLICIES')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_KEYS')).toBe(false);
    expect(isPermitted(ROLES.OPERATOR, 'MANAGE_WEBHOOKS')).toBe(false);
  });

  // ── HTTP enforcement of new permissions ─────────────────────────────────────

  function makeNewPermApp() {
    const store   = makeIsolatedStore();
    const resolve = createRbacResolveMiddleware({ store });
    const rp      = createRequirePermission();
    const app     = express();
    app.use(express.json());
    app.use((req, _res, next) => { req.requestId = `test-${Date.now()}`; next(); });
    app.use(makePreAuthMiddleware(store));
    app.use(resolve);
    app.get('/consent',  rp('MANAGE_CONSENT'),             (_, res) => res.json({ ok: true }));
    app.get('/batch',    rp('SUBMIT_BATCH_CERTIFICATION'),  (_, res) => res.json({ ok: true }));
    app.get('/cancel',   rp('CANCEL_BATCH_CERTIFICATION'),  (_, res) => res.json({ ok: true }));
    app.get('/certread', rp('READ_CERTIFICATIONS'),         (_, res) => res.json({ ok: true }));
    return { app, store };
  }

  async function permGet(app, route, username) {
    return request(app).get(route).set(testActorHeader(username));
  }

  test('RB-101  admin can access MANAGE_CONSENT route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'adm', role: 'admin' });
    expect((await permGet(app, '/consent', 'adm')).status).toBe(200);
  });

  test('RB-102  non-admin roles are denied MANAGE_CONSENT route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'aud',  role: 'auditor'    });
    store.createUser({ username: 'comp', role: 'compliance' });
    store.createUser({ username: 'ops',  role: 'operator'   });
    store.createUser({ username: 'view', role: 'viewer'     });
    expect((await permGet(app, '/consent', 'aud')).status).toBe(403);
    expect((await permGet(app, '/consent', 'comp')).status).toBe(403);
    expect((await permGet(app, '/consent', 'ops')).status).toBe(403);
    expect((await permGet(app, '/consent', 'view')).status).toBe(403);
  });

  test('RB-103  admin and operator can access SUBMIT_BATCH_CERTIFICATION route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'adm', role: 'admin'    });
    store.createUser({ username: 'ops', role: 'operator' });
    expect((await permGet(app, '/batch', 'adm')).status).toBe(200);
    expect((await permGet(app, '/batch', 'ops')).status).toBe(200);
  });

  test('RB-104  auditor and compliance are denied SUBMIT_BATCH_CERTIFICATION route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'aud',  role: 'auditor'    });
    store.createUser({ username: 'comp', role: 'compliance' });
    store.createUser({ username: 'view', role: 'viewer'     });
    expect((await permGet(app, '/batch', 'aud')).status).toBe(403);
    expect((await permGet(app, '/batch', 'comp')).status).toBe(403);
    expect((await permGet(app, '/batch', 'view')).status).toBe(403);
  });

  test('RB-105  admin and operator can access CANCEL_BATCH_CERTIFICATION route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'adm', role: 'admin'    });
    store.createUser({ username: 'ops', role: 'operator' });
    expect((await permGet(app, '/cancel', 'adm')).status).toBe(200);
    expect((await permGet(app, '/cancel', 'ops')).status).toBe(200);
  });

  test('RB-106  auditor and compliance are denied CANCEL_BATCH_CERTIFICATION route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'aud',  role: 'auditor'    });
    store.createUser({ username: 'comp', role: 'compliance' });
    expect((await permGet(app, '/cancel', 'aud')).status).toBe(403);
    expect((await permGet(app, '/cancel', 'comp')).status).toBe(403);
  });

  test('RB-107  operator can access READ_CERTIFICATIONS route (batch monitoring)', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'ops',  role: 'operator'   });
    store.createUser({ username: 'aud',  role: 'auditor'    });
    store.createUser({ username: 'comp', role: 'compliance' });
    store.createUser({ username: 'adm',  role: 'admin'      });
    // All four are permitted
    expect((await permGet(app, '/certread', 'ops')).status).toBe(200);
    expect((await permGet(app, '/certread', 'aud')).status).toBe(200);
    expect((await permGet(app, '/certread', 'comp')).status).toBe(200);
    expect((await permGet(app, '/certread', 'adm')).status).toBe(200);
  });

  test('RB-108  viewer is denied READ_CERTIFICATIONS route', async () => {
    const { app, store } = makeNewPermApp();
    store.createUser({ username: 'view', role: 'viewer' });
    expect((await permGet(app, '/certread', 'view')).status).toBe(403);
  });

  // ── /rbac/permissions API completeness ──────────────────────────────────────

  test('RB-109  /rbac/permissions API includes MANAGE_CONSENT', async () => {
    const { app, store } = makeApp();
    store.createUser({ username: 'admin', role: 'admin' });
    const r = await request(app).get('/rbac/permissions').set(testActorHeader('admin'));
    expect(r.status).toBe(200);
    const { matrix } = r.body.data;
    const entry = matrix.find(m => m.permission === 'MANAGE_CONSENT');
    expect(entry).toBeDefined();
    expect(entry.allowedRoles).toEqual(['admin']);
  });

  test('RB-110  /rbac/permissions API includes all three formerly-missing permissions', async () => {
    const { app, store } = makeApp();
    store.createUser({ username: 'admin', role: 'admin' });
    const r = await request(app).get('/rbac/permissions').set(testActorHeader('admin'));
    expect(r.status).toBe(200);
    const { matrix } = r.body.data;
    const permNames = matrix.map(m => m.permission);
    expect(permNames).toContain('MANAGE_CONSENT');
    expect(permNames).toContain('SUBMIT_BATCH_CERTIFICATION');
    expect(permNames).toContain('CANCEL_BATCH_CERTIFICATION');

    // Removed dead permissions must not appear
    expect(permNames).not.toContain('EXPORT_AUDIT');
    expect(permNames).not.toContain('READ_INVESTIGATIONS');
    expect(permNames).not.toContain('VIEW_DIAGNOSTICS');
    expect(permNames).not.toContain('VERIFY_ARTIFACTS');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-111…RB-130 Custom role admin routes
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-111…RB-130 /rbac/roles custom role admin routes', () => {
  let app, store, customRoleStore;

  beforeEach(() => {
    ({ app, store, customRoleStore } = makeApp());
    store.createUser({ username: 'admin', role: 'admin' });
    store.createUser({ username: 'viewer', role: 'viewer' });
  });

  async function adminGet(path)       { return request(app).get(path).set(testActorHeader('admin')); }
  async function adminPost(path, body){ return request(app).post(path).set(testActorHeader('admin')).send(body); }
  async function adminPut(path, body) { return request(app).put(path).set(testActorHeader('admin')).send(body); }
  async function adminDel(path)       { return request(app).delete(path).set(testActorHeader('admin')); }
  async function viewerGet(path)      { return request(app).get(path).set(testActorHeader('viewer')); }
  async function viewerPost(path, body){ return request(app).post(path).set(testActorHeader('viewer')).send(body); }

  test('RB-111  POST /rbac/roles creates a custom role', async () => {
    const r = await adminPost('/rbac/roles', { name: 'Policy Reviewer', permissions: ['READ_POLICIES', 'REVIEW_POLICY_CHANGE'] });
    expect(r.status).toBe(201);
    expect(r.body.data.role.id).toBe('custom:policy-reviewer');
    expect(r.body.data.role.builtIn).toBe(false);
  });

  test('RB-112  POST /rbac/roles requires MANAGE_USERS (viewer denied)', async () => {
    const r = await viewerPost('/rbac/roles', { name: 'Nope', permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(403);
  });

  test('RB-113  POST /rbac/roles rejects missing fields', async () => {
    const r = await adminPost('/rbac/roles', { name: 'No Perms' });
    // API-9 remediation: schema-validation failures now return 400, not 422.
    expect(r.status).toBe(400);
  });

  test('RB-114  POST /rbac/roles rejects unknown permissions with UNKNOWN_PERMISSION', async () => {
    const r = await adminPost('/rbac/roles', { name: 'Bad Role', permissions: ['NOT_A_REAL_PERMISSION'] });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('UNKNOWN_PERMISSION');
  });

  test('item 9 audit: POST /rbac/roles rejects an unrecognised extra body key (createRoleSchema had no explicit mode — default strip — now .strict())', async () => {
    const r = await adminPost('/rbac/roles', { name: 'Extra Key Role', permissions: ['READ_POLICIES'], unexpectedKey: 'nope' });
    expect(r.status).toBe(400);
  });

  test('RB-115  POST /rbac/roles rejects duplicate permissions with DUPLICATE_PERMISSION', async () => {
    const r = await adminPost('/rbac/roles', { name: 'Dup Role', permissions: ['READ_POLICIES', 'READ_POLICIES'] });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('DUPLICATE_PERMISSION');
  });

  test('RB-116  POST /rbac/roles rejects a name colliding with a built-in role', async () => {
    const r = await adminPost('/rbac/roles', { name: 'admin', permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('RESERVED_ROLE_NAME');
  });

  test('RB-117  POST /rbac/roles returns 409 for a duplicate role name', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const r = await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(409);
    expect(r.body.error.code).toBe('ROLE_EXISTS');
  });

  test('RB-118  GET /rbac/roles lists built-in roles plus custom roles', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const r = await adminGet('/rbac/roles');
    expect(r.status).toBe(200);
    const { roles } = r.body.data;
    expect(roles).toHaveLength(7); // 6 built-in + 1 custom
    const custom = roles.find(x => x.id === 'custom:reviewer');
    expect(custom).toBeDefined();
    expect(custom.builtIn).toBe(false);
    expect(roles.filter(x => x.builtIn).length).toBe(6);
  });

  test('RB-119  GET /rbac/roles/:id returns a custom role', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const r = await adminGet('/rbac/roles/custom:reviewer');
    expect(r.status).toBe(200);
    expect(r.body.data.role.name).toBe('Reviewer');
  });

  test('RB-120  GET /rbac/roles/:id returns a built-in role', async () => {
    const r = await adminGet('/rbac/roles/admin');
    expect(r.status).toBe(200);
    expect(r.body.data.role.builtIn).toBe(true);
    expect(r.body.data.role.permissions.length).toBeGreaterThan(0);
  });

  test('RB-121  GET /rbac/roles/:id returns 404 for an unknown role', async () => {
    const r = await adminGet('/rbac/roles/custom:does-not-exist');
    expect(r.status).toBe(404);
  });

  test('RB-122  PUT /rbac/roles/:id updates a custom role\'s permissions', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const r = await adminPut('/rbac/roles/custom:reviewer', { permissions: ['MANAGE_WEBHOOKS'] });
    expect(r.status).toBe(200);
    expect(r.body.data.role.permissions).toEqual(['MANAGE_WEBHOOKS']);
  });

  test('RB-123  PUT /rbac/roles/:id cannot modify a built-in role', async () => {
    const r = await adminPut('/rbac/roles/admin', { permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('CANNOT_MODIFY_BUILTIN');
  });

  test('RB-124  PUT /rbac/roles/:id returns 404 for an unknown custom role', async () => {
    const r = await adminPut('/rbac/roles/custom:does-not-exist', { permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(404);
  });

  test('RB-125  DELETE /rbac/roles/:id removes an unused custom role', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const r = await adminDel('/rbac/roles/custom:reviewer');
    expect(r.status).toBe(200);
    expect(customRoleStore.getRole('custom:reviewer')).toBeNull();
  });

  test('RB-126  DELETE /rbac/roles/:id cannot delete a built-in role', async () => {
    const r = await adminDel('/rbac/roles/admin');
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('CANNOT_MODIFY_BUILTIN');
  });

  test('RB-127  DELETE /rbac/roles/:id refuses to delete a role assigned to a user (409), and ?force=true overrides', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    await adminPost('/rbac/users', { username: 'reviewer-user', role: 'custom:reviewer' });

    const blocked = await adminDel('/rbac/roles/custom:reviewer');
    expect(blocked.status).toBe(409);
    expect(blocked.body.error.code).toBe('ROLE_IN_USE');
    expect(customRoleStore.getRole('custom:reviewer')).not.toBeNull();

    const forced = await request(app).delete('/rbac/roles/custom:reviewer?force=true').set(testActorHeader('admin'));
    expect(forced.status).toBe(200);
    expect(customRoleStore.getRole('custom:reviewer')).toBeNull();
  });

  test('RB-128  POST /rbac/roles/validate reports valid:true for a good permission set without persisting anything', async () => {
    const r = await adminPost('/rbac/roles/validate', { permissions: ['READ_POLICIES', 'REVIEW_POLICY_CHANGE'] });
    expect(r.status).toBe(200);
    expect(r.body.data.valid).toBe(true);
    expect(customRoleStore.listRoles()).toHaveLength(0);
  });

  test('RB-129  POST /rbac/roles/validate reports valid:false with a code for a bad permission set', async () => {
    const r = await adminPost('/rbac/roles/validate', { permissions: ['READ_POLICIES', 'NOT_REAL'] });
    expect(r.status).toBe(200);
    expect(r.body.data.valid).toBe(false);
    expect(r.body.data.code).toBe('UNKNOWN_PERMISSION');
  });

  test('RB-130  a user assigned a custom role is granted exactly that role\'s permissions end-to-end', async () => {
    await adminPost('/rbac/roles', { name: 'Reviewer', permissions: ['READ_POLICIES'] });
    const created = (await adminPost('/rbac/users', { username: 'reviewer-user', role: 'custom:reviewer' })).body.data.user;

    const r = await adminGet(`/rbac/users/${created.id}/permissions`);
    expect(r.status).toBe(200);
    expect(r.body.data.permissions).toEqual(['READ_POLICIES']);

    // And disabling the role immediately revokes it, without touching the user record
    await adminPut('/rbac/roles/custom:reviewer', { enabled: false });
    const r2 = await adminGet(`/rbac/users/${created.id}/permissions`);
    expect(r2.body.data.permissions).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RB-131…RB-136  API-9 remediation: PATCH is canonical, PUT is a deprecated
// alias
// ─────────────────────────────────────────────────────────────────────────────

describe('RB-131…RB-136  API-9: PATCH canonical / PUT deprecated alias', () => {
  let app, store;

  beforeEach(() => {
    ({ app, store } = makeApp());
    store.createUser({ username: 'admin', role: 'admin' });
  });

  async function adminPost(path, body)  { return request(app).post(path).set(testActorHeader('admin')).send(body); }
  async function adminPut(path, body)   { return request(app).put(path).set(testActorHeader('admin')).send(body); }
  async function adminPatch(path, body) { return request(app).patch(path).set(testActorHeader('admin')).send(body); }

  test('RB-131  PATCH /rbac/users/:id updates a user, identically to the old PUT', async () => {
    const created = (await adminPost('/rbac/users', { username: 'patchme', role: 'viewer' })).body.data.user;
    const r = await adminPatch(`/rbac/users/${created.id}`, { role: 'operator' });
    expect(r.status).toBe(200);
    expect(r.body.data.user.role).toBe('operator');
  });

  test('RB-132  PUT /rbac/users/:id still works but carries Deprecation headers', async () => {
    const created = (await adminPost('/rbac/users', { username: 'putme', role: 'viewer' })).body.data.user;
    const r = await adminPut(`/rbac/users/${created.id}`, { role: 'operator' });
    expect(r.status).toBe(200);
    expect(r.body.data.user.role).toBe('operator');
    expect(r.headers['deprecation']).toBe('true');
    expect(r.headers['link']).toContain(`/rbac/users/${created.id}`);
  });

  test('RB-133  PATCH /rbac/roles/:id updates a custom role, identically to the old PUT', async () => {
    await adminPost('/rbac/roles', { name: 'Patchable', permissions: ['READ_POLICIES'] });
    const r = await adminPatch('/rbac/roles/custom:patchable', { permissions: ['MANAGE_WEBHOOKS'] });
    expect(r.status).toBe(200);
    expect(r.body.data.role.permissions).toEqual(['MANAGE_WEBHOOKS']);
  });

  test('RB-134  PUT /rbac/roles/:id still works but carries Deprecation headers', async () => {
    await adminPost('/rbac/roles', { name: 'Putable', permissions: ['READ_POLICIES'] });
    const r = await adminPut('/rbac/roles/custom:putable', { permissions: ['MANAGE_WEBHOOKS'] });
    expect(r.status).toBe(200);
    expect(r.headers['deprecation']).toBe('true');
    expect(r.headers['link']).toContain('/rbac/roles/custom%3Aputable');
  });

  test('RB-135  PATCH /rbac/users/:id rejects schema-validation failures with 400 (not 422)', async () => {
    const created = (await adminPost('/rbac/users', { username: 'badpatch', role: 'viewer' })).body.data.user;
    const r = await adminPatch(`/rbac/users/${created.id}`, {});
    expect(r.status).toBe(400);
    expect(r.body.error.code).toBe('MISSING_FIELDS');
  });

  test('RB-136  PATCH /rbac/roles/:id still returns 422 for a genuine business-rule violation (built-in role)', async () => {
    const r = await adminPatch('/rbac/roles/admin', { permissions: ['READ_POLICIES'] });
    expect(r.status).toBe(422);
    expect(r.body.error.code).toBe('CANNOT_MODIFY_BUILTIN');
  });
});
