'use strict';

const { createAdminProtection } = require('./adminProtection');

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMiddleware(name) {
  const fn = jest.fn((_req, _res, next) => next());
  fn._name = name;
  return fn;
}

function makeStack() {
  const rateLimit         = makeMiddleware('rateLimit');
  const opsIpAllow        = makeMiddleware('opsIpAllow');
  const opsAuth           = makeMiddleware('opsAuth');
  const rbacResolve       = makeMiddleware('rbacResolve');
  const opsGate           = makeMiddleware('opsGate');
  const adminGate         = makeMiddleware('adminGate');
  const permissionMiddlewares = {};
  const requirePermission = jest.fn(permission => {
    if (!permissionMiddlewares[permission]) {
      permissionMiddlewares[permission] = makeMiddleware(`permission:${permission}`);
    }
    return permissionMiddlewares[permission];
  });

  const { adminStack, opsOnlyStack } = createAdminProtection({
    rateLimit, opsIpAllow, opsAuth, rbacResolve, requirePermission, opsGate, adminGate,
  });

  return { adminStack, opsOnlyStack, rateLimit, opsIpAllow, opsAuth, rbacResolve, opsGate, adminGate, requirePermission, permissionMiddlewares };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('createAdminProtection — adminStack()', () => {
  test('with a permission: returns layers in the exact fixed order', () => {
    const { adminStack, rateLimit, opsIpAllow, opsAuth, rbacResolve, adminGate, requirePermission, permissionMiddlewares } = makeStack();

    const layers = adminStack('READ_AUDIT');

    expect(requirePermission).toHaveBeenCalledWith('READ_AUDIT');
    expect(layers).toEqual([
      rateLimit,
      opsIpAllow,
      opsAuth,
      rbacResolve,
      permissionMiddlewares.READ_AUDIT,
      adminGate,
    ]);
  });

  test('without a permission: omits the permission layer but keeps every other layer and order', () => {
    const { adminStack, rateLimit, opsIpAllow, opsAuth, rbacResolve, adminGate, requirePermission } = makeStack();

    const layers = adminStack();

    expect(requirePermission).not.toHaveBeenCalled();
    expect(layers).toEqual([rateLimit, opsIpAllow, opsAuth, rbacResolve, adminGate]);
  });

  test('adminGate is always the last layer, so a disabled admin kill-switch blocks every mount identically', () => {
    const { adminStack } = makeStack();
    expect(adminStack('MANAGE_KEYS').at(-1)._name).toBe('adminGate');
    expect(adminStack().at(-1)._name).toBe('adminGate');
  });

  // the admin plane no longer shares the diagnostics switch.
  test('adminStack never contains opsGate (the diagnostics switch), in any form', () => {
    const { adminStack, opsGate } = makeStack();
    expect(adminStack('MANAGE_KEYS')).not.toContain(opsGate);
    expect(adminStack()).not.toContain(opsGate);
  });

  test('wiring without adminGate (or opsGate) fails closed at construction', () => {
    const m = makeMiddleware('m');
    const base = { rateLimit: m, opsIpAllow: m, opsAuth: m, rbacResolve: m, requirePermission: () => m };
    expect(() => createAdminProtection({ ...base, opsGate: m })).toThrow(/adminGate middleware is required/);
    expect(() => createAdminProtection({ ...base, adminGate: m })).toThrow(/opsGate middleware is required/);
  });

  test('rateLimit is always the first layer, ahead of any auth/RBAC work', () => {
    const { adminStack } = makeStack();
    expect(adminStack('MANAGE_KEYS')[0]._name).toBe('rateLimit');
    expect(adminStack()[0]._name).toBe('rateLimit');
  });

  test('two different permissions produce two distinct permission middlewares', () => {
    const { adminStack } = makeStack();
    const a = adminStack('MANAGE_KEYS');
    const b = adminStack('READ_AUDIT');
    expect(a[4]).not.toBe(b[4]);
  });
});

describe('createAdminProtection — opsOnlyStack()', () => {
  test('returns rateLimit, opsIpAllow, opsAuth, opsGate — no RBAC layers', () => {
    const { opsOnlyStack, rateLimit, opsIpAllow, opsAuth, opsGate, requirePermission } = makeStack();

    const layers = opsOnlyStack();

    expect(layers).toEqual([rateLimit, opsIpAllow, opsAuth, opsGate]);
    expect(requirePermission).not.toHaveBeenCalled();
  });

  test('opsOnlyStack never contains adminGate', () => {
    const { opsOnlyStack, adminGate } = makeStack();
    expect(opsOnlyStack()).not.toContain(adminGate);
  });
});

// ── Integration: the stack actually enforces order and RBAC end-to-end ───────

describe('createAdminProtection — end-to-end ordering via a real Express app', () => {
  const express = require('express');
  const request = require('supertest');

  function buildApp({ rateLimitBlocks = false, authBlocks = false, rbacBlocks = false, gateBlocks = false } = {}) {
    const calls = [];

    const rateLimit = (req, res, next) => {
      calls.push('rateLimit');
      if (rateLimitBlocks) return res.status(429).json({ decision: 'BLOCK', reason: 'RATE_LIMITED' });
      next();
    };
    const opsIpAllow = (req, res, next) => { calls.push('opsIpAllow'); next(); };
    const opsAuth = (req, res, next) => {
      calls.push('opsAuth');
      if (authBlocks) return res.status(401).json({ decision: 'BLOCK', reason: 'UNAUTHORIZED' });
      req.rbacUser = { role: 'operator' };
      next();
    };
    const rbacResolve = (req, res, next) => {
      calls.push('rbacResolve');
      if (rbacBlocks || !req.rbacUser) return res.status(403).json({ error: 'FORBIDDEN' });
      next();
    };
    const adminGate = (req, res, next) => {
      calls.push('adminGate');
      if (gateBlocks) return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND' });
      next();
    };
    const requirePermission = jest.fn(permission => (req, res, next) => {
      calls.push(`permission:${permission}`);
      if (req.rbacUser.role !== 'admin') return res.status(403).json({ error: 'FORBIDDEN' });
      next();
    });

    const opsGate = (req, res, next) => { calls.push('opsGate'); next(); };
    const { adminStack } = createAdminProtection({ rateLimit, opsIpAllow, opsAuth, rbacResolve, requirePermission, opsGate, adminGate });

    const app = express();
    app.use('/admin-route', ...adminStack('MANAGE_KEYS'), (_req, res) => res.status(200).json({ ok: true }));
    return { app, calls };
  }

  test('a request that clears every layer runs them in order and reaches the handler only for a permitted role', async () => {
    const { app, calls } = buildApp();
    // requirePermission stub denies non-admin roles; opsAuth stub sets role: 'operator'
    const resp = await request(app).get('/admin-route');
    expect(resp.status).toBe(403);
    expect(calls).toEqual(['rateLimit', 'opsIpAllow', 'opsAuth', 'rbacResolve', 'permission:MANAGE_KEYS']);
    // adminGate never runs — permission check denied first, proving fail-closed short-circuit.
  });

  test('rate limiting short-circuits before ops auth ever runs', async () => {
    const { app, calls } = buildApp({ rateLimitBlocks: true });
    const resp = await request(app).get('/admin-route');
    expect(resp.status).toBe(429);
    expect(calls).toEqual(['rateLimit']);
  });

  test('missing RBAC identity denies at rbacResolve, before the permission check runs', async () => {
    const { app, calls } = buildApp({ authBlocks: true });
    const resp = await request(app).get('/admin-route');
    expect(resp.status).toBe(401);
    expect(calls).toEqual(['rateLimit', 'opsIpAllow', 'opsAuth']);
  });

  test('a disabled admin kill-switch denies at adminGate, only after permission is satisfied', async () => {
    const express2 = require('express');
    const calls = [];
    const noop = name => (req, res, next) => { calls.push(name); next(); };
    const requirePermission = () => (req, res, next) => { calls.push('permission:MANAGE_KEYS'); next(); };
    const adminGate = (req, res) => { calls.push('adminGate'); return res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND' }); };
    const opsGate = noop('opsGate');

    const { adminStack } = createAdminProtection({
      rateLimit: noop('rateLimit'), opsIpAllow: noop('opsIpAllow'), opsAuth: noop('opsAuth'),
      rbacResolve: noop('rbacResolve'), requirePermission, opsGate, adminGate,
    });

    const app = express2();
    app.use('/admin-route', ...adminStack('MANAGE_KEYS'), (_req, res) => res.status(200).json({ ok: true }));

    const resp = await request(app).get('/admin-route');
    expect(resp.status).toBe(404);
    expect(calls).toEqual(['rateLimit', 'opsIpAllow', 'opsAuth', 'rbacResolve', 'permission:MANAGE_KEYS', 'adminGate']);
  });
});

// ── R-09 / OD-3 code option: pre-auth plane gates ───────────────────────────────────────────────
describe('createAdminProtection — optional pre-auth plane gates (R-09 / OD-3)', () => {
  const express = require('express');
  const request = require('supertest');
  const { createOpsAdminPreAuthGate, createOpsDiagnosticsPreAuthGate } = require('./opsEnabled');

  test('supplied, adminPreGate / opsPreGate run FIRST; the rest of each stack keeps its order', () => {
    const adminPreGate = makeMiddleware('adminPreGate'); const opsPreGate = makeMiddleware('opsPreGate');
    const m = makeStack();
    const { adminStack, opsOnlyStack } = createAdminProtection({ ...m, adminPreGate, opsPreGate });
    expect(adminStack('audit:read')).toEqual([adminPreGate, m.rateLimit, m.opsIpAllow, m.opsAuth, m.rbacResolve, m.permissionMiddlewares['audit:read'], m.adminGate]);
    expect(opsOnlyStack()).toEqual([opsPreGate, m.rateLimit, m.opsIpAllow, m.opsAuth, m.opsGate]);
  });

  test('omitted, both stacks are exactly the pre-change stacks', () => {
    const m = makeStack();
    expect(m.adminStack('x')[0]).toBe(m.rateLimit);
    expect(m.opsOnlyStack()[0]).toBe(m.rateLimit);
  });

  function app(opsConfig, layersSeen) {
    const a = express();
    const spy = (n) => (_q, _r, next) => { layersSeen.push(n); next(); };
    const { adminStack, opsOnlyStack } = createAdminProtection({
      rateLimit: spy('rateLimit'), opsIpAllow: spy('opsIpAllow'),
      opsAuth: (req, res, next) => { layersSeen.push('opsAuth'); if (req.get('authorization') !== 'Bearer good') return res.status(401).json({ error: 'UNAUTHENTICATED' }); next(); },
      rbacResolve: spy('rbacResolve'), requirePermission: () => spy('perm'), opsGate: spy('opsGate'), adminGate: spy('adminGate'),
      adminPreGate: createOpsAdminPreAuthGate(opsConfig), opsPreGate: createOpsDiagnosticsPreAuthGate(opsConfig),
    });
    a.use('/audit', ...adminStack('audit:read'), (_q, r) => r.status(200).json({ ok: true }));
    a.use('/metrics', ...opsOnlyStack(), (_q, r) => r.status(200).json({ ok: true }));
    return a;
  }

  test('a DISABLED plane is 404 for an anonymous caller, and no later layer (rate limit, auth, RBAC) runs', async () => {
    const seen = [];
    const a = app({ adminEnabled: false, diagnosticsEnabled: false }, seen);
    for (const p of ['/audit', '/audit/anything', '/metrics']) {
      for (const method of ['get', 'post', 'delete']) {
        const r = await request(a)[method](p);
        expect(r.status).toBe(404);
      }
    }
    const authed = await request(a).get('/audit').set('authorization', 'Bearer good');
    expect(authed.status).toBe(404);
    expect(seen).toEqual([]); // nothing past the pre-gate ever ran
  });

  test('an ENABLED plane is unchanged: anonymous 401, authenticated reaches the handler through every layer', async () => {
    const seen = [];
    const a = app({ adminEnabled: true, diagnosticsEnabled: true }, seen);
    expect((await request(a).get('/audit')).status).toBe(401);
    seen.length = 0;
    expect((await request(a).get('/audit').set('authorization', 'Bearer good')).status).toBe(200);
    expect(seen).toEqual(['rateLimit', 'opsIpAllow', 'opsAuth', 'rbacResolve', 'perm', 'adminGate']);
  });

  test('the planes stay independent: admin disabled + diagnostics enabled → /audit 404, /metrics 401 anonymous', async () => {
    const a = app({ adminEnabled: false, diagnosticsEnabled: true }, []);
    expect((await request(a).get('/audit')).status).toBe(404);
    expect((await request(a).get('/metrics')).status).toBe(401);
  });

  test('the pre-auth gate is silent (no per-request log an anonymous scanner could multiply); positive control: the post-auth gate does log', () => {
    const emitted = [];
    jest.isolateModules(() => {
      jest.doMock('../../services/logger', () => ({ emit: (sev, type) => emitted.push(type) }));
      const g = require('./opsEnabled');
      const res = { status() { return this; }, json() { return this; }, set() { return this; }, setHeader() {}, getHeader() {}, locals: {} };
      const req = { path: '/audit/x', get: () => undefined, headers: {} };
      for (let i = 0; i < 20; i++) g.createOpsAdminPreAuthGate({ adminEnabled: false })(req, res, () => { throw new Error('must not call next'); });
      expect(emitted.filter((x) => x === 'OPS_DISABLED_ACCESS_ATTEMPT')).toHaveLength(0);
      g.createOpsAdminGate({ adminEnabled: false })(req, res, () => {});
      expect(emitted.filter((x) => x === 'OPS_DISABLED_ACCESS_ATTEMPT')).toHaveLength(1); // the mock really observes emit()
    });
  });
});
