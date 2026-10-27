'use strict';

/**
 * Task #27 defense-in-depth: every Admin router now rejects unsupported
 * methods/paths with an explicit 405 instead of falling through to the
 * generic global 404 handler. Each router uses its own pre-existing
 * response-envelope convention (there are several distinct ones across the
 * routes directory — unifying them is out of scope for this remediation);
 * this suite spot-checks one representative router per convention.
 */

const express = require('express');
const request = require('supertest');

describe('Admin routers — 405 on unsupported method/path', () => {
  test('transparencyLog admin router — decision/reason/details/requestId convention', async () => {
    const { createTransparencyAdminRouter } = require('../transparencyLog');
    const router = createTransparencyAdminRouter({ requirePermission: () => (_req, _res, next) => next() });
    const app = express();
    app.use('/transparency', router);

    const resp = await request(app).patch('/transparency/nonexistent-path');
    expect(resp.status).toBe(405);
    expect(resp.body.status).toBe('error');
    expect(resp.body.requestId).toBe(null);
    expect(resp.body.error).toEqual({
      code:    'METHOD_NOT_ALLOWED',
      message: 'Method not allowed',
    });
  });

  test('rbacAdmin router — status/code/detail convention', async () => {
    const createRbacAdminRouter = require('../rbacAdmin');
    const router = createRbacAdminRouter({ store: {}, requirePermission: () => (_req, _res, next) => next() });
    const app = express();
    app.use('/rbac', router);

    const resp = await request(app).patch('/rbac/nonexistent-path');
    expect(resp.status).toBe(405);
    expect(resp.body.status).toBe('error');
    expect(resp.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  test('consent router — flat error/message convention', async () => {
    const { createConsentRouter } = require('../consent');
    const router = createConsentRouter();
    const app = express();
    app.use(express.json());
    app.use('/consent', router);

    const resp = await request(app).patch('/consent/nonexistent-path');
    expect(resp.status).toBe(405);
    expect(resp.body.status).toBe('error');
    expect(resp.body.requestId).toBe(null);
    expect(resp.body.error).toEqual({ code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' });
  });

  test('admin/organizations router — flat error/message convention, no factory args', async () => {
    const { createOrganizationsAdminRouter } = require('../admin/organizations');
    const router = createOrganizationsAdminRouter();
    const app = express();
    app.use('/v1/admin/organizations', router);

    const resp = await request(app).put('/v1/admin/organizations');
    expect(resp.status).toBe(405);
    expect(resp.body.status).toBe('error');
    expect(resp.body.requestId).toBe(null);
    expect(resp.body.error).toEqual({ code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed' });
  });

  test('dashboard router — bare module-level router (no factory function)', async () => {
    const router = require('../dashboard');
    const app = express();
    app.use('/dashboard', router);

    const resp = await request(app).patch('/dashboard/nonexistent-path');
    expect(resp.status).toBe(405);
    expect(resp.body.status).toBe('error');
    expect(resp.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  test('key-admin router — pre-existing 405 pattern this remediation matched', async () => {
    const router = require('../keyAdmin');
    const app = express();
    app.use('/key-admin', router);

    const resp = await request(app).patch('/key-admin/nonexistent-path');
    expect(resp.status).toBe(405);
    expect(resp.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });
});
