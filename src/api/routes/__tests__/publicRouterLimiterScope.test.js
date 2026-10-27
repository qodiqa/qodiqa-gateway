'use strict';

/**
 * T-1 / R-09 / H-35: a public router's rate limiter must cover ITS OWN routes only.
 *
 * src/app.js mounts each public router before the admin stack on the same prefix (/v1/certification,
 * /v1/attestation, /v1/transparency, /v1/portal). Each public router used `router.use(limiter)`, which also ran for
 * paths the public router does not serve — the admin paths — so under a burst an anonymous admin path answered the
 * public limiter's 429 instead of reaching the admin plane's pre-auth gate (404 when the plane is disabled, OD-3).
 * Found by the H-35 sweep (3 × 429 under /v1/certification). The limiter now runs per public route.
 *
 * The rate-limit module is replaced by a deterministic counting limiter (BUDGET requests per surface, then 429), so
 * these tests check exactly what changed — where each router attaches its limiter — independent of Redis.
 * A fall-through handler stands in for the disabled admin plane (its pre-auth gate answers 404, OD-3).
 */

const express = require('express');
const request = require('supertest');

const BUDGET = 3;
const mockHits = new Map();
jest.mock('../../../core/rateLimit', () => ({
  createRateLimitMiddleware: (surface) => (req, res, next) => {
    const n = (mockHits.get(surface) || 0) + 1;
    mockHits.set(surface, n);
    if (n > BUDGET) return res.status(429).json({ code: 'RATE_LIMITED', surface });
    return next();
  },
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn().mockReturnValue(false), query: jest.fn() }));

const ROUTERS = [
  {
    name: 'certification', prefix: '/v1/certification', surface: 'certification',
    make: () => require('../certification').createCertificationPublicRouter(),
    publicRoutes: [['get', '/00000000-0000-0000-0000-000000000000'], ['get', '/00000000-0000-0000-0000-000000000000/summary'], ['get', '/00000000-0000-0000-0000-000000000000/certificate']],
    adminPaths: [['get', '/admin/stats'], ['get', '/admin/history'], ['get', '/00000000-0000-0000-0000-000000000000/report'], ['get', '/00000000-0000-0000-0000-000000000000/evidence'], ['post', '/evaluate']],
  },
  {
    name: 'attestation', prefix: '/v1/attestation', surface: 'attestation',
    make: () => require('../attestation').createAttestationPublicRouter(),
    publicRoutes: [['post', '/verify'], ['post', '/evidence/verify'], ['get', '/00000000-0000-0000-0000-000000000000']],
    adminPaths: [['get', '/admin/stats'], ['post', '/admin/anything'], ['get', '/00000000-0000-0000-0000-000000000000/export']],
  },
  {
    name: 'transparency', prefix: '/v1/transparency', surface: 'transparency',
    make: () => require('../transparencyLog').createTransparencyPublicRouter(),
    publicRoutes: [['get', '/entry/x'], ['get', '/entries'], ['get', '/root'], ['get', '/roots'], ['get', '/verify/x'], ['get', '/proof/x'], ['get', '/consistency/a/b']],
    adminPaths: [['post', '/admin/roots/generate'], ['get', '/admin/stats'], ['post', '/admin/anything']],
  },
  {
    name: 'verification portal', prefix: '/v1/portal', surface: 'portal',
    make: () => require('../verificationPortal').createVerificationPortalPublicRouter(),
    publicRoutes: [['post', '/verify'], ['get', '/result/x'], ['get', '/report/x']],
    adminPaths: [['get', '/admin/stats'], ['get', '/admin/verifications'], ['post', '/admin/anything']],
  },
];

function appFor(r) {
  const app = express();
  app.use(express.json());
  app.use(r.prefix, r.make());
  // stands in for the admin stack with its plane disabled: the OD-3 pre-auth gate answers 404 to every caller
  app.use(r.prefix, (_req, res) => res.status(404).json({ code: 'NOT_FOUND', plane: 'admin' }));
  return app;
}
const send = (app, prefix, [method, path]) => request(app)[method](prefix + path).send(method === 'post' ? {} : undefined);

describe.each(ROUTERS)('T-1: the $name public router rate-limits only its own routes', (r) => {
  beforeEach(() => { mockHits.clear(); jest.resetModules(); });

  test('normal traffic: an anonymous admin path reaches the admin plane (404) and does not consume the public budget', async () => {
    const app = appFor(r);
    for (const p of r.adminPaths) {
      const res = await send(app, r.prefix, p);
      expect({ path: p[1], status: res.status, body: res.body }).toEqual({ path: p[1], status: 404, body: { code: 'NOT_FOUND', plane: 'admin' } });
    }
    expect(mockHits.get(r.surface) || 0).toBe(0);
  });

  test('burst: the public limiter still answers 429 on EVERY public route once its budget is spent', async () => {
    const app = appFor(r);
    for (let i = 0; i < BUDGET; i++) await send(app, r.prefix, r.publicRoutes[0]);
    for (const p of r.publicRoutes) {
      const res = await send(app, r.prefix, p);
      expect({ path: p[1], status: res.status, surface: res.body.surface }).toEqual({ path: p[1], status: 429, surface: r.surface });
    }
  });

  test('after a burst exhausts the public limiter, admin and unknown paths are still the plane 404 — never the public 429 (route enumeration)', async () => {
    const app = appFor(r);
    for (let i = 0; i < BUDGET + 2; i++) await send(app, r.prefix, r.publicRoutes[0]);
    expect((await send(app, r.prefix, r.publicRoutes[0])).status).toBe(429);
    for (const p of [...r.adminPaths, ['get', '/does/not/exist'], ['delete', '/whatever']]) {
      const res = await send(app, r.prefix, p);
      expect({ path: p[1], status: res.status, plane: res.body.plane }).toEqual({ path: p[1], status: 404, plane: 'admin' });
    }
  });
});
