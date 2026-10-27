'use strict';

/**
 * Management-envelope cross-route conformance — API-1 (P5) remediation.
 *
 * Before this remediation, the management/admin API surface had 9+ distinct
 * ad hoc JSON envelope shapes (see the root-cause inventory in the
 * remediation writeup) — routes originating from completely independent,
 * hand-rolled `_ok`/`_err`-style helpers. Every one of those routes now
 * delegates to the single canonical builder in src/api/response.js.
 *
 * This suite proves that invariant holds ACROSS routes that came from
 * different original shape families, rather than re-testing any one route's
 * business logic (that's already covered exhaustively by each route's own
 * test file). Every response asserted here must have the identical set of
 * top-level keys and types, regardless of which route produced it.
 *
 * The core protocol surface (/ai/chat, /verify, /sign, /.well-known) is
 * deliberately NOT covered here — it uses its own normative
 * {decision, reason, details, requestId} shape (QODIQA-PROTOCOL-SPEC.md
 * §14.6/14.7) and is covered by errorCodeEndpointStatus.conformance.test.js
 * and crossSurface.parity.test.js instead.
 */

const request = require('supertest');
const express = require('express');
const requestId = require('../../../../middleware/requestId');

// Five routers that export a plain `router` (no factory args needed),
// originally drawn from different ad hoc shape families:
//   keys.js / publicKeys.js / public-key.js — "bare, no envelope" family
//   audit.js                                — "decision shape" family
//   dashboard.js                            — "bare, no envelope" family
const keysRouter       = require('../keys');
const publicKeysRouter = require('../publicKeys');
const publicKeyRouter  = require('../public-key');
const auditRouter      = require('../audit');
const dashboardRouter  = require('../dashboard');

function mount(path, router) {
  const app = express();
  app.use(requestId);
  app.use(express.json());
  app.use(path, router);
  return app;
}

function expectCanonicalSuccess(body) {
  expect(body).toMatchObject({
    status:    'success',
    timestamp: expect.any(String),
    data:      expect.anything(),
  });
  expect(body).toHaveProperty('requestId');
  expect(body).not.toHaveProperty('decision');
  expect(body).not.toHaveProperty('reason');
  expect(body).not.toHaveProperty('ok');
}

function expectCanonicalFailure(body) {
  expect(body).toMatchObject({
    status:    'error',
    timestamp: expect.any(String),
    error:     { code: expect.any(String), message: expect.any(String) },
  });
  expect(body).toHaveProperty('requestId');
  expect(body).not.toHaveProperty('decision');
  expect(body).not.toHaveProperty('reason');
}

describe('canonical management envelope — success responses across routes from different origin families', () => {
  test('GET /keys (was: bare {keys, requestId}, no envelope)', async () => {
    const res = await request(mount('/keys', keysRouter)).get('/keys');
    expect(res.status).toBe(200);
    expectCanonicalSuccess(res.body);
    expect(Array.isArray(res.body.data.keys)).toBe(true);
  });

  test('GET /public-keys (was: bare {keys, requestId}, no envelope)', async () => {
    const res = await request(mount('/public-keys', publicKeysRouter)).get('/public-keys');
    expect(res.status).toBe(200);
    expectCanonicalSuccess(res.body);
    expect(Array.isArray(res.body.data.keys)).toBe(true);
  });

  test('GET /dashboard/status (was: bare, zero envelope of any kind)', async () => {
    const res = await request(mount('/dashboard', dashboardRouter)).get('/dashboard/status');
    expect(res.status).toBe(200);
    expectCanonicalSuccess(res.body);
    expect(res.body.data).toHaveProperty('service', 'qodiqa');
  });
});

describe('canonical management envelope — 405 Method Not Allowed across routes from different origin families', () => {
  test.each([
    ['/keys',        keysRouter],
    ['/public-keys', publicKeysRouter],
    ['/public-key',  publicKeyRouter],
    ['/audit',       auditRouter],
    ['/dashboard',   dashboardRouter],
  ])('%s rejects an unsupported method with the canonical error envelope', async (mountPath, router) => {
    const res = await request(mount(mountPath, router)).delete(mountPath);
    expect(res.status).toBe(405);
    expectCanonicalFailure(res.body);
    expect(res.body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  test('every 405 body has the identical key set regardless of origin route', async () => {
    const paths = [
      ['/keys',        keysRouter],
      ['/public-keys', publicKeysRouter],
      ['/public-key',  publicKeyRouter],
      ['/audit',       auditRouter],
      ['/dashboard',   dashboardRouter],
    ];
    const bodies = await Promise.all(
      paths.map(([p, r]) => request(mount(p, r)).delete(p).then(res => res.body)),
    );
    const keySets = bodies.map(b => Object.keys(b).sort().join(','));
    expect(new Set(keySets).size).toBe(1); // all identical
    for (const body of bodies) {
      const errorKeys = Object.keys(body.error).sort().join(',');
      expect(errorKeys).toBe('code,message');
    }
  });
});

describe('canonical management envelope — requestId propagation', () => {
  test('the X-Request-ID header and the body requestId agree on both success and failure', async () => {
    const okRes = await request(mount('/keys', keysRouter)).get('/keys');
    expect(okRes.body.requestId).toBe(okRes.headers['x-request-id']);

    const errRes = await request(mount('/keys', keysRouter)).delete('/keys');
    expect(errRes.body.requestId).toBe(errRes.headers['x-request-id']);
  });
});
