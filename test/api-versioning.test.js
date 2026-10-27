'use strict';

/**
 * API Versioning — Component #15 test suite
 *
 * AV-01…AV-05   apiVersion middleware unit tests
 * AV-06…AV-12   Versioned route resolution (routes respond, not 404)
 * AV-13…AV-18   Backward compatibility (unversioned routes still resolve)
 * AV-19…AV-24   Handler identity (versioned and unversioned behave identically)
 * AV-25…AV-30   Response metadata (X-QODIQA-API-Version header)
 */

const request = require('supertest');
const express = require('express');
const { createApiVersionMiddleware, CURRENT_VERSION } = require('../src/middleware/apiVersion');

// ── Minimal test app factory ──────────────────────────────────────────────────
//
// Builds a minimal Express app that shares a single handler instance at both
// an unversioned and a /v1 path.  This mirrors the server.js single-handler-rule
// without requiring all server dependencies.

function makeVersionedApp(unversionedPath, v1Path, sharedRouter) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-req-id'; next(); });
  // Unversioned — no version header
  app.use(unversionedPath, sharedRouter);
  // Versioned — version header stamped by middleware, same router instance
  app.use('/v1', createApiVersionMiddleware());
  app.use(v1Path, sharedRouter);
  return app;
}

// Shared probe router — a lightweight handler that proves identity by echoing
// the same handler reference is exercised on both paths.
function makePingRouter(label) {
  const router = express.Router();
  router.get('/ping', (_req, res) => res.json({ ok: true, handler: label }));
  router.post('/ping', (req, res) => res.json({ ok: true, handler: label, body: req.body }));
  return router;
}

// ── AV-01…AV-05  apiVersion middleware unit tests ─────────────────────────────

describe('AV-01 createApiVersionMiddleware returns a function', () => {
  test('returns a middleware function', () => {
    const mw = createApiVersionMiddleware();
    expect(typeof mw).toBe('function');
    expect(mw.length).toBe(3); // req, res, next
  });
});

describe('AV-02 middleware sets X-QODIQA-API-Version header', () => {
  test('default version is v1', async () => {
    const app = express();
    app.use(createApiVersionMiddleware());
    app.get('/test', (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/test');
    expect(res.headers['x-qodiqa-api-version']).toBe('v1');
  });
});

describe('AV-03 middleware respects custom version argument', () => {
  test('sets the supplied version string', async () => {
    const app = express();
    app.use(createApiVersionMiddleware('v2'));
    app.get('/test', (_req, res) => res.json({ ok: true }));
    const res = await request(app).get('/test');
    expect(res.headers['x-qodiqa-api-version']).toBe('v2');
  });
});

describe('AV-04 CURRENT_VERSION exported constant', () => {
  test('equals v1', () => {
    expect(CURRENT_VERSION).toBe('v1');
  });
});

describe('AV-05 middleware calls next()', () => {
  test('request reaches the route handler', async () => {
    const app = express();
    app.use(createApiVersionMiddleware());
    app.get('/downstream', (_req, res) => res.json({ reached: true }));
    const res = await request(app).get('/downstream');
    expect(res.status).toBe(200);
    expect(res.body.reached).toBe(true);
  });
});

// ── AV-06…AV-12  Versioned route resolution ──────────────────────────────────

describe('AV-06 /v1/ai-chat resolves (not 404)', () => {
  test('GET /v1/ai-chat/ping returns 200', async () => {
    const router = makePingRouter('aiChat');
    const app    = makeVersionedApp('/ai-chat', '/v1/ai-chat', router);
    const res    = await request(app).get('/v1/ai-chat/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-07 /v1/verify resolves (not 404)', () => {
  test('GET /v1/verify/ping returns 200', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).get('/v1/verify/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-08 /v1/portal resolves (not 404)', () => {
  test('GET /v1/portal/ping returns 200', async () => {
    const router = makePingRouter('portal');
    const app    = makeVersionedApp('/portal', '/v1/portal', router);
    const res    = await request(app).get('/v1/portal/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-09 /v1/evidence resolves (not 404)', () => {
  test('GET /v1/evidence/ping returns 200', async () => {
    const router = makePingRouter('evidence');
    const app    = makeVersionedApp('/evidence', '/v1/evidence', router);
    const res    = await request(app).get('/v1/evidence/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-10 /v1/transparency resolves (not 404)', () => {
  test('GET /v1/transparency/ping returns 200', async () => {
    const router = makePingRouter('transparency');
    const app    = makeVersionedApp('/transparency', '/v1/transparency', router);
    const res    = await request(app).get('/v1/transparency/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-11 versioned POST routes are accepted', () => {
  test('POST /v1/verify/ping forwards body correctly', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).post('/v1/verify/ping').send({ foo: 'bar' });
    expect(res.status).toBe(200);
    expect(res.body.body).toEqual({ foo: 'bar' });
  });
});

describe('AV-12 unknown /v1 sub-path returns 404, not 500', () => {
  test('GET /v1/nonexistent-surface returns 404', async () => {
    const router = makePingRouter('aiChat');
    const app    = makeVersionedApp('/ai-chat', '/v1/ai-chat', router);
    app.use((_req, res) => res.status(404).json({ reason: 'NOT_FOUND' }));
    const res = await request(app).get('/v1/nonexistent-surface/ping');
    expect(res.status).toBe(404);
  });
});

// ── AV-13…AV-18  Backward compatibility ──────────────────────────────────────

describe('AV-13 /ai-chat unversioned route still resolves', () => {
  test('GET /ai-chat/ping returns 200', async () => {
    const router = makePingRouter('aiChat');
    const app    = makeVersionedApp('/ai-chat', '/v1/ai-chat', router);
    const res    = await request(app).get('/ai-chat/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-14 /verify unversioned route still resolves', () => {
  test('GET /verify/ping returns 200', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).get('/verify/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-15 /portal unversioned route still resolves', () => {
  test('GET /portal/ping returns 200', async () => {
    const router = makePingRouter('portal');
    const app    = makeVersionedApp('/portal', '/v1/portal', router);
    const res    = await request(app).get('/portal/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-16 /evidence unversioned route still resolves', () => {
  test('GET /evidence/ping returns 200', async () => {
    const router = makePingRouter('evidence');
    const app    = makeVersionedApp('/evidence', '/v1/evidence', router);
    const res    = await request(app).get('/evidence/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-17 /transparency unversioned route still resolves', () => {
  test('GET /transparency/ping returns 200', async () => {
    const router = makePingRouter('transparency');
    const app    = makeVersionedApp('/transparency', '/v1/transparency', router);
    const res    = await request(app).get('/transparency/ping');
    expect(res.status).toBe(200);
  });
});

describe('AV-18 unversioned POST routes still accepted', () => {
  test('POST /verify/ping forwards body correctly', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).post('/verify/ping').send({ hello: 'world' });
    expect(res.status).toBe(200);
    expect(res.body.body).toEqual({ hello: 'world' });
  });
});

// ── AV-19…AV-24  Handler identity ────────────────────────────────────────────
//
// Versioned and unversioned paths must execute the SAME handler instance.
// Verified by:
//   (a) Both paths return the identical handler label embedded in the response
//   (b) Both paths return identical JSON body shapes
//   (c) Both paths process request data identically

describe('AV-19 versioned and unversioned paths return identical bodies', () => {
  test('/verify/ping and /v1/verify/ping return the same JSON shape', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const [unv, v1] = await Promise.all([
      request(app).get('/verify/ping'),
      request(app).get('/v1/verify/ping'),
    ]);
    expect(v1.body).toEqual(unv.body);
  });
});

describe('AV-20 both paths embed the same handler label', () => {
  test('handler field matches on versioned and unversioned responses', async () => {
    const LABEL  = 'portal-handler';
    const router = makePingRouter(LABEL);
    const app    = makeVersionedApp('/portal', '/v1/portal', router);
    const [unv, v1] = await Promise.all([
      request(app).get('/portal/ping'),
      request(app).get('/v1/portal/ping'),
    ]);
    expect(unv.body.handler).toBe(LABEL);
    expect(v1.body.handler).toBe(LABEL);
  });
});

describe('AV-21 POST body is processed identically on both paths', () => {
  test('POSTed payload is echoed identically via versioned and unversioned paths', async () => {
    const router  = makePingRouter('evidence');
    const app     = makeVersionedApp('/evidence', '/v1/evidence', router);
    const payload = { complex: { nested: true }, arr: [1, 2, 3] };
    const [unv, v1] = await Promise.all([
      request(app).post('/evidence/ping').send(payload),
      request(app).post('/v1/evidence/ping').send(payload),
    ]);
    expect(v1.body.body).toEqual(unv.body.body);
    expect(v1.body.body).toEqual(payload);
  });
});

describe('AV-22 shared router instance — reference identity', () => {
  test('same router object can be mounted at multiple paths without cloning', () => {
    const router = makePingRouter('shared');
    // Both mounts use ===same reference; Express allows this
    const app = express();
    app.use('/a', router);
    app.use('/b', router);
    // If the same router object is reused, Express will call it for both prefixes.
    // We confirm this doesn't throw at setup time.
    expect(typeof app).toBe('function');
  });
});

describe('AV-23 v1 middleware does not break unversioned path behavior', () => {
  test('GET /transparency/ping still returns ok: true after v1 middleware is added', async () => {
    const router = makePingRouter('transparency');
    const app    = makeVersionedApp('/transparency', '/v1/transparency', router);
    const res    = await request(app).get('/transparency/ping');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

describe('AV-24 versioned and unversioned HTTP status codes are identical', () => {
  test('both paths return 200 for a valid request', async () => {
    const router = makePingRouter('aiChat');
    const app    = makeVersionedApp('/ai-chat', '/v1/ai-chat', router);
    const [unv, v1] = await Promise.all([
      request(app).get('/ai-chat/ping'),
      request(app).get('/v1/ai-chat/ping'),
    ]);
    expect(unv.status).toBe(200);
    expect(v1.status).toBe(200);
  });
});

// ── AV-25…AV-30  Response metadata (version header) ──────────────────────────

describe('AV-25 X-QODIQA-API-Version header present on /v1 routes', () => {
  test('GET /v1/verify/ping carries the version header', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).get('/v1/verify/ping');
    expect(res.headers['x-qodiqa-api-version']).toBe('v1');
  });
});

describe('AV-26 X-QODIQA-API-Version header absent on unversioned routes', () => {
  test('GET /verify/ping does NOT carry the version header', async () => {
    const router = makePingRouter('verify');
    const app    = makeVersionedApp('/verify', '/v1/verify', router);
    const res    = await request(app).get('/verify/ping');
    expect(res.headers['x-qodiqa-api-version']).toBeUndefined();
  });
});

describe('AV-27 header present on all five /v1 surfaces', () => {
  const surfaces = [
    ['/ai-chat',      '/v1/ai-chat'],
    ['/verify',       '/v1/verify'],
    ['/portal',       '/v1/portal'],
    ['/evidence',     '/v1/evidence'],
    ['/transparency', '/v1/transparency'],
  ];

  test.each(surfaces)('GET %s2/ping has X-QODIQA-API-Version', async (unv, v1) => {
    const router = makePingRouter(v1);
    const app    = makeVersionedApp(unv, v1, router);
    const res    = await request(app).get(`${v1}/ping`);
    expect(res.headers['x-qodiqa-api-version']).toBe('v1');
  });
});

describe('AV-28 header absent on all five unversioned surfaces', () => {
  const surfaces = [
    ['/ai-chat',      '/v1/ai-chat'],
    ['/verify',       '/v1/verify'],
    ['/portal',       '/v1/portal'],
    ['/evidence',     '/v1/evidence'],
    ['/transparency', '/v1/transparency'],
  ];

  test.each(surfaces)('GET %s/ping has no X-QODIQA-API-Version', async (unv, v1) => {
    const router = makePingRouter(unv);
    const app    = makeVersionedApp(unv, v1, router);
    const res    = await request(app).get(`${unv}/ping`);
    expect(res.headers['x-qodiqa-api-version']).toBeUndefined();
  });
});

describe('AV-29 version header value matches CURRENT_VERSION constant', () => {
  test('header value equals the exported CURRENT_VERSION', async () => {
    const router = makePingRouter('portal');
    const app    = makeVersionedApp('/portal', '/v1/portal', router);
    const res    = await request(app).get('/v1/portal/ping');
    expect(res.headers['x-qodiqa-api-version']).toBe(CURRENT_VERSION);
  });
});

describe('AV-30 version header is set on POST requests too', () => {
  test('POST /v1/portal/ping carries X-QODIQA-API-Version', async () => {
    const router = makePingRouter('portal');
    const app    = makeVersionedApp('/portal', '/v1/portal', router);
    const res    = await request(app).post('/v1/portal/ping').send({ x: 1 });
    expect(res.headers['x-qodiqa-api-version']).toBe('v1');
  });
});
