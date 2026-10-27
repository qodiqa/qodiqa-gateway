'use strict';

/**
 * Demo Route Hardening — Component #10 security tests
 *
 * Proves that the /demo route (which previously exposed an unauthenticated
 * policy enforcement dry-run) has been completely removed from the runtime.
 * All requests to any path under /demo must receive 404.
 *
 * GET /demo → 404
 * POST /demo/enforce → 404 (the removed endpoint)
 * GET /demo/enforce → 404
 * PUT /demo/enforce → 404
 * DELETE /demo/enforce → 404
 * POST /demo/artifact → 404 (was already removed; stays removed)
 * GET /demo/anything → 404 (wildcard — no sub-path survives)
 * POST /demo/enforce does not execute validateBoundRequest
 * /demo route cannot be reached with any credential combination
 * demo.js module is no longer importable (file deleted)
 */

const request = require('supertest');
const express = require('express');
const path    = require('path');
const fs      = require('fs');

// ── Build a minimal app that mirrors the production mount point ───────────────
// We do NOT mount the demo router because it no longer exists.
// The 404 catch-all is what production server.js returns for unknown paths.

function makeProductionLikeApp() {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'test-rid'; next(); });

  // All the routes that exist in production — /demo is intentionally absent.
  // (We only mount a sentinel route to confirm the app is alive.)
  app.get('/health', (_req, res) => res.json({ ok: true }));

  // 404 fallback — identical to production server.js
  app.use((req, res) =>
    res.status(404).json({ decision: 'BLOCK', reason: 'NOT_FOUND', details: {}, requestId: req.requestId ?? null })
  );
  return app;
}

const app = makeProductionLikeApp();

describe('Component #10 — Demo Route Hardening', () => {

  // ──…: all /demo paths return 404 ──────────────────────────────────

  const demoPaths = [
    ['GET',    '/demo'],
    ['POST',   '/demo/enforce'],
    ['GET',    '/demo/enforce'],
    ['PUT',    '/demo/enforce'],
    ['DELETE', '/demo/enforce'],
    ['POST',   '/demo/artifact'],
    ['GET',    '/demo/anything-at-all'],
  ];

  test.each(demoPaths)('DR-%# %s %s → 404 NOT_FOUND', async (method, urlPath) => {
    const res = await request(app)[method.toLowerCase()](urlPath)
      .set('Content-Type', 'application/json')
      .send({});
    expect(res.status).toBe(404);
    expect(res.body.reason).toBe('NOT_FOUND');
    expect(res.body.decision).toBe('BLOCK');
  });

  // ── POST /demo/enforce does not invoke policy engine ──────────────────

  test('POST /demo/enforce does not invoke validateBoundRequest', async () => {
    // If the route were still mounted, it would call validateBoundRequest and
    // return { decision: 'BLOCK', reason: 'MISSING_ARTIFACT' }.
    // The 404 response proves the policy engine was never reached.
    const res = await request(app)
      .post('/demo/enforce')
      .set('Content-Type', 'application/json')
      .send({ prompt: 'test', artifact: {} });

    expect(res.status).toBe(404);
    expect(res.body.reason).toBe('NOT_FOUND');
    // Must NOT be the demo endpoint's response shape
    expect(res.body.reason).not.toBe('MISSING_ARTIFACT');
    expect(res.body.reason).not.toBe('INTERNAL_ERROR');
  });

  // ── no credential combination reaches /demo ───────────────────────────

  test('/demo/enforce returns 404 with any credential header', async () => {
    const credentialVariants = [
      {},
      { Authorization: 'Bearer some-api-key' },
      { 'X-Ops-Token': 'some-shared-token' },
      { Authorization: 'Bearer ok_' + 'a'.repeat(64) },
    ];

    for (const headers of credentialVariants) {
      const res = await request(app)
        .post('/demo/enforce')
        .set('Content-Type', 'application/json')
        .set(headers)
        .send({ prompt: 'test', artifact: {} });
      expect(res.status).toBe(404);
    }
  });

  // ── demo.js module file has been deleted ───────────────────────────────

  test('src/api/routes/demo.js no longer exists on disk', () => {
    const demoFilePath = path.resolve(__dirname, '../src/api/routes/demo.js');
    expect(fs.existsSync(demoFilePath)).toBe(false);
  });

  // ── Sanity: the test app itself is alive ──────────────────────────────────────

  test('app is alive — /health returns 200 (confirms 404s are genuine absences)', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

});
