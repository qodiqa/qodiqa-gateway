'use strict';

/**
 * Audit remediation 2026-10-27, item 5: X-QODIQA-API-Version must be on every /v1 mount. The version middleware used to be
 * mounted after /v1/actions .. /v1/admin/dsr, so those answered without it.
 *
 *   AV-01 in the REAL app (server.js, same isolation as liveRouteParity.test.js) the version middleware is mounted before every
 *         other layer mounted under /v1
 *   AV-02 responses from /v1 mounts that used to be ahead of it carry the header
 */
const request = require('supertest');
const live = require('./liveRoutes');

jest.setTimeout(120_000);

describe('X-QODIQA-API-Version on every /v1 mount', () => {
  const ISOLATE = { QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'false', IDEMPOTENCY_ENABLED: 'false', QODIQA_CLIENT_ID: 'route-parity-client', LOCAL_BASE_URL: 'http://127.0.0.1:1/v1' };
  const saved = Object.fromEntries(Object.keys(ISOLATE).map((k) => [k, process.env[k]]));
  let app;

  beforeAll(() => {
    for (const [k, v] of Object.entries(ISOLATE)) if (saved[k] === undefined) process.env[k] = v;
    jest.resetModules();
    live.instrument(require('express'));
    app = require('../../server');
  });

  afterAll(async () => {
    try { await require('../../server/startup').stopLoadTimeSideEffects(); } catch { /* server not loaded */ }
    for (const m of ['../runtime/eventLoopMonitor', '../observability/latencySlaMonitor', '../../services/artifact/keyExpiryMonitor']) {
      try { const mod = require(m); if (mod && typeof mod.shutdown === 'function') await mod.shutdown(); } catch { /* not loaded */ }
    }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  const mountPath = (l) => l.__qodiqaMountPath;
  const isV1 = (p) => typeof p === 'string' && (p === '/v1' || p.startsWith('/v1/'));

  test('AV-01 the version middleware precedes every other /v1 mount', () => {
    const stack = app._router.stack;
    const verIdx = stack.findIndex((l) => mountPath(l) === '/v1' && l.handle && l.handle.name === 'apiVersionMiddleware');
    expect(verIdx).toBeGreaterThanOrEqual(0);
    const v1Mounts = stack.map((l, i) => ({ i, p: mountPath(l) })).filter((x) => isV1(x.p) && x.i !== verIdx);
    expect(v1Mounts.length).toBeGreaterThan(20);
    expect(v1Mounts.filter((x) => x.i < verIdx).map((x) => x.p)).toEqual([]);
  });

  test.each(['/v1/actions/x', '/v1/delegations/x', '/v1/tools/x', '/v1/agents', '/v1/proofs/x', '/v1/attestation/x', '/v1/admin/dsr/x'])(
    'AV-02 %s answers with the header', async (p) => {
      const res = await request(app).get(p);
      expect(res.headers['x-qodiqa-api-version']).toBe('v1');
    });
});
