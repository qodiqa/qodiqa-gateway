'use strict';

/**
 * Global kill switch on the REAL application (server.js composition root, control plane in memory mode): while it is
 * active every alias of /sign and /ai/chat answers 503 BLOCK KILL_SWITCH_ACTIVE before anything else runs; probes and the
 * other routes are untouched; releasing it restores the routes' own behaviour.
 *
 *   KAPP-01  all five gated paths refuse while active, with the documented body and Retry-After
 *   KAPP-02  the gate is the FIRST thing in each chain: nothing is signed, no artifact is parsed, no audit entry is written
 *   KAPP-03  health/readiness and the verification endpoints are not gated
 *   KAPP-04  released: the same requests reach the routes' own handling (never KILL_SWITCH_*)
 *   KAPP-05  the admin routes are not reachable without credentials (the kill switch cannot be pulled by an anonymous caller)
 */

const supertest = require('supertest');

jest.setTimeout(120_000);

describe('kill switch on the real application', () => {
  const ISOLATE = { QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'false', IDEMPOTENCY_ENABLED: 'false', QODIQA_CLIENT_ID: 'kill-switch-app-test', LOCAL_BASE_URL: 'http://127.0.0.1:1/v1' };
  const saved = Object.fromEntries(Object.keys(ISOLATE).map((k) => [k, process.env[k]]));
  let app; let killSwitch; let audit;
  const PATHS = ['/sign', '/ai/chat', '/ai/chat/stream', '/v1/ai/chat', '/v1/ai/chat/stream'];

  beforeAll(() => {
    for (const [k, v] of Object.entries(ISOLATE)) if (saved[k] === undefined) process.env[k] = v;
    jest.resetModules();
    app = require('../../../../server');
    killSwitch = require('..');
    audit = require('../../audit/audit-log');
  });
  afterAll(async () => {
    try { await killSwitch.release({ operatorId: 'test' }); } catch { /* nothing to restore */ }
    try { await require('../../../../server/startup').stopLoadTimeSideEffects(); } catch { /* server not loaded */ }
    for (const m of ['../../../runtime/eventLoopMonitor', '../../../observability/latencySlaMonitor', '../../../../services/artifact/keyExpiryMonitor']) {
      try { const mod = require(m); if (mod && typeof mod.shutdown === 'function') await mod.shutdown(); } catch { /* absent */ }
    }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  test('KAPP-01 + KAPP-02 active: every gated path refuses first, writing nothing', async () => {
    await killSwitch.activate({ operatorId: 'tester', reason: 'app test' });
    const before = audit.getChainStats().modernLength;
    for (const p of PATHS) {
      const res = await supertest(app).post(p).set('content-type', 'application/json').send({ prompt: 'hello', model: 'gpt-4' });
      expect({ p, status: res.status, decision: res.body.decision, reason: res.body.reason }).toEqual({ p, status: 503, decision: 'BLOCK', reason: 'KILL_SWITCH_ACTIVE' });
      expect(res.headers['retry-after']).toBe('30');
      expect(res.body.details).toEqual({});
    }
    expect(audit.getChainStats().modernLength).toBe(before);
  });

  test('KAPP-03 active: probes and verification are not gated', async () => {
    await killSwitch.activate({ operatorId: 'tester', reason: 'app test' });
    const health = await supertest(app).get('/health');
    expect(health.status).toBe(200);
    for (const p of ['/verify', '/v1/verify']) {
      const res = await supertest(app).post(p).set('content-type', 'application/json').send({});
      expect(res.body.reason).not.toMatch(/^KILL_SWITCH_/);
    }
  });

  test('KAPP-04 released: the same requests reach the routes\' own handling', async () => {
    await killSwitch.activate({ operatorId: 'tester', reason: 'app test' });
    await killSwitch.release({ operatorId: 'tester' });
    for (const p of PATHS) {
      const res = await supertest(app).post(p).set('content-type', 'application/json').send({ prompt: 'hello', model: 'gpt-4' });
      expect(String(res.body && res.body.reason)).not.toMatch(/^KILL_SWITCH_/);
    }
  });

  test('KAPP-05 an anonymous caller cannot reach the admin routes', async () => {
    for (const [m, p] of [['get', '/v1/admin/kill-switch'], ['post', '/v1/admin/kill-switch/activate'], ['post', '/v1/admin/kill-switch/release']]) {
      const res = await supertest(app)[m](p).set('content-type', 'application/json').send({ reason: 'x' });
      expect([401, 403, 404]).toContain(res.status);
    }
    expect(killSwitch.state().active).toBe(false);
  });
});
