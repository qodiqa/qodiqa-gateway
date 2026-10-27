'use strict';

/**
 * /v1/policy/visual/* was unreachable.
 *
 * src/app.js mounted createPolicySimulateRouter and createPolicyVisualRouter
 * on the same /v1/policy prefix, simulate first. policySimulate.js ends in a
 * next-less 405 catch-all, so every /v1/policy/visual/* request was answered
 * 405 by the simulate router and the visual router was never reached. The fix
 * mounts the visual router on its own /v1/policy/visual prefix BEFORE the broad
 * one, restoring the '/visual' prefix its routes are declared under.
 *
 * Two guards, same shape as policyGovernanceMountOrder.test.js: a static
 * source-order check over src/app.js, and a live topology test with the two
 * REAL routers co-mounted exactly as app.js mounts them.
 */

const fs      = require('fs');
const path    = require('path');
const express = require('express');
const request = require('supertest');

const { createPolicySimulateRouter } = require('../policySimulate');
const { createPolicyVisualRouter }   = require('../policyVisual');

const APP_SRC = fs.readFileSync(path.join(__dirname, '../../../app.js'), 'utf8');

describe('(static) — src/app.js mounts /v1/policy/visual on its own prefix, before /v1/policy', () => {
  test('the scoped visual mount exists and precedes the broad /v1/policy mount', () => {
    const visualIdx = APP_SRC.indexOf("app.use('/v1/policy/visual'");
    const broadIdx  = APP_SRC.indexOf("app.use('/v1/policy'");
    expect(visualIdx).toBeGreaterThan(-1);
    expect(broadIdx).toBeGreaterThan(-1);
    expect(visualIdx).toBeLessThan(broadIdx);
  });

  test('the visual router is no longer mounted on the broad /v1/policy prefix (where it was unreachable)', () => {
    expect(APP_SRC).not.toMatch(/app\.use\('\/v1\/policy',[^\n]*createPolicyVisualRouter/);
  });

  test('the visual mount keeps the same admin stack and permission as the broad mount', () => {
    expect(APP_SRC).toMatch(/app\.use\('\/v1\/policy\/visual', \.\.\.ctx\.adminStack\('READ_POLICIES'\)/);
  });
});

describe('(live topology) — both real routers co-mounted as in src/app.js', () => {
  const POLICY = { id: 'p1', type: 'IP_ALLOWLIST', priority: 10, enabled: true, config: { allow: ['1.2.3.4'] } };

  function makeApp() {
    const app = express();
    app.use(express.json());
    const visual = createPolicyVisualRouter(() => [POLICY]);
    app.use('/v1/policy/visual', (req, res, next) => { req.url = '/visual' + req.url; visual(req, res, next); });
    app.use('/v1/policy', createPolicySimulateRouter(() => [], null));
    return app;
  }

  test('GET /v1/policy/visual/flow reaches the visual router (was 405)', async () => {
    const res = await request(makeApp()).get('/v1/policy/visual/flow');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('success');
    expect(Array.isArray(res.body.data.stages)).toBe(true);
  });

  test.each(['graph', 'tree', 'deps', 'stats', 'export'])('POST /v1/policy/visual/%s reaches the visual router (not the simulate 405)', async (route) => {
    const res = await request(makeApp()).post(`/v1/policy/visual/${route}`).send({ policy: POLICY });
    expect(res.status).not.toBe(405);
    expect(res.body?.error?.message).not.toBe('Method not allowed');
  });

  test('POST /v1/policy/simulate still reaches the simulate router', async () => {
    const res = await request(makeApp()).post('/v1/policy/simulate').send({ context: { ip: '1.2.3.4', timestamp: 1736164800 } });
    expect(res.status).not.toBe(405);
    expect(res.body?.status).toBe('success');
  });

  test('anything else under /v1/policy still gets the simulate router\'s 405 (catch-all not weakened)', async () => {
    const res = await request(makeApp()).get('/v1/policy/nonexistent');
    expect(res.status).toBe(405);
  });

  test('an unknown /v1/policy/visual/* route gets the visual router\'s own 405 (its catch-all not weakened)', async () => {
    const res = await request(makeApp()).get('/v1/policy/visual/nonexistent');
    expect(res.status).toBe(405);
  });
});
