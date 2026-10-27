'use strict';

/**
 * POST /sign — error-disclosure regression coverage (item 8, Track C P3).
 *
 *'s independent re-audit flagged sign.js as one of "two routes [that]
 * still leak raw error internals, bypassing the centralized handler"
 *. Re-verification
 * for this item found that claim does not hold for the current code: every
 * BLOCK response built by _block() (src/api/routes/sign.js) hardcodes
 * `details: {}` in the client-facing JSON — the `extra` argument that
 * carries `err.message` is only ever passed to _auditDecision(), which logs
 * server-side and never reaches res.json(). This suite locks that behavior
 * in with a live HTTP assertion so a future edit can't silently start
 * threading `extra` into the response body.
 */

const request = require('supertest');
const express  = require('express');

const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

function loadApp() {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID = 'default';

  jest.doMock('../../../validation/requestHash', () => {
    const actual = jest.requireActual('../../../validation/requestHash');
    return {
      ...actual,
      computeRequestHash: jest.fn(() => {
        throw new Error(
          'ECONNREFUSED 10.0.0.7:5432 — password authentication failed for user "qodiqa_app" ' +
          'at Object.query (/src/core/dsr/DSRStore.js:184:11)',
        );
      }),
    };
  });

  const createSignRouter       = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');

  const policies = validateAndPrepare({ policies: [{
    id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
    config: { requireValidArtifact: true },
  }] });

  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  return app;
}

function post(app, token, body) {
  return request(app)
    .post('/sign')
    .set('Content-Type', 'application/json')
    .set('Authorization', `Bearer ${token}`)
    .send(body);
}

function nonAiChatBody(payload) {
  return {
    request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } },
    ...(payload !== undefined ? { payload } : {}),
  };
}

afterEach(() => jest.dontMock('../../../validation/requestHash'));

describe('POST /sign — error disclosure', () => {
  test('SIGN-ERR-01 an internal error (computeRequestHash throwing) returns the sanitized BLOCK envelope, byte-exact, no err.message/stack', async () => {
    const app = loadApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });

    const res = await post(app, apiKey, nonAiChatBody());

    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      decision:  'BLOCK',
      reason:    'INVALID_REQUEST',
      details:   {},
      requestId: null,
    });
  });

  test('SIGN-ERR-02 no driver/SQL/credential internals appear anywhere in the response body or headers', async () => {
    const app = loadApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });

    const res = await post(app, apiKey, nonAiChatBody());

    const raw = JSON.stringify(res.body) + JSON.stringify(res.headers);
    expect(raw).not.toContain('10.0.0.7');
    expect(raw).not.toContain('password authentication failed');
    expect(raw).not.toContain('DSRStore.js');
    expect(raw).not.toContain('qodiqa_app');
    expect(raw).not.toContain('ECONNREFUSED');
  });

  test('SIGN-ERR-03 happy path is unaffected: a valid request still signs and returns 200 (no mocked failure)', async () => {
    const app = loadApp();
    jest.dontMock('../../../validation/requestHash');
    jest.resetModules();
    process.env.QODIQA_CLIENT_ID = 'default';
    const createSignRouter       = require('../sign');
    const { validateAndPrepare } = require('../../../../services/policy/loader');
    const policies = validateAndPrepare({ policies: [{
      id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
      config: { requireValidArtifact: true },
    }] });
    const cleanApp = express();
    cleanApp.use(express.json());
    cleanApp.use('/sign', createSignRouter(() => policies));

    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(cleanApp, apiKey, nonAiChatBody());

    expect(res.status).toBe(200);
    expect(res.body.artifact).toBeDefined();
    expect(res.body.artifactId).toBeDefined();
  });
});
