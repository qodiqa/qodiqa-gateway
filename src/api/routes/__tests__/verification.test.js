'use strict';

/**
 * independent verification findings:
 *   3.12  /sign: look-alike reserved claim names (case / whitespace variants) are dropped, not signed; payload.provider must be
 *         a plain provider name on every path (an object or free text used to be signed on non-AI paths).
 *   3.2   POST /consent refuses an unregistered tenant (a consent there is invisible to revokeAll()'s per-tenant sweep).
 */

const request = require('supertest');
const express = require('express');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');

function signApp() {
  jest.resetModules();
  process.env.QODIQA_CLIENT_ID = 'default';
  const createSignRouter = require('../sign');
  const { validateAndPrepare } = require('../../../../services/policy/loader');
  const policies = validateAndPrepare({ policies: [{ id: 'POL-TEST', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }] });
  const app = express();
  app.use(express.json());
  app.use('/sign', createSignRouter(() => policies));
  return app;
}
const post = (app, token, payload) => request(app).post('/sign').set('Authorization', `Bearer ${token}`)
  .send({ request: { method: 'POST', path: '/orders/create', body: { sku: 'S' } }, payload });

function decodePayload(res) {
  const a = res.body.artifact || res.body.data?.artifact || res.body;
  const raw = typeof a === 'string' ? a : (a.payload ? null : null);
  if (a && a.payload) return a.payload;
  return JSON.parse(Buffer.from(String(raw).split('.')[0], 'base64url').toString('utf8')).payload;
}

describe('POST /sign — look-alike reserved keys and provider shape', () => {
  test('F1-SIGN-01 TenantId / tenantid / "tenantId " / CallerContext are not signed into the artifact', async () => {
    const app = signApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey, { TenantId: 'evil', tenantid: 'evil', 'tenantId ': 'evil', CallerContext: { x: 1 }, RequestHash: 'x', keep: 'ok' });
    expect(res.status).toBe(200);
    const p = decodePayload(res);
    expect(Object.keys(p).filter((k) => /^(tenantid|callercontext|requesthash)$/i.test(k.trim()) && !['tenantId', 'callerContext', 'requestHash'].includes(k))).toEqual([]);
    expect(p.keep).toBe('ok');
    expect(p.tenantId).toBe('default');
  });

  test.each([{ a: 1 }, 'attacker provider!', ['x'], 12])('F1-SIGN-02 non-name provider %j is rejected on a non-AI path', async (prov) => {
    const app = signApp();
    const { apiKey } = provisionTestSigningIdentity({ tenantId: 'default' });
    const res = await post(app, apiKey, { provider: prov });
    expect(res.status).toBe(400);
  });
});

describe('POST /consent — unregistered tenant', () => {
  test('F1-CONSENT-01 grant under an unregistered tenant is refused with 400 and never reaches the registry', async () => {
    jest.resetModules();
    const registry = { grant: jest.fn().mockResolvedValue({ id: 'x' }), health: jest.fn(() => ({})) };
    jest.doMock('../../../core/consent', () => registry);
    jest.doMock('../../../core/consent/ConsentStore', () => ({ isSpecialCategoryScope: jest.fn().mockResolvedValue(false) }));
    const { createConsentRouter } = require('../consent');
    const app = express();
    app.use(express.json());
    app.use('/consent', createConsentRouter());
    const res = await request(app).post('/consent').send({ actorId: 'a', action: 'x', tenantId: 'ghost-tenant', lawfulBasis: 'consent', purpose: 'p' });
    expect(res.status).toBe(400);
    expect(registry.grant).not.toHaveBeenCalled();
  });
});
