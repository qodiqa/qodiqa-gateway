'use strict';

/**
 * an ABSENT X-Forwarded-Proto on a request a TRUSTED proxy
 * forwarded is treated as not-HTTPS in production (fail closed). Unchanged: direct TLS, a trusted local caller that
 * forwarded nothing (the shipped Compose in-container healthcheck), untrusted peers (kubelet probes), non-production,
 * and ENFORCE_HTTPS_PROTO=false. supertest connects from 127.0.0.1, which the default TRUSTED_PROXY ('loopback') trusts.
 */

const express   = require('express');
const supertest = require('supertest');
const { createProxyValidationMiddleware } = require('../proxyValidation');

function makeApp(opts = {}) {
  const app = express();
  app.use(createProxyValidationMiddleware(opts));
  app.get('/test', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('missing X-Forwarded-Proto behind a trusted proxy', () => {
  const saved = { NODE_ENV: process.env.NODE_ENV, TRUSTED_PROXY: process.env.TRUSTED_PROXY };
  beforeEach(() => { process.env.NODE_ENV = 'production'; delete process.env.TRUSTED_PROXY; });
  afterAll(() => { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

  test('MP-01 trusted peer forwarded (X-Forwarded-For) without a proto → 400 INSECURE_PROTOCOL', async () => {
    const res = await supertest(makeApp({ enforceHttpsProto: true })).get('/test').set('X-Forwarded-For', '203.0.113.7');
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('INSECURE_PROTOCOL');
    expect(res.body.details).toEqual({ proto: null, missingForwardedProto: true });
  });

  test.each([['X-Real-IP', '203.0.113.7'], ['Forwarded', 'for=203.0.113.7']])('MP-02 %s also counts as forwarded → 400', async (h, v) => {
    const res = await supertest(makeApp({ enforceHttpsProto: true })).get('/test').set(h, v);
    expect(res.status).toBe(400);
    expect(res.body.reason).toBe('INSECURE_PROTOCOL');
  });

  test('MP-03 trusted peer forwarded with X-Forwarded-Proto: https → passes', async () => {
    const res = await supertest(makeApp({ enforceHttpsProto: true })).get('/test')
      .set('X-Forwarded-For', '203.0.113.7').set('X-Forwarded-Proto', 'https');
    expect(res.status).toBe(200);
  });

  test('MP-04 trusted local caller with no forwarding headers (Compose healthcheck shape) → passes', async () => {
    expect((await supertest(makeApp({ enforceHttpsProto: true })).get('/test')).status).toBe(200);
  });

  test('MP-05 untrusted peer (TRUSTED_PROXY empty) forwarding without a proto → passes (its headers are not trusted)', async () => {
    const res = await supertest(makeApp({ enforceHttpsProto: true, trustedProxy: [] })).get('/test').set('X-Forwarded-For', '203.0.113.7');
    expect(res.status).toBe(200);
  });

  test('MP-06 TRUSTED_PROXY env is honoured (explicitly empty → no peer trusted)', async () => {
    process.env.TRUSTED_PROXY = '';
    const res = await supertest(makeApp({ enforceHttpsProto: true })).get('/test').set('X-Forwarded-For', '203.0.113.7');
    expect(res.status).toBe(200);
  });

  test('MP-07 ENFORCE_HTTPS_PROTO off, or non-production → passes', async () => {
    expect((await supertest(makeApp({ enforceHttpsProto: false })).get('/test').set('X-Forwarded-For', '203.0.113.7')).status).toBe(200);
    process.env.NODE_ENV = 'development';
    expect((await supertest(makeApp({ enforceHttpsProto: true })).get('/test').set('X-Forwarded-For', '203.0.113.7')).status).toBe(200);
  });

  test('MP-08 a direct TLS connection (socket.encrypted) passes even from a trusted peer with forwarding headers', () => {
    const mw = createProxyValidationMiddleware({ enforceHttpsProto: true });
    const next = jest.fn();
    const res = { status: jest.fn(() => res), json: jest.fn(() => res) };
    mw({ headers: { 'x-forwarded-for': '203.0.113.7' }, socket: { encrypted: true, remoteAddress: '127.0.0.1' } }, res, next);
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});
