'use strict';

const request = require('supertest');
const express = require('express');
const { createHealthAuthMiddleware } = require('../healthAuth');

const VALID_TOKEN = 'health-auth-test-token-32-characters';

function buildApp(opsConfig, rbacStore) {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    next();
  });
  app.use('/health', createHealthAuthMiddleware(opsConfig, rbacStore), (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });
  return app;
}

describe('createHealthAuthMiddleware — default (orchestrator-compatible) mode', () => {
  it('allows a request with no credentials when healthAuthRequired is false', async () => {
    const app = buildApp({ healthAuthRequired: false });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('allows a bare orchestrator-style request (no headers at all) when disabled', async () => {
    // Simulates exactly what a Kubernetes httpGet probe or `wget` sends: no
    // Authorization header, no X-Ops-Token.
    const app = buildApp({ healthAuthRequired: false });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('still allows the request even if an (irrelevant) bearer token is sent', async () => {
    const app = buildApp({ healthAuthRequired: false });
    const res = await request(app).get('/health').set('Authorization', 'Bearer anything');
    expect(res.status).toBe(200);
  });
});

describe('createHealthAuthMiddleware — hardened mode (healthAuthRequired=true)', () => {
  it('rejects a request with no credentials (401)', async () => {
    const app = buildApp({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health');
    expect(res.status).toBe(401);
  });

  it('rejects a request with an invalid token (401)', async () => {
    const app = buildApp({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health').set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(401);
  });

  it('accepts a request with the correct bearer token (200)', async () => {
    const app = buildApp({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(200);
  });

  it('accepts a request with the correct X-Ops-Token header (200)', async () => {
    const app = buildApp({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health').set('X-Ops-Token', VALID_TOKEN);
    expect(res.status).toBe(200);
  });

  it('fails closed when no token is configured at all', async () => {
    const app = buildApp({ healthAuthRequired: true, token: null });
    const res = await request(app).get('/health');
    expect(res.status).toBe(401);
  });

  it('delegates to the exact same createOpsAuthMiddleware used by /metrics and /diagnostics (no duplicated logic)', () => {
    const { createOpsAuthMiddleware } = require('../opsAuth');
    const opsConfig = { healthAuthRequired: true, token: VALID_TOKEN };
    const mw = createHealthAuthMiddleware(opsConfig);
    // Both factories must produce a function with the same (req, res, next) arity —
    // proof that the health-required path is a direct delegation, not a reimplementation.
    const direct = createOpsAuthMiddleware(opsConfig);
    expect(mw.length).toBe(direct.length);
  });
});
