'use strict';

// #4 — profilingDiagnosticsGate, modeled on opsEnabled.test.js's
// pattern for the sibling createOpsDiagnosticsGate.

const request  = require('supertest');
const express  = require('express');
const { createProfilingDiagnosticsGate } = require('../profilingEnabled');

function buildApp(opsConfig) {
  const app = express();
  app.use((req, res, next) => {
    req.requestId = 'test-req-id';
    res.locals.requestId = 'test-req-id';
    req.clientIp  = '127.0.0.1';
    next();
  });
  app.use('/diagnostics/profile/memory', createProfilingDiagnosticsGate(opsConfig), (_req, res) => res.status(200).json({ type: 'memory' }));
  return app;
}

describe('profilingDiagnosticsGate — disabled (default)', () => {
  const app = buildApp({ profilingDiagnosticsEnabled: false });

  it('returns 404, not 401 (enumeration resistance)', async () => {
    const res = await request(app).get('/diagnostics/profile/memory');
    expect(res.status).toBe(404);
  });

  it('404 response matches the canonical management envelope', async () => {
    const res = await request(app).get('/diagnostics/profile/memory');
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'NOT_FOUND' } });
  });

  it('does not expose endpoint purpose in the body', async () => {
    const res = await request(app).get('/diagnostics/profile/memory');
    expect(JSON.stringify(res.body)).not.toContain('profil');
  });
});

describe('profilingDiagnosticsGate — enabled', () => {
  const app = buildApp({ profilingDiagnosticsEnabled: true });

  it('allows the request through', async () => {
    const res = await request(app).get('/diagnostics/profile/memory');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ type: 'memory' });
  });
});

describe('profilingDiagnosticsGate — independent of diagnosticsEnabled', () => {
  it('profiling stays disabled even when general diagnostics is enabled', async () => {
    const app = buildApp({ diagnosticsEnabled: true, profilingDiagnosticsEnabled: false });
    const res = await request(app).get('/diagnostics/profile/memory');
    expect(res.status).toBe(404);
  });
});
