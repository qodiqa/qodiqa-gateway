'use strict';

const request  = require('supertest');
const express  = require('express');
const { createOpsDiagnosticsGate, createOpsAdminGate } = require('../opsEnabled');

function buildApp(opsConfig) {
  const app = express();
  app.use((req, res, next) => {
    req.requestId = 'test-req-id';
    res.locals.requestId = 'test-req-id';
    req.clientIp  = '127.0.0.1';
    next();
  });
  app.use('/metrics',     createOpsDiagnosticsGate(opsConfig), (_req, res) => res.status(200).json({ type: 'metrics' }));
  app.use('/diagnostics', createOpsDiagnosticsGate(opsConfig), (_req, res) => res.status(200).json({ type: 'diagnostics' }));
  app.use('/audit',       createOpsDiagnosticsGate(opsConfig), (_req, res) => res.status(200).json({ type: 'audit' }));
  return app;
}

// ── Diagnostics disabled (kill switch active) ─────────────────────────────────

describe('opsDiagnosticsGate — disabled', () => {
  const app = buildApp({ diagnosticsEnabled: false });

  it('returns 404 for /metrics', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(404);
  });

  it('returns 404 for /diagnostics', async () => {
    const res = await request(app).get('/diagnostics');
    expect(res.status).toBe(404);
  });

  it('returns 404 for /audit', async () => {
    const res = await request(app).get('/audit');
    expect(res.status).toBe(404);
  });

  it('404 response matches the canonical management envelope', async () => {
    const res = await request(app).get('/metrics');
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'NOT_FOUND' } });
  });

  it('404 does not expose endpoint purpose (no "metrics" in body)', async () => {
    const res = await request(app).get('/metrics');
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('metrics');
    expect(body).not.toContain('diagnostics');
    expect(body).not.toContain('audit');
  });

  it('requestId is included in 404 response', async () => {
    const res = await request(app).get('/metrics');
    expect(res.body.requestId).toBe('test-req-id');
  });
});

// ── Diagnostics enabled (kill switch inactive) ────────────────────────────────

describe('opsDiagnosticsGate — enabled', () => {
  const app = buildApp({ diagnosticsEnabled: true });

  it('allows /metrics through', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ type: 'metrics' });
  });

  it('allows /diagnostics through', async () => {
    const res = await request(app).get('/diagnostics');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ type: 'diagnostics' });
  });

  it('allows /audit through', async () => {
    const res = await request(app).get('/audit');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ type: 'audit' });
  });
});

// ── No information leakage in disabled response ───────────────────────────────

describe('opsDiagnosticsGate — information leakage prevention', () => {
  const app = buildApp({ diagnosticsEnabled: false });

  it('does not expose stack traces', async () => {
    const res = await request(app).get('/metrics');
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/Error:/);
    expect(body).not.toMatch(/at\s+\w+\s+\(/);
  });

  it('does not expose file paths', async () => {
    const res = await request(app).get('/metrics');
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/node_modules/);
    expect(body).not.toMatch(/src\//);
  });

  it('does not expose environment variables', async () => {
    const res = await request(app).get('/metrics');
    const body = JSON.stringify(res.body);
    expect(body).not.toMatch(/QODIQA_/);
    expect(body).not.toMatch(/NODE_ENV/);
  });
});

// ── Transition behavior verification ─────────────────────────────────────────

describe('opsDiagnosticsGate — dynamic config', () => {
  it('disabled config returns 404 consistently', async () => {
    const app = buildApp({ diagnosticsEnabled: false });
    for (let i = 0; i < 3; i++) {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(404);
    }
  });

  it('enabled config returns 200 consistently', async () => {
    const app = buildApp({ diagnosticsEnabled: true });
    for (let i = 0; i < 3; i++) {
      const res = await request(app).get('/metrics');
      expect(res.status).toBe(200);
    }
  });
});

// ── the admin gate keys on adminEnabled ONLY ────────

describe('opsAdminGate — independent of diagnosticsEnabled', () => {
  function adminApp(opsConfig) {
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'test-req-id'; req.clientIp = '127.0.0.1'; next(); });
    app.use('/audit', createOpsAdminGate(opsConfig), (_req, res) => res.status(200).json({ type: 'audit' }));
    return app;
  }

  it('adminEnabled=false → 404 even with diagnosticsEnabled=true', async () => {
    const res = await request(adminApp({ adminEnabled: false, diagnosticsEnabled: true })).get('/audit');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'NOT_FOUND' } });
  });

  it('adminEnabled=true → passes through even with diagnosticsEnabled=false', async () => {
    const res = await request(adminApp({ adminEnabled: true, diagnosticsEnabled: false })).get('/audit');
    expect(res.status).toBe(200);
  });

  it('the diagnostics gate ignores adminEnabled', async () => {
    const app = express();
    app.use('/metrics', createOpsDiagnosticsGate({ diagnosticsEnabled: false, adminEnabled: true }), (_req, res) => res.status(200).end());
    expect((await request(app).get('/metrics')).status).toBe(404);
  });
});
