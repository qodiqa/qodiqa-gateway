'use strict';

const request  = require('supertest');
const express  = require('express');
const { createOpsAuthMiddleware } = require('../opsAuth');

const VALID_TOKEN = 'test-ops-token-at-least-32-chars-long';

function buildApp(config) {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    req.clientIp  = '127.0.0.1';
    next();
  });
  app.use(createOpsAuthMiddleware(config));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

// ── Fail-closed: no token configured ─────────────────────────────────────────

describe('opsAuth — fail-closed (no token configured)', () => {
  const app = buildApp({ token: null });

  it('returns 401 with no Authorization header', async () => {
    const res = await request(app).get('/probe');
    expect(res.status).toBe(401);
  });

  it('returns 401 even with a Bearer token', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(401);
  });

  it('returns 401 even with an X-Ops-Token header', async () => {
    const res = await request(app).get('/probe')
      .set('X-Ops-Token', VALID_TOKEN);
    expect(res.status).toBe(401);
  });

  it('response body matches the canonical management envelope', async () => {
    const res = await request(app).get('/probe');
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'UNAUTHORIZED' } });
  });
});

// ── Bearer token authentication ───────────────────────────────────────────────

describe('opsAuth — Bearer token', () => {
  const app = buildApp({ token: VALID_TOKEN });

  it('allows access with correct Bearer token', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('returns 401 with wrong Bearer token', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', 'Bearer wrong-token');
    expect(res.status).toBe(401);
  });

  it('returns 401 with empty Bearer value', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', 'Bearer ');
    expect(res.status).toBe(401);
  });

  it('returns 401 with missing Authorization header', async () => {
    const res = await request(app).get('/probe');
    expect(res.status).toBe(401);
  });

  it('returns 401 with Authorization header lacking Bearer prefix', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', VALID_TOKEN);
    expect(res.status).toBe(401);
  });

  it('returns 401 with Basic scheme instead of Bearer', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', `Basic ${Buffer.from(`user:${VALID_TOKEN}`).toString('base64')}`);
    expect(res.status).toBe(401);
  });
});

// ── X-Ops-Token header authentication ────────────────────────────────────────

describe('opsAuth — X-Ops-Token header', () => {
  const app = buildApp({ token: VALID_TOKEN });

  it('allows access with correct X-Ops-Token', async () => {
    const res = await request(app).get('/probe')
      .set('X-Ops-Token', VALID_TOKEN);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it('returns 401 with wrong X-Ops-Token', async () => {
    const res = await request(app).get('/probe')
      .set('X-Ops-Token', 'wrong');
    expect(res.status).toBe(401);
  });

  it('returns 401 with empty X-Ops-Token', async () => {
    const res = await request(app).get('/probe')
      .set('X-Ops-Token', '');
    expect(res.status).toBe(401);
  });
});

// ── Bearer takes precedence over X-Ops-Token ─────────────────────────────────

describe('opsAuth — header precedence', () => {
  const app = buildApp({ token: VALID_TOKEN });

  it('uses Bearer when both headers are present', async () => {
    // Valid Bearer + invalid X-Ops-Token → should pass (Bearer wins)
    const res = await request(app).get('/probe')
      .set('Authorization', `Bearer ${VALID_TOKEN}`)
      .set('X-Ops-Token', 'wrong');
    expect(res.status).toBe(200);
  });

  it('invalid Bearer + valid X-Ops-Token → 401 (Bearer checked first)', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', 'Bearer wrong')
      .set('X-Ops-Token', VALID_TOKEN);
    expect(res.status).toBe(401);
  });
});

// ── Timing-safe comparison — tokens of different lengths ─────────────────────

describe('opsAuth — timing-safe comparison', () => {
  const app = buildApp({ token: VALID_TOKEN });

  it('rejects shorter token without granting access', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', `Bearer ${VALID_TOKEN.slice(0, 10)}`);
    expect(res.status).toBe(401);
  });

  it('rejects longer token without granting access', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', `Bearer ${VALID_TOKEN}EXTRA`);
    expect(res.status).toBe(401);
  });
});

// ── Response body never exposes stack traces or internals ─────────────────────

describe('opsAuth — response sanitization', () => {
  const app = buildApp({ token: VALID_TOKEN });

  it('401 body does not contain stack trace', async () => {
    const res = await request(app).get('/probe');
    expect(JSON.stringify(res.body)).not.toMatch(/Error:/);
    expect(JSON.stringify(res.body)).not.toMatch(/at\s+\w+\s+\(/);
  });

  it('401 body does not contain token value', async () => {
    const res = await request(app).get('/probe')
      .set('Authorization', 'Bearer wrong-value');
    expect(JSON.stringify(res.body)).not.toContain('wrong-value');
    expect(JSON.stringify(res.body)).not.toContain(VALID_TOKEN);
  });
});
