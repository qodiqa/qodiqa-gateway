'use strict';

// Integration tests: full middleware stack (IP allowlist → auth → gate → handler)
// and security regression tests covering fail-closed, header spoofing, and
// enumeration resistance.
//
// /health and /ready are intentionally OUT OF SCOPE for this file: as of the
// health-probe remediation they are governed by a dedicated,
// separately-tested middleware chain (createHealthAuthMiddleware /
// createHealthLoopbackMiddleware — see src/middleware/__tests__/healthAuth.test.js,
// healthLoopback.test.js, and healthContentSafety.test.js) precisely because
// they must NOT share /metrics' and /diagnostics' "always require the ops
// token" contract — Kubernetes/Docker probes cannot supply that credential.

const request  = require('supertest');
const express  = require('express');
const { createOpsAuthMiddleware }        = require('../opsAuth');
const { createOpsIpAllowlistMiddleware } = require('../opsIpAllowlist');
const { createOpsDiagnosticsGate }       = require('../opsEnabled');

const VALID_TOKEN = 'integration-test-ops-token-32chars';

function buildFullStack(overrides = {}) {
  const opsConfig = {
    token:                VALID_TOKEN,
    diagnosticsEnabled:   true,
    ipAllowlistEnabled:   false,
    allowlistEntries:     [],
    allowlistConfigValid: true,
    trustProxy:           false,
    ...overrides,
  };

  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'int-test-req-id';
    req.socket    = { remoteAddress: overrides._socketIp || '127.0.0.1' };
    next();
  });

  // /metrics and /diagnostics are gated by the same admin-stack IP-allowlist
  // instance as every other management/admin route in server.js (opsOnlyStack()
  // shares its opsIpAllow with adminStack()) — see src/middleware/adminProtection.js
  // and server.js's `_adminIpAllow` wiring — so this harness mirrors that with
  // the management envelope, not the probe-surface default used for /health/ready.
  const opsIpAllow = createOpsIpAllowlistMiddleware(opsConfig, { envelope: 'management' });
  const opsAuth    = createOpsAuthMiddleware(opsConfig);
  const opsGate    = createOpsDiagnosticsGate(opsConfig);

  app.use('/metrics',     opsIpAllow, opsAuth, opsGate, (_req, res) => res.status(200).json({ data: 'metrics' }));
  app.use('/diagnostics', opsIpAllow, opsAuth, opsGate, (_req, res) => res.status(200).json({ data: 'diagnostics' }));

  return app;
}

// ── Full stack: authorized access ────────────────────────────────────────────

describe('full stack — authorized access succeeds', () => {
  const app = buildFullStack();

  it('/metrics with valid bearer token returns 200', async () => {
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(200);
  });

  it('/diagnostics with valid X-Ops-Token returns 200', async () => {
    const res = await request(app).get('/diagnostics')
      .set('X-Ops-Token', VALID_TOKEN);
    expect(res.status).toBe(200);
  });
});

// ── Full stack: auth failure stops at correct layer ───────────────────────────

describe('full stack — auth failure', () => {
  const app = buildFullStack();

  it('returns 401 (not 404) when token is missing but diagnostics enabled', async () => {
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(401);
  });

  it('returns 401 (not 404) when token is wrong but diagnostics enabled', async () => {
    const res = await request(app).get('/metrics')
      .set('Authorization', 'Bearer wrong');
    expect(res.status).toBe(401);
  });
});

// ── Full stack: kill switch takes effect after auth passes ────────────────────

describe('full stack — kill switch ordering', () => {
  it('returns 401 (not 404) when diagnostics disabled but no auth provided', async () => {
    // Auth check must run BEFORE the gate so the gate cannot leak "disabled" state
    const app = buildFullStack({ diagnosticsEnabled: false });
    const res = await request(app).get('/metrics');
    // Should get 401 (auth), not 404 (gate) — gate runs after auth
    expect(res.status).toBe(401);
  });

  it('returns 404 when diagnostics disabled but auth is valid', async () => {
    const app = buildFullStack({ diagnosticsEnabled: false });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(404);
  });
});

// ── Full stack: IP allowlist + auth + gate ────────────────────────────────────

describe('full stack — IP allowlist layer', () => {
  it('returns 403 (not 401) when IP is blocked', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      _socketIp:            '8.8.8.8',
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(403);
  });

  it('IP allowlist check runs before auth (does not reach auth layer)', async () => {
    // No token set → normally 401, but IP block comes first
    const app = buildFullStack({
      token:                null,
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      _socketIp:            '8.8.8.8',
    });
    const res = await request(app).get('/metrics');
    expect(res.status).toBe(403); // IP block before auth
  });

  it('allowed IP + valid auth + diagnostics enabled returns 200', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['127.0.0.1'],
      allowlistConfigValid: true,
      _socketIp:            '127.0.0.1',
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(200);
  });
});

// ── Security regression: fail-closed behaviors ────────────────────────────────

describe('security regression — fail-closed', () => {
  it('no token configured → 401 on all protected endpoints', async () => {
    // /health and /ready are deliberately excluded — see file header comment.
    const app = buildFullStack({ token: null });
    for (const path of ['/metrics', '/diagnostics']) {
      const res = await request(app).get(path);
      expect(res.status).toBe(401);
    }
  });

  it('empty allowlist with allowlisting enabled → 403 (no fallback)', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     [],
      allowlistConfigValid: true,
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(403);
  });

  it('invalid allowlist config → 403 (no fallback)', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     [],
      allowlistConfigValid: false,
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(403);
  });
});

// ── Security regression: header spoofing resistance ──────────────────────────

describe('security regression — header spoofing', () => {
  it('X-Forwarded-For cannot bypass IP allowlist when trustProxy=false', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      trustProxy:           false,
      _socketIp:            '8.8.8.8',
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`)
      .set('X-Forwarded-For', '10.0.0.1');
    expect(res.status).toBe(403);
  });

  it('X-Real-IP cannot bypass IP allowlist when trustProxy=false', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      trustProxy:           false,
      _socketIp:            '8.8.8.8',
    });
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`)
      .set('X-Real-IP', '10.0.0.1');
    expect(res.status).toBe(403);
  });

  it('multiple XFF hops cannot place an allowed IP at any non-first position', async () => {
    const app = buildFullStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      trustProxy:           true,   // proxy trust enabled
      _socketIp:            '8.8.8.8',
    });
    // Attacker inserts allowed IP somewhere in the middle of the XFF chain
    const res = await request(app).get('/metrics')
      .set('Authorization', `Bearer ${VALID_TOKEN}`)
      .set('X-Forwarded-For', '8.8.8.8, 10.0.0.1, 172.16.0.1');
    // Leftmost (8.8.8.8) is not in allowlist → 403
    expect(res.status).toBe(403);
  });
});

// ── Security regression: enumeration resistance ───────────────────────────────

describe('security regression — enumeration resistance', () => {
  it('unauthenticated request cannot distinguish disabled from non-existent (both 401)', async () => {
    // Gate is disabled, but auth runs first → 401, not 404
    // This prevents an attacker from discovering that the endpoint exists but is disabled
    const disabledApp = buildFullStack({ diagnosticsEnabled: false });
    const enabledApp  = buildFullStack({ diagnosticsEnabled: true });

    const disabledRes = await request(disabledApp).get('/metrics');
    const enabledRes  = await request(enabledApp).get('/metrics');

    expect(disabledRes.status).toBe(401);
    expect(enabledRes.status).toBe(401);
  });

  it('all three error responses (401, 403, 404) have consistent body structure', async () => {
    const authFailApp = buildFullStack();
    const ipBlockApp  = buildFullStack({
      ipAllowlistEnabled: true,
      allowlistEntries: ['10.0.0.1'],
      allowlistConfigValid: true,
      _socketIp: '8.8.8.8',
    });
    const disabledApp = buildFullStack({ diagnosticsEnabled: false });

    const authRes  = await request(authFailApp).get('/metrics');
    const ipRes    = await request(ipBlockApp).get('/metrics').set('Authorization', `Bearer ${VALID_TOKEN}`);
    const gateRes  = await request(disabledApp).get('/metrics').set('Authorization', `Bearer ${VALID_TOKEN}`);

    for (const res of [authRes, ipRes, gateRes]) {
      expect(res.body).toHaveProperty('status', 'error');
      expect(res.body).toHaveProperty('error.code');
      expect(res.body).toHaveProperty('requestId');
    }
  });
});
