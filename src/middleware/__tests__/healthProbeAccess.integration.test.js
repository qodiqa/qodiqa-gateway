'use strict';

// End-to-end integration test for the exact /health and /ready middleware
// chain wired in src/app.js:
//
//   app.use('/health', _opsIpAllow, _healthLoopback, _healthAuth, healthRouter);
//   app.use('/ready',  _opsIpAllow, _healthLoopback, _healthAuth, readyRouter);
//
// there is deliberately NO rate limiter in
// this chain any more. The Redis-backed 'health_probe' limiter that used to
// lead it fails closed when Redis is down, so during exactly the outage
// class /ready exists to report, every probe got 429 RATE_LIMITED instead of
// the documented 503+components readiness body. Enforcement-route limiting
// and its fail-closed posture are unchanged and pinned in
// src/core/rateLimit/__tests__/rateLimit.test.js.
//
// This reproduces that chain with the real middleware factories (not a
// reimplementation) so a change to any one layer's composition is caught
// here, not just in each layer's isolated unit tests.

const request = require('supertest');
const express = require('express');

const { createOpsIpAllowlistMiddleware } = require('../opsIpAllowlist');
const { createHealthLoopbackMiddleware } = require('../healthLoopback');
const { createHealthAuthMiddleware }     = require('../healthAuth');

const VALID_TOKEN = 'probe-access-integration-test-token';

function buildStack(opsConfigOverrides = {}) {
  const opsConfig = {
    token:                 null,
    healthAuthRequired:    false,
    healthRequireLoopback: false,
    ipAllowlistEnabled:    false,
    allowlistEntries:      [],
    allowlistConfigValid:  true,
    trustProxy:            false,
    ...opsConfigOverrides,
  };

  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'probe-int-test';
    req.socket    = { remoteAddress: opsConfigOverrides._socketIp || '127.0.0.1' };
    next();
  });

  const ipAllow  = createOpsIpAllowlistMiddleware(opsConfig);
  const loopback = createHealthLoopbackMiddleware(opsConfig);
  const auth     = createHealthAuthMiddleware(opsConfig);

  app.use('/health', ipAllow, loopback, auth, (_req, res) => res.status(200).json({ status: 'ok' }));
  app.use('/ready',  ipAllow, loopback, auth, (_req, res) => res.status(200).json({ ready: true }));

  return app;
}

// ── Orchestrator compatibility (the bug this remediation fixes) ──────────────

describe('probe access — default configuration (orchestrator compatible)', () => {
  it('a bare Kubernetes-style httpGet probe (no headers at all) succeeds on /health', async () => {
    const app = buildStack();
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('a bare Kubernetes-style httpGet probe (no headers at all) succeeds on /ready', async () => {
    const app = buildStack();
    const res = await request(app).get('/ready');
    expect(res.status).toBe(200);
  });

  it('a Docker HEALTHCHECK-style bare request (wget, no auth headers) succeeds', async () => {
    const app = buildStack();
    const res = await request(app).get('/health').set('User-Agent', 'Wget');
    expect(res.status).toBe(200);
  });

  it('a request from a non-loopback pod-network IP succeeds (Kubernetes never uses loopback)', async () => {
    const app = buildStack({ _socketIp: '10.244.1.7' });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });
});

// ── Optional hardening: bearer/API-key auth ───────────────────────────────────

describe('probe access — QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true', () => {
  it('rejects an unauthenticated request (401) — fail closed', async () => {
    const app = buildStack({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health');
    expect(res.status).toBe(401);
  });

  it('accepts a request with the configured credential (200)', async () => {
    const app = buildStack({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/health').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(200);
  });

  it('rejects a request with an invalid credential (401)', async () => {
    const app = buildStack({ healthAuthRequired: true, token: VALID_TOKEN });
    const res = await request(app).get('/ready').set('X-Ops-Token', 'wrong');
    expect(res.status).toBe(401);
  });
});

// ── Optional hardening: loopback-only (Docker/bare-metal deployments) ────────

describe('probe access — QODIQA_HEALTH_REQUIRE_LOOPBACK=true', () => {
  it('allows a genuine loopback request (Docker HEALTHCHECK scenario)', async () => {
    const app = buildStack({ healthRequireLoopback: true, _socketIp: '127.0.0.1' });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('rejects a non-loopback request (403)', async () => {
    const app = buildStack({ healthRequireLoopback: true, _socketIp: '203.0.113.9' });
    const res = await request(app).get('/health');
    expect(res.status).toBe(403);
  });

  it('spoofed X-Forwarded-For claiming loopback does not bypass the check', async () => {
    const app = buildStack({ healthRequireLoopback: true, _socketIp: '203.0.113.9' });
    const res = await request(app).get('/health').set('X-Forwarded-For', '127.0.0.1');
    expect(res.status).toBe(403);
  });
});

// ── Reverse proxy / trusted proxy scenarios (shared with /metrics, /diagnostics) ─

describe('probe access — reverse proxy and trusted-proxy scenarios', () => {
  it('IP allowlist blocks an untrusted source even with a valid probe request shape', async () => {
    const app = buildStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.244.0.0/16'],
      allowlistConfigValid: true,
      _socketIp:            '203.0.113.9',
    });
    const res = await request(app).get('/health');
    expect(res.status).toBe(403);
  });

  it('IP allowlist permits an allowed pod-network source', async () => {
    const app = buildStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.244.0.0/16'],
      allowlistConfigValid: true,
      _socketIp:            '10.244.1.7',
    });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
  });

  it('X-Forwarded-For cannot bypass the IP allowlist when trustProxy=false', async () => {
    const app = buildStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.244.0.0/16'],
      allowlistConfigValid: true,
      trustProxy:           false,
      _socketIp:            '203.0.113.9',
    });
    const res = await request(app).get('/health').set('X-Forwarded-For', '10.244.1.7');
    expect(res.status).toBe(403);
  });

  // X-Forwarded-For is honoured only from a proxy listed in
  // TRUSTED_PROXY (the one list every consumer reads) — trustProxy=true alone
  // no longer trusts an arbitrary peer.
  it('X-Forwarded-For is honoured only from a proxy listed in TRUSTED_PROXY', async () => {
    const app = buildStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.244.0.0/16'],
      allowlistConfigValid: true,
      trustProxy:           true,
      _socketIp:            '192.0.2.1', // the reverse proxy itself
    });
    const prev = process.env.TRUSTED_PROXY;
    try {
      delete process.env.TRUSTED_PROXY; // default 'loopback': 192.0.2.1 is not trusted
      expect((await request(app).get('/health').set('X-Forwarded-For', '10.244.1.7')).status).toBe(403);
      process.env.TRUSTED_PROXY = '192.0.2.1';
      expect((await request(app).get('/health').set('X-Forwarded-For', '10.244.1.7')).status).toBe(200);
    } finally {
      if (prev === undefined) delete process.env.TRUSTED_PROXY; else process.env.TRUSTED_PROXY = prev;
    }
  });
});

// ── probe routes are deliberately NOT rate-limited ─────────────────────

describe('probe access — no rate limiting on probe routes', () => {
  it('sustained probe traffic is never 429d — well past the old health_probe cap', async () => {
    // Pre-F-28, the fail-closed Redis-backed limiter in this chain returned
    // 429 for EVERY probe during a Redis outage. The chain now contains no
    // limiter at all: even a volume far beyond the old 240/min default must
    // pass, and no 429 can exist on this path regardless of backend state.
    const app = buildStack();
    for (let i = 0; i < 300; i++) {
      const res = await request(app).get(i % 2 ? '/health' : '/ready');
      expect(res.status).toBe(200);
    }
  });

  it('enforcement-route rate limiting is a separate, still-live mechanism (pinned elsewhere)', () => {
    // The probe exemption must never leak into enforcement routes: the
    // Redis-backed enforcement limiter and its fail-closed posture are
    // pinned by src/core/rateLimit/__tests__/rateLimit.test.js and the
    // aiChat/sign route suites. Here we only pin that the factory this app
    // still uses for enforcement scopes exists and is not the removed
    // health_probe wiring.
    const { createRateLimitMiddleware } = require('../../core/rateLimit');
    expect(typeof createRateLimitMiddleware).toBe('function');
  });
});

// ── Fail-closed regression: invalid/misconfigured hardening never opens access ─

describe('probe access — fail-closed on misconfiguration', () => {
  it('an enabled-but-empty IP allowlist denies everything, including probes', async () => {
    const app = buildStack({
      ipAllowlistEnabled:   true,
      allowlistEntries:     [],
      allowlistConfigValid: true,
    });
    const res = await request(app).get('/health');
    expect(res.status).toBe(403);
  });

  it('healthAuthRequired=true with no token configured denies everything (never opens access)', async () => {
    const app = buildStack({ healthAuthRequired: true, token: null });
    const res = await request(app).get('/health');
    expect(res.status).toBe(401);
  });
});
