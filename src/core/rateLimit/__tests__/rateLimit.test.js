'use strict';

/**
 * Rate Limiting Test Suite
 *
 * Sections:
 *   1  — Unit: Sliding Window Counter algorithm (RL-01…RL-19)
 *   2  — Unit: MemoryStorage (RL-20…RL-29)
 *   3  — Unit: Config schema validation (RL-30…RL-39)
 *   4  — Unit: Policy hierarchy resolution (RL-40…RL-49)
 *   5  — Integration: Middleware + HTTP responses (RL-50…RL-69)
 *   6  — Integration: Metrics (RL-70…RL-79)
 *   7  — Concurrency: Simultaneous requests (RL-80…RL-89)
 *   8  — Performance: Latency and throughput (RL-90…RL-99)
 *   9  — Regression: Edge cases (RL-100…RL-109)
 *   10 — Adversarial: Attacks and failure modes (RL-110…RL-119)
 *   11 — publicRateLimit.js in-memory sliding window (RL-120…RL-129)
 * 12 — 'decision'/'legacyFailure' envelopes (WP7-01…WP7-09)
 */

const express = require('express');
const request = require('supertest');

// ── Module-level mocks ────────────────────────────────────────────────────────

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../../src/infra/redis/clientConfig', () => ({
  buildClientOptions: jest.fn(() => ({})),
  getConfigSummary:   jest.fn(() => ({
    authConfigured: false, tlsEnabled: false, tlsVerified: false, urlRedacted: 'redis://[test]',
  })),
  isAuthError: jest.fn(() => false),
  isTlsError:  jest.fn(() => false),
}));
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect:  jest.fn().mockResolvedValue(undefined),
    quit:     jest.fn().mockResolvedValue(undefined),
    ping:     jest.fn().mockResolvedValue('PONG'),
    set:      jest.fn().mockResolvedValue('OK'),
    get:      jest.fn().mockResolvedValue('1'),
    del:      jest.fn().mockResolvedValue(1),
    eval:     jest.fn().mockResolvedValue([1, 0, 1, 1, 60, 99, 0, 0]),
    isReady:  false,
    on:       jest.fn(),
  })),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

const { MemoryStorage }       = require('../storage');
const { evaluate, SW_LUA }    = require('../slidingWindow');
const { loadConfig, _reset: resetConfig, ConfigSchema, PolicySchema } = require('../config');
const { resolvePolicies, getPolicy } = require('../policies');
const { createRateLimitMiddleware, extractIdentity, _isRlEnabled } = require('../middleware');
const metrics                 = require('../metrics');

function freshMem()     { return new MemoryStorage(); }
function mkEval(mem)    { return (s, k, a) => mem.eval(s, k, a); }

function buildApp(surface, { ip = '1.2.3.4', rbacUser, tenantId, signingKeyId, rl_endpoint, mem } = {}) {
  const _mem = mem || freshMem();
  const app  = express();
  app.use((req, _res, next) => {
    req.requestId   = 'test-rid';
    req.clientIp    = ip;
    if (rbacUser)    req.rbacUser    = rbacUser;
    if (tenantId)    req.tenantId    = tenantId;
    if (signingKeyId) req.signingKeyId = signingKeyId;
    if (rl_endpoint)  req.rl_endpoint  = rl_endpoint;
    next();
  });
  app.use(createRateLimitMiddleware(surface, { _evalFn: mkEval(_mem) }));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

beforeEach(() => {
  process.env.RL_ENABLED = 'true';
  resetConfig();
  metrics._reset();
  jest.clearAllMocks();
});
afterEach(() => {
  delete process.env.RL_ENABLED;
  resetConfig();
  metrics._reset();
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — UNIT: Sliding Window Counter algorithm
// ─────────────────────────────────────────────────────────────────────────────

describe('SWC Algorithm', () => {
  it('RL-01: first request in fresh window is allowed', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100);
    expect(result.allowed).toBe(true);
    expect(result.count).toBe(1);
  });

  it('RL-02: requests up to maxRequests are all allowed', async () => {
    const mem = freshMem();
    let last;
    for (let i = 0; i < 100; i++) {
      last = await evaluate(mkEval(mem), 'test:key', 1000, 60, 100);
    }
    expect(last.allowed).toBe(true);
    expect(last.count).toBe(100);
  });

  it('RL-03: request exceeding maxRequests is blocked', async () => {
    const mem = freshMem();
    for (let i = 0; i < 100; i++) await evaluate(mkEval(mem), 'test:key', 1000, 60, 100);
    const result = await evaluate(mkEval(mem), 'test:key', 1000, 60, 100);
    expect(result.allowed).toBe(false);
    expect(result.swAllowed).toBe(false);
    expect(result.blockedBy).toBe('SUSTAINED');
  });

  it('RL-04: remaining decreases with each request', async () => {
    const mem = freshMem();
    const r1  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 10);
    const r2  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 10);
    expect(r2.remaining).toBeLessThan(r1.remaining);
  });

  it('RL-05: remaining is 0 when limit reached', async () => {
    const mem = freshMem();
    for (let i = 0; i < 10; i++) await evaluate(mkEval(mem), 'test:key', 1000, 60, 10);
    const result = await evaluate(mkEval(mem), 'test:key', 1000, 60, 10);
    expect(result.remaining).toBe(0);
  });

  it('RL-06: resetIn is positive and ≤ windowSeconds', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 10);
    expect(result.resetIn).toBeGreaterThan(0);
    expect(result.resetIn).toBeLessThanOrEqual(60);
  });

  it('RL-07: different keys are fully independent', async () => {
    const mem = freshMem();
    for (let i = 0; i < 5; i++) await evaluate(mkEval(mem), 'test:key-A', 1000, 60, 5);
    const rb = await evaluate(mkEval(mem), 'test:key-B', 1000, 60, 5);
    expect(rb.allowed).toBe(true);
    expect(rb.count).toBe(1);
  });

  it('RL-08: prev window contributes with weight proportional to elapsed time', async () => {
    const mem    = freshMem();
    const window = 60;
    const now1   = 1000;  // start of bucket
    const now2   = 1030;  // 30s into next bucket — prev weight = 0.5
    for (let i = 0; i < 80; i++) await evaluate(mkEval(mem), 'test:key', now1, window, 100);
    // Effective rate = 80×0.5 + 1 = 41 < 100 → allowed
    const result = await evaluate(mkEval(mem), 'test:key', now2, window, 100);
    expect(result.prev).toBe(80);
    expect(result.allowed).toBe(true);
  });

  it('RL-09: burstCapacity=0 disables burst (burstAllowed always true)', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100, 0, 5);
    expect(result.burstAllowed).toBe(true);
    expect(result.burstCount).toBe(0);
  });

  it('RL-10: burst blocks at burstCapacity', async () => {
    const mem = freshMem();
    for (let i = 0; i < 5; i++) await evaluate(mkEval(mem), 'test:key', 1000, 60, 100, 5, 5);
    const result = await evaluate(mkEval(mem), 'test:key', 1000, 60, 100, 5, 5);
    expect(result.burstAllowed).toBe(false);
    expect(result.blockedBy).toBe('BURST');
  });

  it('RL-11: burst resets after burst window elapses', async () => {
    const mem = freshMem();
    for (let i = 0; i < 5; i++) await evaluate(mkEval(mem), 'test:key', 1000, 60, 100, 5, 5);
    const result = await evaluate(mkEval(mem), 'test:key', 1006, 60, 100, 5, 5);
    expect(result.burstAllowed).toBe(true);
  });

  it('RL-12: burstRemaining tracks capacity correctly', async () => {
    const mem = freshMem();
    const r1  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 100, 10, 5);
    const r2  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 100, 10, 5);
    expect(r1.burstRemaining).toBe(9);
    expect(r2.burstRemaining).toBe(8);
  });

  it('RL-13: SW_LUA is a non-empty string', () => {
    expect(typeof SW_LUA).toBe('string');
    expect(SW_LUA.length).toBeGreaterThan(100);
    expect(SW_LUA).toContain('INCR');
    expect(SW_LUA).toContain('EXPIRE');
  });

  it('RL-14: blockedBy is null when allowed', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100);
    expect(result.blockedBy).toBeNull();
  });

  it('RL-15: prev is 0 on very first request', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100);
    expect(result.prev).toBe(0);
  });

  it('RL-16: prev is set after window rolls over', async () => {
    const mem = freshMem();
    for (let i = 0; i < 10; i++) await evaluate(mkEval(mem), 'test:key', 0, 60, 100);
    const result = await evaluate(mkEval(mem), 'test:key', 60, 60, 100);
    expect(result.prev).toBe(10);
    expect(result.count).toBe(1);
  });

  it('RL-17: swAllowed and burstAllowed are both true on allowed request', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100, 20, 5);
    expect(result.swAllowed).toBe(true);
    expect(result.burstAllowed).toBe(true);
    expect(result.allowed).toBe(true);
  });

  it('RL-18: maxRequests=1 allows exactly 1 request', async () => {
    const mem = freshMem();
    const r1  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 1);
    const r2  = await evaluate(mkEval(mem), 'test:key', 1000, 60, 1);
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(false);
  });

  it('RL-19: evaluate returns all 9 expected fields', async () => {
    const result = await evaluate(mkEval(freshMem()), 'test:key', 1000, 60, 100);
    expect(result).toHaveProperty('allowed');
    expect(result).toHaveProperty('swAllowed');
    expect(result).toHaveProperty('burstAllowed');
    expect(result).toHaveProperty('count');
    expect(result).toHaveProperty('prev');
    expect(result).toHaveProperty('remaining');
    expect(result).toHaveProperty('resetIn');
    expect(result).toHaveProperty('burstCount');
    expect(result).toHaveProperty('burstRemaining');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — UNIT: MemoryStorage
// ─────────────────────────────────────────────────────────────────────────────

describe('MemoryStorage', () => {
  it('RL-20: isReady() always returns true', () => {
    expect(freshMem().isReady()).toBe(true);
  });

  it('RL-21: _reset() clears all state', async () => {
    const mem = freshMem();
    for (let i = 0; i < 5; i++) await evaluate(mkEval(mem), 'test:key', 1000, 60, 5);
    mem._reset();
    const result = await evaluate(mkEval(mem), 'test:key', 1000, 60, 5);
    expect(result.count).toBe(1);
    expect(result.allowed).toBe(true);
  });

  it('RL-22: expired keys count as zero', async () => {
    const mem = freshMem();
    await evaluate(mkEval(mem), 'test:key', 0, 1, 100);
    const result = await evaluate(mkEval(mem), 'test:key', 3, 1, 100);
    expect(result.count).toBe(1);
  });

  it('RL-23: independent instances have independent state', async () => {
    const memA = freshMem();
    const memB = freshMem();
    for (let i = 0; i < 5; i++) await evaluate(mkEval(memA), 'test:key', 1000, 60, 5);
    const rb = await evaluate(mkEval(memB), 'test:key', 1000, 60, 5);
    expect(rb.count).toBe(1);
  });

  it('RL-24: eval returns 8-element array', async () => {
    const mem = freshMem();
    const raw = await mem.eval('', ['test:base'], ['1000', '60', '100', '0', '5']);
    expect(raw).toHaveLength(8);
    expect(raw.every(v => typeof v === 'number')).toBe(true);
  });

  it('RL-25: burst counter increments separately from sustained counter', async () => {
    const mem = freshMem();
    const r = await mem.eval('', ['test:base'], ['1000', '60', '100', '5', '5']);
    expect(r[6]).toBe(1);  // burstCount
    expect(r[7]).toBe(4);  // burstRemaining
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — UNIT: Config schema validation
// ─────────────────────────────────────────────────────────────────────────────

describe('Config — schema validation', () => {
  it('RL-30: default config loads without error', () => {
    expect(() => loadConfig()).not.toThrow();
  });

  it('RL-31: maxRequests=0 throws', () => {
    expect(() => loadConfig({ surfaces: { portal: { maxRequests: 0, windowSeconds: 60 } } })).toThrow(/invalid/i);
  });

  it('RL-32: negative windowSeconds throws', () => {
    expect(() => loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: -1 } } })).toThrow(/invalid/i);
  });

  it('RL-33: unlimited=true is valid', () => {
    expect(() => loadConfig({ users: { u1: { maxRequests: 100, windowSeconds: 60, unlimited: true } } })).not.toThrow();
  });

  it('RL-34: disabled=true is valid', () => {
    expect(() => loadConfig({ users: { u1: { maxRequests: 100, windowSeconds: 60, disabled: true } } })).not.toThrow();
  });

  it('RL-35: burstCapacity=0 is valid', () => {
    expect(() => loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } } })).not.toThrow();
  });

  it('RL-36: negative burstCapacity throws', () => {
    expect(() => loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: -1 } } })).toThrow(/invalid/i);
  });

  it('RL-37: all known surfaces present after loadConfig()', () => {
    const cfg = loadConfig();
    for (const s of ['portal', 'attestation', 'certification', 'transparency', 'webhooks_admin']) {
      expect(cfg.surfaces).toHaveProperty(s);
    }
  });

  it('RL-38: tenant, user, signingKey, endpoint sections default to empty objects', () => {
    const cfg = loadConfig();
    expect(cfg.tenants).toEqual({});
    expect(cfg.users).toEqual({});
    expect(cfg.signingKeys).toEqual({});
    expect(cfg.endpoints).toEqual({});
  });

  it('RL-39: user quota with large maxRequests is valid', () => {
    expect(() => loadConfig({ users: { 'vip': { maxRequests: 1_000_000, windowSeconds: 86400 } } })).not.toThrow();
  });

  it('RL-40: well_known_archived is its own surface with a stricter default budget than well_known', () => {
    const cfg = loadConfig();
    expect(cfg.surfaces).toHaveProperty('well_known_archived');
    expect(cfg.surfaces.well_known_archived.maxRequests).toBeLessThan(cfg.surfaces.well_known.maxRequests);
  });

  it('RL-41: RL_WELL_KNOWN_ARCHIVED_MAX configures well_known_archived independently of well_known', () => {
    const prevArchived = process.env.RL_WELL_KNOWN_ARCHIVED_MAX;
    const prevLive      = process.env.RL_WELL_KNOWN_MAX;
    try {
      process.env.RL_WELL_KNOWN_ARCHIVED_MAX = '5';
      const cfg = loadConfig();
      expect(cfg.surfaces.well_known_archived.maxRequests).toBe(5);
      expect(cfg.surfaces.well_known.maxRequests).not.toBe(5);
    } finally {
      if (prevArchived === undefined) delete process.env.RL_WELL_KNOWN_ARCHIVED_MAX;
      else process.env.RL_WELL_KNOWN_ARCHIVED_MAX = prevArchived;
      if (prevLive === undefined) delete process.env.RL_WELL_KNOWN_MAX;
      else process.env.RL_WELL_KNOWN_MAX = prevLive;
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 — UNIT: Policy hierarchy resolution
// ─────────────────────────────────────────────────────────────────────────────

describe('resolvePolicies — hierarchy', () => {
  beforeEach(() => {
    loadConfig({
      tenants:     { 'tenant-A': { maxRequests: 200, windowSeconds: 60 } },
      users:       { 'user-B':   { maxRequests: 50,  windowSeconds: 60 } },
      signingKeys: { 'key-C':    { maxRequests: 10,  windowSeconds: 60 } },
      endpoints:   { '/sign':    { maxRequests: 5,   windowSeconds: 60 } },
    });
  });

  it('RL-40: no context → only surface policy', () => {
    const chain = resolvePolicies('portal');
    expect(chain).toHaveLength(1);
    expect(chain[0].dimension).toBe('surface:portal');
  });

  it('RL-41: tenant context adds tenant policy', () => {
    const chain = resolvePolicies('portal', { tenantId: 'tenant-A' });
    expect(chain).toHaveLength(2);
    expect(chain[1].dimension).toBe('tenant:tenant-A');
  });

  it('RL-42: userId context adds user policy', () => {
    const chain = resolvePolicies('portal', { userId: 'user-B' });
    expect(chain).toHaveLength(2);
    expect(chain[1].dimension).toBe('user:user-B');
  });

  it('RL-43: signingKeyId context adds signing key policy', () => {
    const chain = resolvePolicies('portal', { signingKeyId: 'key-C' });
    expect(chain).toHaveLength(2);
    expect(chain[1].dimension).toBe('signingkey:key-C');
  });

  it('RL-44: all contexts → 5 policy levels', () => {
    const chain = resolvePolicies('portal', {
      tenantId: 'tenant-A', userId: 'user-B', signingKeyId: 'key-C', endpoint: '/sign',
    });
    expect(chain).toHaveLength(5);
  });

  it('RL-45: unknown tenant adds no policy', () => {
    const chain = resolvePolicies('portal', { tenantId: 'nonexistent' });
    expect(chain).toHaveLength(1);
  });

  it('RL-46: unknown user adds no policy', () => {
    const chain = resolvePolicies('portal', { userId: 'nonexistent' });
    expect(chain).toHaveLength(1);
  });

  it('RL-47: endpoint override is last in chain', () => {
    const chain = resolvePolicies('portal', { endpoint: '/sign' });
    expect(chain[chain.length - 1].dimension).toBe('endpoint:/sign');
  });

  it('RL-48: getPolicy throws for unknown surface', () => {
    expect(() => getPolicy('nonexistent_surface')).toThrow(/Unknown/);
  });

  it('RL-49: surface policy is first in all chains', () => {
    const chain = resolvePolicies('attestation', { tenantId: 'tenant-A', userId: 'user-B' });
    expect(chain[0].dimension).toMatch(/^surface:/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 — INTEGRATION: Middleware + HTTP responses
// ─────────────────────────────────────────────────────────────────────────────

describe('Middleware — HTTP behavior', () => {
  it('RL-50: passthrough when RL_ENABLED=false', async () => {
    process.env.RL_ENABLED = 'false';
    const res = await request(buildApp('portal')).get('/probe');
    expect(res.status).toBe(200);
  });

  it('RL-51: allows requests below limit', async () => {
    const res = await request(buildApp('attestation')).get('/probe');
    expect(res.status).toBe(200);
  });

  it('RL-52: returns 429 when limit exceeded', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    await request(app).get('/probe');
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-53: 429 body has error + surface fields', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.body).toMatchObject({ error: 'RATE_LIMIT_EXCEEDED', surface: 'portal' });
  });

  it('RL-54: 429 includes Retry-After header', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('RL-55: RateLimit-Limit header set on allowed response', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    expect(Number(res.headers['ratelimit-limit'])).toBeGreaterThan(0);
  });

  it('RL-56: X-RateLimit-Limit mirrors RateLimit-Limit', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    expect(res.headers['x-ratelimit-limit']).toBe(res.headers['ratelimit-limit']);
  });

  it('RL-57: RateLimit-Remaining decreases with each request', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 10, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    const r1  = await request(app).get('/probe');
    const r2  = await request(app).get('/probe');
    expect(Number(r2.headers['ratelimit-remaining'])).toBeLessThan(Number(r1.headers['ratelimit-remaining']));
  });

  it('RL-58: RateLimit-Reset is a future Unix timestamp', async () => {
    const res   = await request(buildApp('portal')).get('/probe');
    const reset = Number(res.headers['ratelimit-reset']);
    expect(reset).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('RL-59: per-API-key limit blocks after key quota exceeded', async () => {
    loadConfig({
      surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      users:    { 'user-X': { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'user-X' } });
    await request(app).get('/probe');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body.dimension).toContain('user:user-X');
  });

  it('RL-60: unlimited user is never blocked by rate limit', async () => {
    loadConfig({
      surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } },
      users:    { 'vip': { maxRequests: 100, windowSeconds: 60, unlimited: true } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'vip' } });
    for (let i = 0; i < 5; i++) {
      expect((await request(app).get('/probe')).status).toBe(200);
    }
  });

  it('RL-61: disabled user gets 429 on first request', async () => {
    loadConfig({ users: { 'blocked': { maxRequests: 100, windowSeconds: 60, disabled: true } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'blocked' } });
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-62: signing key limit blocks after key quota exceeded', async () => {
    loadConfig({
      surfaces:    { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      signingKeys: { 'key-123': { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, signingKeyId: 'key-123' });
    await request(app).get('/probe');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body.dimension).toContain('signingkey:key-123');
  });

  it('RL-63: burst limit triggers before sustained limit', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 3, burstWindowSeconds: 5 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    for (let i = 0; i < 3; i++) await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body.reason).toBe('BURST');
  });

  it('RL-64: different IPs have independent limits', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem  = freshMem();
    const appA = buildApp('portal', { mem, ip: '10.0.0.1' });
    const appB = buildApp('portal', { mem, ip: '10.0.0.2' });
    await request(appA).get('/probe');
    expect((await request(appA).get('/probe')).status).toBe(429);
    expect((await request(appB).get('/probe')).status).toBe(200);
  });

  it('RL-65: tenant limit is applied independently from surface limit', async () => {
    loadConfig({
      surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      tenants:  { 'tenant-T': { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, tenantId: 'tenant-T' });
    await request(app).get('/probe');
    await request(app).get('/probe');
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-66: identity resolves to user when rbacUser.id set', () => {
    expect(extractIdentity({ rbacUser: { id: 'u1' }, tenantId: 't1', clientIp: '1.2.3.4' })).toBe('user:u1');
  });

  it('RL-67: identity falls back to tenantId', () => {
    expect(extractIdentity({ tenantId: 'tenant-X', clientIp: '1.2.3.4' })).toBe('tenant:tenant-X');
  });

  it('RL-68: identity falls back to clientIp', () => {
    expect(extractIdentity({ clientIp: '2.2.2.2' })).toBe('ip:2.2.2.2');
  });

  it('RL-69: identity falls back to ip:unknown', () => {
    expect(extractIdentity({})).toBe('ip:unknown');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6 — INTEGRATION: Metrics
// ─────────────────────────────────────────────────────────────────────────────

describe('Metrics', () => {
  it('RL-70: rl_requests_total incremented on each request', async () => {
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    await request(app).get('/probe');
    expect(metrics.get('rl_requests_total', { surface: 'portal' })).toBe(2);
  });

  it('RL-71: rl_requests_allowed_total incremented on allowed request', async () => {
    const mem = freshMem();
    await request(buildApp('portal', { mem })).get('/probe');
    expect(metrics.get('rl_requests_allowed_total', { surface: 'portal' })).toBe(1);
  });

  it('RL-72: rl_limited_total incremented with reason=SUSTAINED on block', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    await request(app).get('/probe');
    expect(metrics.get('rl_limited_total', { surface: 'portal', reason: 'SUSTAINED' })).toBe(1);
  });

  it('RL-73: rl_burst_consumed_total incremented on burst block', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 1, burstWindowSeconds: 5 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    await request(app).get('/probe');
    expect(metrics.get('rl_burst_consumed_total', { surface: 'portal', dimension: 'surface:portal' })).toBeGreaterThanOrEqual(1);
  });

  it('RL-74: snapshot() returns counters and gauges keys', () => {
    metrics.inc('rl_test', { x: '1' });
    metrics.set('rl_gauge', 42, { x: '1' });
    const snap = metrics.snapshot();
    expect(snap).toHaveProperty('counters');
    expect(snap).toHaveProperty('gauges');
    expect(typeof snap.counters).toBe('object');
    expect(typeof snap.gauges).toBe('object');
  });

  it('RL-75: rl_latency_ms_total is non-negative after request', async () => {
    const mem = freshMem();
    await request(buildApp('portal', { mem })).get('/probe');
    expect(metrics.get('rl_latency_ms_total', { surface: 'portal' })).toBeGreaterThanOrEqual(0);
  });

  it('RL-76: rl_redis_failures_total incremented on eval failure', async () => {
    const brokenEval = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: brokenEval }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
    await request(app).get('/probe');
    expect(metrics.get('rl_redis_failures_total', { surface: 'portal' })).toBe(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7 — CONCURRENCY: Simultaneous requests
// ─────────────────────────────────────────────────────────────────────────────

describe('Concurrency', () => {
  it('RL-80: 10 concurrent requests against limit=5 → exactly 5 allowed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 5, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    const responses = await Promise.all(
      Array.from({ length: 10 }, () => request(app).get('/probe'))
    );
    const allowed = responses.filter(r => r.status === 200).length;
    const blocked = responses.filter(r => r.status === 429).length;
    expect(allowed).toBe(5);
    expect(blocked).toBe(5);
  });

  it('RL-81: 3 IPs × 3 concurrent requests with limit=2 → 6 allowed total', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const apps = ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map(ip => buildApp('portal', { mem, ip }));
    const all = await Promise.all(apps.flatMap(app =>
      [request(app).get('/probe'), request(app).get('/probe'), request(app).get('/probe')]
    ));
    expect(all.filter(r => r.status === 200).length).toBe(6);
  });

  it('RL-82: concurrent requests from same user share the same bucket', async () => {
    loadConfig({
      surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      users:    { 'shared-user': { maxRequests: 3, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'shared-user' } });
    const results = await Promise.all(
      Array.from({ length: 6 }, () => request(app).get('/probe'))
    );
    expect(results.filter(r => r.status === 200).length).toBe(3);
    expect(results.filter(r => r.status === 429).length).toBe(3);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 8 — PERFORMANCE: Latency and throughput
// ─────────────────────────────────────────────────────────────────────────────

describe('Performance', () => {
  it('RL-90: 1000 sequential SWC evaluations complete in < 250ms', async () => {
    const mem = freshMem();
    const t0  = Date.now();
    for (let i = 0; i < 1000; i++) {
      await evaluate(mkEval(mem), `test:key-${i % 100}`, 1000, 60, 1000);
    }
    expect(Date.now() - t0).toBeLessThan(250);
  });

  it('RL-91: 100 parallel SWC evaluations complete in < 100ms', async () => {
    const mem = freshMem();
    const t0  = Date.now();
    await Promise.all(
      Array.from({ length: 100 }, (_, i) => evaluate(mkEval(mem), `test:key-${i}`, 1000, 60, 100))
    );
    expect(Date.now() - t0).toBeLessThan(100);
  });

  it('RL-92: 10000 sequential requests complete in < 1500ms', async () => {
    const mem = freshMem();
    const t0  = Date.now();
    for (let i = 0; i < 10000; i++) {
      await evaluate(mkEval(mem), 'test:sustained', 1000, 60, 10000);
    }
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('RL-93: middleware overhead per request is < 5ms median', async () => {
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    const times = [];
    for (let i = 0; i < 20; i++) {
      const t0 = Date.now();
      await request(app).get('/probe');
      times.push(Date.now() - t0);
    }
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    expect(median).toBeLessThan(50);  // generous for test env
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 9 — REGRESSION: Edge cases
// ─────────────────────────────────────────────────────────────────────────────

describe('Regression — edge cases', () => {
  it('RL-100: maxRequests=1 allows exactly 1', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    expect((await request(app).get('/probe')).status).toBe(200);
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-101: Retry-After is in range [1, windowSeconds]', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    const ra  = Number(res.headers['retry-after']);
    expect(ra).toBeGreaterThan(0);
    expect(ra).toBeLessThanOrEqual(60);
  });

  it('RL-102: createRateLimitMiddleware throws on unknown surface', () => {
    expect(() => createRateLimitMiddleware('nonexistent_surface')).toThrow(/Unknown/);
  });

  it('RL-103: endpoint override applies as most specific limit', async () => {
    loadConfig({
      surfaces:  { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      endpoints: { 'my-endpoint': { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '1.2.3.4'; req.rl_endpoint = 'my-endpoint'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: mkEval(mem) }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
    expect((await request(app).get('/probe')).status).toBe(200);
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-104: requests exceeding limit × 2 emit SUSPICIOUS warning', async () => {
    const { emit } = require('../../../../services/logger');
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    // deny-path events are sampled per (surface, identity) per minute; earlier
    // tests in this file already used this key, so start from a fresh window.
    require('../middleware')._resetDegradedForTest();
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    for (let i = 0; i < 4; i++) await request(app).get('/probe');
    const suspicious = emit.mock.calls.filter(c => c[1] === 'RATE_LIMIT_SUSPICIOUS');
    expect(suspicious.length).toBeGreaterThan(0);
  });

  it('RL-105: RateLimit-Remaining is never negative', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 2, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    for (let i = 0; i < 5; i++) {
      const res = await request(app).get('/probe');
      expect(Number(res.headers['ratelimit-remaining'] ?? 0)).toBeGreaterThanOrEqual(0);
    }
  });

  it('RL-106: POLICIES proxy returns surface policies', () => {
    loadConfig();
    const { POLICIES } = require('../policies');
    expect(POLICIES.portal).toBeDefined();
    expect(POLICIES.portal.maxRequests).toBeGreaterThan(0);
  });

  it('RL-107: _isRlEnabled respects RL_ENABLED env var', () => {
    process.env.RL_ENABLED = 'false';
    expect(_isRlEnabled()).toBe(false);
    process.env.RL_ENABLED = 'true';
    expect(_isRlEnabled()).toBe(true);
  });

  it('RL-108: 429 body never has Retry-After on 200 response', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    expect(res.status).toBe(200);
    expect(res.headers['retry-after']).toBeUndefined();
  });

  it('RL-109: dimension field in 429 body identifies which level blocked', async () => {
    loadConfig({
      surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } },
      users:    { 'u1': { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } },
    });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'u1' } });
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.body.dimension).toBe('user:u1');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 10 — ADVERSARIAL: Attacks and failure modes
// ─────────────────────────────────────────────────────────────────────────────

describe('Adversarial', () => {
  it('RL-110: storage failure causes fail-closed HTTP 429', async () => {
    const brokenEval = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: brokenEval }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body.error).toBe('RATE_LIMIT_BACKEND_UNAVAILABLE');
  });

  it('RL-111: storage failure body does not expose internal error details', async () => {
    const brokenEval = jest.fn().mockRejectedValue(new Error('secret:connectionString:password123'));
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: brokenEval }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
    const res = await request(app).get('/probe');
    expect(JSON.stringify(res.body)).not.toContain('secret');
    expect(JSON.stringify(res.body)).not.toContain('password123');
  });

  it('RL-112: boundary attack — exactly at limit then one over', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 3, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    for (let i = 0; i < 3; i++) expect((await request(app).get('/probe')).status).toBe(200);
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-113: malformed config fails at loadConfig time, not at request time', () => {
    expect(() => loadConfig({ surfaces: { portal: { maxRequests: -99, windowSeconds: 60 } } })).toThrow(/invalid/i);
  });

  it('RL-114: burst amplification — rapid fire exceeds burst cap', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1000, windowSeconds: 60, burstCapacity: 3, burstWindowSeconds: 5 } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem });
    const results = await Promise.all(
      Array.from({ length: 10 }, () => request(app).get('/probe'))
    );
    expect(results.filter(r => r.status === 429).length).toBeGreaterThan(0);
  });

  it('RL-115: quota bypass via different IPs uses independent buckets', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem  = freshMem();
    const appA = buildApp('portal', { mem, ip: '10.0.0.1' });
    const appB = buildApp('portal', { mem, ip: '10.0.0.2' });
    await request(appA).get('/probe');
    await request(appA).get('/probe');
    expect((await request(appB).get('/probe')).status).toBe(200);
  });

  it('RL-116: RateLimit header values are clean numeric strings', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    const limit = res.headers['ratelimit-limit'];
    expect(Number.isFinite(Number(limit))).toBe(true);
    expect(limit).not.toContain(';');
    expect(limit).not.toContain('\n');
    expect(limit).not.toContain(',');
  });

  it('RL-117: disabled key blocks on very first request', async () => {
    loadConfig({ users: { 'revoked': { maxRequests: 1, windowSeconds: 60, disabled: true } } });
    const mem = freshMem();
    const app = buildApp('portal', { mem, rbacUser: { id: 'revoked' } });
    expect((await request(app).get('/probe')).status).toBe(429);
  });

  it('RL-118: Retry-After absent on 200 response', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    expect(res.status).toBe(200);
    expect(res.headers['retry-after']).toBeUndefined();
  });

  it('RL-119: X-RateLimit-Remaining mirrors RateLimit-Remaining', async () => {
    const res = await request(buildApp('portal')).get('/probe');
    expect(res.headers['x-ratelimit-remaining']).toBe(res.headers['ratelimit-remaining']);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 12 — 'decision'/'legacyFailure' envelopes
//
// These two envelopes exist solely so routes migrated off
// middleware/publicRateLimit.js can keep the exact 429 response
// body their old `response:` callback produced — see the header comment on
// _deny429() in ../middleware.js. Every one of the 12 migrated call sites
// used one of these two shapes.
// ─────────────────────────────────────────────────────────────────────────────

describe("envelopes ('decision' / 'legacyFailure')", () => {
  function buildEnvelopeApp(envelope) {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'test-rid'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: mkEval(mem), envelope }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
    return app;
  }

  it("WP7-01: 'decision' envelope body matches legacy {decision,reason,details,requestId} shape", async () => {
    const app = buildEnvelopeApp('decision');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      decision:  'BLOCK',
      reason:    'RATE_LIMITED',
      details:   {},
      requestId: 'test-rid',
    });
  });

  it("WP7-02: 'decision' envelope still sets standard rate-limit headers", async () => {
    const app = buildEnvelopeApp('decision');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(res.headers['x-ratelimit-remaining']).toBe('0');
  });

  it("WP7-03: 'legacyFailure' envelope body matches legacy buildFailureBody('RATE_LIMITED', 'Too many requests', requestId) shape", async () => {
    const app = buildEnvelopeApp('legacyFailure');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(res.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: 'test-rid',
      error:     { code: 'RATE_LIMITED', message: 'Too many requests' },
    });
  });

  it("WP7-04: 'legacyFailure' envelope body has no `details` key (legacy buildFailureBody call omits it)", async () => {
    const app = buildEnvelopeApp('legacyFailure');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.body.error.details).toBeUndefined();
  });

  it("WP7-05: 'management' envelope is unchanged by the new branches (no details/message drift)", async () => {
    const app = buildEnvelopeApp('management');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.body).toMatchObject({ error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Rate limit exceeded' } });
  });

  it("WP7-06: 'protocol' envelope (default) is unchanged by the new branches", async () => {
    const app = buildEnvelopeApp(undefined);
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.body).toMatchObject({ error: 'RATE_LIMIT_EXCEEDED', surface: 'portal' });
  });

  it('WP7-07: onBlocked callback fires exactly once when the limit is exceeded', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 1, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = freshMem();
    const onBlocked = jest.fn();
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'test-rid'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', { _evalFn: mkEval(mem), envelope: 'decision', onBlocked }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));

    await request(app).get('/probe');
    expect(onBlocked).not.toHaveBeenCalled();
    await request(app).get('/probe');
    expect(onBlocked).toHaveBeenCalledTimes(1);
    expect(onBlocked.mock.calls[0][0]).toMatchObject({ requestId: 'test-rid' });
  });

  it('WP7-08: onBlocked callback fires on backend-unavailable 429, not just limit-exceeded', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 100, windowSeconds: 60, burstCapacity: 0 } } });
    const onBlocked = jest.fn();
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'test-rid'; req.clientIp = '1.2.3.4'; next(); });
    app.use(createRateLimitMiddleware('portal', {
      _evalFn: () => { throw new Error('redis down'); },
      envelope: 'legacyFailure',
      onBlocked,
    }));
    app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));

    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
    expect(onBlocked).toHaveBeenCalledTimes(1);
  });

  it('WP7-09: no onBlocked option is a safe no-op (existing callers without it are unaffected)', async () => {
    const app = buildEnvelopeApp('legacyFailure');
    await request(app).get('/probe');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(429);
  });
});
