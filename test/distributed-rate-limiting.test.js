'use strict';

/**
 * Component #12 — Distributed Rate Limiting (Redis-backed)
 *
 * DRL-01   Normal request (below limit) → passes through
 * DRL-02   Request at exactly the limit → passes through (limit is inclusive)
 * DRL-03   Request exceeding limit → HTTP 429 RATE_LIMIT_EXCEEDED
 * DRL-04   HTTP 429 includes required response fields: error, surface, retryAfterSeconds
 * DRL-05   X-RateLimit-Limit header is set on every response
 * DRL-06   X-RateLimit-Remaining header counts down correctly
 * DRL-07   X-RateLimit-Reset header is set on every response (future Unix timestamp)
 * DRL-08   Retry-After header is set on 429 responses only
 * DRL-09   Redis failure (not ready) → fail-closed → HTTP 429 RATE_LIMIT_BACKEND_UNAVAILABLE
 * DRL-10   Redis throw mid-request → fail-closed → HTTP 429
 * DRL-11   Window reset: counter returns to 0 after simulated TTL expiry
 * DRL-12   Multiple tenants are rate-limited independently (separate buckets)
 * DRL-13   Multiple surfaces are rate-limited independently (separate buckets)
 * DRL-14   IP-based identity used when no authenticated identity is available
 * DRL-15   rbacUser.id identity takes priority over IP
 * DRL-16   tenantId identity takes priority over IP (but not over rbacUser)
 * DRL-17   Unknown IP ('unknown') shares one bucket (fail-secure)
 * DRL-18   RL_ENABLED=false → passthrough (no Redis calls, no 429)
 * DRL-19 RL_ENABLED not set + no REDIS_URL → limiter ON
 * DRL-20   RL_ENABLED=true + Redis unavailable → fail-closed on a failMode='closed' surface;
 * DRL-20b … → per-process fallback on a failMode='degrade' surface
 * DRL-21   Portal surface uses correct policy (100 req/min default)
 * DRL-22   Attestation surface uses correct policy (50 req/min default)
 * DRL-23   Certification surface uses correct policy (20 req/min default)
 * DRL-24   Transparency surface uses correct policy (60 req/min default)
 * DRL-25   Each request calls evalFn exactly once (atomic Lua operation)
 * DRL-26   MemoryStorage.eval returns correct 8-element SWC array shape
 * DRL-27   MemoryStorage.isReady() always returns true
 * DRL-28   Unknown surface throws on policy lookup
 * DRL-29   Metrics: rl_requests_total incremented on each request
 * DRL-30   Metrics: rl_limited_total incremented when 429 is returned
 * DRL-31   Metrics: rl_redis_failures_total incremented on Redis failure
 * DRL-32   Attestation public surface: end-to-end middleware integration
 * DRL-33   Certification public surface: end-to-end middleware integration
 * DRL-34   Transparency public surface: end-to-end middleware integration
 * DRL-35   Portal public surface: end-to-end middleware integration
 */

'use strict';

const request  = require('supertest');
const express  = require('express');

// ── Modules under test ────────────────────────────────────────────────────────

const { MemoryStorage }                                              = require('../src/core/rateLimit/storage');
const { createRateLimitMiddleware, extractIdentity, _isRlEnabled }  = require('../src/core/rateLimit/middleware');
const { POLICIES, getPolicy, KNOWN_SURFACES }                       = require('../src/core/rateLimit/policies');
const metrics                                                        = require('../src/core/rateLimit/metrics');

// ── Test helpers ──────────────────────────────────────────────────────────────

/**
 * Build a minimal Express app with the rate limit middleware mounted on /.
 * Every handler responds with 200 { ok: true }.
 */
function makeApp(surface, options = {}) {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    req.clientIp  = options.ip  ?? '1.2.3.4';
    if (options.rbacUser)  req.rbacUser  = options.rbacUser;
    if (options.tenantId)  req.tenantId  = options.tenantId;
    next();
  });
  app.use(createRateLimitMiddleware(surface, { _evalFn: options._evalFn }));
  app.get('/',  (_req, res) => res.json({ ok: true }));
  app.post('/', (_req, res) => res.json({ ok: true }));
  return app;
}

/**
 * Build an injectable evalFn that returns controlled SWC arrays.
 * responses is an array of SWC arrays (8-element) or Error instances.
 *
 * SWC array: [curr, prev, swAllowed, burstAllowed, resetIn, remaining, burstCount, burstRem]
 */
function makeEval(responses) {
  return jest.fn(async (_script, _keys, _args) => {
    const resp = responses.shift();
    if (!resp) throw new Error('No more mock responses');
    if (resp instanceof Error) throw resp;
    return resp;
  });
}

/** SWC array for an allowed response */
function allowed(count, limit, ttl = 59) {
  return [count, 0, 1, 1, ttl, Math.max(0, limit - count), 0, 0];
}
/** SWC array for a blocked (sustained limit exceeded) response */
function blocked(count, _limit, ttl = 30) {
  return [count, 0, 0, 1, ttl, 0, 0, 0];
}

// ── Before/after ──────────────────────────────────────────────────────────────

const _origRedisUrl  = process.env.REDIS_URL;
const _origRlEnabled = process.env.RL_ENABLED;

beforeEach(() => {
  metrics._reset();
  // Ensure passthrough mode during tests (no REDIS_URL by default)
  delete process.env.REDIS_URL;
  delete process.env.RL_ENABLED;
});

afterEach(() => {
  // Restore original env
  if (_origRedisUrl  !== undefined) process.env.REDIS_URL  = _origRedisUrl;
  else delete process.env.REDIS_URL;
  if (_origRlEnabled !== undefined) process.env.RL_ENABLED = _origRlEnabled;
  else delete process.env.RL_ENABLED;
});

// ── DRL-25…DRL-27: MemoryStorage unit tests ──────────────────────────────────

describe('MemoryStorage', () => {

  test('DRL-26 eval returns 8-element SWC array with correct shape', async () => {
    const mem = new MemoryStorage();
    const now = Math.floor(Date.now() / 1000);
    const result = await mem.eval('', ['rl:v2:surface:portal:ip:1.2.3.4'], [
      String(now), '60', '10', '0', '5',
    ]);
    expect(Array.isArray(result)).toBe(true);
    expect(result).toHaveLength(8);
    const [curr, prev, swAllowed, burstAllowed, resetIn, remaining, burstCount, burstRem] = result;
    expect(curr).toBe(1);
    expect(prev).toBeGreaterThanOrEqual(0);
    expect(swAllowed).toBe(1);
    expect(burstAllowed).toBe(1);
    expect(resetIn).toBeGreaterThan(0);
    expect(remaining).toBeGreaterThanOrEqual(0);
    expect(burstCount).toBe(0);  // burst disabled
    expect(burstRem).toBe(0);
  });

  test('DRL-27 MemoryStorage.isReady() always returns true', () => {
    const mem = new MemoryStorage();
    expect(mem.isReady()).toBe(true);
  });

  test('DRL-25 evalFn is called exactly once per request (atomic operation)', async () => {
    process.env.RL_ENABLED = 'true';
    const _evalFn = makeEval([allowed(1, 100), allowed(2, 100)]);
    const app = makeApp('portal', { _evalFn });
    await request(app).get('/').expect(200);
    await request(app).get('/').expect(200);
    // One call per request (one policy dimension: surface)
    expect(_evalFn).toHaveBeenCalledTimes(2);
  });

  test('MemoryStorage.eval blocks when count exceeds maxRequests', async () => {
    const mem = new MemoryStorage();
    const now = Math.floor(Date.now() / 1000);
    const args = [String(now), '60', '3', '0', '5'];
    for (let i = 0; i < 3; i++) {
      await mem.eval('', ['rl:test:key'], args);
    }
    const result = await mem.eval('', ['rl:test:key'], args);
    expect(result[2]).toBe(0);  // swAllowed=0
    expect(result[5]).toBe(0);  // remaining=0
  });

  test('MemoryStorage._reset() clears all state', async () => {
    const mem = new MemoryStorage();
    const now = Math.floor(Date.now() / 1000);
    await mem.eval('', ['rl:test:key'], [String(now), '60', '5', '0', '5']);
    mem._reset();
    const result = await mem.eval('', ['rl:test:key'], [String(now), '60', '5', '0', '5']);
    expect(result[0]).toBe(1);  // reset to 1 after clear
  });

});

// ── DRL-28: Policy validation ─────────────────────────────────────────────────

describe('Policy', () => {

  test('DRL-28 unknown surface throws on getPolicy', () => {
    expect(() => getPolicy('nonexistent_surface')).toThrow('Unknown rate limit surface');
  });

  // (D2 → Moderate): public reads 120/min per IP.
  test('DRL-21 portal policy defaults to 120 req/min', () => {
    expect(POLICIES.portal.maxRequests).toBe(120);
    expect(POLICIES.portal.windowSeconds).toBe(60);
  });

  test('DRL-22 attestation policy defaults to 120 req/min', () => {
    expect(POLICIES.attestation.maxRequests).toBe(120);
  });

  test('DRL-23 certification policy defaults to 120 req/min (evaluate has its own 20/min bucket)', () => {
    expect(POLICIES.certification.maxRequests).toBe(120);
    expect(POLICIES.certification_evaluate.maxRequests).toBe(20);
  });

  test('DRL-24 transparency policy defaults to 120 req/min', () => {
    expect(POLICIES.transparency.maxRequests).toBe(120);
  });

  test('all 8 surfaces are defined in KNOWN_SURFACES', () => {
    const expected = ['portal', 'attestation', 'certification', 'transparency',
                      'portal_admin', 'attestation_admin', 'certification_admin', 'transparency_admin'];
    for (const s of expected) expect(KNOWN_SURFACES.has(s)).toBe(true);
  });

});

// ── DRL-18…DRL-20: Mode detection ─────────────────────────────────────────────

describe('Mode detection', () => {

  test('DRL-18 RL_ENABLED=false → passthrough (no evalFn called)', async () => {
    process.env.RL_ENABLED = 'false';
    const _evalFn = jest.fn();
    const app = makeApp('portal', { _evalFn });
    await request(app).get('/').expect(200);
    expect(_evalFn).not.toHaveBeenCalled();
  });

  // inverted — the limiter no longer depends on REDIS_URL. With no
  // REDIS_URL and no RL_ENABLED it is ON: every request is evaluated.
  test('DRL-19 no REDIS_URL and no RL_ENABLED → limiter ON (evalFn called)', async () => {
    // env already cleared in beforeEach
    const _evalFn = makeEval([allowed(1, 120)]);
    const app = makeApp('portal', { _evalFn });
    await request(app).get('/').expect(200);
    expect(_evalFn).toHaveBeenCalledTimes(1);
  });

  // (D3 → C): 'sign' is a failMode='closed' surface — still 429 when Redis is down.
  test('DRL-20 RL_ENABLED=true + Redis unavailable → fail-closed (429) on a closed surface', async () => {
    process.env.RL_ENABLED = 'true';
    // No _evalFn injected — middleware uses prodStorage which is not connected
    const app = makeApp('sign', {});
    const res = await request(app).get('/').expect(429);
    expect(res.body.error).toBe('RATE_LIMIT_BACKEND_UNAVAILABLE');
  });

  // (D3 → C): 'portal' is failMode='degrade' — the SAME policy runs on the
  // per-process fallback: allowed under the limit, 429 over it, degraded flag set.
  test('DRL-20b RL_ENABLED=true + Redis unavailable → per-process fallback on a degrade surface', async () => {
    process.env.RL_ENABLED = 'true';
    const rl = require('../src/core/rateLimit');
    rl._resetDegradedForTest();
    rl.loadConfig({ surfaces: { portal: { maxRequests: 2, windowSeconds: 60, failMode: 'degrade' } } });
    try {
      const app = makeApp('portal', {});
      await request(app).get('/').expect(200);
      await request(app).get('/').expect(200);
      const res = await request(app).get('/').expect(429);
      expect(res.body.error).toBe('RATE_LIMIT_EXCEEDED');
      expect(rl._isDegraded('portal')).toBe(true);
    } finally {
      rl.loadConfig();
      rl._resetDegradedForTest();
    }
  });

});

// ── DRL-01…DRL-08: Normal operation ──────────────────────────────────────────

describe('Normal operation (RL_ENABLED=true via injection)', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-01 request below limit passes through', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100)]) });
    await request(app).get('/').expect(200);
  });

  test('DRL-02 request at exactly the limit passes through', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(100, 100)]) });
    await request(app).get('/').expect(200);
  });

  test('DRL-03 request exceeding limit → 429', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([blocked(101, 100)]) });
    await request(app).get('/').expect(429);
  });

  test('DRL-04 429 body includes error, surface, retryAfterSeconds', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([blocked(101, 100, 45)]) });
    const res = await request(app).get('/').expect(429);
    expect(res.body.error).toBe('RATE_LIMIT_EXCEEDED');
    expect(res.body.surface).toBe('portal');
    expect(typeof res.body.retryAfterSeconds).toBe('number');
    expect(res.body.retryAfterSeconds).toBe(45);
  });

  test('DRL-05 X-RateLimit-Limit header set on allowed response', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-limit']).toBe('120');
  });

  test('DRL-06 X-RateLimit-Remaining decrements correctly', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(42, 100)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-remaining']).toBe('58');  // 100 - 42
  });

  test('DRL-06 X-RateLimit-Remaining is 0 (not negative) when over limit', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([blocked(105, 100, 30)]) });
    const res = await request(app).get('/').expect(429);
    expect(res.headers['x-ratelimit-remaining']).toBe('0');
  });

  test('DRL-07 X-RateLimit-Reset header is a future Unix timestamp', async () => {
    const before = Math.floor(Date.now() / 1000);
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100, 59)]) });
    const res = await request(app).get('/').expect(200);
    const reset = parseInt(res.headers['x-ratelimit-reset'], 10);
    expect(reset).toBeGreaterThanOrEqual(before + 59);
    expect(reset).toBeLessThanOrEqual(before + 65);  // small tolerance
  });

  test('DRL-08 Retry-After set on 429 responses', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([blocked(101, 100, 45)]) });
    const res = await request(app).get('/').expect(429);
    expect(res.headers['retry-after']).toBe('45');
  });

  test('DRL-08 Retry-After NOT set on 200 responses', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['retry-after']).toBeUndefined();
  });

});

// ── DRL-09…DRL-10: Fail-closed behavior ──────────────────────────────────────

describe('Fail-closed behavior', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-09 Redis not ready → 429 RATE_LIMIT_BACKEND_UNAVAILABLE', async () => {
    const failEval = jest.fn().mockRejectedValue(new Error('Redis not ready — fail-closed'));
    const app = makeApp('attestation', { _evalFn: failEval });
    const res = await request(app).get('/').expect(429);
    expect(res.body.error).toBe('RATE_LIMIT_BACKEND_UNAVAILABLE');
    expect(res.body.surface).toBe('attestation');
    expect(typeof res.body.retryAfterSeconds).toBe('number');
  });

  test('DRL-10 Redis throws mid-request → 429 (fail-closed)', async () => {
    const failEval = jest.fn().mockRejectedValue(new Error('ECONNRESET'));
    const app = makeApp('transparency', { _evalFn: failEval });
    const res = await request(app).get('/').expect(429);
    expect(res.body.error).toBe('RATE_LIMIT_BACKEND_UNAVAILABLE');
  });

  test('fail-closed 429 body does not expose internal error details', async () => {
    const failEval = jest.fn().mockRejectedValue(new Error('internal connection string with secrets'));
    const app = makeApp('portal', { _evalFn: failEval });
    const res = await request(app).get('/').expect(429);
    // Error message must not bleed into HTTP response body
    expect(JSON.stringify(res.body)).not.toContain('internal connection string with secrets');
  });

});

// ── DRL-11: Window reset ──────────────────────────────────────────────────────

describe('Window reset', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-11 counter resets after window expiry (TTL → new window)', async () => {
    // Simulates: first window full, second window starts fresh
    const responses = [
      blocked(101, 100, 5),   // window 1: over limit
      allowed(1,   100, 60),  // window 2: TTL expired, counter reset to 1
    ];
    const _evalFn = makeEval(responses);
    const app = makeApp('portal', { _evalFn });

    const res1 = await request(app).get('/').expect(429);
    expect(res1.body.error).toBe('RATE_LIMIT_EXCEEDED');

    const res2 = await request(app).get('/').expect(200);
    expect(res2.headers['x-ratelimit-remaining']).toBe('99');
  });

});

// ── DRL-12…DRL-17: Identity extraction ───────────────────────────────────────

describe('Identity extraction', () => {

  test('DRL-14 IP-based identity used when no auth', () => {
    const req = { clientIp: '10.0.0.1' };
    expect(extractIdentity(req)).toBe('ip:10.0.0.1');
  });

  test('DRL-15 rbacUser.id takes priority over IP', () => {
    const req = { clientIp: '10.0.0.1', rbacUser: { id: 'user-abc' } };
    expect(extractIdentity(req)).toBe('user:user-abc');
  });

  test('DRL-16 tenantId takes priority over IP (but not rbacUser)', () => {
    const req = { clientIp: '10.0.0.1', tenantId: 'tenant-xyz' };
    expect(extractIdentity(req)).toBe('tenant:tenant-xyz');
  });

  test('DRL-16 rbacUser takes priority over tenantId', () => {
    const req = { clientIp: '10.0.0.1', tenantId: 'tenant-xyz', rbacUser: { id: 'user-abc' } };
    expect(extractIdentity(req)).toBe('user:user-abc');
  });

  test('DRL-17 no IP → unknown bucket', () => {
    const req = {};
    expect(extractIdentity(req)).toBe('ip:unknown');
  });

  test('DRL-12 two different IPs use independent evalFn keys', async () => {
    process.env.RL_ENABLED = 'true';
    const _evalFn = jest.fn()
      .mockResolvedValueOnce(allowed(1, 100))   // IP A
      .mockResolvedValueOnce(allowed(1, 100));  // IP B

    // App A: IP 1.1.1.1
    const appA = makeApp('portal', { _evalFn, ip: '1.1.1.1' });
    await request(appA).get('/').expect(200);

    // App B: IP 2.2.2.2
    const appB = makeApp('portal', { _evalFn, ip: '2.2.2.2' });
    await request(appB).get('/').expect(200);

    // Both calls had different base keys (keys[0] in evalFn call)
    const keys = _evalFn.mock.calls.map(c => c[1][0]);
    expect(keys[0]).not.toBe(keys[1]);
    expect(keys[0]).toContain('1.1.1.1');
    expect(keys[1]).toContain('2.2.2.2');
  });

  test('DRL-12 different tenants get separate buckets', async () => {
    process.env.RL_ENABLED = 'true';
    const _evalFn = jest.fn()
      .mockResolvedValueOnce(allowed(1, 100))
      .mockResolvedValueOnce(allowed(1, 100));

    const appA = makeApp('portal', { _evalFn, tenantId: 'tenant-A' });
    const appB = makeApp('portal', { _evalFn, tenantId: 'tenant-B' });

    await request(appA).get('/').expect(200);
    await request(appB).get('/').expect(200);

    const keys = _evalFn.mock.calls.map(c => c[1][0]);
    expect(keys[0]).toContain('tenant-A');
    expect(keys[1]).toContain('tenant-B');
    expect(keys[0]).not.toBe(keys[1]);
  });

});

// ── DRL-13: Surface isolation ─────────────────────────────────────────────────

describe('Surface isolation', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-13 portal and attestation use different Redis keys', async () => {
    const _evalFn = jest.fn()
      .mockResolvedValueOnce(allowed(1, 100))
      .mockResolvedValueOnce(allowed(1, 50));

    const portalApp = makeApp('portal', { _evalFn });
    const attApp    = makeApp('attestation', { _evalFn });

    await request(portalApp).get('/').expect(200);
    await request(attApp).get('/').expect(200);

    const keys = _evalFn.mock.calls.map(c => c[1][0]);
    expect(keys[0]).toContain('portal');
    expect(keys[1]).toContain('attestation');
    expect(keys[0]).not.toBe(keys[1]);
  });

});

// ── DRL-29…DRL-31: Metrics ────────────────────────────────────────────────────

describe('Metrics', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-29 rl_requests_total incremented on each request', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100), allowed(2, 100)]) });
    await request(app).get('/').expect(200);
    await request(app).get('/').expect(200);
    expect(metrics.get('rl_requests_total', { surface: 'portal' })).toBeGreaterThanOrEqual(2);
  });

  test('DRL-30 rl_limited_total incremented on 429', async () => {
    const before = metrics.get('rl_limited_total', { surface: 'portal', reason: 'SUSTAINED' });
    const app = makeApp('portal', { _evalFn: makeEval([blocked(101, 100)]) });
    await request(app).get('/').expect(429);
    expect(metrics.get('rl_limited_total', { surface: 'portal', reason: 'SUSTAINED' })).toBe(before + 1);
  });

  test('DRL-31 rl_redis_failures_total incremented on Redis error', async () => {
    const before = metrics.get('rl_redis_failures_total', { surface: 'portal' });
    const failEval = jest.fn().mockRejectedValue(new Error('Redis down'));
    const app = makeApp('portal', { _evalFn: failEval });
    await request(app).get('/').expect(429);
    expect(metrics.get('rl_redis_failures_total', { surface: 'portal' })).toBe(before + 1);
  });

});

// ── DRL-32…DRL-35: Surface-specific end-to-end ───────────────────────────────

describe('Per-surface end-to-end middleware integration', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-32 attestation: 200 on first request, correct limit header', async () => {
    const app = makeApp('attestation', { _evalFn: makeEval([allowed(1, 50)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-limit']).toBe('120');
  });

  test('DRL-33 certification: 200 on first request, correct limit header', async () => {
    const app = makeApp('certification', { _evalFn: makeEval([allowed(1, 20)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-limit']).toBe('120');
  });

  test('DRL-34 transparency: 200 on first request, correct limit header', async () => {
    const app = makeApp('transparency', { _evalFn: makeEval([allowed(1, 60)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-limit']).toBe('120');
  });

  test('DRL-35 portal: 200 on first request, correct limit header', async () => {
    const app = makeApp('portal', { _evalFn: makeEval([allowed(1, 100)]) });
    const res = await request(app).get('/').expect(200);
    expect(res.headers['x-ratelimit-limit']).toBe('120');
  });

  test('attestation 429 on exceeded limit with correct surface label', async () => {
    const app = makeApp('attestation', { _evalFn: makeEval([blocked(51, 50, 30)]) });
    const res = await request(app).post('/').expect(429);
    expect(res.body.surface).toBe('attestation');
    expect(res.body.error).toBe('RATE_LIMIT_EXCEEDED');
  });

  test('certification 429 on exceeded limit with correct surface label', async () => {
    const app = makeApp('certification', { _evalFn: makeEval([blocked(21, 20, 30)]) });
    const res = await request(app).post('/').expect(429);
    expect(res.body.surface).toBe('certification');
  });

  test('transparency 429 on exceeded limit with correct surface label', async () => {
    const app = makeApp('transparency', { _evalFn: makeEval([blocked(61, 60, 30)]) });
    const res = await request(app).get('/').expect(429);
    expect(res.body.surface).toBe('transparency');
  });

});

// ── Redis instance isolation (DRL-instance test) ──────────────────────────────

describe('Multi-instance key isolation', () => {

  test('DRL-12 requests from different IPs use different Redis keys regardless of surface', async () => {
    process.env.RL_ENABLED = 'true';
    const keys = [];
    const _evalFn = jest.fn(async (_script, evalKeys) => {
      keys.push(evalKeys[0]);
      return allowed(1, 100);
    });

    const app1 = makeApp('portal', { _evalFn, ip: '10.0.0.1' });
    const app2 = makeApp('portal', { _evalFn, ip: '10.0.0.2' });
    const app3 = makeApp('portal', { _evalFn, ip: '10.0.0.3' });

    await Promise.all([
      request(app1).get('/').expect(200),
      request(app2).get('/').expect(200),
      request(app3).get('/').expect(200),
    ]);

    const uniqueKeys = new Set(keys);
    expect(uniqueKeys.size).toBe(3);
  });

});

// ── Redis restart simulation ──────────────────────────────────────────────────

describe('Redis restart / recovery', () => {

  beforeEach(() => { process.env.RL_ENABLED = 'true'; });

  test('DRL-06 (Redis restart) after recovery, requests proceed normally', async () => {
    let redisDown = true;
    const _evalFn = jest.fn(async () => {
      if (redisDown) throw new Error('Redis not ready');
      return allowed(1, 100);
    });

    const app = makeApp('portal', { _evalFn });

    // Before recovery: fail-closed
    const res1 = await request(app).get('/').expect(429);
    expect(res1.body.error).toBe('RATE_LIMIT_BACKEND_UNAVAILABLE');

    // Simulate Redis recovering
    redisDown = false;

    // After recovery: requests pass
    await request(app).get('/').expect(200);
  });

});
