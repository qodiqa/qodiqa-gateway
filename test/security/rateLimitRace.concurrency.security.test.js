'use strict';

/**
 * Dedicated red-team regression coverage for the
 * rate-limit race condition.
 *
 * ── Root cause being guarded against ──────────────────────────────────────
 * An earlier review described the rate limiter as "check-then-act, not atomic —
 * bypassable under concurrency": a naive implementation reads the current
 * count, decides whether to allow the request, and only afterwards writes
 * the incremented count back. Under concurrent requests, N callers can all
 * read the same pre-increment count, all decide "allowed", and all write —
 * silently admitting far more than the configured limit.
 *
 * ── Current implementation (verified before writing these tests) ─────────
 * src/core/rateLimit/slidingWindow.js executes the read, increment, and
 * limit decision inside a SINGLE Redis Lua `EVAL` (SW_LUA) — there is no
 * separate read step for a second request to interleave with; Redis
 * executes each Lua script to completion before starting the next one.
 * src/core/rateLimit/storage.js's MemoryStorage mirrors this for
 * dev/test: `eval()` is declared `async` but its body contains no `await`,
 * so — because Node is single-threaded — the whole read+increment+decide
 * sequence for one call always finishes before the next queued call's body
 * starts running, even when many calls are kicked off together via
 * `Promise.all`. Existing coverage (src/core/rateLimit/__tests__/
 * rateLimit.test.js "Concurrency" describe block; test/
 * distributed-rate-limiting.test.js "Multi-instance key isolation") already
 * exercises Promise.all bursts against MemoryStorage and against an
 * injected mock evalFn returning pre-canned responses — but nothing in the
 * suite (a) hammers concurrency hard enough to be a meaningful stress test,
 * (b) proves this specific test methodology is actually capable of
 * detecting a reintroduced check-then-act race (a broken implementation
 * could coincidentally still pass a small/lucky concurrency test), or
 * (c) exercises the real Redis EVAL path at all — CI's "Concurrency Tests"
 * job (.github/workflows/test.yml) provisions a live Redis service
 * specifically for this, but no existing test file matching
 * `testPathPattern="concurrency"` ever connects to it for rate limiting.
 * This file closes all three gaps.
 *
 * ── Why these tests would fail if 2.2 came back ───────────────────────────
 * Section "Canary" below runs the exact same concurrency profile through a
 * deliberately non-atomic (read → await → write) storage implementation
 * and proves it DOES overshoot the limit — demonstrating the harness can
 * detect the vulnerability class at all. Every other section asserts, via
 * `allowed <= limit` (never `<=` by coincidence, checked to equality where
 * the math is exact) and `allowed + blocked === total`, that the real
 * implementation never exhibits that overshoot under the same load. If a
 * future refactor reintroduces a read-then-write gap (e.g. splits the Lua
 * EVAL into a GET + a separate SET, or awaits between MemoryStorage's read
 * and write), these assertions fail deterministically — no flaky timing
 * dependency, because the over-admission is a strict per-run count, not a
 * "sometimes reproduces" race.
 */

const express = require('express');
const request = require('supertest');

const { MemoryStorage, RedisStorage }               = require('../../src/core/rateLimit/storage');
const { evaluate }                                  = require('../../src/core/rateLimit/slidingWindow');
const { createRateLimitMiddleware, extractIdentity } = require('../../src/core/rateLimit/middleware');
const { loadConfig, _reset: resetRlConfig }          = require('../../src/core/rateLimit/config');
const metrics                                        = require('../../src/core/rateLimit/metrics');

// ── Test app builder ─────────────────────────────────────────────────────────
//
// Mirrors the real request pipeline: Express + createRateLimitMiddleware,
// not a bare call into the algorithm — so these tests exercise identity
// extraction, policy resolution, and header/response handling exactly as
// production traffic does, in addition to the storage layer's atomicity.

function buildApp(surface, evalFn, { ip = '9.9.9.9', rbacUser, tenantId, signingKeyId } = {}) {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'race-test';
    req.clientIp  = ip;
    if (rbacUser)     req.rbacUser     = rbacUser;
    if (tenantId)     req.tenantId     = tenantId;
    if (signingKeyId) req.signingKeyId = signingKeyId;
    next();
  });
  app.use(createRateLimitMiddleware(surface, { _evalFn: evalFn }));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

async function fireConcurrent(app, count) {
  const responses = await Promise.all(
    Array.from({ length: count }, () => request(app).get('/probe')),
  );
  return {
    allowed: responses.filter(r => r.status === 200).length,
    blocked: responses.filter(r => r.status === 429).length,
    total:   responses.length,
  };
}

beforeEach(() => {
  process.env.RL_ENABLED = 'true';
  resetRlConfig();
  metrics._reset();
});

afterEach(() => {
  delete process.env.RL_ENABLED;
  resetRlConfig();
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — Real algorithm + MemoryStorage under heavy Promise.all bursts
// ─────────────────────────────────────────────────────────────────────────────

describe('Rate-limit race: same identity, high concurrency (real MemoryStorage + real middleware)', () => {

  test('200 concurrent requests, identical client IP, limit=25 → exactly 25 allowed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 25, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = new MemoryStorage();
    const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { ip: '10.0.0.1' });

    const { allowed, blocked, total } = await fireConcurrent(app, 200);

    expect(allowed).toBe(25);
    expect(blocked).toBe(175);
    expect(allowed + blocked).toBe(total);
  });

  test('300 concurrent requests, identical API key (rbacUser.id), limit=40 → exactly 40 allowed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 40, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = new MemoryStorage();
    const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { rbacUser: { id: 'shared-api-key-user' } });

    const { allowed, blocked, total } = await fireConcurrent(app, 300);

    expect(allowed).toBe(40);
    expect(blocked).toBe(260);
    expect(allowed + blocked).toBe(total);
  });

  test('150 concurrent requests, identical tenant, limit=30 → exactly 30 allowed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 30, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = new MemoryStorage();
    const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { tenantId: 'shared-tenant' });

    const { allowed } = await fireConcurrent(app, 150);

    expect(allowed).toBe(30);
  });

  test('150 concurrent requests, identical signing key, limit=15 → exactly 15 allowed', async () => {
    loadConfig({ surfaces: { attestation: { maxRequests: 15, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = new MemoryStorage();
    const app = buildApp('attestation', (s, k, a) => mem.eval(s, k, a), { signingKeyId: 'shared-signing-key' });

    const { allowed } = await fireConcurrent(app, 150);

    expect(allowed).toBe(15);
  });

  test('burst-capacity dimension holds exactly under concurrency even when sustained limit is generous', async () => {
    // burstCapacity is the binding constraint here (10), not maxRequests (1000) —
    // proves the second (burst) Lua/Memory counter is equally atomic, not just
    // the sustained-window counter.
    loadConfig({ surfaces: { portal: { maxRequests: 1000, windowSeconds: 60, burstCapacity: 10, burstWindowSeconds: 5 } } });
    const mem = new MemoryStorage();
    const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { ip: '10.0.0.2' });

    const { allowed } = await fireConcurrent(app, 100);

    expect(allowed).toBe(10);
  });

  test('3 independent identities × 50 concurrent requests each, limit=10 → 30 allowed total, no cross-bucket bleed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 10, windowSeconds: 60, burstCapacity: 0 } } });
    const mem  = new MemoryStorage();
    const apps = ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map(ip =>
      buildApp('portal', (s, k, a) => mem.eval(s, k, a), { ip }));

    const results = await Promise.all(apps.map(app => fireConcurrent(app, 50)));

    for (const r of results) expect(r.allowed).toBe(10);
    expect(results.reduce((sum, r) => sum + r.allowed, 0)).toBe(30);
  });

  test('overlapping-window timing: many concurrent evaluate() calls sharing the exact same timestamp never overshoot', async () => {
    // Simulates the tightest possible race window — every caller believes
    // it is the same instant, so any check-then-act gap would be maximally
    // exploitable here.
    const mem  = new MemoryStorage();
    const now  = Math.floor(Date.now() / 1000);
    const evalFn = (s, k, a) => mem.eval(s, k, a);

    const results = await Promise.all(
      Array.from({ length: 120 }, () => evaluate(evalFn, 'rl:v2:race:boundary', now, 60, 20, 0, 5)),
    );

    const allowedCount = results.filter(r => r.allowed).length;
    expect(allowedCount).toBe(20);
    // Every result's own `count` field must be a distinct integer 1..120 —
    // a lost update under a real race would produce duplicate counts.
    const counts = results.map(r => r.count).sort((a, b) => a - b);
    expect(new Set(counts).size).toBe(120);
    expect(counts).toEqual(Array.from({ length: 120 }, (_, i) => i + 1));
  });

  test('repeated trials never exceed the limit (no flaky one-off pass)', async () => {
    // Runs the same concurrent-burst scenario several times over — a real
    // race would be expected to show up in at least one of these runs even
    // if it didn't in the very first (this is what makes a race regression
    // dangerous: it doesn't reproduce every time under a naive check).
    loadConfig({ surfaces: { portal: { maxRequests: 7, windowSeconds: 60, burstCapacity: 0 } } });
    for (let trial = 0; trial < 5; trial++) {
      const mem = new MemoryStorage();
      const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { ip: `10.1.0.${trial}` });
      const { allowed } = await fireConcurrent(app, 40);
      expect(allowed).toBe(7);
    }
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — Canary: proves this harness is actually capable of catching a
// check-then-act regression, using a deliberately non-atomic storage double.
// ─────────────────────────────────────────────────────────────────────────────

describe('Canary — harness sensitivity control (not testing production code)', () => {

  /**
   * A storage double that reproduces finding 2.2's exact bug: it reads the
   * current count, `await`s a macrotask (yielding to every other pending
   * request), and only then writes the incremented value back — a literal
   * check-then-act gap. This class is NEVER wired into production; it
   * exists solely to prove that if MemoryStorage/slidingWindow regressed to
   * this shape, the assertions above WOULD catch it (i.e. the tests aren't
   * silently vacuous).
   */
  class BrokenCheckThenActStorage {
    constructor() { this._counts = new Map(); }
    isReady() { return true; }
    async eval(_script, keys, args) {
      const key = keys[0];
      const max = Number(args[2]);
      const current = this._counts.get(key) || 0;           // ── READ
      await new Promise(resolve => setImmediate(resolve));   // ── window where a race can land
      const next = current + 1;                              // ── ACT (decide + write, using stale `current`)
      this._counts.set(key, next);
      const allowed = next <= max ? 1 : 0;
      return [next, 0, allowed, 1, 60, Math.max(0, max - next), 0, 0];
    }
  }

  test('control: the broken check-then-act double DOES overshoot under concurrency', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 10, windowSeconds: 60, burstCapacity: 0 } } });
    const broken = new BrokenCheckThenActStorage();
    const app = buildApp('portal', (s, k, a) => broken.eval(s, k, a), { ip: '10.2.0.1' });

    const { allowed } = await fireConcurrent(app, 100);

    // This is the vulnerability finding 2.2 described: many more than 10
    // requests get admitted because every request reads the pre-write count.
    expect(allowed).toBeGreaterThan(10);
  });

  test('contrast: the real MemoryStorage does NOT overshoot under the identical load profile', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 10, windowSeconds: 60, burstCapacity: 0 } } });
    const mem = new MemoryStorage();
    const app = buildApp('portal', (s, k, a) => mem.eval(s, k, a), { ip: '10.2.0.1' });

    const { allowed } = await fireConcurrent(app, 100);

    expect(allowed).toBe(10);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — Real Redis: the actual production atomic path (Lua EVAL)
// under genuine network-level concurrency. Skipped when no Redis is
// reachable (e.g. local dev without REDIS_URL) — always runs in CI's
// "Concurrency Tests" and "Security & Red Team Suite" jobs, both of which
// provision a live redis:7-alpine service (.github/workflows/test.yml).
// ─────────────────────────────────────────────────────────────────────────────

const REAL_REDIS = !!process.env.REDIS_URL;
const describeRedis = REAL_REDIS ? describe : describe.skip;

describeRedis('Rate-limit race: real Redis Lua EVAL under concurrency', () => {
  let redisStorage;

  beforeAll(async () => {
    redisStorage = new RedisStorage();
    await redisStorage.initialize();
  }, 15_000);

  afterAll(async () => {
    if (redisStorage) await redisStorage.disconnect();
  });

  beforeEach(() => {
    if (!redisStorage.isReady()) {
      throw new Error('REDIS_URL is set but Redis did not become ready — check the CI service container');
    }
  });

  function uniqueBaseKey(label) {
    // Unique per test run so parallel Jest workers / repeated runs never
    // collide on leftover keys from a previous run.
    return `rl:v2:race-test:${label}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  }

  test('200 concurrent EVALs against the same key, limit=50 → exactly 50 allowed', async () => {
    const baseKey = uniqueBaseKey('same-key');
    const now = Math.floor(Date.now() / 1000);
    const evalFn = (s, k, a) => redisStorage.eval(s, k, a);

    const results = await Promise.all(
      Array.from({ length: 200 }, () => evaluate(evalFn, baseKey, now, 60, 50, 0, 5)),
    );

    const allowedCount = results.filter(r => r.allowed).length;
    expect(allowedCount).toBe(50);
  }, 20_000);

  test('burst cap holds exactly under real Redis concurrency', async () => {
    const baseKey = uniqueBaseKey('burst');
    const now = Math.floor(Date.now() / 1000);
    const evalFn = (s, k, a) => redisStorage.eval(s, k, a);

    const results = await Promise.all(
      Array.from({ length: 80 }, () => evaluate(evalFn, baseKey, now, 60, 1000, 12, 5)),
    );

    const allowedCount = results.filter(r => r.allowed).length;
    expect(allowedCount).toBe(12);
  }, 20_000);

  test('independent keys under concurrent load never bleed into each other', async () => {
    const now = Math.floor(Date.now() / 1000);
    const evalFn = (s, k, a) => redisStorage.eval(s, k, a);
    const keyA = uniqueBaseKey('iso-a');
    const keyB = uniqueBaseKey('iso-b');

    const [resultsA, resultsB] = await Promise.all([
      Promise.all(Array.from({ length: 30 }, () => evaluate(evalFn, keyA, now, 60, 15, 0, 5))),
      Promise.all(Array.from({ length: 30 }, () => evaluate(evalFn, keyB, now, 60, 15, 0, 5))),
    ]);

    expect(resultsA.filter(r => r.allowed).length).toBe(15);
    expect(resultsB.filter(r => r.allowed).length).toBe(15);
  }, 20_000);

  test('full middleware + Express pipeline against real Redis: identical IP, limit=20 → exactly 20 allowed', async () => {
    loadConfig({ surfaces: { portal: { maxRequests: 20, windowSeconds: 60, burstCapacity: 0 } } });
    const app = buildApp('portal', (s, k, a) => redisStorage.eval(s, k, a), { ip: `10.9.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}` });

    const { allowed, blocked, total } = await fireConcurrent(app, 100);

    expect(allowed).toBe(20);
    expect(blocked).toBe(80);
    expect(allowed + blocked).toBe(total);
  }, 20_000);

});
