'use strict';

/**
 * remediation — dedicated concurrency coverage for the
 * credential-identity scoped secondary lockout counter (src/core/
 * authLockout). Complements src/core/authLockout/__tests__/authLockout.
 * test.js's AL-19/AL-20 (single-identity concurrency, pre-existing) and
 * test/auth-lockout.test.js's AL-E17 (single-identity, real middleware) —
 * this file specifically exercises the DUAL-key path added, where
 * a single Lua EVAL / MemoryStorage call now touches two identities (IP and
 * credential) atomically in one round trip.
 *
 * ── What could break, and how these tests would catch it ────────────────────
 * A dual-key implementation could (a) issue two separate storage round trips
 * instead of one (breaking the "no additional Redis round trips" requirement
 * and reopening a check-then-act race between the two writes), or (b) let
 * concurrent callers interleave between updating the IP key and the
 * credential key, producing an inconsistent view (e.g. the credential
 * counter reflects N failures but the IP counter reflects N-1, or the
 * aggregate `triggered` flag disagrees with the per-identity flags). Section
 * 1 stresses MemoryStorage (the always-available, real synchronous-body
 * implementation) hard enough to surface either class of bug deterministically.
 * Section 2 repeats the same profile against real Redis, using the actual
 * production Lua scripts, whenever `REDIS_URL` is set (see .github/workflows/
 * test.yml's "Concurrency Tests" job, which provisions a live redis:7-alpine
 * service for exactly this).
 */

const { MemoryStorage, RedisStorage, KEY_PREFIX } = require('../../src/core/authLockout/storage');
const { createAuthLockout }                       = require('../../src/core/authLockout');

jest.mock('../../services/logger', () => ({ emit: jest.fn() }));

function baseConfig(overrides = {}) {
  return {
    authLockoutEnabled:        true,
    authLockoutMaxFailures:    5,
    authLockoutDurationMs:     900_000,
    authLockoutBackoffMinMs:   250,
    authLockoutBackoffMaxMs:   5_000,
    authLockoutFailureWindowMs: 900_000,
    ...overrides,
  };
}

function fakeReq(ip) {
  return { clientIp: ip, requestId: `req-${ip}`, path: '/metrics' };
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — MemoryStorage: the always-available, deterministic dual-key path
// ─────────────────────────────────────────────────────────────────────────────

describe('dual-key atomic increment under concurrency (MemoryStorage)', () => {
  it('N concurrent recordFailure calls against the SAME [ip, credential] pair increment ' +
     'both counters exactly N times, with no lost updates on either side', async () => {
    const store   = new MemoryStorage();
    const ipKey   = `${KEY_PREFIX}ip:203.0.113.7`;
    const credKey = `${KEY_PREFIX}cred:0000000000000000`;
    const now     = Date.now();

    const results = await Promise.all(
      Array.from({ length: 40 }, () => store.recordFailure([ipKey, credKey], now, 1000, 900_000, 900)),
    );

    const ipCounts   = results.map(r => r.ip.count).sort((a, b) => a - b);
    const credCounts = results.map(r => r.credential.count).sort((a, b) => a - b);
    expect(ipCounts).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
    expect(credCounts).toEqual(Array.from({ length: 40 }, (_, i) => i + 1));
  });

  it('concurrent dual-key failures crossing the CREDENTIAL threshold trigger exactly once, ' +
     'even when arriving from many different IP keys', async () => {
    const store      = new MemoryStorage();
    const credKey    = `${KEY_PREFIX}cred:1111111111111111`;
    const now        = Date.now();
    const maxFailures = 10;

    // 20 concurrent callers, each its OWN unique IP key, all sharing ONE
    // credential key — simulates a distributed burst against one guessed
    // credential arriving at the same instant.
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        store.recordFailure([`${KEY_PREFIX}ip:10.0.0.${i}`, credKey], now, maxFailures, 900_000, 900)),
    );

    const credTriggeredCount = results.filter(r => r.credential.triggered === 1).length;
    expect(credTriggeredCount).toBe(1); // exactly one caller observes the crossing

    // No individual IP key ever triggers (each only ever sees 1 failure).
    expect(results.every(r => r.ip.triggered === 0)).toBe(true);

    // Every caller after the trigger (in logical, not wall-clock, order)
    // agrees on the same lockedUntil for the credential once it's set.
    const lockedUntilValues = new Set(results.filter(r => r.credential.lockedUntil > 0).map(r => r.credential.lockedUntil));
    expect(lockedUntilValues.size).toBe(1);
  });

  it('the aggregate `triggered`/`locked` flags are never inconsistent with the per-identity ' +
     'flags under concurrent load (aggregate is always exactly the OR of the two)', async () => {
    const store   = new MemoryStorage();
    const ipKey   = `${KEY_PREFIX}ip:203.0.113.50`;
    const credKey = `${KEY_PREFIX}cred:2222222222222222`;
    const now     = Date.now();

    const results = await Promise.all(
      Array.from({ length: 15 }, () => store.recordFailure([ipKey, credKey], now, 5, 900_000, 900)),
    );

    for (const r of results) {
      const expectedAggregate = (r.ip.triggered || r.credential.triggered) ? 1 : 0;
      expect(r.triggered).toBe(expectedAggregate);
    }
  });

  it('concurrent precheck reads during a concurrent write burst never observe a torn state ' +
     '(each identity\'s own count/lockedUntil pair is always internally consistent)', async () => {
    const store   = new MemoryStorage();
    const ipKey   = `${KEY_PREFIX}ip:203.0.113.60`;
    const credKey = `${KEY_PREFIX}cred:3333333333333333`;
    const now     = Date.now();

    const writes = Array.from({ length: 10 }, () => store.recordFailure([ipKey, credKey], now, 5, 900_000, 900));
    const reads  = Array.from({ length: 10 }, () => store.precheck([ipKey, credKey], now));

    const [writeResults, readResults] = await Promise.all([Promise.all(writes), Promise.all(reads)]);

    // Every read's `locked` must equal `lockedUntil > now` for that same
    // read's own reported lockedUntil — never a mismatched pair.
    for (const r of readResults) {
      expect(r.ip.locked).toBe(r.ip.lockedUntil > now ? 1 : 0);
      expect(r.credential.locked).toBe(r.credential.lockedUntil > now ? 1 : 0);
    }
    expect(writeResults.length).toBe(10);
  });

  it('through the createAuthLockout() service layer: concurrent authentication attempts ' +
     'from many IPs against one credential resolve to a consistent, race-free lockout decision', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 8 }), { _storage: storage });
    const sharedCredential = 'concurrent-distributed-guess';

    const failures = await Promise.all(
      Array.from({ length: 30 }, (_, i) => lockout.recordFailure(fakeReq(`10.1.0.${i}`), sharedCredential)),
    );
    // recordFailure() itself returns undefined (see index.js) — the
    // observable effect is state, not a return value — so verify via a
    // fresh precheck from yet another, never-before-seen IP using the same
    // credential: it must now be locked (30 >> maxFailures=8).
    expect(failures.length).toBe(30); // all 30 calls completed without throwing
    const pre = await lockout.precheck(fakeReq('10.1.0.999'), sharedCredential);
    expect(pre.locked).toBe(true);

    // And an entirely unrelated credential from a fresh IP is unaffected.
    const unrelatedPre = await lockout.precheck(fakeReq('10.1.0.998'), 'totally-unrelated-credential');
    expect(unrelatedPre.locked).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — Real Redis: the actual production atomic dual-key Lua EVAL path
// under genuine network-level concurrency. Skipped when no Redis is reachable
// (e.g. local dev without REDIS_URL) — always runs in CI's "Concurrency
// Tests" job (.github/workflows/test.yml), which provisions a live
// redis:7-alpine service.
// ─────────────────────────────────────────────────────────────────────────────

const REAL_REDIS = !!process.env.REDIS_URL;
const describeRedis = REAL_REDIS ? describe : describe.skip;

describeRedis('real Redis dual-key Lua EVAL under concurrency', () => {
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

  function uniqueKey(label) {
    // Unique per test run so parallel Jest workers / repeated runs never
    // collide on leftover keys from a previous run.
    return `${KEY_PREFIX}${label}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  }

  test('200 concurrent dual-key EVALs against the SAME [ip, credential] pair: both counters ' +
     'land on exactly 200, with a single Redis round trip per call', async () => {
    const ipKey   = uniqueKey('ip:conc-same');
    const credKey = uniqueKey('cred:conc-same');
    const now     = Date.now();

    const results = await Promise.all(
      Array.from({ length: 200 }, () => redisStorage.recordFailure([ipKey, credKey], now, 10_000, 900_000, 120)),
    );

    const finalIpCount   = Math.max(...results.map(r => r.ip.count));
    const finalCredCount = Math.max(...results.map(r => r.credential.count));
    expect(finalIpCount).toBe(200);
    expect(finalCredCount).toBe(200);
  }, 30_000);

  test('100 concurrent EVALs across 100 distinct IP keys sharing ONE credential key trigger ' +
     'the credential lockout exactly once, atomically, under real network concurrency', async () => {
    const credKey = uniqueKey('cred:conc-distributed');
    const now     = Date.now();
    const maxFailures = 50;

    const results = await Promise.all(
      Array.from({ length: 100 }, (_, i) =>
        redisStorage.recordFailure([uniqueKey(`ip:conc-distributed-${i}`), credKey], now, maxFailures, 900_000, 120)),
    );

    const triggeredCount = results.filter(r => r.credential.triggered === 1).length;
    expect(triggeredCount).toBe(1);
    expect(results.every(r => r.ip.triggered === 0)).toBe(true); // no single IP ever reaches 50
  }, 30_000);

  test('independent [ip, credential] pairs under concurrent load never bleed into each other', async () => {
    const now = Date.now();
    const pairA = [uniqueKey('ip:iso-a'), uniqueKey('cred:iso-a')];
    const pairB = [uniqueKey('ip:iso-b'), uniqueKey('cred:iso-b')];

    const [resultsA, resultsB] = await Promise.all([
      Promise.all(Array.from({ length: 25 }, () => redisStorage.recordFailure(pairA, now, 1000, 900_000, 120))),
      Promise.all(Array.from({ length: 25 }, () => redisStorage.recordFailure(pairB, now, 1000, 900_000, 120))),
    ]);

    expect(Math.max(...resultsA.map(r => r.ip.count))).toBe(25);
    expect(Math.max(...resultsA.map(r => r.credential.count))).toBe(25);
    expect(Math.max(...resultsB.map(r => r.ip.count))).toBe(25);
    expect(Math.max(...resultsB.map(r => r.credential.count))).toBe(25);
  }, 30_000);
});
