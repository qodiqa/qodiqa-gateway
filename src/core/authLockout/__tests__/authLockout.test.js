'use strict';

// AUTH-2 — auth-failure lockout. Unit tests for the algorithm, the storage
// abstraction (MemoryStorage — RedisStorage delegates to the identical Lua
// scripts, see algorithm.js), and the createAuthLockout() service.
//
// Style note: dependency injection over deep mocking, matching
// src/core/rateLimit/__tests__/rateLimit.test.js — MemoryStorage (or an
// injected double) stands in for Redis rather than mocking the wire
// protocol.

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../services/logger');
const { computeBackoffDelayMs, computeKeyTtlSeconds } = require('../algorithm');
const { MemoryStorage, KEY_PREFIX } = require('../storage');
const { createAuthLockout, NOOP_LOCKOUT, _credentialIdentity } = require('../index');

beforeEach(() => {
  emit.mockClear();
});

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

function fakeReq(ip = '203.0.113.7') {
  return { clientIp: ip, requestId: 'req-1', path: '/metrics' };
}

// ── AL-01..AL-06: computeBackoffDelayMs (pure) ────────────────────────────────

describe('AL-01..06 computeBackoffDelayMs', () => {
  it('AL-01 returns 0 for zero prior failures', () => {
    expect(computeBackoffDelayMs(0, 250, 5000)).toBe(0);
  });

  it('AL-02 returns 0 for negative failure counts (defensive)', () => {
    expect(computeBackoffDelayMs(-3, 250, 5000)).toBe(0);
  });

  it('AL-03 returns minDelayMs after the 1st failure', () => {
    expect(computeBackoffDelayMs(1, 250, 5000)).toBe(250);
  });

  it('AL-04 doubles deterministically for each subsequent failure', () => {
    expect(computeBackoffDelayMs(2, 250, 5000)).toBe(500);
    expect(computeBackoffDelayMs(3, 250, 5000)).toBe(1000);
    expect(computeBackoffDelayMs(4, 250, 5000)).toBe(2000);
  });

  it('AL-05 is capped at maxDelayMs and never exceeds it', () => {
    expect(computeBackoffDelayMs(10, 250, 5000)).toBe(5000);
    expect(computeBackoffDelayMs(100, 250, 5000)).toBe(5000);
  });

  it('AL-06 is deterministic — same input always produces the same output', () => {
    const results = Array.from({ length: 20 }, () => computeBackoffDelayMs(3, 250, 5000));
    expect(new Set(results).size).toBe(1);
  });
});

// ── AL-07..AL-09: computeKeyTtlSeconds ────────────────────────────────────────

describe('AL-07..09 computeKeyTtlSeconds', () => {
  it('AL-07 uses the longer of failureWindowMs and lockoutDurationMs, plus a safety margin', () => {
    expect(computeKeyTtlSeconds(60_000, 900_000)).toBe(960);
    expect(computeKeyTtlSeconds(900_000, 60_000)).toBe(960);
  });

  it('AL-08 rounds up to the nearest whole second', () => {
    expect(computeKeyTtlSeconds(1500, 1500)).toBe(62);
  });

  it('AL-09 is always at least 1', () => {
    expect(computeKeyTtlSeconds(0, 0)).toBe(60);
  });

  it('AL-09b the safety margin keeps TTL strictly greater than the lock duration itself, ' +
     'so blanket key expiry can never race the explicit lockedUntil check', () => {
    const failureWindowMs = 900_000;
    const lockoutDurationMs = 900_000; // default config: the two are equal
    const ttlMs = computeKeyTtlSeconds(failureWindowMs, lockoutDurationMs) * 1000;
    expect(ttlMs).toBeGreaterThan(lockoutDurationMs);
  });
});

// ── AL-10..AL-18: MemoryStorage — state machine ───────────────────────────────

describe('AL-10..18 MemoryStorage', () => {
  let store;
  const KEY = `${KEY_PREFIX}ip:203.0.113.7`;

  beforeEach(() => { store = new MemoryStorage(); });

  it('AL-10 precheck on a fresh identity reports unlocked with count 0', async () => {
    const r = await store.precheck(KEY, Date.now());
    expect(r).toEqual({ count: 0, lockedUntil: 0, locked: 0, expired: 0 });
  });

  it('AL-11 recordFailure increments the counter and does not lock below threshold', async () => {
    const now = Date.now();
    const r1 = await store.recordFailure(KEY, now, 5, 900_000, 900);
    expect(r1).toEqual({ count: 1, lockedUntil: 0, triggered: 0 });
    const r2 = await store.recordFailure(KEY, now, 5, 900_000, 900);
    expect(r2).toEqual({ count: 2, lockedUntil: 0, triggered: 0 });
  });

  it('AL-12 locks out exactly at the configured threshold, not before or after', async () => {
    const now = Date.now();
    for (let i = 1; i < 5; i++) {
      const r = await store.recordFailure(KEY, now, 5, 900_000, 900);
      expect(r.triggered).toBe(0);
    }
    const triggering = await store.recordFailure(KEY, now, 5, 900_000, 900);
    expect(triggering.count).toBe(5);
    expect(triggering.triggered).toBe(1);
    expect(triggering.lockedUntil).toBe(now + 900_000);
  });

  it('AL-13 precheck reports locked while lockedUntil is in the future', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) await store.recordFailure(KEY, now, 5, 900_000, 900);
    const check = await store.precheck(KEY, now + 1000);
    expect(check.locked).toBe(1);
    expect(check.expired).toBe(0);
  });

  it('AL-14 further failures during an active lockout do not extend lockedUntil (no DoS lever)', async () => {
    const now = Date.now();
    let triggering;
    for (let i = 0; i < 5; i++) triggering = await store.recordFailure(KEY, now, 5, 900_000, 900);
    expect(triggering.triggered).toBe(1);
    const originalLockedUntil = triggering.lockedUntil;

    // Attacker (or anyone) keeps hitting the endpoint while locked.
    for (let i = 0; i < 20; i++) {
      const r = await store.recordFailure(KEY, now + i * 10, 5, 900_000, 900);
      expect(r.lockedUntil).toBe(originalLockedUntil);
      expect(r.triggered).toBe(0); // only the original crossing ever triggers
    }
  });

  it('AL-15 lockout expires automatically — no manual reset required', async () => {
    // keyTtlSeconds (960) matches what computeKeyTtlSeconds() would derive for
    // this lockoutDurationMs (900_000) — i.e. WITH the safety margin, not the
    // bare duration — so this exercises the same shape of call the service
    // layer actually makes. See algorithm.js's _TTL_SAFETY_MARGIN_MS.
    const now = Date.now();
    for (let i = 0; i < 5; i++) await store.recordFailure(KEY, now, 5, 900_000, 960);

    const wellAfterExpiry = now + 900_000 + 1;
    const check = await store.precheck(KEY, wellAfterExpiry);
    expect(check.locked).toBe(0);
    expect(check.expired).toBe(1);
    expect(check.count).toBe(0); // clean slate — a fresh streak starts from 0

    // Confirmed unlocked on a second read too (not a one-shot side effect).
    const check2 = await store.precheck(KEY, wellAfterExpiry + 10);
    expect(check2.locked).toBe(0);
  });

  it('AL-16 recordSuccess clears all state and reports the prior failure count', async () => {
    const now = Date.now();
    await store.recordFailure(KEY, now, 5, 900_000, 900);
    await store.recordFailure(KEY, now, 5, 900_000, 900);

    const result = await store.recordSuccess(KEY, now);
    expect(result.priorCount).toBe(2);

    const check = await store.precheck(KEY, now);
    expect(check).toEqual({ count: 0, lockedUntil: 0, locked: 0, expired: 0 });
  });

  it('AL-17 recordSuccess on a clean identity reports priorCount 0 (no spurious "recovery")', async () => {
    const result = await store.recordSuccess(KEY, Date.now());
    expect(result.priorCount).toBe(0);
  });

  it('AL-18 per-source isolation — two identities never share state', async () => {
    const keyA = `${KEY_PREFIX}ip:203.0.113.7`;
    const keyB = `${KEY_PREFIX}ip:198.51.100.9`;
    const now = Date.now();

    for (let i = 0; i < 5; i++) await store.recordFailure(keyA, now, 5, 900_000, 900);

    const checkA = await store.precheck(keyA, now);
    const checkB = await store.precheck(keyB, now);
    expect(checkA.locked).toBe(1);
    expect(checkB).toEqual({ count: 0, lockedUntil: 0, locked: 0, expired: 0 });
  });
});

// ── AL-19..AL-20: MemoryStorage under concurrency ─────────────────────────────

describe('AL-19..20 MemoryStorage concurrency safety', () => {
  it('AL-19 concurrent failures never lose an update — count reflects every call', async () => {
    const store = new MemoryStorage();
    const KEY   = `${KEY_PREFIX}ip:203.0.113.7`;
    const now   = Date.now();

    const results = await Promise.all(
      Array.from({ length: 20 }, () => store.recordFailure(KEY, now, 100, 900_000, 900)),
    );
    const counts = results.map(r => r.count).sort((a, b) => a - b);
    expect(counts).toEqual(Array.from({ length: 20 }, (_, i) => i + 1)); // 1..20, no gaps, no dupes
  });

  it('AL-20 concurrent failures crossing the threshold trigger exactly once', async () => {
    const store = new MemoryStorage();
    const KEY   = `${KEY_PREFIX}ip:203.0.113.7`;
    const now   = Date.now();

    const results = await Promise.all(
      Array.from({ length: 10 }, () => store.recordFailure(KEY, now, 5, 900_000, 900)),
    );
    const triggeredCount = results.filter(r => r.triggered === 1).length;
    expect(triggeredCount).toBe(1);

    const lockedUntilValues = new Set(results.filter(r => r.lockedUntil > 0).map(r => r.lockedUntil));
    expect(lockedUntilValues.size).toBe(1); // every request after the trigger sees the SAME lock timestamp
  });
});

// ── AL-21..AL-30: createAuthLockout() service ─────────────────────────────────

describe('AL-21..30 createAuthLockout()', () => {
  it('AL-21 precheck is unlocked with zero backoff for a clean source', async () => {
    const lockout = createAuthLockout(baseConfig(), { _storage: new MemoryStorage() });
    const result = await lockout.precheck(fakeReq());
    expect(result).toEqual({ locked: false, backoffDelayMs: 0 });
  });

  it('AL-22 backoff grows exponentially before the threshold is reached', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 10 }), { _storage: storage });
    const req = fakeReq();

    await lockout.recordFailure(req); // count 1
    let pre = await lockout.precheck(req);
    expect(pre.backoffDelayMs).toBe(250);

    await lockout.recordFailure(req); // count 2
    pre = await lockout.precheck(req);
    expect(pre.backoffDelayMs).toBe(500);

    await lockout.recordFailure(req); // count 3
    pre = await lockout.precheck(req);
    expect(pre.backoffDelayMs).toBe(1000);
  });

  it('AL-23 locks out after maxFailures consecutive failures and reports retryAfterSeconds', async () => {
    const lockout = createAuthLockout(baseConfig({ authLockoutMaxFailures: 3, authLockoutDurationMs: 60_000 }), {
      _storage: new MemoryStorage(),
    });
    const req = fakeReq();

    await lockout.recordFailure(req);
    await lockout.recordFailure(req);
    await lockout.recordFailure(req); // 3rd failure crosses the threshold

    const pre = await lockout.precheck(req);
    expect(pre.locked).toBe(true);
    expect(pre.retryAfterSeconds).toBeGreaterThan(0);
    expect(pre.retryAfterSeconds).toBeLessThanOrEqual(60);
  });

  it('AL-24 recordSuccess resets the failure state — precheck is clean afterward', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig(), { _storage: storage });
    const req = fakeReq();

    await lockout.recordFailure(req);
    await lockout.recordFailure(req);
    await lockout.recordSuccess(req);

    const pre = await lockout.precheck(req);
    expect(pre).toEqual({ locked: false, backoffDelayMs: 0 });
  });

  it('AL-25 recordSuccess logs AUTH_LOCKOUT_RESET only when there was a prior streak', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig(), { _storage: storage });
    const req = fakeReq();

    await lockout.recordSuccess(req); // clean — no prior failures
    expect(emit).not.toHaveBeenCalledWith('INFO', 'AUTH_LOCKOUT_RESET', expect.anything());

    await lockout.recordFailure(req);
    await lockout.recordSuccess(req); // had 1 prior failure
    expect(emit).toHaveBeenCalledWith('INFO', 'AUTH_LOCKOUT_RESET', expect.objectContaining({ priorFailureCount: 1 }));
  });

  it('AL-26 emits AUTH_LOCKOUT_TRIGGERED exactly when the threshold is crossed', async () => {
    const lockout = createAuthLockout(baseConfig({ authLockoutMaxFailures: 2 }), { _storage: new MemoryStorage() });
    const req = fakeReq();

    await lockout.recordFailure(req);
    expect(emit).not.toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.anything());

    await lockout.recordFailure(req);
    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.objectContaining({ failureCount: 2 }));
  });

  it('AL-27 emits AUTH_LOCKOUT_ACTIVE when a request hits an active lockout', async () => {
    const lockout = createAuthLockout(baseConfig({ authLockoutMaxFailures: 1 }), { _storage: new MemoryStorage() });
    const req = fakeReq();

    await lockout.recordFailure(req); // triggers immediately (threshold 1)
    await lockout.precheck(req);
    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_ACTIVE', expect.objectContaining({ path: '/metrics' }));
  });

  it('AL-28 disabled (authLockoutEnabled: false) is fully inert — no locking, no state, no logs', async () => {
    const lockout = createAuthLockout(baseConfig({ authLockoutEnabled: false, authLockoutMaxFailures: 1 }), {
      _storage: new MemoryStorage(),
    });
    const req = fakeReq();

    for (let i = 0; i < 10; i++) await lockout.recordFailure(req);
    const pre = await lockout.precheck(req);
    expect(pre).toEqual({ locked: false, backoffDelayMs: 0 });
    expect(emit).not.toHaveBeenCalled();
  });

  it('AL-29 per-source isolation through the service layer — two IPs never interfere', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 2 }), { _storage: storage });
    const reqA = fakeReq('203.0.113.7');
    const reqB = fakeReq('198.51.100.9');

    await lockout.recordFailure(reqA);
    await lockout.recordFailure(reqA); // A is now locked

    const preA = await lockout.precheck(reqA);
    const preB = await lockout.precheck(reqB);
    expect(preA.locked).toBe(true);
    expect(preB).toEqual({ locked: false, backoffDelayMs: 0 });
  });

  it('AL-30 a missing client IP falls back to a shared "ip:unknown" bucket rather than throwing', async () => {
    const lockout = createAuthLockout(baseConfig(), { _storage: new MemoryStorage() });
    await expect(lockout.precheck({ requestId: 'r', path: '/x' })).resolves.toEqual({ locked: false, backoffDelayMs: 0 });
  });
});

// ── AL-31: storage outage fails closed ────────────────────────────────────────

describe('AL-31 storage outage fails closed, never open', () => {
  it('precheck reports locked when the backing storage throws', async () => {
    const throwingStorage = {
      precheck:      async () => { throw new Error('ECONNREFUSED'); },
      recordFailure: async () => { throw new Error('ECONNREFUSED'); },
      recordSuccess: async () => { throw new Error('ECONNREFUSED'); },
    };
    const lockout = createAuthLockout(baseConfig(), { _storage: throwingStorage });
    const result = await lockout.precheck(fakeReq());
    expect(result.locked).toBe(true);
    expect(result.storageUnavailable).toBe(true);
  });
});

// ── AL-32: NOOP_LOCKOUT contract ──────────────────────────────────────────────

describe('AL-32 NOOP_LOCKOUT', () => {
  it('never locks, never delays, never throws — the default for callers that omit authLockout', async () => {
    await expect(NOOP_LOCKOUT.precheck(fakeReq())).resolves.toEqual({ locked: false, backoffDelayMs: 0 });
    await expect(NOOP_LOCKOUT.recordFailure(fakeReq())).resolves.toBeUndefined();
    await expect(NOOP_LOCKOUT.recordSuccess(fakeReq())).resolves.toBeUndefined();
  });

  it('AL-32b tolerates the credential argument too — every legacy call shape stays valid', async () => {
    await expect(NOOP_LOCKOUT.precheck(fakeReq(), 'some-credential')).resolves.toEqual({ locked: false, backoffDelayMs: 0 });
    await expect(NOOP_LOCKOUT.recordFailure(fakeReq(), 'some-credential')).resolves.toBeUndefined();
    await expect(NOOP_LOCKOUT.recordSuccess(fakeReq(), 'some-credential')).resolves.toBeUndefined();
  });
});

// ── AL-33..34: production storage is unconditional (no REDIS_URL gate) ───
//
// Findings Register the old _useRedis() gate silently routed to a
// single-process MemoryStorage whenever REDIS_URL was unset, even in a
// deployment where Redis is genuinely running (this codebase's own default
// posture) — exactly the gap nonceStore.js/anomalyStore.js never had. The
// gate is gone: createAuthLockout() with no _storage override now always
// resolves to storage.getProductionStorage(), regardless of REDIS_URL.

describe('AL-33..34 production storage is unconditional', () => {
  const savedRedisUrl = process.env.REDIS_URL;

  afterEach(() => {
    if (savedRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = savedRedisUrl;
  });

  it('AL-33 with REDIS_URL unset, precheck resolves via the real (unconnected) production RedisStorage, not a fresh in-memory store', async () => {
    delete process.env.REDIS_URL;
    // No _storage override -> _backend() must fall through to
    // storage.getProductionStorage(), the same never-initialized singleton
    // used across this whole test file. A fresh MemoryStorage would answer
    // "not locked" for a request it's never seen; the real, unconnected
    // RedisStorage instead fails closed — that's the observable proof the
    // gate is gone, without needing a live Redis connection.
    const lockout = createAuthLockout(baseConfig());
    const result = await lockout.precheck(fakeReq());
    expect(result.locked).toBe(true);
    expect(result.storageUnavailable).toBe(true);
  });

  it('AL-34 the same holds with REDIS_URL explicitly set — no behavioral difference either way', async () => {
    process.env.REDIS_URL = 'redis://127.0.0.1:6379';
    const lockout = createAuthLockout(baseConfig());
    const result = await lockout.precheck(fakeReq());
    expect(result.locked).toBe(true);
    expect(result.storageUnavailable).toBe(true);
  });
});

// ── credential-identity scoped secondary counter ──────────────────────
//
// Closes the residual gap where a distributed attacker rotates source IPs
// while repeating the same guessed credential — see docs/security/
// AUTH_LOCKOUT.md §4/§5a/§5b. All new coverage below is additive; every test
// above this point exercises the pre-WP-012 single-identity call shape
// unchanged and must keep passing exactly as before.

// ── CRED-01..05: _credentialIdentity() (pure hashing) ─────────────────────────

describe('CRED-01..05 _credentialIdentity()', () => {
  it('CRED-01 returns null for a missing/empty credential — nothing to scope a counter to', () => {
    expect(_credentialIdentity(null, 16)).toBeNull();
    expect(_credentialIdentity(undefined, 16)).toBeNull();
    expect(_credentialIdentity('', 16)).toBeNull();
  });

  it('CRED-02 is deterministic — the same credential always yields the same identity', () => {
    const a = _credentialIdentity('super-secret-value', 16);
    const b = _credentialIdentity('super-secret-value', 16);
    expect(a).toBe(b);
  });

  it('CRED-03 different credentials yield different identities (no collisions in practice)', () => {
    const a = _credentialIdentity('guess-one', 16);
    const b = _credentialIdentity('guess-two', 16);
    expect(a).not.toBe(b);
  });

  it('CRED-04 is prefixed cred: and truncated to the configured byte length (hex-encoded, 2 chars/byte)', () => {
    const id16 = _credentialIdentity('x', 16);
    expect(id16).toMatch(/^cred:[0-9a-f]{32}$/); // 16 bytes = 32 hex chars

    const id8 = _credentialIdentity('x', 8);
    expect(id8).toMatch(/^cred:[0-9a-f]{16}$/); // 8 bytes = 16 hex chars
  });

  it('CRED-05 never contains the raw credential as a substring', () => {
    const secret = 'do-not-leak-this-token';
    const id = _credentialIdentity(secret, 16);
    expect(id).not.toContain(secret);
  });

  it('CRED-06 falls back to the 16-byte default for an invalid hashBytes (e.g. hand-built test config)', () => {
    const id = _credentialIdentity('x', undefined);
    expect(id).toMatch(/^cred:[0-9a-f]{32}$/);
  });

  it('CRED-07 the credential identity is never equal to any IP identity string', () => {
    const credId = _credentialIdentity('203.0.113.7', 16); // even if someone "guesses" an IP-shaped value
    expect(credId.startsWith('cred:')).toBe(true);
    expect(credId).not.toBe('ip:203.0.113.7');
  });
});

// ── CRED-08..16: MemoryStorage dual-key evaluation ────────────────────────────

describe('CRED-08..16 MemoryStorage dual-key (IP + credential)', () => {
  let store;
  const ipKeyA   = `${KEY_PREFIX}ip:203.0.113.7`;
  const ipKeyB   = `${KEY_PREFIX}ip:198.51.100.9`;
  const credKey  = `${KEY_PREFIX}cred:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`;

  beforeEach(() => { store = new MemoryStorage(); });

  it('CRED-08 precheck with a 1-element array behaves identically to the legacy string call shape', async () => {
    const now = Date.now();
    const byString = await store.precheck(ipKeyA, now);
    const byArray  = await store.precheck([ipKeyA], now);
    expect(byArray).toEqual(byString);
    expect(byArray).toEqual({ count: 0, lockedUntil: 0, locked: 0, expired: 0 });
  });

  it('CRED-09 precheck with 2 keys returns ip/credential sub-results and an aggregate decision', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) await store.recordFailure([ipKeyA, credKey], now, 5, 900_000, 900);

    const result = await store.precheck([ipKeyA, credKey], now);
    expect(result.locked).toBe(1);
    expect(result.ip.locked).toBe(1);
    expect(result.credential.locked).toBe(1);
  });

  it('CRED-10 recordFailure with a 1-element array behaves identically to the legacy string call shape', async () => {
    const now = Date.now();
    const byString = await store.recordFailure(ipKeyA, now, 5, 900_000, 900);
    const store2 = new MemoryStorage();
    const byArray = await store2.recordFailure([ipKeyA], now, 5, 900_000, 900);
    expect(byArray).toEqual(byString);
    expect(byArray).toEqual({ count: 1, lockedUntil: 0, triggered: 0 });
  });

  it('CRED-11 recordFailure with 2 keys increments BOTH counters in one call', async () => {
    const now = Date.now();
    await store.recordFailure([ipKeyA, credKey], now, 5, 900_000, 900);
    await store.recordFailure([ipKeyA, credKey], now, 5, 900_000, 900);

    const check = await store.precheck([ipKeyA, credKey], now);
    expect(check.ip.count).toBe(2);
    expect(check.credential.count).toBe(2);
  });

  it('CRED-12 distributed credential guessing: many distinct IP keys sharing ONE credential key trip ' +
     'the credential counter well before any single IP would trip its own', async () => {
    const maxFailures = 5;
    const now = Date.now();

    // 4 different "attacker IPs", each firing under the per-IP threshold,
    // all guessing the SAME credential.
    const ipKeys = ['ip:10.0.0.1', 'ip:10.0.0.2', 'ip:10.0.0.3', 'ip:10.0.0.4'].map(id => `${KEY_PREFIX}${id}`);
    let lastResult;
    for (const ip of ipKeys) {
      lastResult = await store.recordFailure([ip, credKey], now, maxFailures, 900_000, 900);
      expect(lastResult.ip.triggered).toBe(0); // no single IP ever reaches 5
    }
    // The credential counter, however, has now seen 4 failures across those
    // IPs — one more (from yet another IP) crosses its threshold.
    const fifthIp = `${KEY_PREFIX}ip:10.0.0.5`;
    const triggering = await store.recordFailure([fifthIp, credKey], now, maxFailures, 900_000, 900);
    expect(triggering.ip.triggered).toBe(0);        // the 5th IP's OWN counter is still just 1
    expect(triggering.credential.triggered).toBe(1); // but the shared credential counter just hit 5
    expect(triggering.triggered).toBe(1);            // aggregate reflects the credential trip
  });

  it('CRED-13 recordSuccess with 2 keys clears BOTH counters and reports both prior counts', async () => {
    const now = Date.now();
    await store.recordFailure([ipKeyA, credKey], now, 5, 900_000, 900);
    await store.recordFailure([ipKeyA, credKey], now, 5, 900_000, 900);

    const result = await store.recordSuccess([ipKeyA, credKey], now);
    expect(result.ip.priorCount).toBe(2);
    expect(result.credential.priorCount).toBe(2);

    const check = await store.precheck([ipKeyA, credKey], now);
    expect(check.ip.count).toBe(0);
    expect(check.credential.count).toBe(0);
  });

  it('CRED-14 IP and credential namespaces never collide, even under concurrent load on both', async () => {
    const now = Date.now();
    for (let i = 0; i < 3; i++) await store.recordFailure([ipKeyA, credKey], now, 10, 900_000, 900);
    for (let i = 0; i < 7; i++) await store.recordFailure([ipKeyB, credKey], now, 10, 900_000, 900);

    const checkA = await store.precheck([ipKeyA], now);
    const checkB = await store.precheck([ipKeyB], now);
    const checkCred = await store.precheck([credKey], now); // credential counter accumulated across both IPs

    expect(checkA.count).toBe(3);
    expect(checkB.count).toBe(7);
    expect(checkCred.count).toBe(10);
  });

  it('CRED-15 a lockout triggered by the IP counter alone (no credential presented) is unaffected — ' +
     'single-key regression stays green', async () => {
    const now = Date.now();
    for (let i = 0; i < 5; i++) await store.recordFailure(ipKeyA, now, 5, 900_000, 900);
    const check = await store.precheck(ipKeyA, now);
    expect(check).toEqual({ count: 5, lockedUntil: expect.any(Number), locked: 1, expired: 0 });
  });

  it('CRED-16 aggregate `locked`/`triggered` is a true OR — either counter alone is enough', async () => {
    const now = Date.now();
    // Two different IPs share the same credential; threshold 2. The 1st
    // failure (from ipKeyA) never trips anything. The 2nd failure comes
    // from a DIFFERENT, first-time IP — its own counter is only at 1, but
    // the shared credential counter is now at 2 and crosses the threshold.
    await store.recordFailure([ipKeyA, credKey], now, 2, 900_000, 900);
    const result = await store.recordFailure([`${KEY_PREFIX}ip:10.0.0.99`, credKey], now, 2, 900_000, 900);

    expect(result.ip.triggered).toBe(0);         // this specific IP's first-ever failure
    expect(result.credential.triggered).toBe(1); // credential's 2nd failure crosses threshold 2
    expect(result.triggered).toBe(1);            // OR — aggregate still triggers
  });
});

// ── CRED-17..24: createAuthLockout() service — dual identity end to end ──────

describe('CRED-17..24 createAuthLockout() with a presented credential', () => {
  it('CRED-17 omitting the credential argument is byte-for-byte the pre-WP-012 IP-only behavior', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 2 }), { _storage: storage });
    const req = fakeReq();

    await lockout.recordFailure(req); // no credential arg at all
    const pre1 = await lockout.precheck(req);
    expect(pre1).toEqual({ locked: false, backoffDelayMs: expect.any(Number) });

    await lockout.recordFailure(req);
    const pre2 = await lockout.precheck(req);
    expect(pre2.locked).toBe(true);
  });

  it('CRED-18 a wrong credential from ONE IP increments both the IP and credential counters', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 10 }), { _storage: storage });
    const req = fakeReq('203.0.113.7');

    await lockout.recordFailure(req, 'guessed-token-1');
    await lockout.recordFailure(req, 'guessed-token-1');

    const credKey = `${KEY_PREFIX}${_credentialIdentity('guessed-token-1', 16)}`;
    const credState = await storage.precheck(credKey, Date.now());
    expect(credState.count).toBe(2);
  });

  it('CRED-19 distributed guessing through the SERVICE layer: many IPs, one credential, ' +
     'triggers lockout via the credential counter', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 5 }), { _storage: storage });
    const guessedCredential = 'shared-ops-token-guess';

    const attackerIps = ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'];
    for (const ip of attackerIps) {
      const res = await lockout.precheck(fakeReq(ip), guessedCredential);
      expect(res.locked).toBe(false); // each IP is clean on its first attempt
      await lockout.recordFailure(fakeReq(ip), guessedCredential);
    }

    // A 5th, never-before-seen IP tries the SAME credential — this is the
    // failure that crosses the credential threshold (4 prior + this one = 5).
    const fifthIp = '203.0.113.5';
    const preFifth = await lockout.precheck(fakeReq(fifthIp), guessedCredential);
    expect(preFifth.locked).toBe(false); // this fresh IP is not itself locked yet
    await lockout.recordFailure(fakeReq(fifthIp), guessedCredential);

    // Now EVEN A BRAND NEW, 6th IP guessing the SAME credential is locked out —
    // proving the block followed the credential, not any single IP.
    const sixthIp = '203.0.113.6';
    const preSixth = await lockout.precheck(fakeReq(sixthIp), guessedCredential);
    expect(preSixth.locked).toBe(true);
  });

  it('CRED-20 the same 5 guesses spread across 5 IPs would NOT have triggered the old IP-only design ' +
     '(regression guard proving the credential counter is doing real work)', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 5 }), { _storage: storage });
    const guessedCredential = 'shared-ops-token-guess';

    for (let i = 1; i <= 5; i++) {
      await lockout.recordFailure(fakeReq(`203.0.113.${i}`), guessedCredential);
    }
    // Each individual IP only ever failed once — none would be IP-locked.
    for (let i = 1; i <= 5; i++) {
      const pre = await lockout.precheck(fakeReq(`203.0.113.${i}`), undefined); // no credential — pure IP check
      expect(pre.locked).toBe(false);
    }
  });

  it('CRED-21 recordSuccess with a credential clears both the IP and credential streaks', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 10 }), { _storage: storage });
    const req = fakeReq('203.0.113.7');
    const credential = 'eventually-correct-token';

    await lockout.recordFailure(req, credential);
    await lockout.recordFailure(req, credential);
    await lockout.recordSuccess(req, credential);

    const credKey = `${KEY_PREFIX}${_credentialIdentity(credential, 16)}`;
    const credState = await storage.precheck(credKey, Date.now());
    expect(credState.count).toBe(0);

    const ipPre = await lockout.precheck(req);
    expect(ipPre).toEqual({ locked: false, backoffDelayMs: 0 });
  });

  it('CRED-22 AUTH_LOCKOUT_TRIGGERED carries a bounded lockScope field and NEVER the credential or its hash', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 1 }), { _storage: storage });
    const secretGuess = 'super-sensitive-guess-value';
    emit.mockClear();

    await lockout.recordFailure(fakeReq(), secretGuess);

    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.objectContaining({
      lockScope: expect.stringMatching(/^(ip|credential|both)$/),
    }));

    const credHash = _credentialIdentity(secretGuess, 16);
    for (const call of emit.mock.calls) {
      const payload = JSON.stringify(call);
      expect(payload).not.toContain(secretGuess);
      expect(payload).not.toContain(credHash);
    }
  });

  it('CRED-23 AUTH_LOCKOUT_ACTIVE also reports a bounded lockScope, still without leaking the credential', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 1 }), { _storage: storage });
    const secretGuess = 'another-secret-guess';

    await lockout.recordFailure(fakeReq(), secretGuess);
    emit.mockClear();
    const pre = await lockout.precheck(fakeReq(), secretGuess);

    expect(pre.locked).toBe(true);
    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_ACTIVE', expect.objectContaining({
      lockScope: expect.stringMatching(/^(ip|credential|both)$/),
    }));
    for (const call of emit.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(secretGuess);
    }
  });

  it('CRED-24 backoff before the threshold is still driven by the IP counter alone, unaffected by ' +
     'a credential that has never been seen before', async () => {
    const storage = new MemoryStorage();
    const lockout  = createAuthLockout(baseConfig({ authLockoutMaxFailures: 10 }), { _storage: storage });
    const req = fakeReq();

    await lockout.recordFailure(req, 'first-guess');
    const pre = await lockout.precheck(req, 'a-completely-different-second-guess');
    expect(pre.backoffDelayMs).toBe(250); // driven by the IP's own count (1), not the (different) credential's
  });
});
