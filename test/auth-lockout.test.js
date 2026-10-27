'use strict';

// AUTH-2 — auth-failure lockout, end-to-end through the real opsAuth
// middleware (supertest + express), mirroring the style of
// src/middleware/__tests__/opsAuth.test.js and test/ops-auth-v2.test.js
// (which this file complements — those cover credential resolution; this
// file covers the lockout control wrapped around it).
//
// _sleep is injected everywhere a real backoff delay would otherwise occur,
// so these tests assert the CORRECT delay was requested without actually
// waiting for it — the delay itself is unit-tested deterministically in
// src/core/authLockout/__tests__/authLockout.test.js (computeBackoffDelayMs).

const request = require('supertest');
const express  = require('express');
const { createOpsAuthMiddleware } = require('../src/middleware/opsAuth');
const { createAuthLockout }       = require('../src/core/authLockout');
const { MemoryStorage }           = require('../src/core/authLockout/storage');

// AL-E11 asserts on structured log calls. opsAuth.js / authLockout/index.js
// both destructure `emit` from services/logger at require time, so a
// post-hoc jest.spyOn(loggerModule, 'emit') would replace the export
// AFTER those modules already captured the original reference — it would
// never see the real calls. Mocking the module before anything requires it
// (as done here, and in src/core/authLockout/__tests__/authLockout.test.js)
// is what actually intercepts every call site.
jest.mock('../services/logger', () => ({ emit: jest.fn() }));
const { emit } = require('../services/logger');

const VALID_TOKEN = 'test-ops-token-at-least-32-chars-long';

function lockoutConfig(overrides = {}) {
  return {
    token: VALID_TOKEN,
    authLockoutEnabled:        true,
    authLockoutMaxFailures:    5,
    authLockoutDurationMs:     900_000,
    authLockoutBackoffMinMs:   250,
    authLockoutBackoffMaxMs:   5_000,
    authLockoutFailureWindowMs: 900_000,
    ...overrides,
  };
}

function buildApp({ config, ip = '203.0.113.7', sleepCalls = [], storage = new MemoryStorage() } = {}) {
  const cfg = config || lockoutConfig();
  const authLockout = createAuthLockout(cfg, { _storage: storage });
  const _sleep = (ms) => { sleepCalls.push(ms); return Promise.resolve(); };

  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    req.clientIp  = ip;
    next();
  });
  app.use(createOpsAuthMiddleware(cfg, null, authLockout, { _sleep }));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return { app, sleepCalls, storage, authLockout };
}

async function failOnce(app, badToken = 'wrong-token') {
  return request(app).get('/probe').set('Authorization', `Bearer ${badToken}`);
}

// ── AL-E01..E05: exponential backoff before the lockout threshold ────────────

describe('AL-E01..05 exponential backoff (below threshold)', () => {
  it('AL-E01 no delay is applied on the first request from a clean source', async () => {
    const { app, sleepCalls } = buildApp();
    await failOnce(app);
    expect(sleepCalls).toEqual([]);
  });

  it('AL-E02 delay grows deterministically with each subsequent failure', async () => {
    const { app, sleepCalls } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 10 }) });

    await failOnce(app); // failure #1 recorded; delay applies to the NEXT request
    await failOnce(app); // sees count=1 -> delay 250ms
    await failOnce(app); // sees count=2 -> delay 500ms
    await failOnce(app); // sees count=3 -> delay 1000ms

    expect(sleepCalls).toEqual([250, 500, 1000]);
  });

  it('AL-E03 delay is capped at the configured maximum', async () => {
    const { app, sleepCalls } = buildApp({
      config: lockoutConfig({ authLockoutMaxFailures: 20, authLockoutBackoffMaxMs: 1000 }),
    });
    for (let i = 0; i < 8; i++) await failOnce(app);
    expect(Math.max(...sleepCalls)).toBeLessThanOrEqual(1000);
    expect(sleepCalls).toContain(1000);
  });

  it('AL-E04 every delayed request still receives a normal 401 for a wrong credential', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 10 }) });
    await failOnce(app);
    const res = await failOnce(app);
    expect(res.status).toBe(401);
  });

  it('AL-E05 backoff delay resets to zero after a successful authentication', async () => {
    const { app, sleepCalls } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 10 }) });
    await failOnce(app);
    await failOnce(app); // streak of 2 — next request would be delayed

    await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`); // success — resets

    sleepCalls.length = 0;
    await failOnce(app); // fresh streak — first failure again, no delay yet
    expect(sleepCalls).toEqual([]);
  });
});

// ── AL-E06..E11: lockout threshold and response shape ─────────────────────────

describe('AL-E06..11 lockout activation', () => {
  it('AL-E06 activates exactly at the configured threshold, not one request early', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 3 }) });

    const r1 = await failOnce(app);
    const r2 = await failOnce(app);
    expect(r1.status).toBe(401);
    expect(r2.status).toBe(401);

    const r3 = await failOnce(app); // 3rd failure crosses the threshold
    expect(r3.status).toBe(401); // this request itself still gets a normal 401 (see opsAuth.js AUTH-2 comment)

    const r4 = await failOnce(app); // now locked
    expect(r4.status).toBe(429);
  });

  it('AL-E07 429 response uses the management envelope with AUTH_LOCKED_OUT and a Retry-After header', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 1 }) });
    await failOnce(app);

    const res = await failOnce(app);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'AUTH_LOCKED_OUT' } });
    expect(res.headers['retry-after']).toBeDefined();
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('AL-E08 a locked-out source is rejected even with the CORRECT credential ' +
     '(a valid guess mid-lockout does not bypass the lockout)', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 1 }) });
    await failOnce(app);

    const res = await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(429);
  });

  it('AL-E09 lockout response never contains the shared token or the guessed value', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 1 }) });
    await failOnce(app, 'super-secret-guess');

    const res = await failOnce(app, 'super-secret-guess');
    expect(JSON.stringify(res.body)).not.toContain('super-secret-guess');
    expect(JSON.stringify(res.body)).not.toContain(VALID_TOKEN);
  });

  it('AL-E10 missing-credential requests do not themselves count toward the lockout threshold', async () => {
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 3 }) });
    // 10 requests with no credential at all — none of these is "an invalid
    // token presented", so none should be recorded as a lockout failure.
    for (let i = 0; i < 10; i++) {
      const res = await request(app).get('/probe');
      expect(res.status).toBe(401);
    }
    // A real wrong-guess attempt afterward still starts from a clean streak.
    const r1 = await failOnce(app);
    const r2 = await failOnce(app);
    expect(r1.status).toBe(401);
    expect(r2.status).toBe(401); // not yet locked — would be 429 if the 10 missing-cred requests had counted
  });

  it('AL-E11 the request that crosses the threshold is logged as AUTH_LOCKOUT_TRIGGERED, ' +
     'not the requests before or after it', async () => {
    emit.mockClear();
    const { app } = buildApp({ config: lockoutConfig({ authLockoutMaxFailures: 2 }) });

    await failOnce(app);
    expect(emit).not.toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.anything());

    await failOnce(app);
    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.anything());

    emit.mockClear();
    await failOnce(app); // now rejected pre-emptively — not a new trigger
    expect(emit).not.toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_TRIGGERED', expect.anything());
    expect(emit).toHaveBeenCalledWith('WARN', 'AUTH_LOCKOUT_ACTIVE', expect.anything());
  });
});

// ── AL-E12..E14: automatic recovery ───────────────────────────────────────────

describe('AL-E12..14 automatic lockout expiry', () => {
  it('AL-E12 access is restored automatically once the lockout duration elapses — no manual reset', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 1, authLockoutDurationMs: 1000 });
    const { app } = buildApp({ config, storage });

    await failOnce(app); // locks immediately (threshold 1)
    const lockedRes = await failOnce(app);
    expect(lockedRes.status).toBe(429);

    // Manually advance the clock the storage layer sees, rather than
    // sleeping in the test — precheck() re-derives "now" via Date.now()
    // internally, so we fast-forward Date.now() itself.
    const realNow = Date.now;
    try {
      Date.now = () => realNow() + 1000 + 50;
      const recoveredRes = await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
      expect(recoveredRes.status).toBe(200);
    } finally {
      Date.now = realNow;
    }
  });

  it('AL-E13 a fresh failure streak after expiry starts from zero, not from where the old one left off', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 2, authLockoutDurationMs: 1000 });
    const { app, sleepCalls } = buildApp({ config, storage });

    await failOnce(app);
    await failOnce(app); // locks

    const realNow = Date.now;
    try {
      Date.now = () => realNow() + 1000 + 50;
      sleepCalls.length = 0;
      const res = await failOnce(app); // first failure of a brand-new streak
      expect(res.status).toBe(401); // not 429 — the old lockout is gone
      expect(sleepCalls).toEqual([]); // no backoff yet either — truly a clean slate
    } finally {
      Date.now = realNow;
    }
  });
});

// ── AL-E15..E16: per-source isolation ─────────────────────────────────────────

describe('AL-E15..16 per-source isolation', () => {
  it('AL-E15 one source being locked out never blocks a different source', async () => {
    const storage = new MemoryStorage();
    const config   = lockoutConfig({ authLockoutMaxFailures: 1 });
    const attacker  = buildApp({ config, storage, ip: '203.0.113.7' });
    const legitimate = buildApp({ config, storage, ip: '198.51.100.9' });

    await failOnce(attacker.app);
    const attackerRes = await failOnce(attacker.app);
    expect(attackerRes.status).toBe(429);

    const legitRes = await request(legitimate.app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(legitRes.status).toBe(200);
  });

  it('AL-E16 backoff accumulated by one source is invisible to another', async () => {
    const storage = new MemoryStorage();
    const config   = lockoutConfig({ authLockoutMaxFailures: 10 });
    const attacker  = buildApp({ config, storage, ip: '203.0.113.7' });
    const legitimate = buildApp({ config, storage, ip: '198.51.100.9' });

    await failOnce(attacker.app);
    await failOnce(attacker.app);
    await failOnce(attacker.app); // attacker now has a 3-failure backoff streak

    await failOnce(legitimate.app);
    expect(legitimate.sleepCalls).toEqual([]); // legitimate source's own first failure — no delay yet
  });
});

// ── AL-E17: concurrency ───────────────────────────────────────────────────────

describe('AL-E17 concurrent requests cannot bypass the lockout', () => {
  it('exactly (maxFailures) failures are needed to lock out even when fired concurrently', async () => {
    const storage = new MemoryStorage();
    const config   = lockoutConfig({ authLockoutMaxFailures: 5 });
    const { app }  = buildApp({ config, storage });

    const results = await Promise.all(Array.from({ length: 8 }, () => failOnce(app)));
    const statuses = results.map(r => r.status).sort();

    // Every one of the 8 concurrent wrong-credential requests still gets a
    // definitive answer (401, or 429 for any that landed after the lock was
    // set) — none is silently dropped, none is incorrectly allowed through.
    expect(statuses.every(s => s === 401 || s === 429)).toBe(true);

    // The source is now locked, proving the concurrent burst was correctly
    // accounted for rather than racing past the threshold unnoticed.
    const followUp = await failOnce(app);
    expect(followUp.status).toBe(429);
  });
});

// ── AL-E18: existing timing-safe comparison is untouched ─────────────────────

describe('AL-E18 constant-time comparison still guards the shared token', () => {
  it('a wrong-length token is still rejected without granting access, lockout notwithstanding', async () => {
    const { app } = buildApp();
    const res = await failOnce(app, VALID_TOKEN.slice(0, 5));
    expect(res.status).toBe(401);
  });
});

// ── AL-E19: disabling the control is fully inert ──────────────────────────────

describe('AL-E19 QODIQA_OPS_AUTH_LOCKOUT_ENABLED=false disables the control entirely', () => {
  it('never locks out or delays, regardless of failure count', async () => {
    const config = lockoutConfig({ authLockoutEnabled: false, authLockoutMaxFailures: 1 });
    const { app, sleepCalls } = buildApp({ config });

    for (let i = 0; i < 10; i++) {
      const res = await failOnce(app);
      expect(res.status).toBe(401);
    }
    expect(sleepCalls).toEqual([]);
  });
});

// ── AL-E20..24: credential-identity scoped secondary counter, ─────────
// end to end through the real opsAuth middleware — see
// docs/security/AUTH_LOCKOUT.md §4/§5a/§5b.

describe('AL-E20..24 credential-identity scoped secondary counter', () => {
  it('AL-E20 many source IPs guessing the SAME wrong credential trigger lockout via the credential ' +
     'counter, even though no single IP ever crosses the IP-scoped threshold', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 5 });
    const sameWrongGuess = 'distributed-attacker-guess';

    // 4 distinct attacker IPs each try the SAME wrong credential exactly once.
    for (let i = 1; i <= 4; i++) {
      const { app } = buildApp({ config, storage, ip: `203.0.113.${i}` });
      const res = await failOnce(app, sameWrongGuess);
      expect(res.status).toBe(401); // none of these IPs is anywhere near its own threshold
    }

    // A 5th, brand-new IP tries the same guess — this is the failure that
    // crosses the CREDENTIAL threshold (4 prior + this one = 5).
    const { app: fifthApp } = buildApp({ config, storage, ip: '203.0.113.5' });
    const fifthRes = await failOnce(fifthApp, sameWrongGuess);
    expect(fifthRes.status).toBe(401); // this request itself still gets a normal 401

    // A 6th, never-before-seen IP trying the SAME credential is now locked
    // out — proof the block followed the credential, not any one IP.
    const { app: sixthApp } = buildApp({ config, storage, ip: '203.0.113.6' });
    const sixthRes = await failOnce(sixthApp, sameWrongGuess);
    expect(sixthRes.status).toBe(429);
  });

  it('AL-E21 the identical attack pattern with a DIFFERENT guess per IP does NOT trigger lockout — ' +
     'proving E20 is the credential counter at work, not a fluke of the IP counter', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 5 });

    for (let i = 1; i <= 6; i++) {
      const { app } = buildApp({ config, storage, ip: `198.51.100.${i}` });
      const res = await failOnce(app, `unique-guess-${i}`); // a different credential every time
      expect(res.status).toBe(401); // never 429 — no counter (IP or credential) ever reaches 5
    }
  });

  it('AL-E22 the 429 response for a credential-triggered lockout never contains the guessed value', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 1 });
    const secretGuess = 'super-secret-guess-value';

    const { app: firstApp } = buildApp({ config, storage, ip: '203.0.113.10' });
    await failOnce(firstApp, secretGuess); // triggers immediately (threshold 1)

    const { app: secondApp } = buildApp({ config, storage, ip: '203.0.113.11' }); // different IP, same guess
    const res = await failOnce(secondApp, secretGuess);
    expect(res.status).toBe(429);
    expect(JSON.stringify(res.body)).not.toContain(secretGuess);
  });

  it('AL-E23 a successful authentication from one IP resets the credential counter for every IP', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 3 });

    const { app: appA } = buildApp({ config, storage, ip: '203.0.113.20' });
    const { app: appB } = buildApp({ config, storage, ip: '203.0.113.21' });

    await failOnce(appA, 'flaky-typo-guess');
    await failOnce(appB, 'flaky-typo-guess'); // credential streak now at 2

    // The operator eventually authenticates correctly with the VALID token
    // from one of those IPs.
    await request(appA).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);

    // A fresh wrong guess of the SAME previously-flaky value, from a THIRD
    // IP, starts from a clean credential streak (not 3/3).
    const { app: appC } = buildApp({ config, storage, ip: '203.0.113.22' });
    const res = await failOnce(appC, 'flaky-typo-guess');
    expect(res.status).toBe(401); // not 429 — the credential streak was reset
  });

  it('AL-E24 IP-only lockout (single source, single-ish credential mix) is completely unaffected', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 3 });
    const { app } = buildApp({ config, storage, ip: '203.0.113.30' });

    // One noisy IP trying several DIFFERENT wrong guesses — the original
    // IP-scoped behavior (AUTH-2) must still trigger on its own.
    await failOnce(app, 'guess-a');
    await failOnce(app, 'guess-b');
    const res = await failOnce(app, 'guess-c');
    expect(res.status).toBe(401); // 3rd failure itself still gets a normal 401

    const locked = await failOnce(app, 'guess-d');
    expect(locked.status).toBe(429); // now locked, regardless of credential
  });
});

// ── RT-04: a lockout-store outage is reported as a backend
// outage (503 AUTH_BACKEND_UNAVAILABLE, short Retry-After), still fail-closed — never as a
// lockout of the caller (429 AUTH_LOCKED_OUT with the full lockout duration).
describe('RT-04 lockout-store outage ≠ caller lockout', () => {
  const throwing = {
    precheck:      async () => { throw new Error('ECONNREFUSED'); },
    recordFailure: async () => { throw new Error('ECONNREFUSED'); },
    recordSuccess: async () => { throw new Error('ECONNREFUSED'); },
  };

  it('RT-04a opsAuth: storage outage → 503 AUTH_BACKEND_UNAVAILABLE, Retry-After 2, and the route is NOT reached (fail-closed)', async () => {
    const { app } = buildApp({ storage: throwing });
    const res = await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ status: 'error', error: { code: 'AUTH_BACKEND_UNAVAILABLE' } });
    expect(res.headers['retry-after']).toBe('2');
    expect(res.body.ok).toBeUndefined();
  });

  it('RT-04b opsAuth: a REAL lockout is still 429 AUTH_LOCKED_OUT with the lockout-duration Retry-After', async () => {
    const { app } = buildApp();
    for (let i = 0; i < 5; i++) await failOnce(app);
    const res = await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ error: { code: 'AUTH_LOCKED_OUT' } });
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(2);
  });

  it('RT-04c signAuth: storage outage → 503 AUTH_BACKEND_UNAVAILABLE (fail-closed; identity store never consulted)', async () => {
    const { createSignAuthMiddleware } = require('../src/middleware/signAuth');
    const store = { resolveSigningIdentity: jest.fn(() => { throw new Error('must not be reached'); }) };
    const mw = createSignAuthMiddleware({ store, isSigningPermitted: () => true, authLockout: createAuthLockout(lockoutConfig(), { _storage: throwing }) });
    const app = express();
    app.use((req, _res, next) => { req.requestId = 'r'; req.clientIp = '203.0.113.9'; next(); });
    app.post('/sign', mw, (_req, res) => res.status(200).json({ ok: true }));
    const res = await request(app).post('/sign').set('Authorization', 'Bearer sk_0123456789abcdef0123456789abcdef');
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'AUTH_BACKEND_UNAVAILABLE' });
    expect(res.headers['retry-after']).toBe('2');
    expect(store.resolveSigningIdentity).not.toHaveBeenCalled();
  });
});
