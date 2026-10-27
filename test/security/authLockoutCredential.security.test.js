'use strict';

/**
 * remediation — dedicated security/red-team coverage for the
 * credential-identity scoped secondary lockout counter (src/core/
 * authLockout). Complements src/core/authLockout/__tests__/authLockout.test.js
 * (unit coverage) and test/auth-lockout.test.js's AL-E20..24 (integration
 * through the real opsAuth middleware) — this file focuses specifically on
 * the threat model was written to close and the privacy guarantees
 * around the credential hash, matching the style of test/rateLimitRace.
 * concurrency.security.test.js and test/security/dashboardXss.security.test.js.
 *
 * ── Threat model ───────────────────────────────────────────────────────────
 * Pre-WP-012, src/core/authLockout/index.js's `_identity(req)` keyed lockout
 * state exclusively by client IP. A distributed attacker who rotates across
 * many source IPs while repeating the SAME guessed credential never
 * accumulates enough failures against any single IP to trip its counter —
 * each IP's slice of the campaign stays under threshold indefinitely, and
 * the also-per-IP admin rate limiter in front of this control doesn't close
 * the gap either. adds a second counter keyed by a truncated SHA-256
 * hash of the presented credential itself, so the credential accumulates
 * failures across every IP it was tried from.
 *
 * ── Privacy requirement under test ──────────────────────────────────────────
 * The presented credential must never be stored, logged, placed in Redis,
 * included in telemetry, embedded in evidence, or surfaced in an exception —
 * only a one-way, truncated hash may be used, and even THAT hash must never
 * leak into logs/responses (see docs/security/AUTH_LOCKOUT.md §10 for why).
 */

const request = require('supertest');
const express  = require('express');

const { createOpsAuthMiddleware } = require('../../src/middleware/opsAuth');
const { createAuthLockout, _credentialIdentity } = require('../../src/core/authLockout');
const { MemoryStorage, KEY_PREFIX }               = require('../../src/core/authLockout/storage');

jest.mock('../../services/logger', () => require('../helpers/sharedMocks').makeLoggerMock());
const { emit } = require('../../services/logger');

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

function buildApp({ config, ip = '203.0.113.7', storage } = {}) {
  const cfg = config || lockoutConfig();
  const authLockout = createAuthLockout(cfg, { _storage: storage });
  const _sleep = () => Promise.resolve();

  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'sec-test-req-id';
    req.clientIp  = ip;
    next();
  });
  app.use(createOpsAuthMiddleware(cfg, null, authLockout, { _sleep }));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

async function guess(app, badToken) {
  return request(app).get('/probe').set('Authorization', `Bearer ${badToken}`);
}

beforeEach(() => {
  emit.mockClear();
});

// ── distributed credential guessing (the core scenario) ──

describe('distributed credential guessing across many source IPs', () => {
  it('a 50-IP botnet each guessing the SAME credential once is locked out well before ' +
     'the IP-scoped counter alone would ever notice', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 5 });
    const targetCredential = 'ops-token-under-attack';

    const results = [];
    for (let i = 1; i <= 50; i++) {
      const app = buildApp({ config, storage, ip: `10.${Math.floor(i / 255)}.${i % 255}.1` });
      results.push(await guess(app, targetCredential));
    }

    // At most the first 4 could possibly precede the credential's trip point;
    // every request from the 5th guess onward must be rejected, and the vast
    // majority of the 50 are rejected with 429 (locked), not merely 401.
    const lockedCount = results.filter(r => r.status === 429).length;
    expect(lockedCount).toBeGreaterThanOrEqual(45); // 50 - (4 pre-threshold) - (1 triggering) = 45
  });

  it('an attacker spreading guesses one-per-IP never trips any INDIVIDUAL IP counter, ' +
     'confirming the credential counter — not a coincidental IP trip — is what caught the attack', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 5 });
    const targetCredential = 'ops-token-under-attack-2';

    // Exactly 4 attempts — one below threshold — from 4 distinct IPs.
    for (let i = 1; i <= 4; i++) {
      const app = buildApp({ config, storage, ip: `10.0.0.${i}` });
      const res = await guess(app, targetCredential);
      expect(res.status).toBe(401); // never 429 — no single IP has more than 1 failure
    }

    // Confirm each of those 4 IPs is individually still unlocked.
    for (let i = 1; i <= 4; i++) {
      const app = buildApp({ config, storage, ip: `10.0.0.${i}` });
      const res = await request(app).get('/probe').set('Authorization', `Bearer ${VALID_TOKEN}`);
      expect(res.status).toBe(200); // still authenticates fine — this IP was never locked
    }
  });

  it('credential rotation mid-campaign resets progress — an attacker cannot "bank" partial ' +
     'progress across different guessed values', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 3 });

    // 2 failures against credential A from 2 different IPs.
    await guess(buildApp({ config, storage, ip: '203.0.113.1' }), 'credential-A');
    await guess(buildApp({ config, storage, ip: '203.0.113.2' }), 'credential-A');

    // Attacker rotates to a DIFFERENT credential B — this does not inherit
    // credential A's 2-failure progress.
    const res1 = await guess(buildApp({ config, storage, ip: '203.0.113.3' }), 'credential-B');
    expect(res1.status).toBe(401);
    const res2 = await guess(buildApp({ config, storage, ip: '203.0.113.4' }), 'credential-B');
    expect(res2.status).toBe(401); // still not locked — credential B only has 2 failures of its own now
  });
});

// ── mixed IP/credential attack patterns ──────────────────────────

describe('mixed IP-scoped and credential-scoped attack patterns', () => {
  it('a single noisy IP guessing many DIFFERENT credentials still trips the IP counter ' +
     '(credential scoping does not weaken the original AUTH-2 protection)', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 3 });
    const app = buildApp({ config, storage, ip: '203.0.113.99' });

    await guess(app, 'unique-guess-1');
    await guess(app, 'unique-guess-2');
    const res = await guess(app, 'unique-guess-3'); // 3rd failure crosses this IP's own threshold
    expect(res.status).toBe(401); // this request itself still gets a normal 401

    const locked = await guess(app, 'unique-guess-4');
    expect(locked.status).toBe(429); // now IP-locked, regardless of credential diversity
  });

  it('a combined attack — some IPs repeat credentials, some vary them — is caught by ' +
     'whichever counter (IP or credential) crosses its threshold first', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 4 });
    const sharedCredential = 'popular-guess';

    // 3 different IPs all guess the SAME credential (credential count -> 3).
    for (let i = 1; i <= 3; i++) {
      const res = await guess(buildApp({ config, storage, ip: `198.51.100.${i}` }), sharedCredential);
      expect(res.status).toBe(401);
    }
    // A 4th, fresh IP also guesses it — credential count now hits 4, triggering.
    const triggeringRes = await guess(buildApp({ config, storage, ip: '198.51.100.4' }), sharedCredential);
    expect(triggeringRes.status).toBe(401); // the triggering request itself still gets 401

    // Any further guess of that SAME credential, from any IP, is now blocked.
    const blockedRes = await guess(buildApp({ config, storage, ip: '198.51.100.99' }), sharedCredential);
    expect(blockedRes.status).toBe(429);
  });
});

// ── credential privacy ───────────────────────────────────────────

describe('credential privacy — the raw value and its hash never leak', () => {
  it('the raw credential never appears in Redis/MemoryStorage keys', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 10 });
    const secret = 'do-not-store-this-raw-value';

    await guess(buildApp({ config, storage }), secret);

    for (const key of storage._state.keys()) {
      expect(key).not.toContain(secret);
    }
  });

  it('the credential identity is a deterministic hash, never a reversible encoding of the ' +
     'credential (e.g. not base64/hex of the raw bytes)', () => {
    const secret = 'reversible-encoding-check';
    const identity = _credentialIdentity(secret, 16);

    expect(identity).not.toBe(Buffer.from(secret).toString('hex'));
    expect(identity).not.toBe(Buffer.from(secret).toString('base64'));
    expect(identity).not.toContain(secret);
  });

  it('no structured log event ever contains the raw credential', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 1 });
    const secret = 'never-log-this-value';
    emit.mockClear();

    await guess(buildApp({ config, storage }), secret); // triggers immediately (threshold 1)
    await guess(buildApp({ config, storage, ip: '203.0.113.55' }), secret); // hits the lockout

    for (const call of emit.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(secret);
    }
  });

  it('no structured log event ever contains the credential HASH either — only the bounded ' +
     'lockScope classification (ip/credential/both)', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 1 });
    const secret = 'hash-must-not-leak-either';
    const hash = _credentialIdentity(secret, config.authLockoutCredentialHashBytes || 16);
    emit.mockClear();

    await guess(buildApp({ config, storage }), secret);
    await guess(buildApp({ config, storage, ip: '203.0.113.56' }), secret);

    for (const call of emit.mock.calls) {
      expect(JSON.stringify(call)).not.toContain(hash);
    }
  });

  it('the HTTP response body for a locked-out request never contains the guessed credential', async () => {
    const storage = new MemoryStorage();
    const config  = lockoutConfig({ authLockoutMaxFailures: 1 });
    const secret = 'response-body-must-not-leak-this';

    await guess(buildApp({ config, storage }), secret);
    const res = await guess(buildApp({ config, storage, ip: '203.0.113.57' }), secret);

    expect(res.status).toBe(429);
    expect(JSON.stringify(res.body)).not.toContain(secret);
  });
});
