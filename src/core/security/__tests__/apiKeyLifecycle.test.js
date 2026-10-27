'use strict';

/**
 * API-key expiry, rotation grace and warning, for both
 * credential stores (operator keys and signing-identity keys).
 */

const lc = require('../apiKeyLifecycle');

const DAY = lc.DAY_MS; const HOUR = lc.HOUR_MS;
const NOW = Date.parse('2026-09-28T12:00:00Z');
const cfg = { ttlDays: 90, graceHours: 24, warnDays: 14 };

describe('lifecycle helper', () => {
  test('defaults are 90 d / 24 h / 14 d', () => {
    const saved = { ...process.env };
    try {
      delete process.env.QODIQA_API_KEY_TTL_DAYS; delete process.env.QODIQA_API_KEY_ROTATION_GRACE_HOURS; delete process.env.QODIQA_API_KEY_EXPIRY_WARNING_DAYS;
      expect(lc.config()).toEqual(cfg);
      process.env.QODIQA_API_KEY_TTL_DAYS = 'junk'; expect(lc.config().ttlDays).toBe(90);
      process.env.QODIQA_API_KEY_TTL_DAYS = '30'; expect(lc.config().ttlDays).toBe(30);
    } finally { process.env = saved; }
  });

  test('first issue: expiry = now + TTL, no previous key', () => {
    const f = lc.issueFields(null, 'h1', NOW, cfg);
    expect(f).toMatchObject({ apiKeyHash: 'h1', apiKeyExpiresAt: new Date(NOW + 90 * DAY).toISOString(), previousApiKeyHash: null, previousApiKeyGraceUntil: null });
  });

  test('rotation: the previous key gets 24 h of grace', () => {
    const f = lc.issueFields({ apiKeyHash: 'old', apiKeyExpiresAt: new Date(NOW + 30 * DAY).toISOString() }, 'new', NOW, cfg);
    expect(f.previousApiKeyHash).toBe('old');
    expect(f.previousApiKeyGraceUntil).toBe(new Date(NOW + 24 * HOUR).toISOString());
  });

  test('grace never extends past the old key’s own expiry; an expired key gets none', () => {
    const near = lc.issueFields({ apiKeyHash: 'old', apiKeyExpiresAt: new Date(NOW + 2 * HOUR).toISOString() }, 'new', NOW, cfg);
    expect(near.previousApiKeyGraceUntil).toBe(new Date(NOW + 2 * HOUR).toISOString());
    const dead = lc.issueFields({ apiKeyHash: 'old', apiKeyExpiresAt: new Date(NOW - HOUR).toISOString() }, 'new', NOW, cfg);
    expect(dead.previousApiKeyHash).toBeNull();
  });

  test('grace 0 → the old key dies at rotation', () => {
    expect(lc.issueFields({ apiKeyHash: 'old' }, 'new', NOW, { ...cfg, graceHours: 0 }).previousApiKeyHash).toBeNull();
  });

  test('status: valid → expiring (≤14 d) → expired; previous → grace → expired', () => {
    const rec = { apiKeyExpiresAt: new Date(NOW + 20 * DAY).toISOString(), previousApiKeyGraceUntil: new Date(NOW + HOUR).toISOString() };
    expect(lc.keyStatus(rec, 'current', NOW, cfg).status).toBe('valid');
    expect(lc.keyStatus(rec, 'current', NOW + 7 * DAY, cfg).status).toBe('expiring');
    expect(lc.keyStatus(rec, 'current', NOW + 21 * DAY, cfg).status).toBe('expired');
    expect(lc.keyStatus(rec, 'previous', NOW, cfg).status).toBe('grace');
    expect(lc.keyStatus(rec, 'previous', NOW + 2 * HOUR, cfg).status).toBe('expired');
  });

  test('transition for an earlier key: max(issued + TTL, now + warning) — nothing dies at deploy', () => {
    expect(lc.transitionExpiry(new Date(NOW - 200 * DAY).toISOString(), NOW, cfg)).toBe(new Date(NOW + 14 * DAY).toISOString());
    expect(lc.transitionExpiry(new Date(NOW - 10 * DAY).toISOString(), NOW, cfg)).toBe(new Date(NOW + 80 * DAY).toISOString());
    expect(lc.transitionExpiry(undefined, NOW, cfg)).toBe(new Date(NOW + 14 * DAY).toISOString());
  });

  test('revocation clears every key immediately (no grace)', () => {
    expect(lc.revokeFields()).toEqual({ apiKeyHash: null, apiKeyIssuedAt: null, apiKeyExpiresAt: null, previousApiKeyHash: null, previousApiKeyGraceUntil: null });
  });
});

describe('operator key store (src/core/rbac/store.js)', () => {
  const store = require('../../rbac/store');
  afterEach(() => jest.useRealTimers());

  test('issue returns the expiry; resolve reports valid → expiring → expired (and resolveOperatorKey refuses expired)', () => {
    const u = store.createUser({ username: `exp-op-${Date.now()}`, role: 'viewer' });
    const t0 = Date.now();
    const { plaintext, expiresAt } = store.issueApiKey(u.id);
    expect(Date.parse(expiresAt) - t0).toBeGreaterThanOrEqual(90 * DAY - 5000);
    expect(store.resolveOperatorKeyDetailed(plaintext).status).toBe('valid');
    jest.useFakeTimers({ now: t0 + 80 * DAY });
    expect(store.resolveOperatorKeyDetailed(plaintext).status).toBe('expiring');
    jest.setSystemTime(t0 + 91 * DAY);
    expect(store.resolveOperatorKeyDetailed(plaintext).status).toBe('expired');
    expect(store.resolveOperatorKey(plaintext)).toBeNull();
  });

  test('rotation: the old key works in grace for 24 h, then is refused; revoke kills both', () => {
    const u = store.createUser({ username: `exp-rot-${Date.now()}`, role: 'viewer' });
    const t0 = Date.now();
    const k1 = store.issueApiKey(u.id).plaintext;
    const r2 = store.issueApiKey(u.id);
    expect(r2.previousKeyGraceUntil).toBeTruthy();
    expect(store.resolveOperatorKeyDetailed(k1)).toMatchObject({ status: 'grace', via: 'previous' });
    expect(store.resolveOperatorKey(k1)).not.toBeNull();
    jest.useFakeTimers({ now: t0 + 25 * HOUR });
    expect(store.resolveOperatorKeyDetailed(k1).status).toBe('expired');
    expect(store.resolveOperatorKey(k1)).toBeNull();
    jest.useRealTimers();
    const k3 = store.issueApiKey(u.id).plaintext; // k2 now in grace
    store.revokeApiKey(u.id);
    expect(store.resolveOperatorKey(k3)).toBeNull();
    expect(store.resolveOperatorKey(r2.plaintext)).toBeNull();
  });
});

describe('signing identity store (src/core/signing/signingIdentityStore.js)', () => {
  // Not one of test/support/jest.dataIsolation.js's six stores: point it at a per-file temp path.
  const os = require('os'); const path = require('path'); const fs = require('fs');
  // Reuse this file's isolation dir (created by test/support/jest.dataIsolation.js, removed by test/support/jest.globalTeardown.js).
  const dir = path.dirname(process.env.QODIQA_RBAC_STORE_PATH || fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-stores-')));
  process.env.QODIQA_SIGNING_STORE_PATH = path.join(dir, 'signing-identities.json');
  const sis = require('../../signing/signingIdentityStore');
  afterEach(() => jest.useRealTimers());

  test('signing keys expire and rotate with the same lifecycle', () => {
    const id = sis.createSigningIdentity({ name: `exp-sign-${Date.now()}`, tenantId: 't1', environment: 'development', permissions: ['SIGN_ARTIFACT'] }).id;
    const t0 = Date.now();
    const k1 = sis.issueSigningKey(id).plaintext;
    const r2 = sis.issueSigningKey(id);
    expect(r2.expiresAt).toBeTruthy();
    expect(sis.resolveSigningIdentityDetailed(k1)).toMatchObject({ status: 'grace', via: 'previous' });
    expect(sis.resolveSigningIdentityDetailed(r2.plaintext).status).toBe('valid');
    jest.useFakeTimers({ now: t0 + 91 * DAY });
    expect(sis.resolveSigningIdentityDetailed(r2.plaintext).status).toBe('expired');
    expect(sis.resolveSigningIdentityDetailed(k1).status).toBe('expired');
  });
});
