'use strict';

/**
 * operator MFA core: RFC 6238 TOTP, encrypted
 * secret at rest, single-use recovery codes, replay guard, 5-failure lock,
 * admin reset, and the RBAC_MFA_* platform events. Uses the real RBAC store
 * (per-file temp path via test/support/jest.dataIsolation.js).
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { emit } = require('../../../../services/logger');
const store = require('../store');
const mfa = require('../mfa');

const T0 = Date.parse('2026-09-28T12:00:00Z');
let n = 0;
function newUser() {
  n += 1;
  const u = store.createUser({ username: `mfa-user-${n}-${Date.now()}`, role: 'admin' });
  return { id: u.id, username: u.username };
}
const events = () => emit.mock.calls.map((c) => c[1]);
function enroll(user, now = T0) {
  const { secret } = mfa.beginEnrollment(user);
  const raw = mfa.base32Decode(secret);
  const { recoveryCodes } = mfa.confirmEnrollment(user, mfa.totp(raw, now), undefined, now);
  return { raw, secret, recoveryCodes };
}

beforeEach(() => { emit.mockClear(); });

describe('RFC 6238 / RFC 4226 primitives', () => {
  const key = Buffer.from('12345678901234567890');
  test('RFC 6238 Appendix B SHA-1 vectors (6-digit truncation)', () => {
    expect(mfa.totp(key, 59 * 1000)).toBe('287082');
    expect(mfa.totp(key, 1111111109 * 1000)).toBe('081804');
    expect(mfa.totp(key, 1234567890 * 1000)).toBe('005924');
    expect(mfa.totp(key, 2000000000 * 1000)).toBe('279037');
  });
  test('RFC 4226 Appendix D HOTP vectors', () => {
    expect(['755224', '287082', '359152', '969429', '338314'].map((_, i) => mfa.hotp(key, i)))
      .toEqual(['755224', '287082', '359152', '969429', '338314']);
  });
  test('base32 round-trips', () => {
    const b = Buffer.from('any bytes \x00\xff here');
    expect(mfa.base32Decode(mfa.base32Encode(b)).equals(b)).toBe(true);
  });
});

describe('enrolment', () => {
  test('begin returns the secret once; it is stored only AES-GCM-encrypted', () => {
    const u = newUser();
    const { secret, otpauthUri } = mfa.beginEnrollment(u);
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(otpauthUri).toContain(`secret=${secret}`);
    const rec = store.getMfaState(u.id);
    expect(JSON.stringify(rec)).not.toContain(secret);
    expect(rec.pending.secret).toEqual({ enc: expect.any(String), iv: expect.any(String), tag: expect.any(String) });
    expect(events()).toContain('RBAC_MFA_ENROLLMENT_STARTED');
  });

  test('confirm with a valid code enrols and returns 10 recovery codes, stored only hashed', () => {
    const u = newUser();
    const { recoveryCodes } = enroll(u);
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);
    const rec = store.getMfaState(u.id);
    expect(rec.enabled).toBe(true);
    for (const c of recoveryCodes) expect(JSON.stringify(rec)).not.toContain(c);
    expect(rec.recoveryCodeHashes).toHaveLength(10);
    expect(mfa.status(u.id)).toMatchObject({ enrolled: true, remainingRecoveryCodes: 10 });
    expect(events()).toContain('RBAC_MFA_ENROLLED');
  });

  test('confirm with a wrong code fails and leaves the user unenrolled', () => {
    const u = newUser();
    mfa.beginEnrollment(u);
    expect(() => mfa.confirmEnrollment(u, '000000', undefined, T0)).toThrow(expect.objectContaining({ code: 'MFA_INVALID' }));
    expect(mfa.status(u.id).enrolled).toBe(false);
    expect(events()).toContain('RBAC_MFA_ENROLLMENT_FAILED');
  });

  test('a pending enrolment expires after 10 minutes', () => {
    const u = newUser();
    const { secret } = mfa.beginEnrollment(u);
    const later = Date.now() + mfa.PENDING_TTL_MS + 1000;
    expect(() => mfa.confirmEnrollment(u, mfa.totp(mfa.base32Decode(secret), later), undefined, later))
      .toThrow(expect.objectContaining({ code: 'MFA_ENROLLMENT_EXPIRED' }));
  });

  test('re-enrolment is refused once enrolled (only an admin reset clears it)', () => {
    const u = newUser();
    enroll(u);
    expect(() => mfa.beginEnrollment(u)).toThrow(expect.objectContaining({ code: 'MFA_ALREADY_ENROLLED' }));
    mfa.reset(u.id, { by: 'admin' });
    expect(mfa.status(u.id).enrolled).toBe(false);
    expect(events()).toContain('RBAC_MFA_RESET');
    expect(() => mfa.beginEnrollment(u)).not.toThrow();
  });
});

describe('step-up verification', () => {
  test('a current code verifies; the same step cannot be replayed', () => {
    const u = newUser();
    const { raw } = enroll(u, T0);
    const t = T0 + 60_000;
    const code = mfa.totp(raw, t);
    expect(mfa.verifyStepUp(u, code, undefined, t)).toMatchObject({ ok: true, method: 'totp' });
    expect(mfa.verifyStepUp(u, code, undefined, t)).toEqual({ ok: false, reason: 'MFA_INVALID' });
    expect(events()).toContain('RBAC_MFA_VERIFIED');
  });

  test('±1 step drift is accepted; ±2 is not', () => {
    const u = newUser();
    const { raw } = enroll(u, T0);
    const t = T0 + 10 * 60_000;
    expect(mfa.verifyStepUp(u, mfa.totp(raw, t - 30_000), undefined, t).ok).toBe(true);
    expect(mfa.verifyStepUp(u, mfa.totp(raw, t + 30_000), undefined, t).ok).toBe(true);
    const t2 = t + 5 * 60_000;
    expect(mfa.verifyStepUp(u, mfa.totp(raw, t2 - 60_000), undefined, t2).ok).toBe(false);
    expect(mfa.verifyStepUp(u, mfa.totp(raw, t2 + 60_000), undefined, t2).ok).toBe(false);
  });

  test('a recovery code works exactly once (any case / separator)', () => {
    const u = newUser();
    const { recoveryCodes } = enroll(u);
    const c = recoveryCodes[3];
    expect(mfa.verifyStepUp(u, c.toUpperCase().replace('-', ' '), undefined, T0 + 60_000))
      .toMatchObject({ ok: true, method: 'recovery', remainingRecoveryCodes: 9 });
    expect(mfa.verifyStepUp(u, c, undefined, T0 + 61_000).ok).toBe(false);
    expect(events()).toContain('RBAC_MFA_RECOVERY_CODE_USED');
  });

  test('5 failures lock MFA for 15 minutes — even a valid code is refused while locked', () => {
    const u = newUser();
    const { raw } = enroll(u, T0);
    const t = T0 + 60_000;
    for (let i = 0; i < 4; i++) expect(mfa.verifyStepUp(u, '000000', undefined, t)).toEqual({ ok: false, reason: 'MFA_INVALID' });
    const fifth = mfa.verifyStepUp(u, '000000', undefined, t);
    expect(fifth).toMatchObject({ ok: false, reason: 'MFA_LOCKED' });
    expect(events()).toContain('RBAC_MFA_LOCKED');
    const locked = mfa.verifyStepUp(u, mfa.totp(raw, t + 60_000), undefined, t + 60_000);
    expect(locked).toMatchObject({ ok: false, reason: 'MFA_LOCKED' });
    expect(locked.retryAfterSeconds).toBeGreaterThan(0);
    const after = t + mfa.LOCK_MS + 60_000;
    expect(mfa.verifyStepUp(u, mfa.totp(raw, after), undefined, after).ok).toBe(true);
  });

  test('a success resets the failure count', () => {
    const u = newUser();
    const { raw } = enroll(u, T0);
    let t = T0 + 60_000;
    for (let i = 0; i < 4; i++) mfa.verifyStepUp(u, '000000', undefined, t);
    t += 60_000;
    expect(mfa.verifyStepUp(u, mfa.totp(raw, t), undefined, t).ok).toBe(true);
    for (let i = 0; i < 4; i++) expect(mfa.verifyStepUp(u, '000000', undefined, t).reason).toBe('MFA_INVALID');
  });

  test('an unenrolled user gets MFA_NOT_ENROLLED', () => {
    const u = newUser();
    expect(mfa.verifyStepUp(u, '123456')).toEqual({ ok: false, reason: 'MFA_NOT_ENROLLED' });
  });

  test('no event carries a code, secret or recovery code', () => {
    const u = newUser();
    const { raw, secret, recoveryCodes } = enroll(u, T0);
    mfa.verifyStepUp(u, recoveryCodes[0], undefined, T0 + 60_000);
    mfa.verifyStepUp(u, mfa.totp(raw, T0 + 120_000), undefined, T0 + 120_000);
    mfa.verifyStepUp(u, '999999', undefined, T0 + 180_000);
    const dump = JSON.stringify(emit.mock.calls);
    expect(dump).not.toContain(secret);
    for (const c of recoveryCodes) expect(dump).not.toContain(c);
    expect(dump).not.toContain('999999');
  });

  test('isRequired defaults to true; only the literal "false" disables it', () => {
    const saved = process.env.QODIQA_OPS_MFA_REQUIRED;
    try {
      delete process.env.QODIQA_OPS_MFA_REQUIRED; expect(mfa.isRequired()).toBe(true);
      process.env.QODIQA_OPS_MFA_REQUIRED = '0'; expect(mfa.isRequired()).toBe(true);
      process.env.QODIQA_OPS_MFA_REQUIRED = 'false'; expect(mfa.isRequired()).toBe(false);
    } finally { process.env.QODIQA_OPS_MFA_REQUIRED = saved; }
  });
});
