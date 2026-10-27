'use strict';

// key lifecycle at verification.
//   KL-01..09  the pure rules (execution and historical), every boundary
//   KL-20      a full rotation end-to-end through the real keystore and validateArtifact

const { checkExecution, checkHistorical, mergeTimelines, DEPRECATED_WINDOW_MS } = require('../keyLifecycle');

const T0 = Date.parse('2026-09-01T00:00:00.000Z');
const iso = (ms) => new Date(ms).toISOString();

describe('key lifecycle rules', () => {
  test('KL-01 the deprecated-key window is max age + future skew = 65 s', () => {
    expect(DEPRECATED_WINDOW_MS).toBe(65_000);
  });

  test('KL-02 active verifies; not for an artifact dated before the key existed (beyond the 5 s skew)', () => {
    const t = { status: 'active', activatedAt: iso(T0) };
    expect(checkExecution(t, T0, T0 + 1000)).toEqual({ valid: true });
    expect(checkExecution(t, T0 - 5_000, T0 + 1000)).toEqual({ valid: true });
    expect(checkExecution(t, T0 - 5_001, T0 + 1000).reason).toBe('KEY_NOT_YET_ACTIVE');
  });

  test('KL-03 deprecated: signed before retirement, verified inside the window → valid', () => {
    const t = { status: 'deprecated', activatedAt: iso(T0 - 86_400_000), deprecatedAt: iso(T0) };
    expect(checkExecution(t, T0 - 1, T0)).toEqual({ valid: true });
    expect(checkExecution(t, T0 - 1, T0 + 64_999)).toEqual({ valid: true });
  });

  test('KL-04 deprecated: window boundary — at deprecatedAt + 65 s it no longer verifies', () => {
    const t = { status: 'deprecated', deprecatedAt: iso(T0) };
    const r = checkExecution(t, T0 - 1, T0 + 65_000);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('KEY_DEPRECATED');
    expect(r.details.issue).toBe('deprecated-key window elapsed');
  });

  test('KL-05 deprecated: an artifact signed AT or after the retirement never verifies (nothing new)', () => {
    const t = { status: 'deprecated', deprecatedAt: iso(T0) };
    expect(checkExecution(t, T0, T0 + 1).reason).toBe('KEY_DEPRECATED');
    expect(checkExecution(t, T0 + 10, T0 + 20).details.issue).toBe('signed after the key was retired');
  });

  test('KL-06 deprecated with unknown retirement time fails closed', () => {
    expect(checkExecution({ status: 'deprecated' }, T0, T0).reason).toBe('KEY_DEPRECATED');
  });

  test('KL-07 archived and revoked never verify for execution; unknown status fails closed', () => {
    expect(checkExecution({ status: 'archived', activatedAt: iso(T0 - 10), deprecatedAt: iso(T0) }, T0 - 1, T0).reason).toBe('KEY_ARCHIVED');
    expect(checkExecution({ status: 'revoked' }, T0, T0).reason).toBe('KEY_REVOKED');
    expect(checkExecution({ status: 'weird' }, T0, T0).reason).toBe('KEY_STATUS_UNKNOWN');
    expect(checkExecution(undefined, T0, T0).reason).toBe('KEY_STATUS_UNKNOWN');
  });

  test('KL-08 historical: valid only if signed while active; revoked never', () => {
    const t = { status: 'archived', activatedAt: iso(T0 - 1000), deprecatedAt: iso(T0), archivedAt: iso(T0 + 1000) };
    expect(checkHistorical(t, T0 - 500)).toEqual({ valid: true });
    expect(checkHistorical(t, T0).reason).toBe('KEY_NOT_ACTIVE_AT_SIGNING_TIME');
    expect(checkHistorical(t, T0 - 7000).reason).toBe('KEY_NOT_ACTIVE_AT_SIGNING_TIME');
    expect(checkHistorical({ ...t, status: 'revoked' }, T0 - 500).reason).toBe('KEY_REVOKED');
    expect(checkHistorical({ status: 'active', activatedAt: iso(T0) }, T0 + 1)).toEqual({ valid: true });
  });

  test('KL-09 merge takes the more advanced status and never moves backwards', () => {
    const local = { status: 'active', activatedAt: iso(T0) };
    const pg = { status: 'revoked', revokedAt: iso(T0 + 5) };
    expect(mergeTimelines(local, pg).status).toBe('revoked');
    expect(mergeTimelines(pg, local).status).toBe('revoked');
    expect(mergeTimelines(local, pg).activatedAt).toBe(iso(T0));
    expect(mergeTimelines(local, null)).toBe(local);
  });
});

describe('KL-20 full rotation end-to-end (real keystore, validateArtifact)', () => {
  const keyStore = require('../../../services/artifact/keyStore');
  const { validateArtifact } = require('../validateArtifact');
  const { signArtifact } = require('../signArtifact');
  const client = 'w6-kl20-client';
  const sign = (key, ts) => signArtifact({ payload: { userId: 'kl20' }, timestamp: ts, expiry: ts + 60_000, publicKeyId: key.keyId }, key.privDer);

  test('active → graceful rotation → window → archive, and emergency revoke', () => {
    keyStore.rotateKey(client, { mode: 'graceful' });
    const live = keyStore.getActiveKey(client);
    // a copy: rotation zeroises the keystore's own Buffer in place — this models a holder of the old key
    const k1 = { keyId: live.keyId, privDer: Buffer.from(live.privDer) };
    const now = Date.now();
    const inFlight = sign(k1, now);
    expect(validateArtifact(inFlight, { _clock: () => now + 10 }).decision).toBe('EXECUTE');           // active

    keyStore.rotateKeyGracefully(client);                                                             // k1 → deprecated
    const retiredAt = Date.parse(keyStore.getPublicKey(k1.keyId).timeline.deprecatedAt);
    expect(keyStore.getPublicKey(k1.keyId).timeline.status).toBe('deprecated');
    expect(validateArtifact(inFlight, { _clock: () => retiredAt + 1_000 }).decision).toBe('EXECUTE');   // in flight, inside 65 s
    // at retirement + 65 s the in-flight artifact is refused (its own 60 s life ends first; KL-04 pins the window itself)
    expect(validateArtifact(inFlight, { _clock: () => retiredAt + 65_000 }).decision).toBe('BLOCK');
    const lateWithOldKey = sign(k1, retiredAt + 10);                                                  // old key used after retirement
    expect(validateArtifact(lateWithOldKey, { _clock: () => retiredAt + 20 }).reason).toBe('KEY_DEPRECATED');

    const k2live = keyStore.getActiveKey(client);
    const k2 = { keyId: k2live.keyId, privDer: Buffer.from(k2live.privDer) };
    expect(k2.keyId).not.toBe(k1.keyId);
    const fresh = sign(k2, Date.now());
    expect(validateArtifact(fresh).decision).toBe('EXECUTE');                                         // the new active key

    keyStore.rotateKey(client, { mode: 'emergency' });                                                // k2 → revoked
    expect(validateArtifact(fresh).reason).toBe('INVALID_SIGNATURE');                                 // revoked: never
  });
});
