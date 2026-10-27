'use strict';

/**
 * step 6 (M1) — checkpoint key store + signed checkpoint format.
 *
 *   CK-01  a checkpoint signed with the active checkpoint key verifies
 *   CK-02  any change to a payload field is detected (payload hash), and a recomputed hash does not help (signature)
 *   CK-03  a signature made by another key (e.g. the transparency key) does not verify
 *   CK-04  separate trust domain: own file, purpose 'audit-checkpoint', 'cp-' key ids; the transparency store does
 *          not know checkpoint key ids
 *   CK-05  graceful rotation keeps old checkpoints verifiable; emergency rotation (default) revokes them
 *   CK-06  publishedKeys(): every non-revoked public key; an independent verification with node:crypto only works
 *   CK-07  malformed input is refused, never thrown
 * CK-08 a deprecated key verifies what it signed before retirement, never a checkpoint signed (dated)
 *          after its retirement; a deprecated key with no retirement time is refused
 */

const crypto = require('crypto');
const fs = require('fs');

describe('audit checkpoint signing', () => {
  let ks; let cp; let tks;
  beforeEach(() => {
    jest.resetModules();
    ks = require('../checkpointKeyStore');
    cp = require('../checkpoint');
    tks = require('../../../transparency/transparencyKeyStore');
  });
  const fields = () => ({ chainLength: 1000, headHash: 'a'.repeat(64), pgSeq: 1000, previousCheckpointHash: null });

  test('CK-01 sign → verify', () => {
    const s = cp.signCheckpoint(fields());
    expect(s.payload).toMatchObject({ v: 1, chainLength: 1000, headHash: 'a'.repeat(64), pgSeq: 1000, keyId: expect.stringMatching(/^cp-[^:]+:key_v\d+$/) });
    expect(s.payloadHash).toMatch(/^[0-9a-f]{64}$/);
    expect(cp.verifyCheckpoint(s)).toEqual({ ok: true });
  });

  test('CK-02 tampering with any field is detected', () => {
    const s = cp.signCheckpoint(fields());
    for (const [f, v] of [['chainLength', 999], ['headHash', 'b'.repeat(64)], ['pgSeq', 1], ['createdAt', '2020-01-01T00:00:00.000Z'], ['previousCheckpointHash', 'c'.repeat(64)]]) {
      const t = { ...s, payload: { ...s.payload, [f]: v } };
      expect(cp.verifyCheckpoint(t)).toEqual({ ok: false, reason: 'CHECKPOINT_PAYLOAD_HASH_MISMATCH' });
      const rehashed = { ...t, payloadHash: cp.checkpointDigest(t.payload).toString('hex') };
      expect(cp.verifyCheckpoint(rehashed)).toEqual({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' });
    }
    expect(cp.verifyCheckpoint({ ...s, payload: { ...s.payload, extra: 1 } }).reason).toBe('CHECKPOINT_UNKNOWN_FIELD');
  });

  test('CK-03 a signature by another key does not verify', () => {
    const s = cp.signCheckpoint(fields());
    tks.rotateKey();
    const other = require('../../../../infra/crypto/ed25519').sign(cp.checkpointDigest(s.payload), tks.getActiveKey().privDer);
    expect(cp.verifyCheckpoint({ ...s, signature: other })).toEqual({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' });
  });

  test('CK-04 separate trust domain', () => {
    const s = cp.signCheckpoint(fields());
    expect(ks.DATA_PATH).toMatch(/checkpoint-keys\.json$/);
    expect(ks.DATA_PATH).not.toBe(process.env.QODIQA_TRANSPARENCY_KEYS_PATH);
    const file = JSON.parse(fs.readFileSync(ks.DATA_PATH, 'utf8'));
    expect(Object.values(file.keys).every((k) => k.purpose === 'audit-checkpoint' && k.encryptedPrivateKeyDer && !k.privateKeyDer)).toBe(true);
    expect(file.kekFingerprint).toBeTruthy();
    expect(() => tks.getPublicKey(s.payload.keyId)).toThrow(/unknown transparency keyId/);
  });

  test('CK-05 graceful rotation keeps old checkpoints verifiable; emergency rotation revokes', () => {
    const s1 = cp.signCheckpoint(fields());
    ks.rotateKeyGracefully();
    const s2 = cp.signCheckpoint({ ...fields(), chainLength: 2000, previousCheckpointHash: s1.payloadHash });
    expect(s2.payload.keyId).not.toBe(s1.payload.keyId);
    expect(cp.verifyCheckpoint(s1)).toEqual({ ok: true });
    ks.rotateKey();                                   // emergency: s2's key revoked
    expect(cp.verifyCheckpoint(s2).reason).toMatch(/^CHECKPOINT_KEY_UNAVAILABLE: .*revoked/);
    expect(cp.verifyCheckpoint(s1)).toEqual({ ok: true });
  });

  test('CK-06 published keys verify independently with node:crypto only', () => {
    const s = cp.signCheckpoint(fields());
    const pub = ks.publishedKeys().find((k) => k.keyId === s.payload.keyId);
    expect(pub).toMatchObject({ algorithm: 'ed25519', purpose: 'audit-checkpoint', status: 'active' });
    // what an external verifier does: rebuild the digest from the documented construction, verify with the SPKI key
    const stable = require('../../../../utils/stableStringify');
    const canonical = {}; for (const f of cp.CANONICAL_FIELDS) canonical[f] = s.payload[f];
    const digest = crypto.createHash('sha256').update('QODIQA::AUDIT_CHECKPOINT::V1').update(stable(canonical)).digest();
    const key = crypto.createPublicKey({ key: Buffer.from(pub.publicKeySpkiDerB64, 'base64'), format: 'der', type: 'spki' });
    expect(crypto.verify(null, digest, key, Buffer.from(s.signature, 'base64'))).toBe(true);
    ks.rotateKey();
    expect(ks.publishedKeys().some((k) => k.keyId === s.payload.keyId)).toBe(false);   // revoked → not published
  });

  test('CK-07 malformed input is refused, never thrown', () => {
    expect(cp.verifyCheckpoint(null).ok).toBe(false);
    expect(cp.verifyCheckpoint({ payload: {}, signature: 'x' }).ok).toBe(false);
    expect(() => cp.signCheckpoint({ chainLength: 0, headHash: 'a'.repeat(64) })).toThrow(/chainLength/);
    expect(() => cp.signCheckpoint({ chainLength: 5, headHash: 'nope' })).toThrow(/headHash/);
  });

  test('CK-08 a retired (deprecated) key never verifies a checkpoint dated at or after its retirement', () => {
    const before = cp.signCheckpoint({ ...fields(), createdAt: new Date(Date.now() - 60_000).toISOString() });
    // the key that is about to be retired, private part included — COPIED: the store zeroes
    // the retired key's own buffer, so a "holder of the retired key" must hold its own copy
    const live = ks.ensureActiveKey();
    const oldKey = { ...live, privDer: Buffer.from(live.privDer) };
    ks.rotateKeyGracefully();
    const rec = ks.getPublicKey(oldKey.keyId);
    expect(rec).toMatchObject({ status: 'deprecated', retiredAt: expect.any(String) });
    expect(cp.verifyCheckpoint(before)).toEqual({ ok: true });                    // history stays verifiable
    // the retired key signs a NEW checkpoint (a holder of the retired key, or a stale signer)
    const forged = cp.signCheckpoint({ ...fields(), createdAt: new Date(Date.parse(rec.retiredAt) + 365 * 86_400_000).toISOString() },
      { keyStore: { ensureActiveKey: () => oldKey } });
    expect(forged.payload.keyId).toBe(oldKey.keyId);
    expect(cp.verifyCheckpoint(forged)).toEqual({ ok: false, reason: 'CHECKPOINT_KEY_RETIRED: signed after the key was retired' });
    const justAfter = cp.signCheckpoint({ ...fields(), createdAt: new Date(Date.parse(rec.retiredAt) + 1).toISOString() }, { keyStore: { ensureActiveKey: () => oldKey } });
    expect(cp.verifyCheckpoint(justAfter).ok).toBe(false);
    // signed in the same millisecond as the retirement = signed while still active (CK-05's graceful path)
    const sameMs = cp.signCheckpoint({ ...fields(), createdAt: rec.retiredAt }, { keyStore: { ensureActiveKey: () => oldKey } });
    expect(cp.verifyCheckpoint(sameMs)).toEqual({ ok: true });
    // an explicit record resolver gets the same check; a bare-key resolver (offline verifier) keeps the old contract
    expect(cp.verifyCheckpoint(forged, { resolvePublicKey: () => ({ ...rec }) }).ok).toBe(false);
    expect(cp.verifyCheckpoint(forged, { resolvePublicKey: () => ({ ...rec, retiredAt: null }) }))
      .toEqual({ ok: false, reason: 'CHECKPOINT_KEY_RETIRED: retirement time unknown' });
    expect(cp.verifyCheckpoint(forged, { resolvePublicKey: () => rec.pubDer })).toEqual({ ok: true });
  });

  // a key-file writer without the KEK can rewrite public metadata. A 'deprecated' record with a
  // far-future retiredAt made every forged checkpoint dated before that time verify. Retirement is stamped at rotation
  // time, so a future retiredAt (beyond 5 s of clock skew) is refused.
  test('CK-09 a deprecated key record with a retirement time in the future is refused', () => {
    const live = ks.ensureActiveKey();
    const oldKey = { ...live, privDer: Buffer.from(live.privDer) };
    ks.rotateKeyGracefully();
    const rec = ks.getPublicKey(oldKey.keyId);
    const forged = cp.signCheckpoint({ ...fields(), createdAt: new Date().toISOString() }, { keyStore: { ensureActiveKey: () => oldKey } });
    const injected = { ...rec, retiredAt: new Date(Date.now() + 10 * 365 * 86_400_000).toISOString() };
    expect(cp.verifyCheckpoint(forged, { resolvePublicKey: () => injected }))
      .toEqual({ ok: false, reason: 'CHECKPOINT_KEY_RETIRED: retirement time is in the future' });
    // within clock-skew tolerance it is still a normal historical check
    const skew = { ...rec, retiredAt: new Date(Date.now() + 2_000).toISOString() };
    expect(cp.verifyCheckpoint(cp.signCheckpoint({ ...fields(), createdAt: new Date(Date.now() - 1_000).toISOString() },
      { keyStore: { ensureActiveKey: () => oldKey } }), { resolvePublicKey: () => skew })).toEqual({ ok: true });
  });
});
