'use strict';

/**
 *timed key revocation. A REVOKED transparency key stays unusable by default; only when the caller
 * supplies a trusted time from an authority independent of the record (trustedAt) and that time precedes the key's revokedAt does the
 * key verify - so an emergency rotation no longer has to invalidate every signature made BEFORE the compromise.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KEK = 'c'.repeat(64);

function store() {
  jest.resetModules();
  jest.doMock('../../../../services/logger', () => ({ emit: () => {} }));
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  require('../../../../services/secrets/secretsProvider')._clearCache();
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f29-')), 'transparency-keys.json');
  const { createEd25519KeyStore } = require('../ed25519KeyStore');
  return createEd25519KeyStore({
    dataPath: file, purpose: 'transparency', resolveClientId: () => 'tr-f29', storeName: 'TransparencyKeyStore', noun: 'transparency',
    title: 'Transparency', eventPrefix: 'TRANSPARENCY_KEY', storeEvent: 'TRANSPARENCY_KEYSTORE_LOADED', violationNoun: 'TRANSPARENCY',
  });
}

describe('timed revocation of a transparency key', () => {
  let ks; let firstId; let revokedAt;
  beforeEach(() => {
    ks = store();
    ks.rotateKey({ mode: 'graceful' });             // provision the first key
    firstId = ks.getActiveKey().keyId;
    ks.rotateKey({ mode: 'emergency' });            // revokes the first key now
    revokedAt = ks.listKeys().find((k) => k.keyId === firstId).revokedAt;
  });

  test('F2-TR-01 default: a revoked key throws, with or without a time argument it cannot be trusted by itself', () => {
    expect(() => ks.getPublicKey(firstId)).toThrow(/revoked/);
    expect(() => ks.getPublicKey(firstId, {})).toThrow(/revoked/);
  });

  test('F2-TR-02 a trusted time BEFORE revokedAt returns the key, flagged as timed validity', () => {
    const before = new Date(new Date(revokedAt).getTime() - 60_000).toISOString();
    const k = ks.getPublicKey(firstId, { trustedAt: before });
    expect(Buffer.isBuffer(k.pubDer)).toBe(true);
    expect(k).toMatchObject({ status: 'revoked', timedValidity: true, revokedAt });
  });

  test('F2-TR-03 a trusted time at or after revokedAt is refused', () => {
    expect(() => ks.getPublicKey(firstId, { trustedAt: revokedAt })).toThrow(/revoked/);
    expect(() => ks.getPublicKey(firstId, { trustedAt: new Date(new Date(revokedAt).getTime() + 1).toISOString() })).toThrow(/revoked/);
  });

  test('F2-TR-04 garbage or missing trusted times are refused', () => {
    for (const bad of ['not-a-date', NaN, {}, '']) expect(() => ks.getPublicKey(firstId, { trustedAt: bad })).toThrow(/revoked/);
  });

  test('F2-TR-05 the active key is unaffected by the option', () => {
    const active = ks.getActiveKey().keyId;
    expect(ks.getPublicKey(active, { trustedAt: '2000-01-01T00:00:00Z' }).status).toBe('active');
  });
});

describe('checkSignatureTrust timed mode', () => {
  const log = require('../log');
  const { checkSignatureTrust } = require('../signatureTrust');

  function adapter(status, revokedAt) {
    const { publicKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } });
    return {
      getKeyStatus: () => status,
      getPublicKey: (_id, o = {}) => {
        if (status !== 'revoked') return { pubDer: publicKey };
        if (o.trustedAt != null && new Date(o.trustedAt) < new Date(revokedAt)) return { pubDer: publicKey };
        throw new Error('revoked');
      },
    };
  }
  const rec = { signature: 'x', signer_key_id: 'k1' };

  test('F2-TR-06 without trustedAt a revoked key is KEY_NOT_VERIFIABLE (unchanged default)', () => {
    const r = checkSignatureTrust('entry', rec, { keys: adapter('revoked', '2026-01-02T00:00:00Z') });
    expect(r).toMatchObject({ ok: false, code: 'KEY_NOT_VERIFIABLE', keyStatus: 'revoked' });
  });

  test('F2-TR-07 with a trustedAt after revocation it stays KEY_NOT_VERIFIABLE', () => {
    const r = checkSignatureTrust('entry', rec, { keys: adapter('revoked', '2026-01-02T00:00:00Z'), trustedAt: '2026-02-01T00:00:00Z' });
    expect(r).toMatchObject({ ok: false, code: 'KEY_NOT_VERIFIABLE' });
  });

  test('F2-TR-08 with a trustedAt before revocation the signature itself is still checked (a bad signature fails)', () => {
    const spy = jest.spyOn(log, 'verifyEntrySignature');
    spy.mockReturnValueOnce(false);
    expect(checkSignatureTrust('entry', rec, { keys: adapter('revoked', '2026-01-02T00:00:00Z'), trustedAt: '2026-01-01T00:00:00Z' }))
      .toMatchObject({ ok: false, code: 'SIGNATURE_INVALID' });
    spy.mockReturnValueOnce(true);
    expect(checkSignatureTrust('entry', rec, { keys: adapter('revoked', '2026-01-02T00:00:00Z'), trustedAt: '2026-01-01T00:00:00Z' }))
      .toMatchObject({ ok: true, keyStatus: 'revoked', timedRevocation: true });
    spy.mockRestore();
  });
});
