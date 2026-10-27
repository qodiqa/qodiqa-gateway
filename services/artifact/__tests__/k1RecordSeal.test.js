'use strict';

/**
 * K1 — residual / authenticated artifact key-store records.
 *
 *
 *   K1-A01  every save is sealed: recordSeal marker, a recordMac per record, AAD-bound active ciphertexts
 *   K1-A02  a record injected WITHOUT the KEK (no MAC) is refused: at reload (store kept), at boot (FATAL), and the
 *           on-disk scan reports it as a validation violation (startup FATAL) — CRITICAL KEY_RECORD_MAC_REFUSED
 *   K1-A03  tampered status / retiredAt / a MAC copied from another record are refused
 *   K1-A04  a legacy (pre-K1) store is sealed once on first load (TOFU) and its keys keep signing and verifying
 *   K1-A05  no downgrade: a sealed instance refuses an unsealed file at reload; QODIQA_KEYSTORE_REQUIRE_SEALED=true
 *           refuses the TOFU migration at boot; without it the TOFU path is taken (documented residual)
 *   K1-A06  AAD: a ciphertext moved to another record does not decrypt even with valid MACs; a sealed file carrying an
 *           AAD-less ciphertext is refused; keyEncryption refuses a wrong / missing / stripped AAD
 *   K1-A07  legacy AAD-less ciphertexts still decrypt; an unknown recordSeal version is refused
 *   K1-A08  the MAC key is an HKDF subkey: deterministic, label-separated, never the KEK
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KEK = '7'.repeat(64);
let events = [];

function tmpKeys() { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-k1-seal-')), 'keys.json'); }
function instance(keysPath, env = {}) {
  jest.resetModules();
  jest.doMock('../../logger', () => ({ ...jest.requireActual('../../logger'),
    emit: (severity, eventType, data) => events.push({ severity, eventType, ...(data || {}) }) }));
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  delete process.env.QODIQA_KEYSTORE_REQUIRE_SEALED;
  Object.assign(process.env, env);
  require('../../secrets/secretsProvider')._clearCache();
  return require('../keyStore');
}
const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));
const ev = (t) => events.filter((e) => e.eventType === t);
function resealKeys(d) { // a KEK holder's deliberate edit (call after instance(): same registry and KEK)
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}
function attackerRecord(clientId, version, status, extra = {}) {
  const { publicKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } });
  return { clientId, keyId: `${clientId}:key_v${version}`, version, algorithm: 'ed25519',
    publicKeyDer: Buffer.from(publicKey).toString('base64'), status, createdAt: new Date(Date.now() - 3600e3).toISOString(),
    retiredAt: status === 'deprecated' ? new Date(Date.now() + 2000).toISOString() : null, rotationDeadline: null, expiresAt: null, ...extra };
}
// Rewrite a sealed file into EXACTLY what pre-K1 code wrote: no marker, no MACs, AAD-less ciphertexts.
function toLegacy(ks, f) {
  const d = read(f);
  delete d.recordSeal;
  const { encryptKeyMaterial } = require('../keyEncryption');
  for (const [cid, cd] of Object.entries(d.clients)) {
    for (const [kid, e] of Object.entries(cd)) {
      delete e.recordMac;
      if (e.status === 'active') e.encryptedPrivateKeyDer = encryptKeyMaterial(ks.getActiveKey(cid).privDer, { keyId: kid, createdAt: e.createdAt });
    }
  }
  write(f, d);
  return d;
}

const ORIG = { KEK: process.env.QODIQA_KEY_ENCRYPTION_KEY, KP: process.env.QODIQA_KEYS_PATH, RS: process.env.QODIQA_KEYSTORE_REQUIRE_SEALED };
beforeEach(() => { events = []; });
afterAll(() => {
  jest.dontMock('../../logger');
  for (const [k, v] of [['QODIQA_KEY_ENCRYPTION_KEY', ORIG.KEK], ['QODIQA_KEYS_PATH', ORIG.KP], ['QODIQA_KEYSTORE_REQUIRE_SEALED', ORIG.RS]]) {
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

test('K1-A01 every save is sealed: marker, a MAC per record, AAD-bound active ciphertexts; a fresh instance loads it', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  a.rotateKey('acme', { mode: 'graceful' });
  const d = read(f);
  expect(d.recordSeal).toMatchObject({ version: 1, mac: 'HMAC-SHA256', aad: 'qodiqa-keyrec-aad-v1' });
  for (const e of Object.values(d.clients.acme)) expect(e.recordMac).toMatch(/^[0-9a-f]{64}$/);
  expect(d.clients.acme['acme:key_v2'].encryptedPrivateKeyDer.aad).toBe('qodiqa-keyrec-aad-v1');
  const b = instance(f);
  expect(b.getActiveKey('acme').keyId).toBe('acme:key_v2');
  expect(b.getPublicKey('acme:key_v1').status).toBe('deprecated');
  expect(b.validateKeyStore().violations).toEqual([]);
});

test('K1-A02 an injected record without a MAC is refused at reload (store kept), at boot (FATAL) and by validation', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  const d = read(f);
  d.clients.acme['acme:key_v9'] = attackerRecord('acme', 9, 'deprecated'); // the J1 injection
  write(f, d);

  const r = a.reloadFromDisk();
  expect(r.reloaded).toBe(false);
  expect(r.error).toMatch(/record MAC missing for "acme:key_v9"/);
  expect(() => a.getPublicKey('acme:key_v9')).toThrow(/unknown keyId/);
  expect(a.getActiveKey('acme').keyId).toBe('acme:key_v1');
  expect(ev('KEY_RECORD_MAC_REFUSED')[0]).toMatchObject({ severity: 'CRITICAL', kind: 'mac', failures: [{ keyId: 'acme:key_v9', reason: 'missing' }] });
  expect(a.validateKeyStore().violations).toEqual(expect.arrayContaining([
    expect.objectContaining({ type: 'KEY_RECORD_MAC_INVALID', keyId: 'acme:key_v9' })]));
  // a mutation over the refused file is refused too (reload-before-mutation, fail closed)
  expect(() => a.rotateKey('acme', { mode: 'graceful' })).toThrow(/mutation refused/);

  expect(() => instance(f).getPublicKey('acme:key_v9')).toThrow(/FATAL.*record MAC missing/);
});

test('K1-A03 tampered status, tampered retiredAt and a MAC copied from another record are refused', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  a.rotateKey('acme', { mode: 'graceful' });              // v1 deprecated
  a.rotateKey('acme', { mode: 'emergency' });             // v2 revoked, v3 active
  const sealed = read(f);
  const tampers = {
    'revoked → deprecated': (d) => { d.clients.acme['acme:key_v2'].status = 'deprecated'; d.clients.acme['acme:key_v2'].retiredAt = new Date().toISOString(); delete d.clients.acme['acme:key_v2'].revokedAt; },
    'retiredAt moved': (d) => { d.clients.acme['acme:key_v1'].retiredAt = new Date(Date.now() + 1000).toISOString(); },
    'publicKey swapped': (d) => { d.clients.acme['acme:key_v1'].publicKeyDer = attackerRecord('acme', 1, 'deprecated').publicKeyDer; },
    'MAC copied': (d) => { const inj = attackerRecord('acme', 9, 'deprecated'); inj.recordMac = d.clients.acme['acme:key_v1'].recordMac; d.clients.acme['acme:key_v9'] = inj; },
  };
  for (const [name, tamper] of Object.entries(tampers)) {
    const d = JSON.parse(JSON.stringify(sealed));
    tamper(d);
    write(f, d);
    let err = null;
    try { instance(f).listKeys(); } catch (e) { err = e; }
    expect([name, !!err && /record MAC invalid/.test(err.message)]).toEqual([name, true]);
  }
});

test('K1-A04 a legacy (pre-K1) store is sealed once on first load and its keys keep signing and verifying', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  a.rotateKey('acme', { mode: 'graceful' });
  const { privDer, keyId } = a.getActiveKey('acme');
  const digest = crypto.createHash('sha256').update('signed before the upgrade').digest();
  const { sign, verify } = require('../../../src/infra/crypto/ed25519');
  const sig = sign(digest, privDer);
  toLegacy(a, f);
  expect(read(f).recordSeal).toBeUndefined();

  events = [];
  const b = instance(f);
  expect(b.getActiveKey('acme').keyId).toBe(keyId);
  expect(verify(digest, sig, b.getPublicKey(keyId).pubDer)).toBe(true);
  expect(b.getPublicKey('acme:key_v1').status).toBe('deprecated');
  expect(ev('KEY_RECORDS_SEALED')).toEqual([expect.objectContaining({ severity: 'WARN', tofu: true })]);
  const d = read(f);
  expect(d.recordSeal).toBeDefined();
  expect(d.clients.acme[keyId].encryptedPrivateKeyDer.aad).toBe('qodiqa-keyrec-aad-v1');
  expect(b.validateKeyStore().violations).toEqual([]);
  // the migrated key signs and the next fresh instance (sealed path, no TOFU) verifies
  const sig2 = sign(digest, b.getActiveKey('acme').privDer);
  events = [];
  const c = instance(f);
  expect(verify(digest, sig2, c.getPublicKey(keyId).pubDer)).toBe(true);
  expect(ev('KEY_RECORDS_SEALED')).toEqual([]);
});

test('K1-A05 no downgrade: unsealed file refused at reload; REQUIRE_SEALED refuses TOFU at boot; default boot TOFUs (residual)', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  const legacy = toLegacy(a, f);
  legacy.clients.acme['acme:key_v9'] = attackerRecord('acme', 9, 'deprecated');
  write(f, legacy);

  const r = a.reloadFromDisk();
  expect(r.reloaded).toBe(false);
  expect(r.error).toMatch(/not sealed.*never downgraded at reload/);
  expect(() => a.getPublicKey('acme:key_v9')).toThrow(/unknown keyId/);

  expect(() => instance(f, { QODIQA_KEYSTORE_REQUIRE_SEALED: 'true' }).listKeys()).toThrow(/FATAL.*QODIQA_KEYSTORE_REQUIRE_SEALED=true/);
  expect(ev('KEY_RECORD_MAC_REFUSED').some((e) => e.kind === 'unsealed')).toBe(true);

  // Residual, by design of the TOFU migration: a fresh boot WITHOUT the env var seals what it finds — visibly.
  events = [];
  const b = instance(f);
  expect(b.getPublicKey('acme:key_v9').status).toBe('deprecated');
  expect(ev('KEY_RECORDS_SEALED')).toHaveLength(1);
});

test('K1-A06 AAD binds each ciphertext to its record; sealed files never carry AAD-less ciphertexts', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('acme');
  a.rotateKey('beta');
  const d = read(f);
  const x = d.clients.acme['acme:key_v1'].encryptedPrivateKeyDer;
  d.clients.acme['acme:key_v1'].encryptedPrivateKeyDer = d.clients.beta['beta:key_v1'].encryptedPrivateKeyDer;
  d.clients.beta['beta:key_v1'].encryptedPrivateKeyDer = x;
  write(f, resealKeys(d)); // even with VALID MACs (a KEK holder's mistake), the swapped ciphertexts do not decrypt
  expect(() => instance(f).listKeys()).toThrow(/decryption failed/);

  const g = tmpKeys();
  const c = instance(g);
  c.rotateKey('acme');
  const legacy = toLegacy(c, g);
  write(g, resealKeys(legacy)); // sealed marker + MACs, but an AAD-less ciphertext
  expect(() => instance(g).listKeys()).toThrow(/without the record AAD binding/);

  const ke = require('../keyEncryption');
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  const priv = crypto.randomBytes(48);
  const ids = { keyId: 'acme:key_v1', clientId: 'acme', version: 1, publicKeyDer: Buffer.from('pub-a') };
  const bound = ke.encryptKeyMaterial(priv, { keyId: 'acme:key_v1', aad: seal.recordAad('artifact', ids), aadLabel: seal.AAD_LABEL });
  expect(ke.decryptKeyMaterial(bound, { aad: seal.recordAad('artifact', ids), aadLabel: seal.AAD_LABEL }).equals(priv)).toBe(true);
  expect(() => ke.decryptKeyMaterial(bound, { aad: seal.recordAad('artifact', { ...ids, keyId: 'acme:key_v2' }), aadLabel: seal.AAD_LABEL })).toThrow(/decryption failed/);
  expect(() => ke.decryptKeyMaterial(bound, { aad: seal.recordAad('transparency', ids), aadLabel: seal.AAD_LABEL })).toThrow(/decryption failed/);
  expect(() => ke.decryptKeyMaterial(bound)).toThrow(/AAD-bound/);
  const stripped = { ...bound }; delete stripped.aad;
  expect(() => ke.decryptKeyMaterial(stripped)).toThrow(/decryption failed/);
});

test('K1-A07 legacy AAD-less ciphertexts still decrypt; an unknown recordSeal version is refused', () => {
  const ke = (instance(tmpKeys()), require('../keyEncryption'));
  const priv = crypto.randomBytes(48);
  const legacy = ke.encryptKeyMaterial(priv, { keyId: 'x' });
  expect(legacy.aad).toBeUndefined();
  expect(ke.decryptKeyMaterial(legacy).equals(priv)).toBe(true);
  expect(ke.decryptKeyMaterial({ algorithm: legacy.algorithm, iv: legacy.iv, ciphertext: legacy.encryptedPrivateKey, tag: legacy.authTag }).equals(priv)).toBe(true);

  const f = tmpKeys();
  instance(f).rotateKey('acme');
  const d = read(f);
  d.recordSeal = { ...d.recordSeal, version: 2 };
  write(f, d);
  expect(() => instance(f).listKeys()).toThrow(/unsupported recordSeal marker/);
});

test('K1-A08 the record MAC key is an HKDF subkey of the KEK: deterministic, label-separated, never the KEK', () => {
  instance(tmpKeys());
  const ke = require('../keyEncryption');
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  const k1 = ke.deriveKekSubkey(seal.RECORD_MAC_INFO);
  expect(k1).toHaveLength(32);
  expect(k1.equals(ke.deriveKekSubkey(seal.RECORD_MAC_INFO))).toBe(true);
  expect(k1.equals(ke.deriveKekSubkey('another-label-v1'))).toBe(false);
  expect(k1.equals(Buffer.from(KEK, 'hex'))).toBe(false);
  expect(k1.toString('hex')).not.toBe(ke.computeKekFingerprint());
  expect(() => ke.deriveKekSubkey('short')).toThrow(/at least 8/);
});
