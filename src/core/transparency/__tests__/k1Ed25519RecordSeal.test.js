'use strict';

/**
 * K1 — residual / for the shared Ed25519 store (transparency + audit-checkpoint).
 *
 *
 *   K1-T01  every save is sealed (marker, per-record MAC, AAD-bound ciphertext) — both trust domains
 *   K1-T02  the checkpoint J1 attack end to end: a public-only 'deprecated' key injected without the KEK, plus a
 *           checkpoint forged with it, never verifies — the reload is refused (store kept), boot is FATAL, and the
 *           on-disk scan is a violation (startup FATAL); genuine checkpoints keep verifying
 *   K1-T03  tampered status / retiredAt refused; a sealed record moved into the other trust domain is refused
 *   K1-T04  a legacy store is sealed once on first load (TOFU); what its keys signed still verifies
 *   K1-T05  no downgrade at reload; QODIQA_KEYSTORE_REQUIRE_SEALED=true refuses TOFU at boot
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KEK = '8'.repeat(64);
let events = [];

function tmpFile(name) { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-k1-ed-')), name); }
const DOMAINS = {
  transparency: { purpose: 'transparency', clientId: 'tr-k1', file: 'transparency-keys.json', E: 'TRANSPARENCY_KEY', V: 'TRANSPARENCY' },
  checkpoint: { purpose: 'audit-checkpoint', clientId: 'cp-k1', file: 'checkpoint-keys.json', E: 'CHECKPOINT_KEY', V: 'CHECKPOINT' },
};
function instance(file, dom, env = {}) {
  jest.resetModules();
  jest.doMock('../../../../services/logger', () => ({ emit: (severity, eventType, data) => events.push({ severity, eventType, ...(data || {}) }) }));
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  delete process.env.QODIQA_KEYSTORE_REQUIRE_SEALED;
  Object.assign(process.env, env);
  require('../../../../services/secrets/secretsProvider')._clearCache();
  const { createEd25519KeyStore } = require('../ed25519KeyStore');
  return createEd25519KeyStore({ dataPath: file, purpose: dom.purpose, resolveClientId: () => dom.clientId,
    storeName: 'K1Store', noun: dom === DOMAINS.checkpoint ? 'checkpoint' : 'transparency', title: 'K1',
    eventPrefix: dom.E, storeEvent: `${dom.E}STORE_LOADED`, violationNoun: dom.V });
}
const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));
const ev = (t) => events.filter((e) => e.eventType === t);
function reseal(d, purpose) {
  const seal = require('../../../infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), purpose);
}
function attacker(clientId, version, purpose) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
  const keyId = `${clientId}:key_v${version}`;
  return { keyId, privDer: Buffer.from(privateKey), version,
    record: { clientId, keyId, version, algorithm: 'ed25519', purpose, publicKeyDer: Buffer.from(publicKey).toString('base64'),
      status: 'deprecated', createdAt: new Date(Date.now() - 3600e3).toISOString(), retiredAt: new Date(Date.now() + 2000).toISOString(),
      rotationDeadline: null, expiresAt: null } };
}
function toLegacy(store, f) {
  const d = read(f);
  delete d.recordSeal;
  const { encryptKeyMaterial } = require('../../../../services/artifact/keyEncryption');
  for (const [kid, e] of Object.entries(d.keys)) {
    delete e.recordMac;
    if (e.status === 'active') e.encryptedPrivateKeyDer = encryptKeyMaterial(store.getActiveKey().privDer, { keyId: kid, createdAt: e.createdAt });
  }
  write(f, d);
  return d;
}
const H = 'a'.repeat(64);

const ORIG = { KEK: process.env.QODIQA_KEY_ENCRYPTION_KEY, RS: process.env.QODIQA_KEYSTORE_REQUIRE_SEALED };
beforeEach(() => { events = []; });
afterAll(() => {
  jest.dontMock('../../../../services/logger');
  if (ORIG.KEK === undefined) delete process.env.QODIQA_KEY_ENCRYPTION_KEY; else process.env.QODIQA_KEY_ENCRYPTION_KEY = ORIG.KEK;
  if (ORIG.RS === undefined) delete process.env.QODIQA_KEYSTORE_REQUIRE_SEALED; else process.env.QODIQA_KEYSTORE_REQUIRE_SEALED = ORIG.RS;
});

describe.each(Object.keys(DOMAINS))('%s store', (name) => {
  const dom = DOMAINS[name];

  test('K1-T01 every save is sealed and a fresh instance loads it', () => {
    const f = tmpFile(dom.file);
    const s = instance(f, dom);
    s.rotateKey();
    s.rotateKey({ mode: 'graceful' });
    const d = read(f);
    expect(d.recordSeal).toMatchObject({ version: 1 });
    for (const e of Object.values(d.keys)) expect(e.recordMac).toMatch(/^[0-9a-f]{64}$/);
    expect(d.keys[`${dom.clientId}:key_v2`].encryptedPrivateKeyDer.aad).toBe('qodiqa-keyrec-aad-v1');
    const t = instance(f, dom);
    expect(t.getActiveKey().keyId).toBe(`${dom.clientId}:key_v2`);
    expect(t.validateKeyStore().violations).toEqual([]);
  });

  test('K1-T03 tampered status and retiredAt are refused; a sealed record moved across trust domains is refused', () => {
    const f = tmpFile(dom.file);
    const s = instance(f, dom);
    s.rotateKey();
    s.rotateKey({ mode: 'graceful' });   // v1 deprecated
    s.rotateKey({ mode: 'emergency' });  // v2 revoked
    const sealed = read(f);
    for (const tamper of [
      (d) => { const e = d.keys[`${dom.clientId}:key_v2`]; e.status = 'deprecated'; e.retiredAt = new Date().toISOString(); delete e.revokedAt; },
      (d) => { d.keys[`${dom.clientId}:key_v1`].retiredAt = new Date(Date.now() + 1000).toISOString(); },
    ]) {
      const d = JSON.parse(JSON.stringify(sealed));
      tamper(d);
      write(f, d);
      expect(() => instance(f, dom).listKeys()).toThrow(/record MAC invalid/);
    }
    // the other trust domain's sealed record, relabelled as ours, does not authenticate (domain-separated MAC)
    const other = name === 'transparency' ? DOMAINS.checkpoint : DOMAINS.transparency;
    const g = tmpFile(other.file);
    instance(g, other).rotateKey();
    const od = read(g);
    const [oid, oe] = Object.entries(od.keys)[0];
    const moved = { ...oe, clientId: dom.clientId, keyId: `${dom.clientId}:key_v7`, version: 7, purpose: dom.purpose, status: 'deprecated', retiredAt: new Date().toISOString() };
    delete moved.encryptedPrivateKeyDer;
    expect(oid).toBeTruthy();
    const d = JSON.parse(JSON.stringify(sealed));
    d.keys[moved.keyId] = moved;
    write(f, d);
    expect(() => instance(f, dom).listKeys()).toThrow(/record MAC invalid/);
  });

  test('K1-T04 a legacy store is sealed once on first load; what its keys signed still verifies', () => {
    const f = tmpFile(dom.file);
    const s = instance(f, dom);
    s.rotateKey();
    const { sign, verify } = require('../../../infra/crypto/ed25519');
    const digest = crypto.createHash('sha256').update('root before upgrade').digest();
    const old = s.getActiveKey();
    const sig = sign(digest, old.privDer);
    toLegacy(s, f);
    events = [];
    const t = instance(f, dom);
    expect(t.getActiveKey().keyId).toBe(old.keyId);
    expect(verify(digest, sig, t.getPublicKey(old.keyId).pubDer)).toBe(true);
    expect(ev(`${dom.E}_RECORDS_SEALED`)).toEqual([expect.objectContaining({ severity: 'WARN', tofu: true })]);
    expect(read(f).recordSeal).toBeDefined();
    expect(t.validateKeyStore().violations).toEqual([]);
  });

  test('K1-T05 no downgrade at reload; QODIQA_KEYSTORE_REQUIRE_SEALED=true refuses the TOFU seal at boot', () => {
    const f = tmpFile(dom.file);
    const s = instance(f, dom);
    s.rotateKey();
    const d = toLegacy(s, f);
    const a = attacker(dom.clientId, 9, dom.purpose);
    d.keys[a.keyId] = a.record;
    write(f, d);
    const r = s.reloadFromDisk();
    expect(r.reloaded).toBe(false);
    expect(r.error).toMatch(/never downgraded at reload/);
    expect(() => s.getPublicKey(a.keyId)).toThrow(/unknown/);
    expect(() => instance(f, dom, { QODIQA_KEYSTORE_REQUIRE_SEALED: 'true' }).listKeys()).toThrow(/QODIQA_KEYSTORE_REQUIRE_SEALED=true/);
    expect(ev(`${dom.E}_RECORD_MAC_REFUSED`).length).toBeGreaterThan(0);
  });
});

test('K1-T02 checkpoint J1 attack: an injected deprecated key and a checkpoint forged with it never verify', () => {
  const dom = DOMAINS.checkpoint;
  const f = tmpFile(dom.file);
  const s = instance(f, dom);
  s.rotateKey();
  const { signCheckpoint, verifyCheckpoint } = require('../../audit/checkpoint/checkpoint');
  const ks = { ensureActiveKey: () => s.getActiveKey() };
  const resolve = { resolvePublicKey: (id) => s.getPublicKey(id) };
  const genuine = signCheckpoint({ chainLength: 10, headHash: H }, { keyStore: ks });
  expect(verifyCheckpoint(genuine, resolve)).toEqual({ ok: true });

  const a = attacker(dom.clientId, 9, dom.purpose);
  const forged = signCheckpoint({ chainLength: 11, headHash: H }, { keyStore: { ensureActiveKey: () => a } });
  const d = read(f);
  d.keys[a.keyId] = a.record; // KEK-less write of a public-only record
  write(f, d);

  const r = s.reloadFromDisk();
  expect(r.reloaded).toBe(false);
  expect(r.error).toMatch(/record MAC missing/);
  expect(ev('CHECKPOINT_KEY_RECORD_MAC_REFUSED')[0]).toMatchObject({ severity: 'CRITICAL' });
  expect(verifyCheckpoint(forged, resolve)).toMatchObject({ ok: false, reason: expect.stringMatching(/CHECKPOINT_KEY_UNAVAILABLE/) });
  expect(verifyCheckpoint(genuine, resolve)).toEqual({ ok: true });
  expect(s.validateKeyStore().violations).toEqual(expect.arrayContaining([
    expect.objectContaining({ type: 'CHECKPOINT_KEY_RECORD_MAC_INVALID', keyId: a.keyId })]));
  expect(() => instance(f, dom).listKeys()).toThrow(/FATAL.*record MAC missing/);
});
