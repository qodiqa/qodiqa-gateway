'use strict';

/**
 * phase 6 — the shared Ed25519 key store (transparency + audit-checkpoint trust domains) brought to parity
 * with the artifact key store.
 *
 * PL-K06-01..03 (i) plaintext private key: migrated + re-scanned at bootstrap, a violation at
 *                                  validation, never adopted by a reload
 * PL-K06-04..05 (ii) rotation mode: an unrecognised explicit mode throws; an omitted mode is the
 * documented 'emergency' default and is flagged modeDefaulted in the events
 * PL-K06-06..07 (iii) the outgoing key's private bytes are zeroed on rotate and on revoke
 * PL-K06-08..09 (iv) ownership: map key / keyId / clientId:key_v<version> / purpose must agree
 * PL-K06-10..13 (v) cross-instance reload: revocation propagates, a reload never un-revokes, a stale
 *                                  writer re-loads before mutating, keyManager.reload() drives both trust domains
 * PL-K10-01..03 revokedAt persisted and reloaded; files written before the field load with null
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const KEK = 'c'.repeat(64);
let events;

function tmpFile(name = 'transparency-keys.json') {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-ed25519-')), name);
}

// A fresh, independent store instance over `file` (a separate process sharing the same volume).
function instance(file, { purpose = 'transparency', clientId = 'tr-plk06' } = {}) {
  jest.resetModules();
  events = events || [];
  jest.doMock('../../../../services/logger', () => ({ emit: (severity, eventType, data) => events.push({ severity, eventType, ...(data || {}) }) }));
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  require('../../../../services/secrets/secretsProvider')._clearCache();
  const { createEd25519KeyStore } = require('../ed25519KeyStore');
  return createEd25519KeyStore({
    dataPath: file, purpose, resolveClientId: () => clientId, storeName: 'TransparencyKeyStore', noun: 'transparency',
    title: 'Transparency', eventPrefix: 'TRANSPARENCY_KEY', storeEvent: 'TRANSPARENCY_KEYSTORE_LOADED', violationNoun: 'TRANSPARENCY',
  });
}

const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const write = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));
const ev = (type) => events.filter((e) => e.eventType === type);
// K1: fixtures that tamper with a file to exercise a NON-MAC layer (plaintext scan, revokedAt parsing)
// re-seal it as a KEK holder would — otherwise the record-MAC check (src/infra/crypto/keyRecordSeal.js) refuses the
// file first and the layer under test is never reached. Call after instance() (same module registry and KEK).
function reseal(d, purpose = 'transparency') {
  const seal = require('../../../infra/crypto/keyRecordSeal');
  const macKey = require('../../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO);
  d.recordSeal = seal.SEAL_DESCRIPTOR;
  for (const [k, e] of Object.entries(d.keys)) { delete e.recordMac; e.recordMac = seal.computeRecordMac(macKey, purpose, e, { mapKey: k }); }
  return d;
}

function plaintextEntry(clientId = 'tr-plk06', version = 1) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const now = new Date().toISOString();
  return {
    clientId, keyId: `${clientId}:key_v${version}`, version, algorithm: 'ed25519', purpose: 'transparency',
    publicKeyDer: Buffer.from(publicKey).toString('base64'), privateKeyDer: Buffer.from(privateKey).toString('base64'),
    status: 'active', createdAt: now, retiredAt: null,
    rotationDeadline: new Date(Date.now() + 90 * 864e5).toISOString(), expiresAt: new Date(Date.now() + 180 * 864e5).toISOString(),
  };
}

const ORIG_KEK = process.env.QODIQA_KEY_ENCRYPTION_KEY;
beforeEach(() => { events = []; });
afterAll(() => {
  jest.dontMock('../../../../services/logger');
  if (ORIG_KEK === undefined) delete process.env.QODIQA_KEY_ENCRYPTION_KEY; else process.env.QODIQA_KEY_ENCRYPTION_KEY = ORIG_KEK;
});

describe('(i) — plaintext private key', () => {
  test('PL-K06-01 a legacy plaintext active key is re-encrypted at bootstrap and never stays plaintext on disk', () => {
    const f = tmpFile();
    const e = plaintextEntry();
    write(f, { version: 1, keys: { [e.keyId]: e } });
    const s = instance(f);
    expect(s.getActiveKey().keyId).toBe(e.keyId);
    const disk = read(f);
    expect(disk.keys[e.keyId].privateKeyDer).toBeUndefined();
    expect(disk.keys[e.keyId].encryptedPrivateKeyDer).toBeDefined();
    expect(disk.kekFingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(ev('TRANSPARENCY_KEY_MIGRATION_COMPLETED')).toHaveLength(1);
    // the re-encrypted key is the same key (a fresh instance decrypts it and signs with it)
    expect(instance(f).getActiveKey().pubDer.toString('base64')).toBe(e.publicKeyDer);
  });

  test('PL-K06-02 plaintext that appears on disk after bootstrap is a validation violation (startup treats it as FATAL)', () => {
    const f = tmpFile();
    const s = instance(f);
    s.rotateKey();
    const disk = read(f);
    const id = Object.keys(disk.keys)[0];
    disk.keys[id].privateKeyDer = 'AAAA';
    write(f, reseal(disk));
    const v = s.validateKeyStore().violations;
    expect(v).toEqual([expect.objectContaining({ type: 'PLAINTEXT_TRANSPARENCY_KEY', keyId: id })]);
    expect(ev('TRANSPARENCY_KEY_PLAINTEXT_DETECTED').length).toBeGreaterThan(0);
  });

  test('PL-K06-03 a reload never adopts a file holding a plaintext key (live store kept)', () => {
    const f = tmpFile();
    const s = instance(f);
    s.rotateKey();
    const liveId = s.getActiveKey().keyId;
    const e = plaintextEntry('tr-plk06', 9);
    write(f, reseal({ version: 1, keys: { [e.keyId]: e } }));
    const r = s.reloadFromDisk();
    expect(r.reloaded).toBe(false);
    expect(r.error).toMatch(/plaintext/);
    expect(s.getActiveKey().keyId).toBe(liveId);
  });
});

describe('(ii) — rotation mode', () => {
  test('PL-K06-04 an explicit but unrecognised mode throws and changes nothing', () => {
    const f = tmpFile();
    const s = instance(f);
    s.rotateKey();
    const before = fs.readFileSync(f, 'utf8');
    for (const mode of ['gracefull', 'GRACEFUL', '', null, 1]) {
      expect(() => s.rotateKey({ mode })).toThrow(/opts\.mode must be exactly 'graceful' or 'emergency'/);
    }
    expect(fs.readFileSync(f, 'utf8')).toBe(before);
  });

  test('PL-K06-05 an omitted mode is the emergency default, flagged modeDefaulted; explicit modes are not', () => {
    const f = tmpFile();
    const s = instance(f);
    s.rotateKey();
    const r1 = s.rotateKey();
    expect(r1).toMatchObject({ mode: 'emergency', previousKeyStatus: 'revoked' });
    expect(ev('TRANSPARENCY_KEY_ROTATED').at(-1)).toMatchObject({ mode: 'emergency', modeDefaulted: true });
    const r2 = s.rotateKey({ mode: 'emergency' });
    expect(r2.mode).toBe('emergency');
    expect(ev('TRANSPARENCY_KEY_ROTATED').at(-1).modeDefaulted).toBeUndefined();
    expect(s.rotateKey({ mode: 'graceful' }).previousKeyStatus).toBe('deprecated');
  });
});

describe('(iii) — zeroization', () => {
  test('PL-K06-06 rotation zeroes the outgoing private key bytes (graceful and emergency)', () => {
    const s = instance(tmpFile());
    s.rotateKey();
    const k1 = s.getActiveKey().privDer;
    expect(k1.some((b) => b !== 0)).toBe(true);
    s.rotateKey({ mode: 'graceful' });
    expect(k1.every((b) => b === 0)).toBe(true);
    const k2 = s.getActiveKey().privDer;
    s.rotateKey({ mode: 'emergency' });
    expect(k2.every((b) => b === 0)).toBe(true);
    expect(s.getActiveKey().privDer.some((b) => b !== 0)).toBe(true);
  });

  test('PL-K06-07 revocation zeroes the revoked key\'s private bytes', () => {
    const s = instance(tmpFile());
    s.rotateKey();
    const { keyId, privDer } = s.getActiveKey();
    s.revokeKey(keyId);
    expect(privDer.every((b) => b === 0)).toBe(true);
  });
});

describe('(iv) — ownership / identity check', () => {
  test('PL-K06-08 a record whose map key does not match clientId:key_v<version> (or its keyId) is FATAL', () => {
    for (const tamper of [
      (d, id) => { d.keys[id].version = 7; },
      (d, id) => { d.keys[id].clientId = 'tr-other'; },
      (d, id) => { d.keys[id].keyId = 'tr-other:key_v1'; },
      (d, id) => { d.keys['tr-plk06:key_v5'] = d.keys[id]; delete d.keys[id]; },
    ]) {
      const f = tmpFile();
      instance(f).rotateKey();
      const d = read(f);
      tamper(d, Object.keys(d.keys)[0]);
      write(f, d);
      expect(() => instance(f).getActiveKey()).toThrow(/not self-consistent|ownership check failed/);
    }
  });

  test('PL-K06-09 a record of another trust domain (purpose) is refused', () => {
    const f = tmpFile('checkpoint-keys.json');
    instance(f, { purpose: 'audit-checkpoint', clientId: 'cp-x' }).rotateKey();
    // the checkpoint file mounted where the transparency store expects its own file
    expect(() => instance(f, { purpose: 'transparency', clientId: 'cp-x' }).getActiveKey())
      .toThrow(/purpose "audit-checkpoint", expected "transparency"/);
  });
});

describe('(v) — cross-instance reload, never un-revoke', () => {
  test('PL-K06-10 a revocation on instance A reaches instance B through reloadFromDisk()', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    a.rotateKey({ mode: 'graceful' }); // v1 deprecated, v2 active
    const b = instance(f);
    expect(b.getPublicKey('tr-plk06:key_v1').status).toBe('deprecated');
    a.revokeKey('tr-plk06:key_v1');
    const r = b.reloadFromDisk();
    expect(r).toMatchObject({ reloaded: true, revoked: 1 });
    expect(() => b.getPublicKey('tr-plk06:key_v1')).toThrow(/revoked/);
    expect(ev('TRANSPARENCY_KEY_REVOCATION_PROPAGATED')).toEqual([expect.objectContaining({ keyId: 'tr-plk06:key_v1' })]);
  });

  test('PL-K06-11 a reload never un-revokes: the key stays revoked, CRITICAL is emitted and the disk is repaired', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    a.rotateKey({ mode: 'graceful' });
    const staleSnapshot = fs.readFileSync(f, 'utf8'); // v1 deprecated
    a.revokeKey('tr-plk06:key_v1');
    fs.writeFileSync(f, staleSnapshot); // a stale writer puts the pre-revocation state back
    const r = a.reloadFromDisk();
    expect(r.reloaded).toBe(true);
    expect(() => a.getPublicKey('tr-plk06:key_v1')).toThrow(/revoked/);
    expect(ev('TRANSPARENCY_KEY_REVOCATION_REGRESSION_DETECTED')).toHaveLength(1);
    expect(read(f).keys['tr-plk06:key_v1'].status).toBe('revoked');
  });

  test('PL-K06-12 a stale instance re-loads before mutating: its rotation cannot erase another instance\'s key or revocation', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    const b = instance(f);
    b.getActiveKey(); // B bootstraps (v1 active)
    a.rotateKey({ mode: 'emergency' }); // A: v1 revoked, v2 active
    b.rotateKey({ mode: 'graceful' }); // B was stale (v1 active); must build on A's state
    const d = read(f);
    expect(d.keys['tr-plk06:key_v1'].status).toBe('revoked');
    expect(d.keys['tr-plk06:key_v2'].status).toBe('deprecated');
    expect(d.keys['tr-plk06:key_v3'].status).toBe('active');
  });

  test('PL-K06-13 keyManager.reload() also reloads the transparency and checkpoint stores (fleet-wide tick)', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-km-reload-'));
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
    process.env.QODIQA_KEYS_PATH = path.join(dir, 'keys.json');
    process.env.QODIQA_TRANSPARENCY_KEYS_PATH = path.join(dir, 'transparency-keys.json');
    require('../../../../services/secrets/secretsProvider')._clearCache();
    const tks = require('../transparencyKeyStore');
    const cks = require('../../audit/checkpoint/checkpointKeyStore');
    tks.rotateKey(); cks.ensureActiveKey();
    const r = require('../../../../services/artifact/keyManager').reload();
    expect(r.trustDomains.transparency).toMatchObject({ reloaded: true });
    expect(r.trustDomains.checkpoint).toMatchObject({ reloaded: true });
  });
});

describe('revokedAt is persisted', () => {
  test('PL-K10-01 revokeKey() stamps revokedAt; it survives a save and a fresh load, and listKeys() returns it', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    const before = Date.now();
    a.revokeKey('tr-plk06:key_v1');
    const onDisk = read(f).keys['tr-plk06:key_v1'].revokedAt;
    expect(new Date(onDisk).getTime()).toBeGreaterThanOrEqual(before - 1000);
    const listed = instance(f).listKeys().find((k) => k.keyId === 'tr-plk06:key_v1');
    expect(listed).toMatchObject({ status: 'revoked', revokedAt: onDisk });
  });

  test('PL-K10-02 an emergency rotation stamps revokedAt on the outgoing key; non-revoked keys carry none', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    a.rotateKey({ mode: 'emergency' });
    const d = read(f).keys;
    expect(typeof d['tr-plk06:key_v1'].revokedAt).toBe('string');
    expect('revokedAt' in d['tr-plk06:key_v2']).toBe(false);
    expect(ev('TRANSPARENCY_KEY_REVOKED').at(-1).revokedAt).toBe(d['tr-plk06:key_v1'].revokedAt);
  });

  test('PL-K10-03 a file written before the field loads (revokedAt: null); an unparseable revokedAt is FATAL', () => {
    const f = tmpFile();
    const a = instance(f);
    a.rotateKey();
    a.revokeKey('tr-plk06:key_v1');
    const d = read(f);
    delete d.keys['tr-plk06:key_v1'].revokedAt;
    write(f, reseal(d));
    expect(instance(f).listKeys()[0]).toMatchObject({ status: 'revoked', revokedAt: null });
    d.keys['tr-plk06:key_v1'].revokedAt = 'not-a-date';
    write(f, reseal(d));
    expect(() => instance(f).listKeys()).toThrow(/unparseable revokedAt/);
  });
});
