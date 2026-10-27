'use strict';

/**
 * non-semantic remediation sprint — key-store fixes
 *.
 *
 * PL-SEC03-01..03 a persisted `nativeKey:true` active record is honoured ONLY when a
 *                               NativeSigningProvider is configured; otherwise load fails closed
 * PL-K07-01..02 synchronous rotateKey()/rotateKeyGracefully() refuse under a native
 *                               signing provider (no LOCAL software key in an HSM deployment)
 * PL-K02-01..05 reload-before-mutation (a stale second writer can no
 *                               longer erase another writer's new key or resurrect a revoked key),
 *                               and reloadFromDisk() never un-revokes a key
 */

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const crypto = require('crypto');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const KPF_PATH = '../../../src/infra/keys/keyProviderFactory';

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-prelive-ks-'));
  return path.join(dir, 'keys.json');
}

// A fresh, independent keyStore module instance bound to keysPath (simulates a
// separate process / instance sharing the same keys.json).
function loadInstance(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../secrets/secretsProvider')._clearCache();
  return require('../keyStore');
}

function mockNativeProvider() {
  jest.doMock(KPF_PATH, () => ({
    isNativeSigning: () => true,
    getNativeSigningProvider: () => ({ name: 'mock-hsm' }),
  }));
}

function readStore(keysPath) { return JSON.parse(fs.readFileSync(keysPath, 'utf8')); }

function captureEvents() {
  const events = [];
  const orig = process.stderr.write.bind(process.stderr);
  const spy = jest.spyOn(process.stderr, 'write').mockImplementation((data) => {
    if (typeof data === 'string') { try { events.push(JSON.parse(data.trim())); } catch { /* not JSON */ } }
    return orig(data);
  });
  return { events, restore: () => spy.mockRestore() };
}

afterEach(() => {
  jest.dontMock(KPF_PATH);
});

// ═════════════════════════════════════════════════════════════════════════════
//
// ═════════════════════════════════════════════════════════════════════════════

describe('nativeKey:true is honoured only with a native signing provider', () => {
  function plantNativeRecord(keysPath) {
    const { publicKey } = crypto.generateKeyPairSync('ed25519', { publicKeyEncoding: { type: 'spki', format: 'der' } });
    const data = readStore(keysPath);
    const rec  = data.clients.legit['legit:key_v1'];
    delete rec.encryptedPrivateKeyDer;
    rec.publicKeyDer = Buffer.from(publicKey).toString('base64'); // attacker-chosen public key
    rec.nativeKey    = true;
    fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2));
    return Buffer.from(publicKey).toString('base64');
  }

  test('PL-SEC03-01: local mode — a planted nativeKey active record makes bootstrap fail closed', () => {
    const keysPath = makeTempPath();
    loadInstance(keysPath).rotateKey('legit');
    plantNativeRecord(keysPath);

    const ks = loadInstance(keysPath);
    expect(() => ks.validateKeyStore()).toThrow(/invalid key material for "legit:key_v1".*nativeKey:true but no native signing provider/);
    expect(() => ks.getActiveKey('legit')).toThrow(/invalid key material/);
  });

  test('PL-SEC03-02: local mode — a live instance refuses the planted record on reload and keeps the real key', () => {
    const keysPath = makeTempPath();
    const ks = loadInstance(keysPath);
    const { fingerprint } = ks.rotateKey('legit');
    const attackerPub = plantNativeRecord(keysPath);

    const r = ks.reloadFromDisk();
    expect(r.reloaded).toBe(false);
    expect(r.error).toMatch(/nativeKey:true but no native signing provider/);
    const active = ks.getActiveKey('legit');
    expect(active.keyId).toBe('legit:key_v1');
    expect(crypto.createHash('sha256').update(active.pubDer).digest('hex')).toBe(fingerprint);
    expect(active.pubDer.toString('base64')).not.toBe(attackerPub);
  });

  test('PL-SEC03-03: with a native signing provider configured the same record still loads (KRA-13 path kept)', () => {
    const keysPath = makeTempPath();
    loadInstance(keysPath).rotateKey('legit');
    const pub = plantNativeRecord(keysPath);

    mockNativeProvider();
    const ks = loadInstance(keysPath);
    expect(() => ks.validateKeyStore()).not.toThrow();
    const active = ks.getActiveKey('legit');
    expect(active.privDer).toBeNull();
    expect(active.pubDer.toString('base64')).toBe(pub);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//
// ═════════════════════════════════════════════════════════════════════════════

describe('synchronous rotation refuses under a native signing provider', () => {
  test('PL-K07-01: rotateKey()/rotateKeyGracefully() throw and keys.json is unchanged', () => {
    const keysPath = makeTempPath();
    loadInstance(keysPath).rotateKey('c1');
    const before = fs.readFileSync(keysPath);

    mockNativeProvider();
    const ks = loadInstance(keysPath);
    expect(() => ks.rotateKey('c1', { mode: 'graceful' })).toThrow(/native signing provider \("mock-hsm"\) is active.*LOCAL software key/);
    expect(() => ks.rotateKeyGracefully('c1')).toThrow(/rotateKeyAsync/);
    expect(() => ks.rotateKey('brand-new-client', { mode: 'emergency' })).toThrow(/LOCAL software key/);
    expect(fs.readFileSync(keysPath).equals(before)).toBe(true);
  });

  test('PL-K07-02: default local mode is unaffected (startup tenant path: rotateKeyGracefully still provisions)', () => {
    const ks = loadInstance(makeTempPath());
    const r = ks.rotateKeyGracefully('tenant-x');
    expect(r.keyId).toBe('tenant-x:key_v1');
    expect(ks.rotateKeyGracefully('tenant-x').keyId).toBe('tenant-x:key_v2');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
//
// ═════════════════════════════════════════════════════════════════════════════

describe('reload-before-mutation and monotonic revocation', () => {
  test('PL-K02-01: a stale instance rotating client Y does not erase client X\'s new key (E3 lost update)', () => {
    const keysPath = makeTempPath();
    const a = loadInstance(keysPath);
    a.rotateKey('client-X');
    a.rotateKey('client-Y');
    const b = loadInstance(keysPath);
    b.getActiveKey('client-Y'); // B bootstrapped — its view is now the pre-rotation file

    const ax = a.rotateKey('client-X', { mode: 'emergency' }); // A: X v1 revoked, X v2 active
    const by = b.rotateKey('client-Y', { mode: 'graceful' });  // B (stale) rotates Y

    const disk = readStore(keysPath);
    expect(disk.clients['client-X'][ax.keyId].status).toBe('active');
    expect(disk.clients['client-X'][ax.keyId].encryptedPrivateKeyDer).toBeTruthy();
    expect(disk.clients['client-X']['client-X:key_v1'].status).toBe('revoked');
    expect(disk.clients['client-Y'][by.keyId].status).toBe('active');
    // and B now serves A's rotation too
    expect(b.getActiveKey('client-X').keyId).toBe(ax.keyId);
  });

  test('PL-K02-02: a stale instance cannot resurrect a key another instance revoked', () => {
    const keysPath = makeTempPath();
    const a = loadInstance(keysPath);
    a.rotateKey('client-X');
    a.rotateKey('client-Y');
    const b = loadInstance(keysPath);
    b.getActiveKey('client-X');

    a.revokeKey('client-X:key_v1');
    b.rotateKey('client-Y', { mode: 'emergency' });

    expect(readStore(keysPath).clients['client-X']['client-X:key_v1'].status).toBe('revoked');
    expect(() => b.getActiveKey('client-X')).toThrow();
    a.reloadFromDisk();
    expect(a.getKeyStatus('client-X:key_v1')).toBe('revoked');
  });

  test('PL-K02-03: reloadFromDisk() never un-revokes — the key stays revoked, CRITICAL is emitted, disk is repaired', () => {
    const keysPath = makeTempPath();
    const a = loadInstance(keysPath);
    a.rotateKey('client-X');
    const staleBytes = fs.readFileSync(keysPath); // X v1 active
    a.revokeKey('client-X:key_v1');
    fs.writeFileSync(keysPath, staleBytes);      // a stale writer / restored file puts it back as active

    const cap = captureEvents();
    let r;
    try { r = a.reloadFromDisk(); } finally { cap.restore(); }
    expect(r.reloaded).toBe(true);
    expect(a.getKeyStatus('client-X:key_v1')).toBe('revoked');
    expect(() => a.getActiveKey('client-X')).toThrow();
    const crit = cap.events.filter((e) => e.eventType === 'KEY_REVOCATION_REGRESSION_DETECTED');
    expect(crit).toHaveLength(1);
    expect(crit[0].severity).toBe('CRITICAL');
    const disk = readStore(keysPath).clients['client-X']['client-X:key_v1'];
    expect(disk.status).toBe('revoked');
    expect(disk.encryptedPrivateKeyDer).toBeUndefined();
  });

  test('PL-K02-04: a revoked record missing from disk is kept (revocation knowledge is never dropped)', () => {
    const keysPath = makeTempPath();
    const a = loadInstance(keysPath);
    a.rotateKey('client-X');
    a.rotateKey('client-Z');
    a.revokeKey('client-X:key_v1');
    const data = readStore(keysPath);
    delete data.clients['client-X'];
    fs.writeFileSync(keysPath, JSON.stringify(data, null, 2));

    const cap = captureEvents();
    try { a.reloadFromDisk(); } finally { cap.restore(); }
    expect(a.getKeyStatus('client-X:key_v1')).toBe('revoked');
    expect(readStore(keysPath).clients['client-X']['client-X:key_v1'].status).toBe('revoked');
  });

  test('PL-K02-05: a changed but unloadable file refuses the mutation (fail closed) and is left untouched', () => {
    const keysPath = makeTempPath();
    const a = loadInstance(keysPath);
    a.rotateKey('client-X');
    fs.writeFileSync(keysPath, '{ not json');
    expect(() => a.rotateKey('client-X', { mode: 'emergency' })).toThrow(/changed on disk and could not be reloaded — mutation refused/);
    expect(() => a.revokeKey('client-X:key_v1')).toThrow(/mutation refused/);
    expect(fs.readFileSync(keysPath, 'utf8')).toBe('{ not json');
    // the live in-memory store is retained for signing
    expect(a.getActiveKey('client-X').keyId).toBe('client-X:key_v1');
  });
});
