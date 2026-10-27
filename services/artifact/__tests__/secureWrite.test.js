'use strict';

/**
 * (patch P1) — secure, durable key-file writes.
 *
 *   PL-SW-01  writeFileAtomicSecure: exclusive unique temp (<target>.<pid>.<hex>.tmp), fsync BEFORE rename,
 *             content intact, no temp left behind, a stale fixed-name "<target>.tmp" is neither used nor touched
 *   PL-SW-02  two writes use two different temp names
 *   PL-SW-03  (POSIX only) the target ends 0600 even when pre-created 0644
 *   PL-SW-04  keys.json (keyStore.saveKeys), key-archive.json (keyStore purge), the Ed25519 transparency store
 *             and mac-keys.json are all written through it (fsync'ed unique temp), and end 0600 on POSIX
 *
 * Windows ignores POSIX mode bits (files inherit the folder ACL —'s Windows half is an owner
 * decision), so ONLY the mode assertions are skipped on win32; the fsync / rename / unique-temp
 * behaviour is asserted on every platform.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}

const TEST_KEK = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const IS_WIN = process.platform === 'win32';
const TMP_RE = /\.\d+\.[0-9a-f]{12}\.tmp$/;

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-prelive-sw-')); }
const modeOf = (p) => fs.statSync(p).mode & 0o777;

// Records the ordered fs calls that touch `prefix` (the target path) — open, fsync (by fd), rename.
function traceFs(prefix) {
  const calls = [];
  const fds = new Map();
  const realOpen = fs.openSync, realFsync = fs.fsyncSync, realRename = fs.renameSync;
  const spies = [
    jest.spyOn(fs, 'openSync').mockImplementation((p, flags, mode) => {
      const fd = realOpen(p, flags, mode);
      if (typeof p === 'string' && p.startsWith(prefix)) { fds.set(fd, p); calls.push(['open', p, flags, mode]); }
      return fd;
    }),
    jest.spyOn(fs, 'fsyncSync').mockImplementation((fd) => {
      if (fds.has(fd)) calls.push(['fsync', fds.get(fd)]);
      return realFsync(fd);
    }),
    jest.spyOn(fs, 'renameSync').mockImplementation((a, b) => {
      if (typeof a === 'string' && a.startsWith(prefix)) calls.push(['rename', a, b]);
      return realRename(a, b);
    }),
  ];
  return { calls, restore: () => spies.forEach((s) => s.mockRestore()) };
}

// Asserts one secure write of `target` happened: exclusive 0600 open of a unique temp, fsync, then rename onto target.
function expectSecureWrite(calls, target) {
  const open = calls.find((c) => c[0] === 'open' && TMP_RE.test(c[1]) && c[1].startsWith(`${target}.`));
  expect(open).toBeDefined();
  expect(open[1].startsWith(`${target}.${process.pid}.`)).toBe(true);
  expect(open[2]).toBe('wx');
  expect(open[3]).toBe(0o600);
  const iFsync  = calls.findIndex((c) => c[0] === 'fsync' && c[1] === open[1]);
  const iRename = calls.findIndex((c) => c[0] === 'rename' && c[1] === open[1] && c[2] === target);
  expect(iFsync).toBeGreaterThan(-1);
  expect(iRename).toBeGreaterThan(iFsync);
}

describe('secureWrite.writeFileAtomicSecure', () => {
  const { writeFileAtomicSecure } = require('../secureWrite');

  test('PL-SW-01: unique exclusive temp, fsync before rename, content intact, stale fixed .tmp untouched', () => {
    const dir = tmpDir();
    const target = path.join(dir, 'keys.json');
    fs.writeFileSync(`${target}.tmp`, 'STALE');            // what the old fixed-name writer would have re-used
    const t = traceFs(target);
    try { writeFileAtomicSecure(target, '{"a":1}'); } finally { t.restore(); }

    expectSecureWrite(t.calls, target);
    expect(fs.readFileSync(target, 'utf8')).toBe('{"a":1}');
    expect(fs.readFileSync(`${target}.tmp`, 'utf8')).toBe('STALE');
    expect(fs.readdirSync(dir).filter((f) => TMP_RE.test(f))).toEqual([]);
  });

  test('PL-SW-02: two writes use two different temp names', () => {
    const target = path.join(tmpDir(), 'keys.json');
    const t = traceFs(target);
    try { writeFileAtomicSecure(target, 'one'); writeFileAtomicSecure(target, 'two'); } finally { t.restore(); }
    const temps = t.calls.filter((c) => c[0] === 'open').map((c) => c[1]);
    expect(temps).toHaveLength(2);
    expect(new Set(temps).size).toBe(2);
    expect(fs.readFileSync(target, 'utf8')).toBe('two');
  });

  // POSIX only — Windows ignores mode bits (see header).
  (IS_WIN ? test.skip : test)('PL-SW-03: target ends 0600 even when pre-created 0644', () => {
    const target = path.join(tmpDir(), 'keys.json');
    fs.writeFileSync(target, 'old', { mode: 0o644 });
    fs.chmodSync(target, 0o644);
    writeFileAtomicSecure(target, 'new');
    expect(modeOf(target)).toBe(0o600);
  });
});

describe('PL-SW-04: every key-file writer goes through the secure writer', () => {
  function freshEnv(dir) {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = TEST_KEK;
    process.env.QODIQA_KEYS_PATH = path.join(dir, 'keys.json');
    process.env.QODIQA_KEYS_ARCHIVE_PATH = path.join(dir, 'key-archive.json');
    process.env.QODIQA_MAC_KEYS_PATH = path.join(dir, 'mac-keys.json');
    require('../../secrets/secretsProvider')._clearCache();
  }
  afterEach(() => { delete process.env.QODIQA_KEYS_ARCHIVE_PATH; delete process.env.QODIQA_MAC_KEYS_PATH; });

  test('keys.json via keyStore.saveKeys()', () => {
    const dir = tmpDir();
    freshEnv(dir);
    const target = path.join(dir, 'keys.json');
    const ks = require('../keyStore');
    const t = traceFs(target);
    try { ks.rotateKey('sw-client'); } finally { t.restore(); }
    expectSecureWrite(t.calls, target);
    if (!IS_WIN) expect(modeOf(target)).toBe(0o600);
  });

  test('key-archive.json via keyStore.purgeExpiredDeprecated()', () => {
    const dir = tmpDir();
    freshEnv(dir);
    const keysPath = path.join(dir, 'keys.json');
    let ks = require('../keyStore');
    ks.rotateKey('arch-client');
    ks.rotateKey('arch-client', { mode: 'graceful' });
    // age the deprecated key past the retention window
    const data = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
    data.clients['arch-client']['arch-client:key_v1'].retiredAt = new Date(Date.now() - 400 * 86_400_000).toISOString();
    fs.writeFileSync(keysPath, JSON.stringify(resealKeys(data), null, 2));
    freshEnv(dir);
    ks = require('../keyStore');
    const archive = path.join(dir, 'key-archive.json');
    const t = traceFs(archive);
    let res;
    try { res = ks.purgeExpiredDeprecated('arch-client'); } finally { t.restore(); }
    expect(res.purged).toBe(1);
    expectSecureWrite(t.calls, archive);
    if (!IS_WIN) expect(modeOf(archive)).toBe(0o600);
  });

  test('Ed25519 trust-domain store (ed25519KeyStore._saveKeys)', () => {
    const dir = tmpDir();
    freshEnv(dir);
    const target = path.join(dir, 'transparency-keys.json');
    const { createEd25519KeyStore } = require('../../../src/core/transparency/ed25519KeyStore');
    const store = createEd25519KeyStore({
      dataPath: target, purpose: 'transparency', resolveClientId: () => 'tr-sw', storeName: 'SwStore',
      noun: 'transparency', title: 'Transparency', eventPrefix: 'SW_KEY', storeEvent: 'SW_KEYSTORE_LOADED', violationNoun: 'SW',
    });
    const t = traceFs(target);
    try { store.rotateKey(); store.rotateKeyGracefully(); } finally { t.restore(); }
    expectSecureWrite(t.calls, target);
    if (!IS_WIN) expect(modeOf(target)).toBe(0o600);
  });

  test('mac-keys.json via macKeyring', () => {
    const dir = tmpDir();
    freshEnv(dir);
    const target = path.join(dir, 'mac-keys.json');
    const macKeyring = require('../../../src/core/security/macKeyring');
    macKeyring._resetForTest();
    const t = traceFs(target);
    try { macKeyring.init(); macKeyring.rotate({ by: 'test' }); } finally { t.restore(); }
    expect(t.calls.filter((c) => c[0] === 'rename' && c[2] === target)).toHaveLength(2);
    expectSecureWrite(t.calls, target);
    if (!IS_WIN) expect(modeOf(target)).toBe(0o600);
  });
});
