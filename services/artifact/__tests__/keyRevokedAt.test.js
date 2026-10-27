'use strict';

/**
 * phase 6 — the artifact key store persists WHEN a key was revoked
 *.
 *
 *   PL-K10-A1  revokeKey() stamps revokedAt; it is written to keys.json, survives a fresh load, and is returned by
 *              listKeyTimelines() and getInventory()
 *   PL-K10-A2  an emergency rotation stamps revokedAt on the outgoing key; active/deprecated keys carry none
 *   PL-K10-A3  a keys.json written before the field still loads (revokedAt: null); an unparseable one is FATAL
 *   PL-K10-A4  a reload that repairs a revocation regression keeps the ORIGINAL revokedAt
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

const KEK = 'd'.repeat(64);

function tmpKeys() { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-revokedat-')), 'keys.json'); }
function instance(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../secrets/secretsProvider')._clearCache();
  return require('../keyStore');
}
const read = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));

const ORIG = { KEK: process.env.QODIQA_KEY_ENCRYPTION_KEY, KP: process.env.QODIQA_KEYS_PATH };
afterAll(() => {
  if (ORIG.KEK === undefined) delete process.env.QODIQA_KEY_ENCRYPTION_KEY; else process.env.QODIQA_KEY_ENCRYPTION_KEY = ORIG.KEK;
  if (ORIG.KP === undefined) delete process.env.QODIQA_KEYS_PATH; else process.env.QODIQA_KEYS_PATH = ORIG.KP;
});

test('PL-K10-A1 revokeKey() persists revokedAt; a fresh load returns it from listKeyTimelines() and getInventory()', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('rv');
  a.rotateKey('rv', { mode: 'graceful' });
  const before = Date.now();
  a.revokeKey('rv', 'rv:key_v1');
  const onDisk = read(f).clients.rv['rv:key_v1'].revokedAt;
  expect(typeof onDisk).toBe('string');
  expect(new Date(onDisk).getTime()).toBeGreaterThanOrEqual(before - 1000);

  const b = instance(f);
  const tl = b.listKeyTimelines().find((t) => t.keyId === 'rv:key_v1');
  expect(tl.timeline.revokedAt).toBe(onDisk);
  const inv = b.getInventory().entries.find((k) => k.keyId === 'rv:key_v1');
  expect(inv.revokedAt).toBe(onDisk);
});

test('PL-K10-A2 an emergency rotation stamps revokedAt on the outgoing key only', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('rv');
  a.rotateKey('rv', { mode: 'emergency' });
  a.rotateKey('rv', { mode: 'graceful' });
  const c = read(f).clients.rv;
  expect(typeof c['rv:key_v1'].revokedAt).toBe('string');
  expect('revokedAt' in c['rv:key_v2']).toBe(false); // deprecated
  expect('revokedAt' in c['rv:key_v3']).toBe(false); // active
  expect(instance(f).listKeyTimelines().find((t) => t.keyId === 'rv:key_v2').timeline.revokedAt).toBeNull();
});

test('PL-K10-A3 a pre-field keys.json loads with revokedAt null; an unparseable revokedAt is FATAL', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('rv');
  a.rotateKey('rv', { mode: 'emergency' });
  const d = read(f);
  delete d.clients.rv['rv:key_v1'].revokedAt;
  fs.writeFileSync(f, JSON.stringify(resealKeys(d), null, 2));
  expect(instance(f).listKeyTimelines().find((t) => t.keyId === 'rv:key_v1').timeline.revokedAt).toBeNull();
  d.clients.rv['rv:key_v1'].revokedAt = 'yesterday-ish';
  fs.writeFileSync(f, JSON.stringify(resealKeys(d), null, 2));
  expect(() => instance(f).listKeyTimelines()).toThrow(/invalid revokedAt/);
});

test('PL-K10-A4 a revocation-regression repair keeps the original revokedAt', () => {
  const f = tmpKeys();
  const a = instance(f);
  a.rotateKey('rv');
  a.rotateKey('rv', { mode: 'graceful' });
  const stale = fs.readFileSync(f, 'utf8');
  a.revokeKey('rv', 'rv:key_v1');
  const original = read(f).clients.rv['rv:key_v1'].revokedAt;
  fs.writeFileSync(f, stale);
  expect(a.reloadFromDisk().reloaded).toBe(true);
  expect(read(f).clients.rv['rv:key_v1']).toMatchObject({ status: 'revoked', revokedAt: original });
});
