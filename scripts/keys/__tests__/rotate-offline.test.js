'use strict';

/**
 * scripts/keys/rotate-offline.js, the supported offline recovery for an EXPIRED artifact key
 *.
 *
 *   RO-01  usage errors (no mode default, bad client, no operator/reason) exit 64 before anything is loaded
 *   RO-02  default is a DRY RUN: plan reported, exit 2, key file byte-identical
 *   RO-03  refused (exit 3) when the client's key is not expired or the client has no active key
 *   RO-04  lock: no REDIS_URL and no --no-lock → refused (4); busy / unreachable lock → refused (4), file untouched;
 *          an acquired lock is released with its own token
 *   RO-05  graceful recovery: exit 0, expired key deprecated, new key active, and keyManager.validateStartup() — FATAL
 *          before — passes afterwards
 *   RO-06  emergency recovery: the expired key is revoked with a persisted revokedAt
 *   RO-07  every step is logged: STARTED / COMPLETED with operator + reason; the key store's own events carry
 *          reason + triggeredBy
 *   RO-08  the real CLI end to end (spawned, its own environment only — never .env)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');

// K1: this fixture edits keys.json deliberately, as a KEK holder would, so it re-seals the record MACs
// (an edit WITHOUT the KEK is exactly what src/infra/crypto/keyRecordSeal.js now refuses).
function resealKeys(d) {
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  return seal.sealFileData(d, require('../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), 'artifact');
}
const KEK = 'e'.repeat(64);
let events;

function tmpKeys() { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-rotoff-')), 'keys.json'); }
function fresh(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../../services/secrets/secretsProvider')._clearCache();
  return require('../../../services/artifact/keyStore');
}
// keys.json with client `acme` whose ACTIVE key has expired
function expiredStore() {
  const f = tmpKeys();
  fresh(f).rotateKey('acme');
  const d = JSON.parse(fs.readFileSync(f, 'utf8'));
  const rec = d.clients.acme['acme:key_v1'];
  rec.createdAt = new Date(Date.now() - 400 * 864e5).toISOString();
  rec.rotationDeadline = new Date(Date.now() - 310 * 864e5).toISOString();
  rec.expiresAt = new Date(Date.now() - 220 * 864e5).toISOString();
  fs.writeFileSync(f, JSON.stringify(resealKeys(d), null, 2));
  return f;
}
function deps(keysPath, { env = {}, lock } = {}) {
  const keyStore = fresh(keysPath);
  const kpf = { initialize: jest.fn(async () => {}), wireIntoSecretsProvider: jest.fn(async () => {}) };
  const rotationLock = lock || { acquire: jest.fn(), release: jest.fn() };
  return { keyStore, kpf, rotationLock, env, emit: (severity, eventType, data) => events.push({ severity, eventType, ...data }) };
}
const BASE = ['--client', 'acme', '--operator', 'alice', '--reason', 'INC-42 expired signing key'];
const { run } = require('../rotate-offline');

const ORIG = { KEK: process.env.QODIQA_KEY_ENCRYPTION_KEY, KP: process.env.QODIQA_KEYS_PATH };
beforeEach(() => { events = []; });
afterAll(() => {
  if (ORIG.KEK === undefined) delete process.env.QODIQA_KEY_ENCRYPTION_KEY; else process.env.QODIQA_KEY_ENCRYPTION_KEY = ORIG.KEK;
  if (ORIG.KP === undefined) delete process.env.QODIQA_KEYS_PATH; else process.env.QODIQA_KEYS_PATH = ORIG.KP;
});

test('RO-01 usage errors exit 64 before the KMS provider or key file is touched', async () => {
  const f = expiredStore();
  for (const argv of [
    BASE, // no --mode: there is no default
    [...BASE, '--mode', 'gracefull'],
    ['--client', 'a b', '--mode', 'graceful', '--operator', 'x', '--reason', 'why not'],
    ['--client', 'acme', '--mode', 'graceful', '--reason', 'why not'],
    ['--client', 'acme', '--mode', 'graceful', '--operator', 'x'],
    [...BASE, '--mode', 'graceful', '--force'],
  ]) {
    const d = deps(f);
    const r = await run(argv, d);
    expect(r.exitCode).toBe(64);
    expect(d.kpf.initialize).not.toHaveBeenCalled();
  }
});

test('RO-02 without --confirm-offline-recovery it is a dry run: exit 2, nothing written', async () => {
  const f = expiredStore();
  const before = fs.readFileSync(f, 'utf8');
  const r = await run([...BASE, '--mode', 'graceful', '--no-lock'], deps(f));
  expect(r.exitCode).toBe(2);
  expect(r.report).toMatchObject({ status: 'DRY_RUN', plan: { clientId: 'acme', expiredKeyId: 'acme:key_v1', mode: 'graceful' } });
  expect(fs.readFileSync(f, 'utf8')).toBe(before);
  expect(events.filter((e) => e.eventType === 'KEY_OFFLINE_RECOVERY_STARTED')).toEqual([]);
});

test('RO-03 refused (exit 3) for an unexpired key and for a client without an active key', async () => {
  const f = tmpKeys();
  fresh(f).rotateKey('acme');
  const r1 = await run([...BASE, '--mode', 'graceful', '--confirm-offline-recovery', '--no-lock'], deps(f));
  expect(r1.exitCode).toBe(3);
  expect(r1.report.detail).toMatch(/not expired/);
  const r2 = await run(['--client', 'nobody', '--mode', 'graceful', '--operator', 'a', '--reason', 'abc', '--confirm-offline-recovery', '--no-lock'], deps(f));
  expect(r2.exitCode).toBe(3);
  expect(r2.report.detail).toMatch(/no active key/);
});

test('RO-04 the fleet rotation lock is mandatory unless --no-lock is asserted; it fails closed', async () => {
  const f = expiredStore();
  const before = fs.readFileSync(f, 'utf8');
  const argv = [...BASE, '--mode', 'graceful', '--confirm-offline-recovery'];
  expect((await run(argv, deps(f))).exitCode).toBe(4); // no REDIS_URL, no --no-lock
  const busy = { acquire: jest.fn(async () => ({ acquired: false })), release: jest.fn() };
  expect((await run(argv, deps(f, { env: { REDIS_URL: 'rediss://lock.invalid:6380' }, lock: busy }))).exitCode).toBe(4);
  const down = { acquire: jest.fn(async () => { throw new Error('KEY_ROTATION_LOCK: Redis not connected'); }), release: jest.fn() };
  expect((await run(argv, deps(f, { env: { REDIS_URL: 'rediss://lock.invalid:6380' }, lock: down }))).exitCode).toBe(4);
  expect(fs.readFileSync(f, 'utf8')).toBe(before);
  const ok = { acquire: jest.fn(async () => ({ acquired: true, token: 'tok-1', fence: 1 })), release: jest.fn(async () => true) };
  expect((await run(argv, deps(f, { env: { REDIS_URL: 'rediss://lock.invalid:6380' }, lock: ok }))).exitCode).toBe(0);
  expect(ok.acquire).toHaveBeenCalledWith('acme', expect.any(Number));
  expect(ok.release).toHaveBeenCalledWith('acme', 'tok-1');
});

test('RO-05 graceful recovery: exit 0, expired key deprecated, and validateStartup() passes (it was FATAL before)', async () => {
  const f = expiredStore();
  fresh(f);
  expect(() => require('../../../services/artifact/keyManager').validateStartup()).toThrow(/expired/);
  const r = await run([...BASE, '--mode', 'graceful', '--confirm-offline-recovery', '--no-lock'], deps(f));
  expect(r.exitCode).toBe(0);
  expect(r.report).toMatchObject({ status: 'ROTATED', keyId: 'acme:key_v2', previousKeyId: 'acme:key_v1', previousKeyStatus: 'deprecated' });
  const c = JSON.parse(fs.readFileSync(f, 'utf8')).clients.acme;
  expect(c['acme:key_v1'].status).toBe('deprecated');
  expect(c['acme:key_v2'].status).toBe('active');
  fresh(f);
  expect(() => require('../../../services/artifact/keyManager').validateStartup()).not.toThrow();
});

test('RO-06 emergency recovery revokes the expired key and persists revokedAt', async () => {
  const f = expiredStore();
  const r = await run([...BASE, '--mode', 'emergency', '--confirm-offline-recovery', '--no-lock'], deps(f));
  expect(r.exitCode).toBe(0);
  const old = JSON.parse(fs.readFileSync(f, 'utf8')).clients.acme['acme:key_v1'];
  expect(old.status).toBe('revoked');
  expect(typeof old.revokedAt).toBe('string');
});

test('RO-07 the recovery is logged: STARTED/COMPLETED with operator and reason, and an UNLOCKED warning for --no-lock', async () => {
  const f = expiredStore();
  await run([...BASE, '--mode', 'graceful', '--confirm-offline-recovery', '--no-lock'], deps(f));
  const types = events.map((e) => e.eventType);
  expect(types).toEqual(['KEY_OFFLINE_RECOVERY_UNLOCKED', 'KEY_OFFLINE_RECOVERY_STARTED', 'KEY_OFFLINE_RECOVERY_COMPLETED']);
  for (const e of events) expect(e).toMatchObject({ clientId: 'acme', operator: 'alice', reason: 'INC-42 expired signing key', mode: 'graceful' });
  expect(events[1]).toMatchObject({ keyId: 'acme:key_v1', locked: false });
  expect(JSON.stringify(events)).not.toMatch(/privDer|encryptedPrivateKey|"privateKey/);
});

test('RO-08 the real CLI end to end: dry run exits 2, a confirmed run exits 0 and prints ROTATED', () => {
  const f = expiredStore();
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: os.tmpdir(), TMP: os.tmpdir(),
    NODE_ENV: 'test', QODIQA_KEY_ENCRYPTION_KEY: KEK, QODIQA_KEYS_PATH: f, QODIQA_KMS_PROVIDER: 'local' };
  const cli = (extra) => spawnSync(process.execPath, ['scripts/keys/rotate-offline.js', ...BASE, '--mode', 'graceful', ...extra],
    { cwd: REPO, env, encoding: 'utf8', timeout: 60_000 });
  const dry = cli(['--no-lock']);
  expect(dry.status).toBe(2);
  const go = cli(['--no-lock', '--confirm-offline-recovery']);
  expect(go.status).toBe(0);
  const report = JSON.parse(go.stdout.match(/\{\n {2}"status"[\s\S]*?\n\}\n/)[0]); // the pretty-printed report among JSON log lines
  expect(report).toMatchObject({ status: 'ROTATED', keyId: 'acme:key_v2', previousKeyStatus: 'deprecated' });
  expect(go.stdout + go.stderr).toMatch(/KEY_OFFLINE_RECOVERY_COMPLETED/);
}, 90_000);
