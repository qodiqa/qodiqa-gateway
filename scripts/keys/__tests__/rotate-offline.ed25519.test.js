'use strict';

/**
 * K1 — a supported, operator-run rotation path for the TRANSPARENCY and
 * AUDIT-CHECKPOINT Ed25519 keys (scripts/keys/rotate-offline.js --store transparency|checkpoint).
 *
 *
 *   RE-01  usage: unknown --store, --client with an Ed25519 store, no --mode → exit 64 before anything is loaded
 *   RE-02  dry run by default (exit 2, key file byte-identical); a store without an active key is refused (exit 3)
 *   RE-03  transparency, graceful: the day-180-expired key made boot FATAL (signer.validateStartup()); after the
 *          rotation boot passes, roots signed by the old key still verify, new roots are signed by the new key
 *   RE-04  checkpoint, graceful: same for checkpoints (server/startup.js's ensureActiveKey + validateKeyStore check)
 *   RE-05  emergency mode revokes the outgoing key: what it signed stops verifying
 *   RE-06  lock: mandatory unless --no-lock; taken under "ed25519-store:<store>" and released with its token
 *   RE-07  the real CLI end to end (spawned, its own environment only)
 *   RE-08  the expired-key boot error and the validateKeyStore() finding name the rotation command
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const REPO = path.join(__dirname, '..', '..', '..');
const KEK = '9'.repeat(64);
let events;

function tmpDir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-k1-rotate-')); }
function paths(dir) { return { t: path.join(dir, 'transparency-keys.json'), c: path.join(dir, 'checkpoint-keys.json') }; }
function fresh(dir) {
  jest.resetModules();
  const p = paths(dir);
  process.env.QODIQA_KEY_ENCRYPTION_KEY = KEK;
  process.env.QODIQA_TRANSPARENCY_KEYS_PATH = p.t;
  process.env.QODIQA_CHECKPOINT_KEYS_PATH = p.c;
  require('../../../services/secrets/secretsProvider')._clearCache();
  return {
    transparency: require('../../../src/core/transparency/transparencyKeyStore'),
    checkpoint: require('../../../src/core/audit/checkpoint/checkpointKeyStore'),
    signer: require('../../../src/core/transparency/transparencySigner').createTransparencySigner(),
    cp: require('../../../src/core/audit/checkpoint/checkpoint'),
  };
}
// Simulate day 181: back-date the active key's lifecycle, as a KEK holder would (re-sealing the record MACs).
function expire(file, purpose) {
  const seal = require('../../../src/infra/crypto/keyRecordSeal');
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const e of Object.values(d.keys)) {
    if (e.status !== 'active') continue;
    e.createdAt = new Date(Date.now() - 181 * 864e5).toISOString();
    e.rotationDeadline = new Date(Date.now() - 91 * 864e5).toISOString();
    e.expiresAt = new Date(Date.now() - 864e5).toISOString();
  }
  seal.sealFileData(d, require('../../../services/artifact/keyEncryption').deriveKekSubkey(seal.RECORD_MAC_INFO), purpose);
  fs.writeFileSync(file, JSON.stringify(d, null, 2));
}
const H = crypto.createHash('sha256').update('root-1').digest();
const HEAD = 'b'.repeat(64);
// Both stores provisioned, one root and one checkpoint signed by the v1 keys, then both keys expired.
async function expiredFleet() {
  const dir = tmpDir();
  const m = fresh(dir);
  m.signer.validateStartup();                     // auto-provisions the transparency key (as boot does)
  m.checkpoint.ensureActiveKey();                 // as boot does
  const root = await m.signer.sign(H);
  const checkpoint = m.cp.signCheckpoint({ chainLength: 5, headHash: HEAD });
  expire(paths(dir).t, 'transparency');
  expire(paths(dir).c, 'audit-checkpoint');
  return { dir, root, checkpoint };
}
function deps(dir, { env = {}, lock } = {}) {
  const m = fresh(dir);
  const kpf = { initialize: jest.fn(async () => {}), wireIntoSecretsProvider: jest.fn(async () => {}) };
  return { m, d: { ed25519Store: (n) => m[n], keyStore: null, kpf, rotationLock: lock || { acquire: jest.fn(), release: jest.fn() }, env,
    emit: (severity, eventType, data) => events.push({ severity, eventType, ...data }) } };
}
const argv = (store, mode, ...extra) => ['--store', store, '--mode', mode, '--operator', 'alice', '--reason', 'day-180 expiry', ...extra];
const { run } = require('../rotate-offline');

const ORIG = ['QODIQA_KEY_ENCRYPTION_KEY', 'QODIQA_TRANSPARENCY_KEYS_PATH', 'QODIQA_CHECKPOINT_KEYS_PATH'].map((k) => [k, process.env[k]]);
beforeEach(() => { events = []; });
afterAll(() => { for (const [k, v] of ORIG) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

test('RE-01 usage errors exit 64 before anything is loaded', async () => {
  const dir = tmpDir();
  for (const a of [
    ['--store', 'artefact', '--mode', 'graceful', '--operator', 'a', '--reason', 'abc'],
    [...argv('transparency', 'graceful'), '--client', 'acme'],
    ['--store', 'checkpoint', '--operator', 'a', '--reason', 'abc'],
  ]) {
    const { d } = deps(dir);
    const r = await run(a, d);
    expect(r.exitCode).toBe(64);
    expect(d.kpf.initialize).not.toHaveBeenCalled();
  }
});

test('RE-02 dry run by default (nothing written); a store without an active key is refused (exit 3)', async () => {
  const { dir } = await expiredFleet();
  const before = fs.readFileSync(paths(dir).t, 'utf8');
  const r = await run(argv('transparency', 'graceful', '--no-lock'), deps(dir).d);
  expect(r.exitCode).toBe(2);
  expect(r.report).toMatchObject({ status: 'DRY_RUN', plan: { store: 'transparency', activeKeyId: 'tr-default:key_v1', keyState: 'expired', mode: 'graceful' } });
  expect(fs.readFileSync(paths(dir).t, 'utf8')).toBe(before);
  const empty = tmpDir();
  const r3 = await run(argv('checkpoint', 'graceful', '--confirm-offline-recovery', '--no-lock'), deps(empty).d);
  expect(r3.exitCode).toBe(3);
  expect(fs.existsSync(paths(empty).c)).toBe(false);
});

test('RE-03 transparency (graceful): boot FATAL before, passes after; old roots verify, new roots use the new key', async () => {
  const { dir, root } = await expiredFleet();
  expect(() => fresh(dir).signer.validateStartup()).toThrow(/expired/);

  const r = await run(argv('transparency', 'graceful', '--confirm-offline-recovery', '--no-lock'), deps(dir).d);
  expect(r.exitCode).toBe(0);
  expect(r.report).toMatchObject({ status: 'ROTATED', keyId: 'tr-default:key_v2', previousKeyId: 'tr-default:key_v1', previousKeyStatus: 'deprecated' });
  expect(events.map((e) => e.eventType)).toEqual(['KEY_OFFLINE_RECOVERY_UNLOCKED', 'KEY_OFFLINE_RECOVERY_STARTED', 'KEY_OFFLINE_RECOVERY_COMPLETED']);
  for (const e of events) expect(e).toMatchObject({ store: 'transparency', operator: 'alice', reason: 'day-180 expiry', mode: 'graceful' });
  expect(JSON.stringify(events)).not.toMatch(/privDer|encryptedPrivateKey|"privateKey/);

  const m = fresh(dir); // the next boot
  expect(() => m.signer.validateStartup()).not.toThrow();
  expect(m.signer.verify(H, root.signature, root.keyId)).toBe(true);
  expect(m.transparency.getPublicKey('tr-default:key_v1')).toMatchObject({ status: 'deprecated', retiredAt: expect.any(String) });
  const next = await m.signer.sign(crypto.createHash('sha256').update('root-2').digest());
  expect(next.keyId).toBe('tr-default:key_v2');
  expect(m.signer.verify(crypto.createHash('sha256').update('root-2').digest(), next.signature, next.keyId)).toBe(true);
  // the checkpoint store was not touched
  expect(() => m.checkpoint.ensureActiveKey()).toThrow(/EXPIRED/);
});

test('RE-04 checkpoint (graceful): boot FATAL before, passes after; old checkpoints verify, new ones use the new key', async () => {
  const { dir, checkpoint } = await expiredFleet();
  // server/startup.js: ensureActiveKey() then validateKeyStore() — either failing is CHECKPOINT_KEY_STARTUP_FAILED
  expect(() => fresh(dir).checkpoint.ensureActiveKey()).toThrow(/CHECKPOINT_KEY_EXPIRED/);

  const r = await run(argv('checkpoint', 'graceful', '--confirm-offline-recovery', '--no-lock'), deps(dir).d);
  expect(r.exitCode).toBe(0);
  expect(r.report).toMatchObject({ status: 'ROTATED', keyId: 'cp-default:key_v2', previousKeyStatus: 'deprecated' });

  const m = fresh(dir);
  expect(m.checkpoint.ensureActiveKey().keyId).toBe('cp-default:key_v2');
  const v = m.checkpoint.validateKeyStore();
  expect(v.violations).toEqual([]);
  expect(v.expiredKeys).toEqual([]);
  expect(m.cp.verifyCheckpoint(checkpoint)).toEqual({ ok: true });
  const next = m.cp.signCheckpoint({ chainLength: 6, headHash: HEAD });
  expect(next.payload.keyId).toBe('cp-default:key_v2');
  expect(m.cp.verifyCheckpoint(next)).toEqual({ ok: true });
  expect(m.checkpoint.publishedKeys().map((k) => k.keyId).sort()).toEqual(['cp-default:key_v1', 'cp-default:key_v2']);
});

test('RE-05 emergency mode revokes the outgoing key: what it signed stops verifying', async () => {
  const { dir, root, checkpoint } = await expiredFleet();
  expect((await run(argv('transparency', 'emergency', '--confirm-offline-recovery', '--no-lock'), deps(dir).d)).exitCode).toBe(0);
  expect((await run(argv('checkpoint', 'emergency', '--confirm-offline-recovery', '--no-lock'), deps(dir).d)).exitCode).toBe(0);
  const m = fresh(dir);
  expect(() => m.signer.validateStartup()).not.toThrow();
  expect(m.signer.verify(H, root.signature, root.keyId)).toBe(false);
  expect(m.cp.verifyCheckpoint(checkpoint)).toMatchObject({ ok: false, reason: expect.stringMatching(/revoked/) });
});

test('RE-06 the fleet lock is mandatory unless --no-lock, taken as ed25519-store:<store> and released', async () => {
  const { dir } = await expiredFleet();
  const before = fs.readFileSync(paths(dir).c, 'utf8');
  const a = argv('checkpoint', 'graceful', '--confirm-offline-recovery');
  expect((await run(a, deps(dir).d)).exitCode).toBe(4);
  const busy = { acquire: jest.fn(async () => ({ acquired: false })), release: jest.fn() };
  expect((await run(a, deps(dir, { env: { REDIS_URL: 'rediss://lock.invalid:6380' }, lock: busy }).d)).exitCode).toBe(4);
  expect(fs.readFileSync(paths(dir).c, 'utf8')).toBe(before);
  const ok = { acquire: jest.fn(async () => ({ acquired: true, token: 'tok-9', fence: 1 })), release: jest.fn(async () => true) };
  expect((await run(a, deps(dir, { env: { REDIS_URL: 'rediss://lock.invalid:6380' }, lock: ok }).d)).exitCode).toBe(0);
  expect(ok.acquire).toHaveBeenCalledWith('ed25519-store:checkpoint', expect.any(Number));
  expect(ok.release).toHaveBeenCalledWith('ed25519-store:checkpoint', 'tok-9');
});

test('RE-07 the real CLI end to end: dry run exits 2, a confirmed run exits 0 and the next boot is not FATAL', async () => {
  const { dir } = await expiredFleet();
  const p = paths(dir);
  const env = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: os.tmpdir(), TMP: os.tmpdir(), NODE_ENV: 'test',
    QODIQA_KEY_ENCRYPTION_KEY: KEK, QODIQA_TRANSPARENCY_KEYS_PATH: p.t, QODIQA_CHECKPOINT_KEYS_PATH: p.c, QODIQA_KMS_PROVIDER: 'local' };
  const cli = (extra) => spawnSync(process.execPath, ['scripts/keys/rotate-offline.js', ...argv('checkpoint', 'graceful'), ...extra],
    { cwd: REPO, env, encoding: 'utf8', timeout: 60_000 });
  expect(cli(['--no-lock']).status).toBe(2);
  const go = cli(['--no-lock', '--confirm-offline-recovery']);
  expect(go.status).toBe(0);
  const report = JSON.parse(go.stdout.match(/\{\n {2}"status"[\s\S]*?\n\}\n/)[0]);
  expect(report).toMatchObject({ status: 'ROTATED', keyId: 'cp-default:key_v2', previousKeyStatus: 'deprecated' });
  expect(fresh(dir).checkpoint.ensureActiveKey().keyId).toBe('cp-default:key_v2');
}, 90_000);

test('RE-08 the expired-key error and the expiry finding name the rotation command', async () => {
  const { dir } = await expiredFleet();
  const m = fresh(dir);
  expect(() => m.transparency.getActiveKey()).toThrow(/rotate-offline\.js --store transparency/);
  expect(m.checkpoint.validateKeyStore().expiredKeys[0].rotateCommand).toMatch(/^node scripts\/keys\/rotate-offline\.js --store checkpoint --mode graceful/);
});
