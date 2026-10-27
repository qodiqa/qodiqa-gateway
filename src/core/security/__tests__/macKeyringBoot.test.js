'use strict';

/**
 * phase 6 — boot wiring: a production server/startup.js boot decrypts and self-tests the MAC
 * keyring BEFORE serving, and a keyring it cannot use is FATAL MAC_KEYRING_STARTUP_FAILED (it used to surface only
 * at the first signed revocation / consent-cache read). Real spawned server.js children, never mocked; the check
 * runs before any PostgreSQL/Redis connection, and the positive case is killed as soon as MAC_KEYRING_READY appears.
 *
 *   PL-K13-B1  keyring encrypted under ANOTHER KEK        → FATAL MAC_KEYRING_STARTUP_FAILED (code MAC_KEYRING_KEK_MISMATCH), exit ≠ 0
 *   PL-K13-B2  keyring encrypted under the process's KEK  → MAC_KEYRING_READY (public status only), no MAC FATAL
 *   PL-K13-B3  static pin: the check sits after the key-store checks and is production-only
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const { validProductionEnv, pickIsolation, systemEnv, REPO_ROOT } = require('../../../../test/helpers/productionEnv');

const BOOT_TIMEOUT_MS = 45_000;
const hex = () => crypto.randomBytes(32).toString('hex');

function provision(dir, kek, clientId) {
  const env = { ...systemEnv(), NODE_ENV: 'test', QODIQA_KEY_ENCRYPTION_KEY: kek, QODIQA_KEYS_PATH: path.join(dir, 'keys.json') };
  const r = spawnSync(process.execPath, ['-e', `require('./services/artifact/keyStore').rotateKey(${JSON.stringify(clientId)})`],
    { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 30_000 });
  if (r.status !== 0) throw new Error(`keystore provisioning failed: ${(r.stderr || r.stdout).slice(-500)}`);
}
function macInit(ringPath, kek) {
  const r = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts/security/macKeyring.js'), 'init'], {
    cwd: REPO_ROOT, encoding: 'utf8', timeout: 30_000,
    env: { ...systemEnv(), NODE_ENV: 'test', QODIQA_KEY_ENCRYPTION_KEY: kek, QODIQA_MAC_KEYS_PATH: ringPath },
  });
  if (r.status !== 0) throw new Error(`MAC keyring init failed: ${(r.stderr || r.stdout).slice(-500)}`);
}

function boot(env, resolveOnEvent) {
  return new Promise((resolve, reject) => {
    const events = []; const chunks = [];
    const child = spawn(process.execPath, ['server.js'], { cwd: REPO_ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false;
    const settle = (r) => { if (done) return; done = true; clearTimeout(t); try { child.kill('SIGKILL'); } catch { /* gone */ } resolve(r); };
    const t = setTimeout(() => settle({ timedOut: true, exitCode: null, events, output: chunks.join('') }), BOOT_TIMEOUT_MS);
    const onData = (buf) => {
      const text = buf.toString(); chunks.push(text);
      for (const line of text.split('\n')) {
        let e; try { e = JSON.parse(line.trim()); } catch { continue; }
        if (!e.eventType) continue;
        events.push(e);
        if (e.eventType === resolveOnEvent) settle({ timedOut: false, exitCode: null, events, output: chunks.join('') });
      }
    };
    child.stdout.on('data', onData); child.stderr.on('data', onData);
    child.on('error', reject);
    child.on('exit', (code) => settle({ timedOut: false, exitCode: code, events, output: chunks.join('') }));
  });
}

const roots = [];
afterAll(() => { for (const r of roots) fs.rmSync(r, { recursive: true, force: true }); });

function productionChild(ringKek) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-pl-k13-boot-'));
  roots.push(dir);
  const kek = hex(); const clientId = 'plk13-client';
  provision(dir, kek, clientId);
  const ring = path.join(dir, 'mac-keys.json');
  macInit(ring, ringKek === 'same' ? kek : hex());
  return validProductionEnv({
    keysPath: path.join(dir, 'keys.json'),
    overrides: {
      ...pickIsolation(process.env), // isolated store paths for everything else the boot touches
      QODIQA_KEYS_PATH: path.join(dir, 'keys.json'), QODIQA_KEY_ENCRYPTION_KEY: kek, QODIQA_CLIENT_ID: clientId,
      QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'transparency-keys.json'), QODIQA_AUDIT_LOG: path.join(dir, 'audit.log'),
      QODIQA_MAC_KEYS_PATH: ring, QODIQA_DEPLOYMENT_MODE: 'single-node',
    },
  });
}

test('PL-K13-B1 production: a keyring under another KEK is FATAL MAC_KEYRING_STARTUP_FAILED before serving', async () => {
  const r = await boot(productionChild('other'), null);
  expect(r.timedOut).toBe(false);
  const fatal = r.events.find((e) => e.eventType === 'MAC_KEYRING_STARTUP_FAILED');
  if (!fatal) throw new Error(`no MAC_KEYRING_STARTUP_FAILED; exit=${r.exitCode}\n${r.output.slice(-3000)}`);
  expect(fatal.severity).toBe('FATAL');
  expect(fatal.code).toBe('MAC_KEYRING_KEK_MISMATCH');
  expect(r.exitCode).not.toBe(0);
  expect(r.events.some((e) => e.eventType === 'GATEWAY_START')).toBe(false);
  // the earlier key-store checks passed — the refusal is the keyring, not a misconfigured fixture
  expect(r.events.some((e) => e.eventType === 'CHECKPOINT_KEY_READY')).toBe(true);
}, BOOT_TIMEOUT_MS + 15_000);

test('PL-K13-B2 production: a keyring under the process KEK passes the boot check (MAC_KEYRING_READY)', async () => {
  const r = await boot(productionChild('same'), 'MAC_KEYRING_READY');
  const ready = r.events.find((e) => e.eventType === 'MAC_KEYRING_READY');
  if (!ready) throw new Error(`no MAC_KEYRING_READY; exit=${r.exitCode}\n${r.output.slice(-3000)}`);
  expect(ready).toMatchObject({ activeKid: expect.stringMatching(/^mk_/), kekFingerprintChecked: true });
  expect(r.events.some((e) => e.eventType === 'MAC_KEYRING_STARTUP_FAILED')).toBe(false);
}, BOOT_TIMEOUT_MS + 15_000);

test('PL-K13-B3 static pin: production-only, after the checkpoint-key check, FATAL + exit', () => {
  const src = fs.readFileSync(path.join(REPO_ROOT, 'server', 'startup.js'), 'utf8');
  const cp = src.indexOf("'CHECKPOINT_KEY_STARTUP_FAILED'");
  const mac = src.indexOf("'MAC_KEYRING_STARTUP_FAILED'");
  expect(cp).toBeGreaterThan(-1);
  expect(mac).toBeGreaterThan(cp);
  const block = src.slice(mac - 700, mac + 200);
  expect(block).toMatch(/process\.env\.NODE_ENV === 'production'/);
  expect(block).toMatch(/assertUsable\(\)/);
  expect(block).toMatch(/process\.exit\(1\)/);
});
