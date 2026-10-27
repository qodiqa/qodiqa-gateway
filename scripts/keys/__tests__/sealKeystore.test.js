'use strict';

/**
 * OA-RC-2 — sealed key stores required in production; the offline seal step.
 * Acceptance K-1..K-3:
 *
 *   SK-1  sealRequired(): production → true unless QODIQA_KEYSTORE_REQUIRE_SEALED=false; elsewhere only on exact 'true'
 *   SK-2  production boot validation: 'false' is a WARN naming the risk; a mis-spelt value is refused (strict boolean)
 *   SK-3  a legacy (pre-K1, unsealed) artifact key file is REFUSED by a production load; the offline tool seals it with
 *         the deployment KEK; the production load then succeeds and the key still signs
 *   SK-4  wrong KEK → SEAL_FAILED, the file is byte-identical afterwards; --seal without --confirm-gateway-stopped is
 *         a usage error (exit 2) that writes nothing; report-only mode writes nothing
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const TOOL = path.join(ROOT, 'scripts', 'keys', 'seal-keystore.js');
const KEK = '7'.repeat(64);
const seal = require('../../../src/infra/crypto/keyRecordSeal');

test('SK-1 sealRequired(): required by default in production only', () => {
  expect(seal.sealRequired({ NODE_ENV: 'production' })).toBe(true);
  expect(seal.sealRequired({ NODE_ENV: 'production', QODIQA_KEYSTORE_REQUIRE_SEALED: 'false' })).toBe(false);
  expect(seal.sealRequired({ NODE_ENV: 'production', QODIQA_KEYSTORE_REQUIRE_SEALED: 'true' })).toBe(true);
  expect(seal.sealRequired({ NODE_ENV: 'production', QODIQA_KEYSTORE_REQUIRE_SEALED: 'TRUE' })).toBe(true);   // never weaker
  expect(seal.sealRequired({ NODE_ENV: 'development' })).toBe(false);
  expect(seal.sealRequired({ NODE_ENV: 'test' })).toBe(false);
  expect(seal.sealRequired({ NODE_ENV: 'test', QODIQA_KEYSTORE_REQUIRE_SEALED: 'true' })).toBe(true);
});

test('SK-2 production boot validation: explicit false is a WARN; a mis-spelt value is refused', () => {
  const { validateBoot } = require('../../../src/infra/config/bootValidator');
  const base = { ...process.env, NODE_ENV: 'production' };
  const off = validateBoot({ ...base, QODIQA_KEYSTORE_REQUIRE_SEALED: 'false' });
  expect(off.warnings.some((w) => w.variable === 'QODIQA_KEYSTORE_REQUIRE_SEALED' && /seal-keystore/.test(w.message))).toBe(true);
  const bad = validateBoot({ ...base, QODIQA_KEYSTORE_REQUIRE_SEALED: 'yes' });
  expect(bad.fatal.some((f) => f.variable === 'QODIQA_KEYSTORE_REQUIRE_SEALED')).toBe(true);
  const dflt = validateBoot({ ...base, QODIQA_KEYSTORE_REQUIRE_SEALED: undefined });
  expect(dflt.warnings.some((w) => w.variable === 'QODIQA_KEYSTORE_REQUIRE_SEALED')).toBe(false);
});

describe('the offline seal tool', () => {
  let dir; let keys;
  const env = (extra = {}) => ({ ...process.env, QODIQA_KEY_ENCRYPTION_KEY: KEK, QODIQA_KEYS_PATH: keys,
    QODIQA_TRANSPARENCY_KEYS_PATH: path.join(dir, 'transparency-keys.json'), QODIQA_CHECKPOINT_KEYS_PATH: path.join(dir, 'checkpoint-keys.json'),
    NODE_ENV: 'test', ...extra });
  const node = (js, extra) => spawnSync(process.execPath, ['-e', js], { cwd: ROOT, env: env(extra), encoding: 'utf8' });
  const tool = (args, extra) => spawnSync(process.execPath, [TOOL, ...args], { cwd: ROOT, env: env(extra), encoding: 'utf8' });

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-seal-tool-'));
    keys = path.join(dir, 'keys.json');
    // a store as the current code writes it (sealed) …
    const mk = node("const ks=require('./services/artifact/keyStore'); ks.rotateKey('acme',{mode:'graceful'}); console.log('ok')");
    expect(mk.stdout).toMatch(/ok/);
    // … rewritten into exactly what pre-K1 code wrote: no marker, no MACs, AAD-less ciphertext (k1RecordSeal.test.js)
    const legacy = node(`
      const fs=require('fs'); const ks=require('./services/artifact/keyStore'); const { encryptKeyMaterial } = require('./services/artifact/keyEncryption');
      const d=JSON.parse(fs.readFileSync(process.env.QODIQA_KEYS_PATH,'utf8')); delete d.recordSeal;
      for (const [cid, cd] of Object.entries(d.clients)) for (const [kid, e] of Object.entries(cd)) { delete e.recordMac;
        if (e.status==='active') e.encryptedPrivateKeyDer = encryptKeyMaterial(ks.getActiveKey(cid).privDer, { keyId: kid, createdAt: e.createdAt }); }
      fs.writeFileSync(process.env.QODIQA_KEYS_PATH, JSON.stringify(d, null, 2)); console.log('legacy');`);
    expect(legacy.stdout).toMatch(/legacy/);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const prodLoad = () => node("try { const ks=require('./services/artifact/keyStore'); ks.listKeys(); const k=ks.getActiveKey('acme'); console.log('LOADED '+k.keyId); } catch (e) { console.log('REFUSED '+e.message.slice(0,160)); }",
    { NODE_ENV: 'production', QODIQA_KEYSTORE_REQUIRE_SEALED: undefined });

  test('SK-3 a legacy file is refused in production, sealed offline, then loads', () => {
    expect(prodLoad().stdout).toMatch(/REFUSED .*key file is not sealed/);
    const report = tool([]);
    expect(report.status).toBe(0);
    expect(report.stdout).toMatch(/"sealed": false/);
    const r = tool(['--seal', '--confirm-gateway-stopped']);
    expect(r.stdout).toMatch(/SEAL_OK/);
    expect(r.status).toBe(0);
    expect(seal.isSealedFile(JSON.parse(fs.readFileSync(keys, 'utf8')))).toBe(true);
    expect(prodLoad().stdout).toMatch(/LOADED acme:key_v1/);
  });

  test('SK-4 wrong KEK fails without writing; usage errors and report mode write nothing', () => {
    const before = fs.readFileSync(keys);
    const usage = tool(['--seal']);
    expect(usage.status).toBe(2);
    expect(tool([]).status).toBe(0);
    const wrong = tool(['--seal', '--confirm-gateway-stopped'], { QODIQA_KEY_ENCRYPTION_KEY: '8'.repeat(64) });
    expect(wrong.stdout).toMatch(/SEAL_FAILED/);
    expect(wrong.status).toBe(1);
    expect(fs.readFileSync(keys).equals(before)).toBe(true);
  });
});
