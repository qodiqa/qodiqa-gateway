'use strict';

/**
 * keys.json KEK migration script — _migrate() logic.
 *
 * MKK-01  keys.json already under the target KEK → 'already-current', no write
 * MKK-02  keys.json under a legacy KEK, legacy KEK supplied, dry run → 'dry-run', no write
 * MKK-03  keys.json under a legacy KEK, legacy KEK supplied, --execute → 'migrated',
 *          re-encrypted keys.json decrypts correctly under the target KEK afterward
 * MKK-04  keys.json under a legacy KEK, NO legacy KEK supplied → 'failed', not silently skipped
 * MKK-05  secretsProvider is left pointed at the target KEK after processing (any outcome)
 * MKK-06  no file on disk at all → 'already-current' (trivially, nothing to migrate)
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');

function makeTempPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-kek-migrate-'));
  return path.join(dir, 'keys.json');
}

const TARGET_KEK = Buffer.alloc(32, 0x01);
const LEGACY_KEK = Buffer.alloc(32, 0x02);

function loadFreshKeyStore(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEYS_PATH = keysPath;
  const secretsProvider = require('../../services/secrets/secretsProvider');
  secretsProvider._clearCache();
  const keyStore = require('../../services/artifact/keyStore');
  const { _migrate } = require('../migrate-keys-json-kek');
  return { keyStore, secretsProvider, _migrate };
}

describe('scripts/migrate-keys-json-kek — _migrate', () => {
  afterEach(() => {
    delete process.env.QODIQA_KEYS_PATH;
  });

  test('MKK-01. keys.json already under the target KEK is reported already-current', () => {
    const keysPath = makeTempPath();
    const { keyStore, secretsProvider, _migrate } = loadFreshKeyStore(keysPath);
    secretsProvider._setExternalKek(TARGET_KEK);
    keyStore.rotateKey('mkk-client-1'); // provisions + persists under TARGET_KEK

    const result = _migrate({ keyStore, secretsProvider, targetKek: TARGET_KEK, legacyKek: LEGACY_KEK, execute: false });
    expect(result.outcome).toBe('already-current');
    expect(result.activeKeys).toBeGreaterThanOrEqual(1);
  });

  test('MKK-02. keys.json under a legacy KEK, dry run — reports dry-run, does not write', () => {
    const keysPath = makeTempPath();
    let ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(LEGACY_KEK);
    ks.keyStore.rotateKey('mkk-client-2'); // provisions + persists under LEGACY_KEK

    // Fresh module instance simulating a new process, now with the target KEK
    // (post-rotation) as the "current" one.
    ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(TARGET_KEK);

    const result = ks._migrate({
      keyStore: ks.keyStore, secretsProvider: ks.secretsProvider,
      targetKek: TARGET_KEK, legacyKek: LEGACY_KEK, execute: false,
    });
    expect(result.outcome).toBe('dry-run');
    expect(result.activeKeys).toBe(1);

    // Dry run must not have written — reloading fresh under the target KEK
    // (with no legacy fallback offered) must still fail.
    const verify = loadFreshKeyStore(keysPath);
    verify.secretsProvider._setExternalKek(TARGET_KEK);
    const reload = verify.keyStore.reloadFromDisk();
    expect(reload.reloaded).toBe(false);
    expect(reload.error).toBeTruthy();
  });

  test('MKK-03. keys.json under a legacy KEK, --execute — migrates and is decryptable under the target KEK afterward', () => {
    const keysPath = makeTempPath();
    let ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(LEGACY_KEK);
    const { keyId } = ks.keyStore.rotateKey('mkk-client-3');

    ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(TARGET_KEK);

    const result = ks._migrate({
      keyStore: ks.keyStore, secretsProvider: ks.secretsProvider,
      targetKek: TARGET_KEK, legacyKek: LEGACY_KEK, execute: true,
    });
    expect(result.outcome).toBe('migrated');
    expect(result.activeKeys).toBe(1);

    // A brand-new process, target KEK only (no legacy KEK available), must
    // now be able to load keys.json directly.
    const verify = loadFreshKeyStore(keysPath);
    verify.secretsProvider._setExternalKek(TARGET_KEK);
    const reload = verify.keyStore.reloadFromDisk();
    expect(reload.reloaded).toBe(true);
    const key = verify.keyStore.getActiveKey('mkk-client-3');
    expect(key.keyId).toBe(keyId);
    expect(Buffer.isBuffer(key.privDer)).toBe(true);
  });

  test('MKK-04. keys.json under a legacy KEK with no legacy KEK supplied is reported failed, not silently skipped', () => {
    const keysPath = makeTempPath();
    let ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(LEGACY_KEK);
    ks.keyStore.rotateKey('mkk-client-4');

    ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(TARGET_KEK);

    const result = ks._migrate({
      keyStore: ks.keyStore, secretsProvider: ks.secretsProvider,
      targetKek: TARGET_KEK, legacyKek: null, execute: true,
    });
    expect(result.outcome).toBe('failed');
    expect(result.error).toBeTruthy();
  });

  test('MKK-05. secretsProvider is left pointed at the target KEK regardless of outcome', () => {
    const keysPath = makeTempPath();
    let ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(LEGACY_KEK);
    ks.keyStore.rotateKey('mkk-client-5');

    ks = loadFreshKeyStore(keysPath);
    ks.secretsProvider._setExternalKek(TARGET_KEK);
    ks._migrate({
      keyStore: ks.keyStore, secretsProvider: ks.secretsProvider,
      targetKek: TARGET_KEK, legacyKek: LEGACY_KEK, execute: true,
    });

    // If secretsProvider were still pointed at legacyKek, a fresh rotate
    // under it and immediate active-key read (implicitly re-encrypting under
    // whatever KEK is current) would still succeed, so probe by comparing
    // against getKeyEncryptionKey() directly instead.
    expect(ks.secretsProvider.getKeyEncryptionKey().equals(TARGET_KEK)).toBe(true);
  });

  test('MKK-06. no keys.json file on disk at all is reported already-current (nothing to migrate)', () => {
    const keysPath = makeTempPath(); // directory created, file never written
    const { keyStore, secretsProvider, _migrate } = loadFreshKeyStore(keysPath);
    secretsProvider._setExternalKek(TARGET_KEK);

    const result = _migrate({ keyStore, secretsProvider, targetKek: TARGET_KEK, legacyKek: LEGACY_KEK, execute: false });
    expect(result.outcome).toBe('already-current');
    expect(result.activeKeys).toBe(0);
  });
});

// the local -> KMS migration is the one place a NEW wrapped KEK is legitimately minted, so the
// script carries the explicit switch for its own process — and never as part of a dry run.
describe('migrate-keys-json-kek — explicit new-KEK provisioning switch', () => {
  const { _kekProvisioningSwitch } = require('../migrate-keys-json-kek');
  test('MKK-07. --provision-new-kek with --execute sets QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true for this process', () => {
    const env = {};
    expect(_kekProvisioningSwitch(['node', 's', '--execute', '--provision-new-kek'], env)).toEqual({ provision: true, error: null });
    expect(env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY).toBe('true');
  });
  test('MKK-08. --provision-new-kek without --execute is refused and sets nothing; no flag leaves the env untouched', () => {
    const env = {};
    const r = _kekProvisioningSwitch(['node', 's', '--provision-new-kek'], env);
    expect(r.provision).toBe(false);
    expect(r.error).toMatch(/requires --execute/);
    expect(env).toEqual({});
    expect(_kekProvisioningSwitch(['node', 's', '--execute'], env)).toEqual({ provision: false, error: null });
    expect(env).toEqual({});
  });
});
