'use strict';

/**
 * (found while implementing the remediation): ensureActiveKey()
 * used to gate on the WHOLE store being empty (`totalActive === 0`), not
 * just the given clientId — so provisioning a second clientId into a store
 * that already had one active client silently no-op'd, despite the second
 * clientId never having a key. Never triggered before this fix because
 * every existing call site only ever provisioned a single clientId into its
 * own fresh store. The regression this suite locks in: a second, distinct
 * clientId still gets provisioned even when an earlier clientId already has
 * an active key in the same store.
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

function makeTempKeysPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-key-provisioning-'));
  return path.join(dir, 'keys.json');
}

function loadFresh(keysPath) {
  jest.resetModules();
  process.env.QODIQA_KEY_ENCRYPTION_KEY = 'a'.repeat(64);
  process.env.QODIQA_KEYS_PATH = keysPath;
  require('../../services/secrets/secretsProvider')._clearCache();
  return {
    provisioning: require('./keyStoreProvisioning'),
    keyStore: require('../../services/artifact/keyStore'),
  };
}

describe('ensureActiveKey()', () => {
  let keysPath;

  beforeEach(() => {
    keysPath = makeTempKeysPath();
  });

  afterEach(() => {
    jest.resetModules();
  });

  test('provisions a key for a clientId in a fresh, empty store', () => {
    const { provisioning, keyStore } = loadFresh(keysPath);

    const provisioned = provisioning.ensureActiveKey('clientA');

    expect(provisioned).toBe(true);
    expect(keyStore.validateKeyStore().clients.clientA).toBeDefined();
  });

  test('is a no-op the second time for the same clientId', () => {
    const { provisioning, keyStore } = loadFresh(keysPath);
    provisioning.ensureActiveKey('clientA');
    const before = keyStore.getActiveKey('clientA').keyId;

    const provisioned = provisioning.ensureActiveKey('clientA');

    expect(provisioned).toBe(false);
    expect(keyStore.getActiveKey('clientA').keyId).toBe(before);
  });

  // regression — the actual bug this suite exists to lock in.
  test('still provisions a second, distinct clientId even when an earlier clientId already has an active key', () => {
    const { provisioning, keyStore } = loadFresh(keysPath);

    provisioning.ensureActiveKey('clientA');
    const provisionedB = provisioning.ensureActiveKey('clientB');

    expect(provisionedB).toBe(true);
    expect(keyStore.validateKeyStore().clients.clientB).toBeDefined();
    // clientA's own key is untouched by provisioning clientB.
    expect(keyStore.validateKeyStore().clients.clientA).toBeDefined();
  });
});
