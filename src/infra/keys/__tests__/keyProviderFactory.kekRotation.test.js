'use strict';

/**
 * remediation — keyProviderFactory.rotateWrappingKey() propagation
 *
 * Previously, rotateWrappingKey() only mutated the KEK provider's own
 * internal reference and returned — the new KEK never reached
 * secretsProvider (the module every encrypt/decrypt call in the codebase
 * actually reads its KEK from via getKeyEncryptionKey()), so rotation had no
 * observable effect anywhere. This suite proves the fix: after
 * rotateWrappingKey() resolves, secretsProvider.getKeyEncryptionKey()
 * reflects the NEW key, not the one active before rotation.
 */

// A minimal fake KEK provider with real internal state — rotateWrappingKey()
// genuinely changes what getWrappingKey() subsequently returns, unlike the
// real LocalKekProvider (which documents its own rotation as operator/env-var
// driven and a no-op). This isolates the test to keyProviderFactory's own
// propagation logic rather than any specific cloud provider's behavior.
// Defined inline inside the mock factory — jest.mock factories may not
// reference out-of-scope variables except ones prefixed `mock`, so the class
// lives entirely inside the factory closure.
jest.mock('../providers/local', () => {
  class FakeKekProvider {
    constructor() {
      this._kek = Buffer.alloc(32, 0xAA);
    }
    get name() { return 'fake:test'; }
    async initialize() {}
    async getWrappingKey() { return this._kek; }
    async rotateWrappingKey() {
      this._kek = Buffer.alloc(32, 0xBB);
      return { version: 'fake-v2' };
    }
    async healthCheck() { return { healthy: true, detail: 'fake' }; }
    async shutdown() {}
  }
  return { LocalKekProvider: FakeKekProvider };
});

describe('keyProviderFactory.rotateWrappingKey() propagates the new KEK', () => {
  let keyProviderFactory;
  let secretsProvider;

  beforeEach(async () => {
    jest.resetModules();
    process.env.QODIQA_KMS_PROVIDER = 'local';
    keyProviderFactory = require('../keyProviderFactory');
    secretsProvider    = require('../../../../services/secrets/secretsProvider');
    secretsProvider._clearCache();
    await keyProviderFactory.initialize();
    await keyProviderFactory.wireIntoSecretsProvider();
  });

  afterEach(async () => {
    await keyProviderFactory.shutdown().catch(() => {});
    delete process.env.QODIQA_KMS_PROVIDER;
  });

  test('secretsProvider sees the pre-rotation KEK before rotateWrappingKey() is called', () => {
    const before = secretsProvider.getKeyEncryptionKey();
    expect(before.equals(Buffer.alloc(32, 0xAA))).toBe(true);
  });

  test('after rotateWrappingKey(), secretsProvider.getKeyEncryptionKey() returns the NEW KEK, not the old one', async () => {
    await keyProviderFactory.rotateWrappingKey();
    const after = secretsProvider.getKeyEncryptionKey();
    expect(after.equals(Buffer.alloc(32, 0xBB))).toBe(true);
    expect(after.equals(Buffer.alloc(32, 0xAA))).toBe(false);
  });

  test('rotateWrappingKey() still returns the underlying provider result unchanged', async () => {
    const result = await keyProviderFactory.rotateWrappingKey();
    expect(result).toEqual({ version: 'fake-v2' });
  });
});
