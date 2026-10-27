'use strict';

/**
 * keyProviderFactory.getKekProviderType() reports the KEK provider TYPE the
 * /key-admin/kek/rotate route uses to refuse a no-op "rotation" on the local provider.
 *
 *   PL-KPT-01  before initialize(): derived from the environment the way initialize() derives it
 *   PL-KPT-02  after initialize() with the local provider: 'local'; reset by shutdown()
 */

const ENV = ['QODIQA_KMS_PROVIDER', 'QODIQA_KMS_KEK_PROVIDER'];
const saved = {};
beforeEach(() => { for (const k of ENV) { saved[k] = process.env[k]; delete process.env[k]; } jest.resetModules(); });
afterEach(() => { for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

test('PL-KPT-01: derived from the environment before initialize()', () => {
  const kpf = require('../keyProviderFactory');
  expect(kpf.getKekProviderType()).toBe('local');                      // unset → local
  process.env.QODIQA_KMS_PROVIDER = 'aws-kms';
  expect(kpf.getKekProviderType()).toBe('aws-kms');
  process.env.QODIQA_KMS_PROVIDER = 'vault-transit';                    // native signing → KEK defaults to local
  expect(kpf.getKekProviderType()).toBe('local');
  process.env.QODIQA_KMS_PROVIDER = 'hsm';
  process.env.QODIQA_KMS_KEK_PROVIDER = 'gcp-kms';
  expect(kpf.getKekProviderType()).toBe('gcp-kms');
});

test('PL-KPT-02: the initialized local provider reports local; shutdown() resets it', async () => {
  process.env.QODIQA_KMS_PROVIDER = 'local';
  const kpf = require('../keyProviderFactory');
  await kpf.initialize();
  try {
    expect(kpf.getKekProviderType()).toBe('local');
  } finally {
    await kpf.shutdown();
  }
  process.env.QODIQA_KMS_PROVIDER = 'azure-kv';
  expect(kpf.getKekProviderType()).toBe('azure-kv');
});
