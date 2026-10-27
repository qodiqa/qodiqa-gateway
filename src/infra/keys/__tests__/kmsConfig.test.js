'use strict';

// Item 21 — per-field validation tests for src/infra/keys/kmsConfig.js.
// Every required field, for every provider, gets its own "missing -> exact
// message" test, plus one "fully valid config passes" test per provider.

const ALL_KMS_ENV_VARS = [
  'QODIQA_KMS_PROVIDER',
  'VAULT_ADDR', 'VAULT_TOKEN', 'VAULT_ROLE_ID', 'VAULT_SECRET_ID', 'VAULT_NAMESPACE',
  'VAULT_KEK_PATH', 'VAULT_KEK_MOUNT', 'VAULT_TRANSIT_MOUNT', 'VAULT_TLS_CA_CERT',
  'AWS_KMS_KEY_ID', 'AWS_KMS_REGION', 'AWS_KMS_EDK_PATH',
  'AZURE_KEY_VAULT_URI', 'AZURE_KEY_VAULT_KEY_NAME', 'AZURE_KEY_VAULT_KEY_VER', 'AZURE_WRAPPED_KEY_PATH',
  'GCP_KMS_PROJECT', 'GCP_KMS_KEYRING', 'GCP_KMS_KEY', 'GCP_KMS_LOCATION', 'GCP_KMS_KEY_VERSION',
  'GCP_KMS_KEY_TYPE', 'GCP_WRAPPED_KEY_PATH',
  'HSM_PKCS11_LIB', 'HSM_PKCS11_SLOT', 'HSM_PKCS11_PIN', 'HSM_PKCS11_PIN_FILE', 'HSM_KEY_INDEX_PATH',
];

function withEnv(overrides) {
  const saved = {};
  for (const k of ALL_KMS_ENV_VARS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  for (const [k, v] of Object.entries(overrides)) {
    process.env[k] = v;
  }
  return function restore() {
    for (const k of ALL_KMS_ENV_VARS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  };
}

describe('kmsConfig.validateKmsConfig', () => {
  let validateKmsConfig;

  beforeAll(() => {
    ({ validateKmsConfig } = require('../kmsConfig'));
  });

  describe('local (default) provider', () => {
    test('unset QODIQA_KMS_PROVIDER passes with no required fields', () => {
      const restore = withEnv({});
      try {
        expect(() => validateKmsConfig()).not.toThrow();
        expect(validateKmsConfig()).toEqual({ provider: 'local', valid: true, errors: [], data: { provider: 'local' } });
      } finally { restore(); }
    });

    test('explicit "local" passes with no required fields', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'local' });
      try {
        expect(() => validateKmsConfig()).not.toThrow();
      } finally { restore(); }
    });
  });

  describe('unrecognized provider name', () => {
    test('no-ops — left to keyProviderFactory\'s own error', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'totally-not-a-provider' });
      try {
        expect(() => validateKmsConfig()).not.toThrow();
        expect(validateKmsConfig()).toEqual({ provider: 'totally-not-a-provider', valid: true, errors: [] });
      } finally { restore(); }
    });
  });

  describe('vault-kv provider', () => {
    const VALID = {
      QODIQA_KMS_PROVIDER: 'vault-kv',
      VAULT_ADDR:       'https://vault.internal:8200',
      VAULT_ROLE_ID:    'role-123',
      VAULT_SECRET_ID:  'secret-456',
    };

    test('fully valid AppRole config passes', () => {
      const restore = withEnv(VALID);
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('fully valid VAULT_TOKEN config passes', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-kv', VAULT_TOKEN: 'a-real-token' });
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('no credentials at all fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-kv', VAULT_ADDR: 'https://vault.internal:8200' });
      try {
        expect(() => validateKmsConfig()).toThrow(
          /No Vault credentials configured — set VAULT_ROLE_ID \+ VAULT_SECRET_ID \(preferred\) or VAULT_TOKEN\./
        );
      } finally { restore(); }
    });

    test('VAULT_ROLE_ID without VAULT_SECRET_ID fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-kv', VAULT_ROLE_ID: 'role-123' });
      try {
        expect(() => validateKmsConfig()).toThrow(
          /VAULT_SECRET_ID is not set — required alongside VAULT_ROLE_ID for AppRole authentication\./
        );
      } finally { restore(); }
    });

    test('VAULT_SECRET_ID without VAULT_ROLE_ID fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-kv', VAULT_SECRET_ID: 'secret-456' });
      try {
        expect(() => validateKmsConfig()).toThrow(
          /VAULT_ROLE_ID is not set — required alongside VAULT_SECRET_ID for AppRole authentication\./
        );
      } finally { restore(); }
    });
  });

  describe('vault-transit provider', () => {
    test('fully valid config passes', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-transit', VAULT_TOKEN: 'a-real-token' });
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('no credentials fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'vault-transit' });
      try {
        expect(() => validateKmsConfig()).toThrow(
          /No Vault credentials configured — set VAULT_ROLE_ID \+ VAULT_SECRET_ID \(preferred\) or VAULT_TOKEN\./
        );
      } finally { restore(); }
    });
  });

  describe('aws-kms provider', () => {
    const VALID = { QODIQA_KMS_PROVIDER: 'aws-kms', AWS_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123:key/abc', AWS_KMS_REGION: 'us-east-1' };

    test('fully valid config passes', () => {
      const restore = withEnv(VALID);
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('missing AWS_KMS_KEY_ID fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'aws-kms', AWS_KMS_REGION: 'us-east-1' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AWS_KMS_KEY_ID is not set\./);
      } finally { restore(); }
    });

    test('missing AWS_KMS_REGION fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'aws-kms', AWS_KMS_KEY_ID: 'arn:aws:kms:us-east-1:123:key/abc' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AWS_KMS_REGION is not set\./);
      } finally { restore(); }
    });

    test('empty-string AWS_KMS_KEY_ID fails the same as missing', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'aws-kms', AWS_KMS_KEY_ID: '', AWS_KMS_REGION: 'us-east-1' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AWS_KMS_KEY_ID is not set\./);
      } finally { restore(); }
    });

    test('both missing produces both messages in one FATAL', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'aws-kms' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AWS_KMS_KEY_ID is not set\..*AWS_KMS_REGION is not set\./s);
      } finally { restore(); }
    });
  });

  describe('azure-kv provider', () => {
    const VALID = { QODIQA_KMS_PROVIDER: 'azure-kv', AZURE_KEY_VAULT_URI: 'https://my-vault.vault.azure.net', AZURE_KEY_VAULT_KEY_NAME: 'qodiqa-kek' };

    test('fully valid config passes', () => {
      const restore = withEnv(VALID);
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('missing AZURE_KEY_VAULT_URI fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'azure-kv', AZURE_KEY_VAULT_KEY_NAME: 'qodiqa-kek' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AZURE_KEY_VAULT_URI is not set\./);
      } finally { restore(); }
    });

    test('missing AZURE_KEY_VAULT_KEY_NAME fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'azure-kv', AZURE_KEY_VAULT_URI: 'https://my-vault.vault.azure.net' });
      try {
        expect(() => validateKmsConfig()).toThrow(/AZURE_KEY_VAULT_KEY_NAME is not set\./);
      } finally { restore(); }
    });
  });

  describe('gcp-kms provider', () => {
    const VALID = { QODIQA_KMS_PROVIDER: 'gcp-kms', GCP_KMS_PROJECT: 'my-project', GCP_KMS_KEYRING: 'my-keyring', GCP_KMS_KEY: 'my-key' };

    test('fully valid config passes', () => {
      const restore = withEnv(VALID);
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('missing GCP_KMS_PROJECT fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'gcp-kms', GCP_KMS_KEYRING: 'my-keyring', GCP_KMS_KEY: 'my-key' });
      try {
        expect(() => validateKmsConfig()).toThrow(/GCP_KMS_PROJECT is not set\./);
      } finally { restore(); }
    });

    test('missing GCP_KMS_KEYRING fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'gcp-kms', GCP_KMS_PROJECT: 'my-project', GCP_KMS_KEY: 'my-key' });
      try {
        expect(() => validateKmsConfig()).toThrow(/GCP_KMS_KEYRING is not set\./);
      } finally { restore(); }
    });

    test('missing GCP_KMS_KEY fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'gcp-kms', GCP_KMS_PROJECT: 'my-project', GCP_KMS_KEYRING: 'my-keyring' });
      try {
        expect(() => validateKmsConfig()).toThrow(/GCP_KMS_KEY is not set\./);
      } finally { restore(); }
    });

    test('invalid GCP_KMS_KEY_TYPE fails with exact message', () => {
      const restore = withEnv({ ...VALID, GCP_KMS_KEY_TYPE: 'not-a-real-type' });
      try {
        expect(() => validateKmsConfig()).toThrow(/GCP_KMS_KEY_TYPE must be "symmetric" or "asymmetric"\./);
      } finally { restore(); }
    });

    test('valid GCP_KMS_KEY_TYPE values pass', () => {
      for (const t of ['symmetric', 'asymmetric']) {
        const restore = withEnv({ ...VALID, GCP_KMS_KEY_TYPE: t });
        try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
      }
    });
  });

  describe('hsm provider', () => {
    test('fully valid config with HSM_PKCS11_PIN passes', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'hsm', HSM_PKCS11_LIB: '/usr/lib/softhsm/libsofthsm2.so', HSM_PKCS11_PIN: '1234' });
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('fully valid config with HSM_PKCS11_PIN_FILE passes', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'hsm', HSM_PKCS11_LIB: '/usr/lib/softhsm/libsofthsm2.so', HSM_PKCS11_PIN_FILE: '/run/secrets/hsm-pin' });
      try { expect(() => validateKmsConfig()).not.toThrow(); } finally { restore(); }
    });

    test('missing HSM_PKCS11_LIB fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'hsm', HSM_PKCS11_PIN: '1234' });
      try {
        expect(() => validateKmsConfig()).toThrow(/HSM_PKCS11_LIB is not set\./);
      } finally { restore(); }
    });

    test('missing both PIN and PIN_FILE fails with exact message', () => {
      const restore = withEnv({ QODIQA_KMS_PROVIDER: 'hsm', HSM_PKCS11_LIB: '/usr/lib/softhsm/libsofthsm2.so' });
      try {
        expect(() => validateKmsConfig()).toThrow(/No PIN configured — set HSM_PKCS11_PIN or HSM_PKCS11_PIN_FILE\./);
      } finally { restore(); }
    });
  });
});

describe('kmsConfig._FIELDS_BY_PROVIDER (C2 lock-in)', () => {
  // Findings Group C, C2: scripts/kms-config-doc-check.js imports this
  // export directly as its ground truth for docs/configuration/reference.md's
  // KMS table — this test exists so a future refactor that renames or
  // restructures the export is caught here, not as an opaque crash in that
  // separate script.
  test('_FIELDS_BY_PROVIDER is exported with exactly KNOWN_PROVIDERS as keys, each value an array of strings', () => {
    const { _FIELDS_BY_PROVIDER, KNOWN_PROVIDERS } = require('../kmsConfig');
    expect(_FIELDS_BY_PROVIDER).toBeDefined();
    expect(Object.keys(_FIELDS_BY_PROVIDER).sort()).toEqual([...KNOWN_PROVIDERS].sort());
    for (const provider of KNOWN_PROVIDERS) {
      const fields = _FIELDS_BY_PROVIDER[provider];
      expect(Array.isArray(fields)).toBe(true);
      // 'local' is the one provider with no KMS-specific env vars at all
      // (the KEK is read directly from QODIQA_KEY_ENCRYPTION_KEY) — every
      // other provider must have at least one.
      if (provider === 'local') {
        expect(fields.length).toBe(0);
      } else {
        expect(fields.length).toBeGreaterThan(0);
      }
      for (const f of fields) expect(typeof f).toBe('string');
    }
  });
});
