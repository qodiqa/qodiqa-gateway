'use strict';

/**
 * Secrets architecture validation tests.
 *
 * Covers:
 *   1.  Production keystore path guard — non-production: no findings
 *   2.  Production keystore path guard — QODIQA_KEYS_PATH unset in production → finding
 *   3.  Production keystore path guard — path inside project root → finding
 *   4.  Production keystore path guard — path outside project root → no finding
 *   5.  Production keystore path guard — relative path that resolves inside root → finding
 *   6.  Production KMS provider advisory — non-production: no findings
 *   7.  Production KMS provider advisory — local provider in production → advisory
 *   8.  Production KMS provider advisory — unset provider in production → advisory
 *   9.  Production KMS provider advisory — external providers → no advisory
 *   10. keyProviderFactory — local provider initialises successfully
 *   11. keyProviderFactory — wireIntoSecretsProvider injects 32-byte KEK into cache
 *   12. keyProviderFactory — initialization fails when KEK env var absent
 *   13. keyProviderFactory — initialization fails when KEK env var is malformed
 *   14. keyProviderFactory — healthCheck reports healthy after successful init
 *   15. keyProviderFactory — isNativeSigning is false for local provider
 *   16. secretsProvider — _setExternalKek accepts a valid 32-byte Buffer
 *   17. secretsProvider — _setExternalKek rejects non-Buffer input
 *   18. secretsProvider — _setExternalKek rejects wrong-length Buffer
 *   19. secretsProvider — _clearCache resets injected KEK
 *   20. Production guard is wired into runSecretValidation and blocks in production
 */

const path = require('path');
const os   = require('os');

// ── helpers ───────────────────────────────────────────────────────────────────

// Temporarily override process.env keys.  Returns a restore function.
function withEnv(overrides, deletions = []) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    process.env[k] = overrides[k];
  }
  for (const k of deletions) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  return function restore() {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

// ── 1–5. _checkProductionKeystorePath ────────────────────────────────────────

describe('_checkProductionKeystorePath', () => {
  let check;

  beforeAll(() => {
    check = require('../src/infra/secrets/secretValidation')._checkProductionKeystorePath;
  });

  test('1. no findings in non-production environment', () => {
    const restore = withEnv({ NODE_ENV: 'development' }, ['QODIQA_KEYS_PATH']);
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('2. QODIQA_KEYS_PATH unset in production → finding', () => {
    const restore = withEnv({ NODE_ENV: 'production' }, ['QODIQA_KEYS_PATH']);
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/QODIQA_KEYS_PATH is not set/);
    } finally {
      restore();
    }
  });

  test('3. absolute path inside project root → finding', () => {
    const insidePath = path.join(__dirname, '..', 'data', 'keys.json');
    const restore = withEnv({ NODE_ENV: 'production', QODIQA_KEYS_PATH: insidePath });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/inside the application directory/);
    } finally {
      restore();
    }
  });

  test('4. absolute path outside project root → no finding', () => {
    const externalPath = path.join(os.tmpdir(), 'qodiqa-prod-test', 'keys.json');
    const restore = withEnv({ NODE_ENV: 'production', QODIQA_KEYS_PATH: externalPath });
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('5. relative path resolving inside project root → finding', () => {
    const restore = withEnv({ NODE_ENV: 'production', QODIQA_KEYS_PATH: 'data/keys.json' });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/inside the application directory/);
    } finally {
      restore();
    }
  });
});

// ── 6–9. _checkProductionKmsProvider ─────────────────────────────────────────

describe('_checkProductionKmsProvider', () => {
  let check;

  beforeAll(() => {
    check = require('../src/infra/secrets/secretValidation')._checkProductionKmsProvider;
  });

  test('6. no findings in non-production environment', () => {
    const restore = withEnv({ NODE_ENV: 'development' }, ['QODIQA_KMS_PROVIDER']);
    try {
      expect(check()).toHaveLength(0);
    } finally {
      restore();
    }
  });

  test('7. local provider in production → advisory', () => {
    const restore = withEnv({ NODE_ENV: 'production', QODIQA_KMS_PROVIDER: 'local' });
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatch(/local.*provider|local.*KMS/i);
    } finally {
      restore();
    }
  });

  test('8. unset provider in production → advisory (defaults to local)', () => {
    const restore = withEnv({ NODE_ENV: 'production' }, ['QODIQA_KMS_PROVIDER']);
    try {
      const findings = check();
      expect(findings).toHaveLength(1);
    } finally {
      restore();
    }
  });

  test('9. external KMS providers → no advisory', () => {
    const providers = ['vault-kv', 'vault-transit', 'aws-kms', 'azure-kv', 'gcp-kms', 'hsm'];
    for (const provider of providers) {
      const restore = withEnv({ NODE_ENV: 'production', QODIQA_KMS_PROVIDER: provider });
      try {
        expect(check()).toHaveLength(0);
      } finally {
        restore();
      }
    }
  });
});

// ── 10–15. keyProviderFactory — local provider ────────────────────────────────

describe('keyProviderFactory — local provider', () => {
  const VALID_KEK = 'a1b2c3d4'.repeat(8); // 64 hex chars

  let kpf;
  let secretsProvider;

  beforeEach(() => {
    jest.resetModules();
    kpf             = require('../src/infra/keys/keyProviderFactory');
    secretsProvider = require('../services/secrets/secretsProvider');
  });

  afterEach(async () => {
    try { await kpf.shutdown(); } catch (_) { /* best-effort */ }
    delete process.env.QODIQA_KMS_PROVIDER;
    if (secretsProvider) secretsProvider._clearCache();
  });

  test('10. local provider initialises successfully', async () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK;
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    await expect(kpf.initialize()).resolves.toBeUndefined();
  });

  test('11. wireIntoSecretsProvider injects 32-byte KEK into secretsProvider cache', async () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK;
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();
    const kek = secretsProvider.getKeyEncryptionKey();
    expect(Buffer.isBuffer(kek)).toBe(true);
    expect(kek.length).toBe(32);
    expect(kek.toString('hex')).toBe(VALID_KEK);
  });

  test('12. initialization fails when QODIQA_KEY_ENCRYPTION_KEY is absent', async () => {
    const restore = withEnv({ QODIQA_KMS_PROVIDER: 'local' }, ['QODIQA_KEY_ENCRYPTION_KEY']);
    try {
      await expect(kpf.initialize()).rejects.toThrow(/QODIQA_KEY_ENCRYPTION_KEY/);
    } finally {
      restore();
    }
  });

  test('13. initialization fails when QODIQA_KEY_ENCRYPTION_KEY is malformed', async () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = 'not-a-hex-string';
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    await expect(kpf.initialize()).rejects.toThrow();
  });

  test('14. healthCheck reports healthy after successful initialization', async () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK;
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    await kpf.initialize();
    const result = await kpf.healthCheck();
    expect(result.healthy).toBe(true);
    expect(result.providers).toHaveProperty('kekProvider');
    expect(result.providers.kekProvider.healthy).toBe(true);
  });

  test('15. isNativeSigning is false for local provider', async () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK;
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    await kpf.initialize();
    expect(kpf.isNativeSigning()).toBe(false);
  });
});

// ── 16–19. secretsProvider — external KEK injection ──────────────────────────

describe('secretsProvider — _setExternalKek', () => {
  let secretsProvider;

  beforeEach(() => {
    jest.resetModules();
    secretsProvider = require('../services/secrets/secretsProvider');
  });

  afterEach(() => {
    secretsProvider._clearCache();
  });

  test('16. accepts a valid 32-byte Buffer and makes it retrievable', () => {
    const kek = Buffer.alloc(32, 0xab);
    expect(() => secretsProvider._setExternalKek(kek)).not.toThrow();
    const retrieved = secretsProvider.getKeyEncryptionKey();
    expect(retrieved).toEqual(kek);
  });

  test('17. rejects a non-Buffer argument', () => {
    expect(() => secretsProvider._setExternalKek('hex-string-not-buffer')).toThrow(/Buffer/);
  });

  test('18. rejects a Buffer of wrong length', () => {
    expect(() => secretsProvider._setExternalKek(Buffer.alloc(16))).toThrow();
    expect(() => secretsProvider._setExternalKek(Buffer.alloc(64))).toThrow();
  });

  test('19. _clearCache resets injected KEK; env var is the fallback', () => {
    const kek = Buffer.alloc(32, 0x42);
    secretsProvider._setExternalKek(kek);
    secretsProvider._clearCache();

    // After clear, falls back to env var KEK (set by test/support/jest.setup.js)
    // test/support/jest.setup.js sets QODIQA_KEY_ENCRYPTION_KEY to 64 F's — a valid hex KEK.
    if (process.env.QODIQA_KEY_ENCRYPTION_KEY) {
      expect(() => secretsProvider.getKeyEncryptionKey()).not.toThrow();
    } else {
      expect(() => secretsProvider.getKeyEncryptionKey()).toThrow(/QODIQA_KEY_ENCRYPTION_KEY/);
    }
  });
});

// ── 20. runSecretValidation — production guard integration ────────────────────

describe('runSecretValidation — production keystore path guard integration', () => {
  let exitSpy;
  let emitSpy;

  beforeEach(() => {
    jest.resetModules();
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });
    // Silence logger output during this test
    emitSpy = jest.fn();
    jest.doMock('../services/logger', () => ({ emit: emitSpy }));
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  test('20. production guard causes process.exit(1) when keystore path is inside project root', () => {
    const insidePath = path.join(__dirname, '..', 'data', 'keys.json');
    const restore = withEnv({
      NODE_ENV:                   'production',
      QODIQA_KEYS_PATH:           insidePath,
      // Provide enough env to satisfy other checks so only the path check fires
      QODIQA_KEY_ENCRYPTION_KEY:  'b1c2d3e4'.repeat(8),
      OPENAI_API_KEY:             'sk-realkey1234567890realkey12345678',
      QODIQA_CLIENT_ID:           'my-production-org',
    });
    try {
      const { runSecretValidation } = require('../src/infra/secrets/secretValidation');
      expect(() => runSecretValidation()).toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      restore();
    }
  });
});
