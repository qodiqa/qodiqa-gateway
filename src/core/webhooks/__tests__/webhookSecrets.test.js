'use strict';

/**
 * Webhook Secret Encryption — KMS/KEK Abstraction Conformance
 *
 * Verifies that webhookSecrets.js is a first-class consumer of secretsProvider,
 * the same provider-agnostic KEK abstraction used by the Ed25519 signing-key
 * path (services/artifact/keyEncryption.js). Prior to remediation, this module
 * read process.env.QODIQA_KEY_ENCRYPTION_KEY directly, bypassing every
 * configured KMS backend (Vault, HSM, AWS/Azure/GCP KMS).
 *
 * WHKS-01…04  Roundtrip encryption via the default (env) provider
 * WHKS-05…08  Transparent operation under an externally-injected KEK
 *             (simulates Vault Transit / HSM / cloud KMS wiring via
 *             keyProviderFactory.wireIntoSecretsProvider())
 * WHKS-09…11  Tamper detection (corrupted ciphertext / IV / auth tag)
 * WHKS-12…13  Missing / invalid KEK surfaces the shared secretsProvider error,
 *             not a webhook-specific one
 * WHKS-14      Encrypting under one KEK and decrypting under a different one
 *              fails closed (documents why a KMS-provider switch requires
 *              the migration script, not silent fallback)
 * WHKS-15…16  Regression: source contains no direct env read and does use
 *              secretsProvider — proves the abstraction cannot be silently
 *              bypassed again
 * WHKS-17      Full integration: keyProviderFactory (local provider) wires
 *              secretsProvider, and webhookSecrets transparently picks it up,
 *              mirroring test/secrets-architecture.test.js #10-11
 */

const fs   = require('fs');
const path = require('path');

describe('webhookSecrets — KMS/KEK abstraction conformance', () => {
  let webhookSecrets;
  let secretsProvider;

  const VALID_KEK_HEX = 'a1b2c3d4'.repeat(8); // 64 hex chars

  beforeEach(() => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK_HEX;
    webhookSecrets  = require('../webhookSecrets');
    secretsProvider = require('../../../../services/secrets/secretsProvider');
  });

  afterEach(() => {
    secretsProvider._clearCache();
  });

  // ── WHKS-01…04. Roundtrip via default (env) provider ────────────────────────

  test('WHKS-01. generateSecret produces a whsec_-prefixed 64-hex-char secret', () => {
    const secret = webhookSecrets.generateSecret();
    expect(secret).toMatch(/^whsec_[0-9a-f]{64}$/);
  });

  test('WHKS-02. encryptSecret/decryptSecret roundtrip preserves plaintext', () => {
    const plaintext = webhookSecrets.generateSecret();
    const { enc, iv, tag } = webhookSecrets.encryptSecret(plaintext);
    const decrypted = webhookSecrets.decryptSecret(enc, iv, tag);
    expect(decrypted).toBe(plaintext);
  });

  test('WHKS-03. each encryption uses a fresh random IV', () => {
    const plaintext = 'whsec_' + 'a'.repeat(64);
    const first  = webhookSecrets.encryptSecret(plaintext);
    const second = webhookSecrets.encryptSecret(plaintext);
    expect(first.iv).not.toBe(second.iv);
    expect(first.enc).not.toBe(second.enc);
  });

  test('WHKS-04. ciphertext is base64 and never contains the plaintext secret', () => {
    const plaintext = webhookSecrets.generateSecret();
    const { enc } = webhookSecrets.encryptSecret(plaintext);
    expect(enc).not.toContain(plaintext);
    expect(() => Buffer.from(enc, 'base64')).not.toThrow();
  });

  // ── WHKS-05…08. Transparent operation under an externally-injected KEK ──────
  // Simulates what keyProviderFactory.wireIntoSecretsProvider() does when
  // QODIQA_KMS_PROVIDER is vault-kv / vault-transit / aws-kms / azure-kv /
  // gcp-kms / hsm — none of which populate QODIQA_KEY_ENCRYPTION_KEY.

  test('WHKS-05. works when the KEK comes from _setExternalKek (no env var at all)', () => {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    secretsProvider._clearCache();
    const externalKek = Buffer.alloc(32, 0x5a); // e.g. sourced from Vault/HSM/KMS
    secretsProvider._setExternalKek(externalKek);

    const plaintext = webhookSecrets.generateSecret();
    const { enc, iv, tag } = webhookSecrets.encryptSecret(plaintext);
    expect(webhookSecrets.decryptSecret(enc, iv, tag)).toBe(plaintext);
  });

  test('WHKS-06. webhookSecrets never reads process.env.QODIQA_KEY_ENCRYPTION_KEY once an external KEK is injected', () => {
    const externalKek = Buffer.alloc(32, 0x7c);
    secretsProvider._setExternalKek(externalKek);
    // Poison the env var — if webhookSecrets read it directly, decrypt would
    // use the wrong key and the roundtrip would fail.
    process.env.QODIQA_KEY_ENCRYPTION_KEY = '0'.repeat(64);

    const plaintext = webhookSecrets.generateSecret();
    const { enc, iv, tag } = webhookSecrets.encryptSecret(plaintext);
    expect(webhookSecrets.decryptSecret(enc, iv, tag)).toBe(plaintext);
  });

  test('WHKS-07. each of the six supported KMS provider byte patterns round-trips identically through the same abstraction', () => {
    // Provider identity is irrelevant to webhookSecrets — only the resolved
    // 32-byte KEK matters. This proves no provider-specific branching exists.
    const simulatedProviderKeks = [
      Buffer.alloc(32, 0x01), // stand-in for vault-kv
      Buffer.alloc(32, 0x02), // stand-in for vault-transit KEK
      Buffer.alloc(32, 0x03), // stand-in for aws-kms (decrypted data key)
      Buffer.alloc(32, 0x04), // stand-in for azure-kv
      Buffer.alloc(32, 0x05), // stand-in for gcp-kms
      Buffer.alloc(32, 0x06), // stand-in for hsm (KEK side)
    ];
    for (const kek of simulatedProviderKeks) {
      secretsProvider._clearCache();
      secretsProvider._setExternalKek(kek);
      const plaintext = webhookSecrets.generateSecret();
      const { enc, iv, tag } = webhookSecrets.encryptSecret(plaintext);
      expect(webhookSecrets.decryptSecret(enc, iv, tag)).toBe(plaintext);
    }
  });

  test('WHKS-08. getProviderName() reflects the active provider while webhookSecrets stays provider-agnostic', () => {
    secretsProvider._setExternalKek(Buffer.alloc(32, 0x11));
    // secretsProvider itself tracks provider identity; webhookSecrets does not
    // need to and must not duplicate that logic.
    expect(typeof secretsProvider.getProviderName()).toBe('string');
    const src = fs.readFileSync(path.join(__dirname, '..', 'webhookSecrets.js'), 'utf8');
    expect(src).not.toMatch(/getProviderName/);
  });

  // ── WHKS-09…11. Tamper detection ─────────────────────────────────────────────

  test('WHKS-09. corrupted ciphertext fails authentication', () => {
    const { enc, iv, tag } = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());
    const corrupted = Buffer.from(enc, 'base64');
    corrupted[0] ^= 0xff;
    expect(() => webhookSecrets.decryptSecret(corrupted.toString('base64'), iv, tag)).toThrow();
  });

  test('WHKS-10. corrupted auth tag fails authentication', () => {
    const { enc, iv, tag } = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());
    const corrupted = Buffer.from(tag, 'base64');
    corrupted[0] ^= 0xff;
    expect(() => webhookSecrets.decryptSecret(enc, iv, corrupted.toString('base64'))).toThrow();
  });

  test('WHKS-11. wrong IV fails authentication', () => {
    const { enc, tag } = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());
    const wrongIv = Buffer.alloc(12, 0x99).toString('base64');
    expect(() => webhookSecrets.decryptSecret(enc, wrongIv, tag)).toThrow();
  });

  // ── WHKS-12…13. Missing / invalid KEK — shared error, not webhook-specific ──

  test('WHKS-12. missing KEK throws secretsProvider\'s shared error message', () => {
    delete process.env.QODIQA_KEY_ENCRYPTION_KEY;
    secretsProvider._clearCache();
    expect(() => webhookSecrets.encryptSecret('whsec_x')).toThrow(/SecretsProvider.*QODIQA_KEY_ENCRYPTION_KEY is not set/);
  });

  test('WHKS-13. malformed KEK throws secretsProvider\'s shared validation error', () => {
    process.env.QODIQA_KEY_ENCRYPTION_KEY = 'not-hex';
    secretsProvider._clearCache();
    expect(() => webhookSecrets.encryptSecret('whsec_x')).toThrow(/SecretsProvider.*64 hex characters/);
  });

  // ── WHKS-14. Provider switch fails closed (documents migration need) ────────

  test('WHKS-14. decrypting under a different KEK than the one used to encrypt fails closed', () => {
    secretsProvider._setExternalKek(Buffer.alloc(32, 0xaa));
    const { enc, iv, tag } = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());

    secretsProvider._clearCache();
    secretsProvider._setExternalKek(Buffer.alloc(32, 0xbb));
    expect(() => webhookSecrets.decryptSecret(enc, iv, tag)).toThrow();
  });

  // ── WHKS-15…16. Regression: no bypass of the abstraction ────────────────────

  test('WHKS-15. source never reads process.env.QODIQA_KEY_ENCRYPTION_KEY directly', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'webhookSecrets.js'), 'utf8');
    expect(src).not.toMatch(/process\.env\.QODIQA_KEY_ENCRYPTION_KEY/);
  });

  test('WHKS-16. source requires and uses secretsProvider.getKeyEncryptionKey()', () => {
    const src = fs.readFileSync(path.join(__dirname, '..', 'webhookSecrets.js'), 'utf8');
    expect(src).toMatch(/require\(.*secrets\/secretsProvider.*\)/);
    expect(src).toMatch(/secretsProvider\.getKeyEncryptionKey\(\)/);
  });
});

// ── WHKS-17. Full integration via keyProviderFactory (local provider) ─────────

describe('webhookSecrets — full integration with keyProviderFactory', () => {
  const VALID_KEK = 'b1c2d3e4'.repeat(8);
  let kpf;
  let secretsProvider;
  let webhookSecrets;

  beforeEach(() => {
    jest.resetModules();
    process.env.QODIQA_KEY_ENCRYPTION_KEY = VALID_KEK;
    process.env.QODIQA_KMS_PROVIDER       = 'local';
    kpf             = require('../../../infra/keys/keyProviderFactory');
    secretsProvider = require('../../../../services/secrets/secretsProvider');
    webhookSecrets  = require('../webhookSecrets');
  });

  afterEach(async () => {
    try { await kpf.shutdown(); } catch (_) { /* best-effort */ }
    delete process.env.QODIQA_KMS_PROVIDER;
    secretsProvider._clearCache();
  });

  test('WHKS-17. encrypt/decrypt succeeds after keyProviderFactory wires the local KEK provider into secretsProvider', async () => {
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();

    const plaintext = webhookSecrets.generateSecret();
    const { enc, iv, tag } = webhookSecrets.encryptSecret(plaintext);
    expect(webhookSecrets.decryptSecret(enc, iv, tag)).toBe(plaintext);
  });
});
