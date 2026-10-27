'use strict';

/**
 * Webhook secret KEK migration script — _migrateRow() logic.
 *
 * MWK-01  Row already decryptable under the target KEK → 'already-current', no update
 * MWK-02  Row encrypted under a legacy KEK, legacy KEK supplied → 'migrated',
 *          re-encrypted ciphertext decrypts correctly under the target KEK
 * MWK-03  Row encrypted under a legacy KEK, NO legacy KEK supplied → 'failed'
 * MWK-04  Row undecryptable under both target and legacy KEK (corrupted) → 'failed'
 * MWK-05  secretsProvider is left pointed at the target KEK after processing
 *          any row (so subsequent rows / the caller always see the correct state)
 * MWK-06  Migrated ciphertext is never equal to the original (fresh IV every time)
 */

describe('scripts/migrate-webhook-secrets-kek — _migrateRow', () => {
  let secretsProvider;
  let webhookSecrets;
  let migrateScript;

  const targetKek = Buffer.alloc(32, 0x01);
  const legacyKek = Buffer.alloc(32, 0x02);

  // webhookSecrets.encryptSecret() returns {enc, iv, tag}; the DB row (and
  // therefore _migrateRow's input) uses column names secret_enc/secret_iv/secret_tag.
  function toRow({ enc, iv, tag }) {
    return { secret_enc: enc, secret_iv: iv, secret_tag: tag };
  }

  beforeEach(() => {
    jest.resetModules();
    secretsProvider = require('../../services/secrets/secretsProvider');
    webhookSecrets  = require('../../src/core/webhooks/webhookSecrets');
    migrateScript   = require('../migrate-webhook-secrets-kek');
  });

  afterEach(() => {
    secretsProvider._clearCache();
  });

  test('MWK-01. row already under the target KEK is reported already-current', () => {
    secretsProvider._setExternalKek(targetKek);
    const plaintext = webhookSecrets.generateSecret();
    const row = toRow(webhookSecrets.encryptSecret(plaintext));

    const result = migrateScript._migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });
    expect(result.outcome).toBe('already-current');
    expect(result.update).toBeNull();
  });

  test('MWK-02. row under the legacy KEK is migrated and decrypts correctly under the target KEK', () => {
    secretsProvider._setExternalKek(legacyKek);
    const plaintext = webhookSecrets.generateSecret();
    const row = toRow(webhookSecrets.encryptSecret(plaintext));

    const result = migrateScript._migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });
    expect(result.outcome).toBe('migrated');
    expect(result.update).toEqual(expect.objectContaining({ enc: expect.any(String), iv: expect.any(String), tag: expect.any(String) }));

    secretsProvider._setExternalKek(targetKek);
    const decrypted = webhookSecrets.decryptSecret(result.update.enc, result.update.iv, result.update.tag);
    expect(decrypted).toBe(plaintext);
  });

  test('MWK-03. row under the legacy KEK with no legacy KEK supplied is reported failed, not silently skipped', () => {
    secretsProvider._setExternalKek(legacyKek);
    const row = toRow(webhookSecrets.encryptSecret(webhookSecrets.generateSecret()));

    const result = migrateScript._migrateRow(row, targetKek, null, { secretsProvider, webhookSecrets });
    expect(result.outcome).toBe('failed');
    expect(result.update).toBeNull();
  });

  test('MWK-04. row undecryptable under target or legacy KEK (corrupted) is reported failed', () => {
    secretsProvider._setExternalKek(legacyKek);
    const encrypted = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());
    // Corrupt the tag so neither KEK can authenticate it.
    const tagBuf = Buffer.from(encrypted.tag, 'base64');
    tagBuf[0] ^= 0xff;
    const row = { secret_enc: encrypted.enc, secret_iv: encrypted.iv, secret_tag: tagBuf.toString('base64') };

    const result = migrateScript._migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });
    expect(result.outcome).toBe('failed');
    expect(result.update).toBeNull();
  });

  test('MWK-05. secretsProvider is left pointed at the target KEK regardless of outcome', () => {
    secretsProvider._setExternalKek(legacyKek);
    const row = toRow(webhookSecrets.encryptSecret(webhookSecrets.generateSecret()));

    migrateScript._migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });

    // If the provider were still pointed at legacyKek, this would throw.
    const probe = (() => {
      secretsProvider._setExternalKek(targetKek);
      const r = webhookSecrets.encryptSecret('whsec_probe');
      return webhookSecrets.decryptSecret(r.enc, r.iv, r.tag);
    })();
    expect(probe).toBe('whsec_probe');
  });

  test('MWK-06. re-encrypted ciphertext differs from the original (fresh IV, not a copy)', () => {
    secretsProvider._setExternalKek(legacyKek);
    const encrypted = webhookSecrets.encryptSecret(webhookSecrets.generateSecret());
    const row = toRow(encrypted);

    const result = migrateScript._migrateRow(row, targetKek, legacyKek, { secretsProvider, webhookSecrets });
    expect(result.update.enc).not.toBe(encrypted.enc);
    expect(result.update.iv).not.toBe(encrypted.iv);
  });
});
