#!/usr/bin/env node
'use strict';

/**
 * keys.json KEK Migration — remediation
 *
 * Background: keyProviderFactory.rotateWrappingKey() rotates the active KMS
 * provider's own wrapping key (KEK) — the key that encrypts every active
 * artifact-signing private key at rest in keys.json. Rotation takes effect
 * immediately for all FUTURE encryption (new keys, future rotations), but it
 * does not retroactively re-encrypt ciphertext already written to keys.json
 * under the OLD KEK. Until this script runs, keys.json remains encrypted
 * under the old KEK (still fine — it's still known — but not the end state
 * an operator rotating the KEK usually wants).
 *
 * This script reuses keyStore.js's own reloadFromDisk()/saveKeys() for every
 * cryptographic and file operation — it contains no independent crypto or
 * file-I/O implementation. It works by temporarily pointing secretsProvider
 * at the LEGACY KEK (via the same _setExternalKek() hook
 * keyProviderFactory.wireIntoSecretsProvider() itself uses) to decrypt the
 * existing file into memory, then switching to the CURRENT (post-rotation)
 * KEK before calling saveKeys() — which keyStore.js's own logic already
 * re-encrypts every active record's private key material under whatever KEK
 * is current every time it runs, atomically (temp file + rename), exactly as
 * it does on every ordinary rotation.
 *
 * Safety:
 *   - Defaults to DRY RUN: decrypts under the legacy KEK to prove it's
 *     recoverable and reports how many active keys would be migrated, but
 *     never calls saveKeys(). Pass --execute to actually write.
 *   - Idempotent: if keys.json is already encrypted under the CURRENT KEK
 *     (e.g. this script already ran, or the deployment never had a stale
 *     ciphertext in the first place), reloadFromDisk() under the current KEK
 *     succeeds directly and the script reports "already current" without
 *     needing the legacy KEK at all.
 *   - Never logs private key material or KEK bytes, only outcomes and counts.
 *   - If decryption fails under BOTH the current and legacy KEK, the script
 *     aborts without writing anything — it never discards or corrupts
 *     keys.json.
 *
 * Usage:
 *   QODIQA_KMS_PROVIDER=vault-kv QODIQA_LEGACY_KEY_ENCRYPTION_KEY=<old hex KEK> \
 *     node scripts/migrate-keys-json-kek.js              # dry run
 *
 *   QODIQA_KMS_PROVIDER=vault-kv QODIQA_LEGACY_KEY_ENCRYPTION_KEY=<old hex KEK> \
 *     node scripts/migrate-keys-json-kek.js --execute     # apply
 *
 * QODIQA_LEGACY_KEY_ENCRYPTION_KEY is the KEK keys.json was encrypted under
 * BEFORE the most recent POST /key-admin/kek/rotate call — required only to
 * recover a file still under the old KEK. For the 'local' provider, this is
 * simply the previous value of QODIQA_KEY_ENCRYPTION_KEY (rotation for that
 * provider is an operator-driven env-var swap, not a real rotation call).
 * If not set, a file that isn't already current is reported as needing it,
 * rather than being silently skipped.
 *
 * in production a cloud KMS provider (aws-kms, gcp-kms,
 * azure-kv) never mints a NEW KEK implicitly when its wrapped-key file is
 * missing. The local -> KMS migration is exactly the case where it must, so it
 * is made explicit here:
 *
 *   QODIQA_KMS_PROVIDER=aws-kms QODIQA_LEGACY_KEY_ENCRYPTION_KEY=<old hex KEK>  *     node scripts/migrate-keys-json-kek.js --execute --provision-new-kek
 *
 * --provision-new-kek sets QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true for THIS
 * process only, and is refused without --execute (minting a KEK writes the
 * wrapped-key file, so it is never part of a dry run).
 */

/**
 * resolve the explicit new-KEK provisioning switch from argv.
 * @returns {{ provision: boolean, error: string|null }}
 */
function _kekProvisioningSwitch(argv, env) {
  if (!argv.includes('--provision-new-kek')) return { provision: false, error: null };
  if (!argv.includes('--execute')) {
    return { provision: false, error: '--provision-new-kek requires --execute (minting a KEK writes the wrapped-key file; it is never part of a dry run).' };
  }
  env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY = 'true';
  return { provision: true, error: null };
}

/**
 * Core migration logic, isolated from process.env/argv/dotenv for testability.
 * Contains no independent crypto — every decrypt/encrypt happens implicitly
 * inside keyStore.reloadFromDisk()/saveKeys() via whatever KEK
 * secretsProvider currently points at.
 *
 * @param {{
 *   keyStore: object, secretsProvider: object,
 *   targetKek: Buffer, legacyKek: Buffer|null, execute: boolean,
 *   log?: function,
 * }} deps
 * @returns {{
 *   outcome: 'already-current'|'migrated'|'dry-run'|'failed',
 *   activeKeys: number, error: string|null,
 * }}
 */
function _migrate({ keyStore, secretsProvider, targetKek, legacyKek, execute, log = () => {} }) {
  // First, try decrypting under the CURRENT KEK — if keys.json is already
  // current (nothing to migrate, or this script already ran), this succeeds
  // directly and no legacy KEK is needed at all.
  let reload = keyStore.reloadFromDisk();
  // reloadFromDisk() returns { reloaded: false, error: null } for "no file on
  // disk" (nothing to migrate — trivially current) as well as for a genuine
  // successful reload ({ reloaded: true, ... }). Only { reloaded: false,
  // error: <message> } — a real decrypt/parse failure under the current
  // KEK — means the file needs the legacy-KEK recovery path below.
  const needsLegacyAttempt = reload.reloaded === false && !!reload.error;

  if (!needsLegacyAttempt) {
    const activeKeys = keyStore.listKeys().filter(k => k.status === 'active').length;
    log('INFO', 'keys.json is already encrypted under the current KEK — nothing to migrate.', { activeKeys });
    return { outcome: 'already-current', activeKeys, error: null };
  }

  if (!legacyKek) {
    log('ERROR', 'keys.json is not decryptable under the current KEK, and no legacy KEK was provided.', { detail: reload.error });
    return { outcome: 'failed', activeKeys: 0, error: reload.error };
  }

  log('INFO', 'keys.json is not current — attempting decrypt under the legacy KEK');
  secretsProvider._setExternalKek(legacyKek);
  reload = keyStore.reloadFromDisk();

  if (reload.reloaded === false && reload.error) {
    // Restore the target KEK before returning — never leave secretsProvider
    // pointed at the legacy KEK for the caller's subsequent operations.
    secretsProvider._setExternalKek(targetKek);
    log('ERROR', 'keys.json is not decryptable under EITHER the current or legacy KEK — aborting without writing anything.', { detail: reload.error });
    return { outcome: 'failed', activeKeys: 0, error: reload.error };
  }

  secretsProvider._setExternalKek(targetKek);
  const activeKeys = keyStore.listKeys().filter(k => k.status === 'active').length;
  log('INFO', `Recovered keys.json under the legacy KEK — ${activeKeys} active key(s) will be re-encrypted under the current KEK.`);

  if (!execute) {
    log('INFO', 'Dry run complete — re-run with --execute to write keys.json under the current KEK.');
    return { outcome: 'dry-run', activeKeys, error: null };
  }

  keyStore.saveKeys();
  log('INFO', 'Migration complete — keys.json re-encrypted under the current KEK.', { activeKeys });
  return { outcome: 'migrated', activeKeys, error: null };
}

function _defaultLog(level, msg, data = {}) {
  const prefix = { INFO: '✓', WARN: '⚠', ERROR: '✗' }[level] ?? '·';
  const extra  = Object.keys(data).length ? `  ${JSON.stringify(data)}` : '';
  console.log(`${prefix} ${msg}${extra}`);
}

async function main() {
  require('dotenv').config();
  const EXECUTE = process.argv.includes('--execute');

  const kpf              = require('../src/infra/keys/keyProviderFactory');
  const secretsProvider   = require('../services/secrets/secretsProvider');
  const keyStore          = require('../services/artifact/keyStore');

  _defaultLog('INFO', EXECUTE ? 'Starting migration (writes enabled)' : 'DRY RUN — no writes will occur (pass --execute to apply)');

  const legacyKekHex = process.env.QODIQA_LEGACY_KEY_ENCRYPTION_KEY || null;
  let legacyKek = null;
  if (legacyKekHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(legacyKekHex)) {
      _defaultLog('ERROR', 'QODIQA_LEGACY_KEY_ENCRYPTION_KEY is set but is not 64 hex characters — cannot use as legacy KEK.');
      process.exitCode = 1;
      return;
    }
    legacyKek = Buffer.from(legacyKekHex, 'hex');
  }

  const sw = _kekProvisioningSwitch(process.argv, process.env); //
  if (sw.error) {
    _defaultLog('ERROR', sw.error);
    process.exitCode = 1;
    return;
  }
  if (sw.provision) _defaultLog('WARN', 'Explicit new-KEK provisioning enabled for this run (QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true): a missing wrapped-key file will be created under a NEW KEK.');

  try {
    await kpf.initialize();
    await kpf.wireIntoSecretsProvider();
  } catch (err) {
    _defaultLog('ERROR', `Failed to initialize the configured KMS provider: ${err.message}`);
    process.exitCode = 1;
    return;
  }

  const targetKek = secretsProvider.getKeyEncryptionKey();
  _defaultLog('INFO', 'Target (current, post-rotation) KEK resolved via secretsProvider');

  const result = _migrate({ keyStore, secretsProvider, targetKek, legacyKek, execute: EXECUTE, log: _defaultLog });
  if (result.outcome === 'failed') {
    if (!legacyKek) {
      _defaultLog('ERROR', 'Set QODIQA_LEGACY_KEY_ENCRYPTION_KEY to the KEK keys.json was encrypted under and re-run.');
    }
    process.exitCode = 1;
  }
}

module.exports = { _migrate, _kekProvisioningSwitch, main };

if (require.main === module) {
  main()
    .catch((err) => {
      _defaultLog('ERROR', `Migration FAILED: ${err.message}`);
      console.error(err.stack);
      process.exitCode = 1;
    });
}
