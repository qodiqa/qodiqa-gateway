'use strict';

/**
 * explicit, fail-closed provisioning of a NEW wrapped KEK.
 *
 * A cloud KMS KEK provider (aws-kms, gcp-kms, azure-kv) keeps its data-encryption KEK only in wrapped form, in one
 * file (kek.edk / kek.gcp / kek.wk). Before this guard a missing file (lost volume, wrong path, partial restore)
 * silently made the provider mint a brand-new KEK and write it at the configured path. Every KEK-encrypted store then
 * failed closed later (KEK_FINGERPRINT_MISMATCH), but the fresh wrapped key now sat exactly where the operator would
 * restore the real one — easy to overwrite or to confuse with it.
 *
 * Rule:
 *   - QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true (exact string) is the explicit provisioning switch: a new KEK may be
 *     minted (first provisioning, or the documented local -> KMS migration:
 *     `node scripts/migrate-keys-json-kek.js --provision-new-kek`, which sets it for its own process only).
 *   - Otherwise, in production (NODE_ENV=production), generation is refused BEFORE any KMS call:
 *     KMS_WRAPPED_KEY_MISSING, nothing written.
 * - Development / test keep the previous implicit first-run generation (the provider unit tests, the
 *     emulator suites and `npm run start:aws|gcp|azure` against a fresh volume rely on it).
 * The callers additionally create the file with flag 'wx', so a wrapped key that appears concurrently (another node)
 * is never overwritten, and every generation is logged (WARN KMS_WRAPPED_KEY_PROVISIONED — never key material).
 */

function assertMayGenerateWrappedKey(providerName, wrappedKeyPath, env = process.env) {
  if (env.QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY === 'true') return { explicit: true };
  if (env.NODE_ENV !== 'production') return { explicit: false };
  /** @type {any} */ const err = new Error(
    `${providerName}: wrapped KEK file not found at ${wrappedKeyPath}, and production never mints a KEK implicitly. ` +
    'Refusing to generate a new KEK (nothing was written). Restore the original wrapped-key file to the configured ' +
    'path — or, ONLY for a deliberate first provisioning / migration, set QODIQA_KMS_ALLOW_NEW_WRAPPED_KEY=true for ' +
    'that one run (KMS_WRAPPED_KEY_MISSING).',
  );
  err.code = 'KMS_WRAPPED_KEY_MISSING';
  throw err;
}

/** Audit trail for a minted KEK (path and provider only — never key material). Logging must never break init. */
function recordWrappedKeyProvisioned(providerName, wrappedKeyPath, explicit) {
  try {
    require('../../../../services/logger').emit('WARN', 'KMS_WRAPPED_KEY_PROVISIONED', {
      provider: providerName, path: wrappedKeyPath, explicit: !!explicit, production: process.env.NODE_ENV === 'production',
      message: 'A NEW KEK was generated and its wrapped form written. Every KEK-encrypted store written under a previous ' +
               'KEK is unreadable under this one — expected only on first provisioning or a deliberate migration.',
    });
  } catch { /* the logger is best-effort here; the key was already written */ }
}

module.exports = { assertMayGenerateWrappedKey, recordWrappedKeyProvisioned };
