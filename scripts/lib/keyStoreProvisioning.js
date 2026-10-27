'use strict';

/**
 * Shared key-store provisioning helpers.
 *
 * Used by both the Jest test environment (test/support/jest.setup.js) and the
 * development bootstrap (scripts/bootstrap-dev.js) to idempotently ensure
 * an active signing key exists, without duplicating the provisioning logic
 * in two places.
 *
 * This module does not choose paths or generate secrets itself. Callers are
 * responsible for setting QODIQA_KEYS_PATH, QODIQA_KEY_ENCRYPTION_KEY, and
 * QODIQA_TRANSPARENCY_KEYS_PATH in process.env before calling ensureActiveKey()
 * / ensureActiveTransparencyKey() below.
 *
 * services/artifact/keyStore.js (used by ensureActiveKey) is side-effect-free
 * on require() — it bootstraps lazily from those env vars on its first real
 * operation, which is the validateKeyStore() call inside ensureActiveKey().
 * src/core/transparency/transparencyKeyStore.js (used by
 * ensureActiveTransparencyKey) still bootstraps synchronously the first time
 * it is require()'d, so QODIQA_TRANSPARENCY_KEYS_PATH must be set before that
 * module — or this one — is required.
 */

/**
 * Ensure an active artifact-signing key exists for `clientId` in the
 * currently-configured key store (services/artifact/keyStore.js, whose
 * on-disk path is QODIQA_KEYS_PATH). No-op if one already exists.
 *
 * F19-remediation: this used to also require `state.totalActive === 0`
 * — i.e. the WHOLE store empty, not just this clientId — so provisioning a
 * second clientId (e.g. `consent-signer` alongside `dev-local` in the same
 * store) silently no-op'd once the first clientId's key existed, despite the
 * second clientId never having one. Never triggered before this fix because
 * every existing call site (test/support/jest.setup.js's 'default', devEnvironment.js's
 * dev tenant) was the only clientId ever provisioned into its own fresh
 * store — harmless until a second clientId was added to the same store.
 *
 * @param {string} clientId
 * @returns {boolean} true if a new key was provisioned, false if one already existed.
 */
function ensureActiveKey(clientId) {
  const { validateKeyStore, rotateKey } = require('../../services/artifact/keyStore');
  const state = validateKeyStore();
  if (!state.clients[clientId]) {
    rotateKey(clientId);
    return true;
  }
  return false;
}

/**
 * Ensure an active transparency-log signing key exists in the
 * currently-configured transparency key store (a completely separate trust
 * domain from the artifact key store — see src/core/transparency/transparencyKeyStore.js,
 * whose on-disk path is QODIQA_TRANSPARENCY_KEYS_PATH). No-op if one already exists.
 *
 * @returns {boolean} true if a new key was provisioned, false if one already existed.
 */
function ensureActiveTransparencyKey() {
  const tKeyStore = require('../../src/core/transparency/transparencyKeyStore');
  const state = tKeyStore.validateKeyStore();
  if (state.totalActive === 0) {
    tKeyStore.rotateKey();
    return true;
  }
  return false;
}

module.exports = { ensureActiveKey, ensureActiveTransparencyKey };
