'use strict';

/**
 * Cloud/Vault/HSM SDK availability gate (item 22).
 *
 * Every SDK below is already loaded lazily inside its provider file's own
 * `_requireX()` helper (see ./providers/*.js), each with its own try/catch
 * producing a clear "X is not installed. Run: npm install Y" Error. This
 * module does not replace that pattern — it formalizes the SAME check into
 * something callable BEFORE a provider is constructed, so the failure
 * happens at one predictable point (with the backend name attached) instead
 * of wherever inside an async initialize() call the provider happens to
 * first touch its SDK.
 *
 * The resolver is injectable (defaults to require.resolve) specifically so
 * tests can simulate "SDK not installed" by mocking resolution failure,
 * never by actually installing/uninstalling a real package.
 */

const { emit } = require('../../../services/logger');

const SDK_MANIFEST = Object.freeze({
  'vault-kv':      Object.freeze(['node-vault']),
  'vault-transit': Object.freeze(['node-vault']),
  'aws-kms':       Object.freeze(['@aws-sdk/client-kms']),
  'azure-kv':      Object.freeze(['@azure/keyvault-keys', '@azure/identity']),
  'gcp-kms':       Object.freeze(['@google-cloud/kms']),
  'hsm':           Object.freeze(['pkcs11js']),
});

/**
 * @param {string} provider
 * @param {{ resolve?: (id: string) => string }} [opts] - resolver override for tests.
 * @returns {{ provider: string, ok: true, missing: [] }}
 * @throws {Error} if the provider requires an SDK and it cannot be resolved —
 *   after emitting a single FATAL naming the backend, the missing package(s),
 *   and the install command. No-op (does not throw, does not emit) when the
 *   provider requires no SDK (local, or an unrecognized provider name — left
 *   to keyProviderFactory.js's own selection error, same rationale as
 *   kmsConfig.js).
 */
function checkSdkAvailability(provider, opts = {}) {
  const packages = SDK_MANIFEST[provider];
  if (!packages) {
    return { provider, ok: true, missing: [] };
  }

  const resolve = opts.resolve || require.resolve;
  const missing = [];
  for (const pkg of packages) {
    try {
      resolve(pkg);
    } catch {
      missing.push(pkg);
    }
  }

  if (missing.length > 0) {
    const installCommand = `npm install ${missing.join(' ')}`;
    emit('FATAL', 'KMS_SDK_UNAVAILABLE', { provider, missing, installCommand });
    throw new Error(
      `KMS provider "${provider}" is configured but ${missing.length > 1 ? 'its SDKs are' : 'its SDK is'} ` +
      `not installed: ${missing.join(', ')}. Run: ${installCommand}`,
    );
  }

  emit('INFO', 'KMS_SDK_AVAILABLE', { provider, packages });
  return { provider, ok: true, missing: [] };
}

module.exports = { checkSdkAvailability, SDK_MANIFEST };
