'use strict';

/**
 * QODIQA Key Provider Factory
 *
 * Single entry point for configuring and initializing the active KEK provider
 * and (optionally) the native signing provider.
 *
 * Provider selection — QODIQA_KMS_PROVIDER env var:
 *   "local"         — env var KEK (default, backward-compatible)
 *   "vault-kv"      — HashiCorp Vault KV v2 for KEK storage
 *   "vault-transit" — HashiCorp Vault Transit for native Ed25519 signing
 *   "aws-kms"       — AWS KMS data-key wrapping
 *   "azure-kv"      — Azure Key Vault key wrapping
 *   "gcp-kms"       — Google Cloud KMS wrapping
 *   "hsm"           — PKCS#11 HSM for native signing
 *
 * Usage (in start.js, before keyStore's first real operation):
 *
 *   const kpf = require('./src/infra/keys/keyProviderFactory');
 *   await kpf.initialize();                     // async provider boot
 *   kpf.wireIntoSecretsProvider();              // populates secretsProvider cache
 *
 * If QODIQA_KMS_PROVIDER is "vault-transit" or "hsm", the factory also
 * registers the NativeSigningProvider with nativeSigningRegistry so that
 * keyManager.js can delegate signing/keygen to the external backend.
 */

const { emit } = require('../../../services/logger');
const secretsProvider = require('../../../services/secrets/secretsProvider');
const { ResilientKekProvider }     = require('./resilience/resilientKekProvider');
const { ResilientSigningProvider } = require('./resilience/resilientSigningProvider');
const resilienceCircuitBreaker     = require('./resilience/circuitBreaker');
const resilienceHealthMonitor      = require('./resilience/healthMonitor');
const { validateKmsConfig }        = require('./kmsConfig');
const { checkSdkAvailability }     = require('./sdkAvailability');

// ── Lazy provider constructors ────────────────────────────────────────────────

function _buildKekProvider(type, opts) {
  switch (type) {
    case 'local': {
      const { LocalKekProvider } = require('./providers/local');
      return new (/** @type {any} */ (LocalKekProvider))(opts);
    }
    case 'vault-kv': {
      const { VaultKekProvider } = require('./providers/vault');
      return new VaultKekProvider(opts);
    }
    case 'aws-kms': {
      const { AwsKmsKekProvider } = require('./providers/awsKms');
      return new AwsKmsKekProvider(opts);
    }
    case 'azure-kv': {
      const { AzureKeyVaultKekProvider } = require('./providers/azureKeyVault');
      return new AzureKeyVaultKekProvider(opts);
    }
    case 'gcp-kms': {
      const { GcpKmsKekProvider } = require('./providers/gcpKms');
      return new GcpKmsKekProvider(opts);
    }
    default: {
      const known = ['local', 'vault-kv', 'aws-kms', 'azure-kv', 'gcp-kms'];
      throw new Error(
        `keyProviderFactory: unknown KEK provider "${type}". Valid values: ${known.join(', ')}`,
      );
    }
  }
}

function _buildNativeSigningProvider(type, opts) {
  switch (type) {
    case 'vault-transit': {
      const { VaultTransitSigningProvider } = require('./providers/vault');
      return new VaultTransitSigningProvider(opts);
    }
    case 'hsm': {
      const { HsmSigningProvider } = require('./providers/hsm');
      return new HsmSigningProvider(opts);
    }
    default: {
      const known = ['vault-transit', 'hsm'];
      throw new Error(
        `keyProviderFactory: unknown native signing provider "${type}". Valid values: ${known.join(', ')}`,
      );
    }
  }
}

// ── Module state ──────────────────────────────────────────────────────────────

let _kekProvider            = null;
let _nativeSigningProvider  = null;
let _initialized            = false;
let _kekProviderType        = null; //

// the KEK provider TYPE ('local' | 'aws-kms' | 'gcp-kms' |
// 'azure-kv' | 'vault-kv' | …). Before initialize() it is derived from the
// environment exactly as initialize() would derive it (vault-transit/hsm use
// QODIQA_KMS_KEK_PROVIDER, default 'local'), so a caller can tell that a
// wrapping-key rotation would be a no-op on the local provider.
function getKekProviderType() {
  if (_kekProviderType) return _kekProviderType;
  const providerType = process.env.QODIQA_KMS_PROVIDER || 'local';
  return (providerType === 'vault-transit' || providerType === 'hsm')
    ? (process.env.QODIQA_KMS_KEK_PROVIDER || 'local')
    : providerType;
}

// ── Native signing registry ───────────────────────────────────────────────────
// keyManager.js checks this at sign-time and delegates to the native provider
// when present.  When null, keyManager.js falls back to local Ed25519 via keyStore.

function getNativeSigningProvider() {
  return _nativeSigningProvider;
}

function isNativeSigning() {
  return _nativeSigningProvider !== null;
}

/**
 * Synchronous check for whether initialize() has already completed
 * successfully in this process. Lets a synchronous caller (server.js's
 * Finding-D entrypoint gate) decide, without awaiting anything, whether the
 * async KMS bootstrap has already run — e.g. because start.js already did it
 * before requiring server.js — so it can take the plain synchronous
 * app-construction path instead of re-entering the async one.
 */
function isInitialized() {
  return _initialized;
}

// ── Initialization ────────────────────────────────────────────────────────────

async function initialize(opts = {}) {
  if (_initialized) return;

  const providerType = opts.provider || process.env.QODIQA_KMS_PROVIDER || 'local';
  emit('INFO', 'KMS_PROVIDER_INIT_START', { provider: providerType });

  // Vault-transit and HSM are native-signing providers; they also need a KEK
  // source for the local keyStore file (deprecated keys need their public DER,
  // and the keyStore file holds metadata).  Default the KEK to 'local' in those
  // cases unless a KEK provider override is given.
  const isNativeSigningType = providerType === 'vault-transit' || providerType === 'hsm';
  const kekType = isNativeSigningType
    ? (opts.kekProvider || process.env.QODIQA_KMS_KEK_PROVIDER || 'local')
    : providerType;

  // Items 21/22: centralized config + SDK-availability validation for every
  // backend this call will actually construct, BEFORE any provider-specific
  // construction runs. Each throws (after emitting one precise FATAL naming
  // the exact field/package) rather than letting the failure surface later,
  // deep inside a provider's own ad hoc initialize()-time check. Validates
  // kekType too when it differs from providerType (vault-transit/hsm with an
  // independently-configured QODIQA_KMS_KEK_PROVIDER).
  validateKmsConfig(providerType);
  checkSdkAvailability(providerType);
  if (kekType !== providerType) {
    validateKmsConfig(kekType);
    checkSdkAvailability(kekType);
  }

  try {
    // every provider — KEK or native-signing, cloud KMS or Vault/HSM —
    // is wrapped in the centralized resilience layer (timeout, bounded
    // jittered retry, circuit breaker, health monitoring, metrics,
    // structured logs) BEFORE its own initialize() ever runs. No provider
    // file under ./providers/ is modified; the wrapper is the only thing
    // that changes, and it changes identically for all of them.
    _kekProvider = new ResilientKekProvider(_buildKekProvider(kekType, opts));
    if (_kekProvider) {
      await _kekProvider.initialize();
      emit('INFO', 'KMS_KEK_PROVIDER_READY', { provider: _kekProvider.name });
    }

    if (isNativeSigningType) {
      _nativeSigningProvider = new ResilientSigningProvider(_buildNativeSigningProvider(providerType, opts));
      if (_nativeSigningProvider) {
        await _nativeSigningProvider.initialize();
        emit('INFO', 'KMS_NATIVE_SIGNING_PROVIDER_READY', { provider: _nativeSigningProvider.name });
      }
    }

    _initialized = true;
    _kekProviderType = kekType;
    emit('INFO', 'KMS_PROVIDER_INIT_COMPLETE', {
      provider:             providerType,
      kekProvider:          _kekProvider?.name    ?? 'none',
      nativeSigningProvider: _nativeSigningProvider?.name ?? 'none (local Ed25519)',
    });
  } catch (err) {
    emit('ERROR', 'KMS_PROVIDER_INIT_FAILED', { provider: providerType, error: err.message });
    throw err;
  }
}

/**
 * After initialize(), call this to propagate the KEK into secretsProvider's cache
 * so that keyStore.js (which calls getKeyEncryptionKey() on its first real
 * key-store operation — not at require() time) sees the externally-sourced
 * KEK immediately.
 *
 * Must be called before keyStore.js's or keyManager.js's first real operation
 * (in practice, before server.js's startup validation runs).
 */
async function wireIntoSecretsProvider() {
  if (!_kekProvider) {
    throw new Error('keyProviderFactory: initialize() must be called before wireIntoSecretsProvider()');
  }
  const kek = await _kekProvider.getWrappingKey();
  secretsProvider._setExternalKek(kek);
}

/**
 * Run initialize() + wireIntoSecretsProvider() with process.exit(1) on
 * failure — the exact two-step sequence start.js has always performed as
 * its own steps 1-2, extracted here so start.js and server.js's Finding-D
 * entrypoint gate (the fix for `npm start`/`node server.js` silently
 * ignoring QODIQA_KMS_PROVIDER when run directly — see
 *) share exactly one
 * implementation instead of two copies that could drift.
 *
 * Writes the same "[FATAL] ..." messages to stderr and exits with the same
 * code 1 that start.js has always used for this failure — this function's
 * behavior for start.js's own callers is unchanged, only its location moved.
 */
async function bootstrapOrExit() {
  const provider = process.env.QODIQA_KMS_PROVIDER || 'local';
  try {
    await initialize();
  } catch (err) {
    process.stderr.write(
      `[FATAL] KMS provider initialisation failed` +
      ` (QODIQA_KMS_PROVIDER=${provider}): ${err.message}\n`,
    );
    process.exit(1);
  }
  try {
    await wireIntoSecretsProvider();
  } catch (err) {
    process.stderr.write(
      `[FATAL] Failed to wire KEK into secretsProvider: ${err.message}\n`,
    );
    process.exit(1);
  }
}

// ── Health check ──────────────────────────────────────────────────────────────

async function healthCheck() {
  const results = {};
  if (_kekProvider) {
    results.kekProvider = await _kekProvider.healthCheck().catch(e => ({
      healthy: false, detail: e.message,
    }));
  }
  if (_nativeSigningProvider) {
    results.nativeSigningProvider = await _nativeSigningProvider.healthCheck().catch(e => ({
      healthy: false, detail: e.message,
    }));
  }
  const allHealthy = Object.values(results).every(r => r.healthy);
  return { healthy: allHealthy, providers: results };
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

async function shutdown() {
  const errors = [];
  if (_nativeSigningProvider) {
    await _nativeSigningProvider.shutdown().catch(e => errors.push(e.message));
    _nativeSigningProvider = null;
  }
  if (_kekProvider) {
    await _kekProvider.shutdown().catch(e => errors.push(e.message));
    _kekProvider = null;
  }
  _initialized = false;
  _kekProviderType = null;
  if (errors.length) {
    emit('WARN', 'KMS_PROVIDER_SHUTDOWN_ERRORS', { errors });
  }
}

// ── Provider wrapping-key rotation ───────────────────────────────────────────

// previously this only rotated the provider's own internal KEK
// reference and returned — the new KEK never reached secretsProvider (whose
// getKeyEncryptionKey() every encrypt/decrypt call in the codebase actually
// reads from), so no subsequent operation ever used it. wireIntoSecretsProvider()
// is the SAME function initialize()/startup already calls to populate that
// cache in the first place — calling it again here is the minimal, correct
// fix: the new KEK takes effect for every future encryptKeyMaterial() call
// immediately after this function returns.
//
// This does NOT retroactively re-encrypt ciphertext already written under the
// old KEK (keys.json, encrypted webhook secrets, etc.) — that is a separate,
// explicit, operator-run migration step. See scripts/migrate-keys-json-kek.js
// (mirrors the existing scripts/migrate-webhook-secrets-kek.js for).
async function rotateWrappingKey() {
  if (!_kekProvider) throw new Error('keyProviderFactory: not initialized');
  const result = await _kekProvider.rotateWrappingKey();
  await wireIntoSecretsProvider();
  emit('INFO', 'KMS_WRAPPING_KEY_ROTATED', { provider: _kekProvider.name, ...result });
  return result;
}

// ── Resilience diagnostics ─────────────────────────────────────────────
//
// Circuit breaker state + health for every wrapped provider — for operator
// tooling and tests. Not wired to an HTTP route by this change; the metrics
// already exported via src/observability/metrics.js (qodiqa_signing_*) are
// the intended production monitoring surface.

function getResilienceSnapshot() {
  return {
    circuitBreakers: resilienceCircuitBreaker.snapshot(),
    health:          resilienceHealthMonitor.snapshotAll(),
  };
}

module.exports = {
  initialize,
  wireIntoSecretsProvider,
  bootstrapOrExit,
  isInitialized,
  getNativeSigningProvider,
  isNativeSigning,
  getKekProviderType,
  healthCheck,
  getResilienceSnapshot,
  shutdown,
  rotateWrappingKey,
};
