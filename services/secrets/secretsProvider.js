'use strict';

// Provider-agnostic secrets abstraction.
//
// Current implementation: environment variable (QODIQA_KEY_ENCRYPTION_KEY,
// QODIQA_EXECUTION_INVARIANT_SECRET).
// Future implementations: swap _provider below for an AWS Secrets Manager,
// GCP Secret Manager, Azure Key Vault, or HashiCorp Vault adapter.
//
// All key encryption key (KEK) access in the system flows through this module.
// No component should read QODIQA_KEY_ENCRYPTION_KEY directly.
//
// the execution-invariant HMAC secret is a SEPARATE credential from
// the KEK — purpose isolation (the same principle transparencyKeyStore.js
// applies to signing keys) means a secret used to sign the execution
// invariant token must never be the same material used to encrypt key
// material at rest. It is loaded and cached the same way, from its own
// dedicated environment variable, so a KEK rotation/compromise and an
// execution-invariant-secret rotation/compromise are independent events.

const KEK_BYTE_LENGTH = 32; // 256 bits — required for AES-256-GCM
const EXECUTION_INVARIANT_SECRET_BYTE_LENGTH = 32; // 256 bits — HMAC-SHA256 key

// ── Provider interface ────────────────────────────────────────────────────────
//
// A provider must implement:
//   load() → Buffer  — synchronously or synchronously-wrapped async load of KEK.
//   name   → string  — human-readable provider name for observability events.

const _envProvider = {
  name: 'env:QODIQA_KEY_ENCRYPTION_KEY',

  load() {
    const raw = process.env.QODIQA_KEY_ENCRYPTION_KEY;
    if (!raw) {
      throw new Error(
        'SecretsProvider: QODIQA_KEY_ENCRYPTION_KEY is not set. ' +
        'A 256-bit key encryption key (64 hex characters) is required for ' +
        'encrypted-at-rest key storage. Set this environment variable before starting.',
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error(
        `SecretsProvider: QODIQA_KEY_ENCRYPTION_KEY must be exactly 64 hex characters ` +
        `(256 bits / 32 bytes). Got ${raw.length} character(s).`,
      );
    }
    const kek = Buffer.from(raw, 'hex');
    if (kek.length !== KEK_BYTE_LENGTH) {
      throw new Error(
        `SecretsProvider: decoded key is ${kek.length} bytes; expected ${KEK_BYTE_LENGTH}.`,
      );
    }
    return kek;
  },
};

// Loader for the execution-invariant HMAC secret. Kept as its own
// provider object (not folded into _envProvider) so a future non-local
// backend can supply the KEK and this secret independently, exactly as the
// KEK provider itself is swappable.
const _executionInvariantSecretProvider = {
  name: 'env:QODIQA_EXECUTION_INVARIANT_SECRET',

  load() {
    const raw = process.env.QODIQA_EXECUTION_INVARIANT_SECRET;
    if (!raw) {
      throw new Error(
        'SecretsProvider: QODIQA_EXECUTION_INVARIANT_SECRET is not set. ' +
        'A 256-bit secret (64 hex characters) is required to HMAC-bind the ' +
        'execution invariant context. Set this environment variable before starting. ' +
        'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      );
    }
    if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
      throw new Error(
        `SecretsProvider: QODIQA_EXECUTION_INVARIANT_SECRET must be exactly 64 hex characters ` +
        `(256 bits / 32 bytes). Got ${raw.length} character(s).`,
      );
    }
    const secret = Buffer.from(raw, 'hex');
    if (secret.length !== EXECUTION_INVARIANT_SECRET_BYTE_LENGTH) {
      throw new Error(
        `SecretsProvider: decoded execution invariant secret is ${secret.length} bytes; ` +
        `expected ${EXECUTION_INVARIANT_SECRET_BYTE_LENGTH}.`,
      );
    }
    return secret;
  },
};

// ── Active provider — swap here to change the secrets backend ─────────────────
let _provider  = _envProvider;
let _cachedKek = null; // shallow cache — avoids re-reading env on every operation

let _executionInvariantSecretProviderRef = _executionInvariantSecretProvider;
let _cachedExecutionInvariantSecret      = null;

// ── Public API ────────────────────────────────────────────────────────────────

// the audit key stores can each have their OWN key-encryption key, so one leaked KEK does not open the signing keys of the
// artifact, transparency and checkpoint trust domains at once. A scope's variable, when set, REPLACES the shared KEK for that store
// (and must be 64 hex characters, not a trivial pattern — a malformed value is a hard failure, never a silent fallback); when it is
// unset the store keeps using the shared KEK, so existing deployments and key files are unaffected.
const SCOPED_KEK_ENV = Object.freeze({
  transparency: 'QODIQA_TRANSPARENCY_KEY_ENCRYPTION_KEY',
  'audit-checkpoint': 'QODIQA_CHECKPOINT_KEY_ENCRYPTION_KEY',
  field: 'QODIQA_FIELD_KEY_ENCRYPTION_KEY',                // application-level field encryption (src/infra/crypto/fieldEncryption.js); unset = the shared KEK
});
const _scopedCache = new Map(); // raw env value → Buffer

/** The environment variable that holds the KEK of a scope (or the shared one for no scope). */
function kekEnvName(scope) {
  if (scope === undefined || scope === null) return 'QODIQA_KEY_ENCRYPTION_KEY';
  return SCOPED_KEK_ENV[scope] || null;
}

function _scopedKek(scope) {
  const name = SCOPED_KEK_ENV[scope];
  if (!name) throw new TypeError('SecretsProvider: unknown key-encryption scope "' + scope + '"');
  const raw = process.env[name];
  if (raw === undefined || raw === '') return null;
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) throw new Error('SecretsProvider: ' + name + ' must be exactly 64 hex characters (256 bits). Got ' + raw.length + ' character(s).');
  if (/^0+$/.test(raw) || /^(.)\1+$/.test(raw) || /^(.{2})\1{15,}$/.test(raw)) throw new Error('SecretsProvider: ' + name + ' is a trivial repeating pattern and provides no protection.');
  let k = _scopedCache.get(raw);
  if (!k) { k = Buffer.from(raw, 'hex'); _scopedCache.set(raw, k); }
  return k;
}

function getKeyEncryptionKey(scope) {
  if (scope !== undefined && scope !== null) {
    const k = _scopedKek(scope);
    if (k) return k;                       // a dedicated KEK for this scope; otherwise the shared one below
  }
  if (!_cachedKek) {
    _cachedKek = _provider.load();
  }
  return _cachedKek;
}

/** Does this scope have a KEK of its own (as opposed to the shared one)? */
function hasScopedKek(scope) {
  try { return _scopedKek(scope) !== null; } catch { return false; }
}

function getProviderName() {
  return _provider.name;
}

function isConfigured() {
  try {
    getKeyEncryptionKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * Return the 32-byte execution-invariant HMAC secret, cached for
 * the process lifetime. Never logged, never serialized, never returned to
 * any caller outside services/executionInvariantToken.js.
 * @returns {Buffer}
 */
function getExecutionInvariantSecret() {
  if (!_cachedExecutionInvariantSecret) {
    _cachedExecutionInvariantSecret = _executionInvariantSecretProviderRef.load();
  }
  return _cachedExecutionInvariantSecret;
}

// ── Internal — for testing and future provider injection ──────────────────────

function _setProvider(provider) {
  _provider  = provider;
  _cachedKek = null;
}

function _clearCache() {
  _cachedKek = null;
  _scopedCache.clear();
}

function _setExecutionInvariantSecretProvider(provider) {
  _executionInvariantSecretProviderRef = provider;
  _cachedExecutionInvariantSecret      = null;
}

function _clearExecutionInvariantSecretCache() {
  _cachedExecutionInvariantSecret = null;
}

/**
 * Inject a pre-fetched KEK from an external provider (Vault, AWS KMS, etc.).
 * Called by keyProviderFactory.wireIntoSecretsProvider() before keyStore's
 * first real key-store operation (its lazy bootstrap runs on first use, not
 * at require() time — see services/artifact/keyStore.js), so that keyStore
 * sees the cached KEK instead of reading QODIQA_KEY_ENCRYPTION_KEY.
 * The injected KEK bypasses _provider.load() entirely for this process lifetime.
 * @param {Buffer} kek  32-byte key encryption key
 */
function _setExternalKek(kek) {
  if (!Buffer.isBuffer(kek) || kek.length !== KEK_BYTE_LENGTH) {
    throw new Error(
      `SecretsProvider._setExternalKek: expected a ${KEK_BYTE_LENGTH}-byte Buffer, ` +
      `got ${Buffer.isBuffer(kek) ? kek.length : typeof kek}`,
    );
  }
  _cachedKek = kek;
}

module.exports = {
  getKeyEncryptionKey,
  kekEnvName,
  hasScopedKek,
  SCOPED_KEK_ENV,
  getProviderName,
  isConfigured,
  _setProvider,
  _clearCache,
  _setExternalKek,
  getExecutionInvariantSecret,
  _setExecutionInvariantSecretProvider,
  _clearExecutionInvariantSecretCache,
};
