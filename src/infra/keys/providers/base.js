'use strict';

/**
 * QODIQA Distributed Key Management — Provider Abstractions
 *
 * Two orthogonal provider contracts:
 *
 *   KekProvider         — asynchronously supplies the 256-bit Key Encryption Key
 *                         used by keyEncryption.js to wrap Ed25519 private keys at
 *                         rest.  All cloud KMS variants (AWS, Azure, GCP, Vault KV)
 *                         implement this interface.
 *
 *   NativeSigningProvider — delegates Ed25519 sign/verify/keygen to a remote HSM or
 *                           Vault Transit backend.  Private key material never leaves
 *                           the provider.  Only Vault Transit and PKCS#11 HSM
 *                           implement this interface.  When active, keyStore.js
 *                           bypasses its local private-key path entirely.
 *
 * Both are abstract base classes that throw on any unimplemented method, keeping
 * the duck-typing safe without TypeScript.
 */

// ── KEK Provider ──────────────────────────────────────────────────────────────

class KekProvider {
  /** @returns {string} Human-readable provider identifier for audit events. */
  get name() {
    throw new Error(`${this.constructor.name}: name getter not implemented`);
  }

  /**
   * Perform any async setup (network handshake, credential exchange, etc.).
   * Called once by keyProviderFactory during process startup, before keyStore
   * is bootstrapped.  Must resolve before getWrappingKey() is called.
   */
  async initialize() {}

  /**
   * Return the 256-bit (32-byte) wrapping key for AES-256-GCM.
   * For cloud KMS providers this is a data-key obtained by decrypting the
   * encrypted data key (EDK) stored in the local keystore file.
   * @returns {Promise<Buffer>}
   */
  async getWrappingKey() {
    throw new Error(`${this.constructor.name}: getWrappingKey() not implemented`);
  }

  /**
   * Rotate the wrapping key.  Providers that manage their own key rotation
   * (e.g. AWS KMS automatic rotation) can no-op this.  Providers that hold
   * a static EDK should re-encrypt the EDK under the new master key version.
   * @returns {Promise<{ version: string }>}
   */
  async rotateWrappingKey() {
    throw new Error(`${this.constructor.name}: rotateWrappingKey() not implemented`);
  }

  /**
   * Return a liveness / configuration health object.
   * @returns {Promise<{ healthy: boolean, detail: string }>}
   */
  async healthCheck() {
    throw new Error(`${this.constructor.name}: healthCheck() not implemented`);
  }

  /** Release connections / credentials on graceful shutdown. */
  async shutdown() {}
}

// ── Revocation capability model ─────────────────────────────────────────────
//
// Not every native signing backend can permanently destroy key material
// (IAM policy may forbid it, or the backend may only support disabling).
// Providers advertise what they support via getRevocationCapabilities();
// callers (keyStore.js) pick the strongest supported method rather than
// assuming any one operation is universally available.
//
// Ordered strongest → weakest.  "strongest" means: least likely to leave the
// key usable at the provider boundary after revocation completes.
const REVOCATION_METHODS = Object.freeze({
  DESTROY:           'destroy',           // irreversible deletion of key material
  SCHEDULE_DELETION:  'schedule_deletion', // deletion queued, honors a mandatory waiting period (e.g. cloud KMS)
  DISABLE:           'disable',           // key object retained but marked unusable for new operations
  ARCHIVE:           'archive',           // key moved out of the active keyring; recoverable by an operator
  DEPRECATE:         'deprecate',         // weakest: blocks new signing, but the provider still considers the key valid for existing purposes
});

const REVOCATION_STRENGTH_ORDER = Object.freeze([
  REVOCATION_METHODS.DESTROY,
  REVOCATION_METHODS.SCHEDULE_DELETION,
  REVOCATION_METHODS.DISABLE,
  REVOCATION_METHODS.ARCHIVE,
  REVOCATION_METHODS.DEPRECATE,
]);

/**
 * Given the list of methods a provider advertises via getRevocationCapabilities(),
 * return the strongest one QODIQA should use for a full key revocation.
 * @param {string[]} supportedMethods
 * @returns {string|null} the strongest supported method, or null if none are recognised.
 */
function pickStrongestRevocationMethod(supportedMethods) {
  if (!Array.isArray(supportedMethods) || supportedMethods.length === 0) return null;
  for (const method of REVOCATION_STRENGTH_ORDER) {
    if (supportedMethods.includes(method)) return method;
  }
  return null;
}

// ── Native Signing Provider ───────────────────────────────────────────────────

class NativeSigningProvider {
  /** @returns {string} Human-readable provider identifier. */
  get name() {
    throw new Error(`${this.constructor.name}: name getter not implemented`);
  }

  async initialize() {}

  /**
   * Generate an Ed25519 key pair inside the provider.
   * The private key never leaves the provider boundary.
   * @param {string} keyName  Provider-scoped key identifier (e.g. "qodiqa/default:key_v3").
   * @returns {Promise<{ publicKeyDer: Buffer, keyName: string }>}
   */
  async generateKeyPair(keyName) {
    throw new Error(`${this.constructor.name}: generateKeyPair() not implemented`);
  }

  /**
   * Sign a pre-hashed message with Ed25519.
   * The caller is responsible for hashing: SHA-256("QODIQA::ARTIFACT::V1" || payload).
   * @param {string} keyName     Provider-scoped key identifier.
   * @param {Buffer} messageHash 32-byte SHA-256 digest.
   * @returns {Promise<Buffer>}  64-byte Ed25519 signature.
   */
  async sign(keyName, messageHash) {
    throw new Error(`${this.constructor.name}: sign() not implemented`);
  }

  /**
   * Return the DER-encoded SPKI public key for a named key.
   * @param {string} keyName
   * @returns {Promise<{ publicKeyDer: Buffer, status: string }>}
   */
  async getPublicKey(keyName) {
    throw new Error(`${this.constructor.name}: getPublicKey() not implemented`);
  }

  /**
   * Deprecate (retire) the named key.  The provider should preserve the
   * public key for verification but disallow further signing.
   * @param {string} keyName
   */
  async deprecateKey(keyName) {
    throw new Error(`${this.constructor.name}: deprecateKey() not implemented`);
  }

  /**
   * Return the revocation methods this provider supports, in no particular
   * order (keyStore.js ranks them via pickStrongestRevocationMethod()).
   * Every concrete provider MUST override this — there is no safe default,
   * because silently claiming a capability a backend doesn't have would let
   * a caller believe a key is fully revoked when it is not.
   * @returns {string[]} a subset of REVOCATION_METHODS values.
   */
  getRevocationCapabilities() {
    throw new Error(`${this.constructor.name}: getRevocationCapabilities() not implemented`);
  }

  /**
   * Revoke the named key at the provider boundary using the given method
   * (one of the values returned by getRevocationCapabilities() — the caller,
   * not this method, is responsible for choosing the strongest one).
   *
   * MUST throw on any failure — never resolve as if revocation succeeded
   * when it did not. The thrown Error should carry enough detail (message,
   * and ideally a `.cause`/provider error body) for the caller to build a
   * complete audit record.
   *
   * @param {string} keyName
   * @param {{ method?: string }} [opts]  Defaults to this provider's strongest
   *   supported method when omitted.
   * @returns {Promise<{ method: string, provider: string, revokedAt: string, providerResponse?: object }>}
   */
  async revokeKey(keyName, opts) {
    throw new Error(`${this.constructor.name}: revokeKey() not implemented`);
  }

  /** @returns {Promise<{ healthy: boolean, detail: string }>} */
  async healthCheck() {
    throw new Error(`${this.constructor.name}: healthCheck() not implemented`);
  }

  async shutdown() {}
}

module.exports = {
  KekProvider,
  NativeSigningProvider,
  REVOCATION_METHODS,
  REVOCATION_STRENGTH_ORDER,
  pickStrongestRevocationMethod,
};
