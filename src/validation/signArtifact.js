'use strict';

/**
 * QODIQA Artifact Signer — full-envelope binding (V2)
 *
 * Every field that influences access control decisions MUST be included in the
 * signed structure.  Signing over only the payload (V1) allowed an attacker to
 * reuse a captured signature with a fresh timestamp/expiry, or to extend the
 * expiry of an existing artifact indefinitely.
 *
 * Signed structure (canonicalized with stableStringify, domain-separated hash):
 *   {
 *     expiry:      number   — Unix ms, must be > timestamp
 *     payload:     object   — plain object, no undefined values
 *     publicKeyId: string   — key ID that will be used for verification
 *     timestamp:   number   — Unix ms, must be > 0
 *   }
 *
 * The signature is:
 *   Ed25519.sign(SHA-256("QODIQA::ARTIFACT::V1" || stableStringify(above)), privateKey)
 */

const { envelopeHash, isPlainObject, hasUndefined } = require('./canonicalize');
const { sign } = require('../infra/crypto/ed25519');

/**
 * Input validation shared by signArtifact() and signArtifactNative(): any invalid input throws synchronously so that callers
 * cannot accidentally produce an artifact that will fail verification.
 *
 * @param {{ payload: object, timestamp: number, expiry: number, publicKeyId: string }} envelope
 * @throws {TypeError}   On any invalid input.
 */
function _validateEnvelope({ payload, timestamp, expiry, publicKeyId }) {
  // ── Input validation ────────────────────────────────────────────────────────

  if (!isPlainObject(payload)) {
    throw new TypeError('signArtifact: payload must be a plain object (Object.prototype or null prototype)');
  }
  if (hasUndefined(payload)) {
    throw new TypeError('signArtifact: payload must not contain undefined values — use null for absent fields');
  }

  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp) || timestamp <= 0) {
    throw new TypeError(`signArtifact: timestamp must be a positive finite number, got ${timestamp}`);
  }
  if (typeof expiry !== 'number' || !Number.isFinite(expiry) || expiry <= 0) {
    throw new TypeError(`signArtifact: expiry must be a positive finite number, got ${expiry}`);
  }
  if (expiry <= timestamp) {
    throw new TypeError(`signArtifact: expiry (${expiry}) must be strictly greater than timestamp (${timestamp})`);
  }

  if (typeof publicKeyId !== 'string' || !publicKeyId.trim()) {
    throw new TypeError('signArtifact: publicKeyId must be a non-empty string');
  }

}

/**
 * Sign a QODIQA artifact with full-envelope binding.
 *
 * Validates all inputs before signing — any invalid input throws synchronously
 * so that callers cannot accidentally produce an artifact that will fail
 * verification.
 *
 * @param {{ payload: object, timestamp: number, expiry: number, publicKeyId: string }} envelope
 * @param {Buffer} privDer  Ed25519 private key in PKCS8 DER format.
 * @returns {Readonly<{ payload: object, signature: string, timestamp: number, expiry: number, publicKeyId: string }>}
 * @throws {TypeError}   On any invalid input.
 */
function signArtifact({ payload, timestamp, expiry, publicKeyId }, privDer) {
  _validateEnvelope({ payload, timestamp, expiry, publicKeyId });
  if (!Buffer.isBuffer(privDer) || privDer.length === 0) {
    throw new TypeError('signArtifact: privDer must be a non-empty Buffer');
  }

  // ── Signing ─────────────────────────────────────────────────────────────────

  const hashBuf   = envelopeHash({ expiry, payload, publicKeyId, timestamp });
  const signature = sign(hashBuf, privDer);

  return Object.freeze({ expiry, payload, publicKeyId, signature, timestamp });
}

/**
 * Same artifact, signed by a NativeSigningProvider (Vault Transit / HSM) — the private key never enters this process.
 * `nativeSign(keyId, hash32)` must resolve to a 64-byte Ed25519 signature Buffer over the SAME envelope hash the local
 * path signs (keyManager.nativeSign). The signature is checked for length here; verification against the public key is
 * the caller's decision (the /sign route verifies before releasing the artifact).
 *
 */
async function signArtifactNative({ payload, timestamp, expiry, publicKeyId }, nativeSign) {
  _validateEnvelope({ payload, timestamp, expiry, publicKeyId });
  if (typeof nativeSign !== 'function') {
    throw new TypeError('signArtifactNative: nativeSign must be a function');
  }
  const hashBuf = envelopeHash({ expiry, payload, publicKeyId, timestamp });
  const sigBuf  = await nativeSign(publicKeyId, hashBuf);
  if (!Buffer.isBuffer(sigBuf) || sigBuf.length !== 64) {
    throw new Error('signArtifactNative: the native signing provider did not return a 64-byte Ed25519 signature');
  }
  return Object.freeze({ expiry, payload, publicKeyId, signature: sigBuf.toString('base64'), timestamp });
}

module.exports = { signArtifact, signArtifactNative };
