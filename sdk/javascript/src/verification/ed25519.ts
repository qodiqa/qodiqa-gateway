/**
 * Ed25519 verification — SDK-side port of `src/infra/crypto/ed25519.js`'s
 * `verify()`. Signing is intentionally not ported: only the server signs
 * artifacts, the SDK only ever verifies.
 *
 * Key format: public keys are SPKI DER (not raw 32 bytes, not PEM, not JWK) —
 * exactly what `/.well-known/qodiqa/keys` and `/.well-known/qodiqa/transparency-keys`
 * serve, base64-encoded.
 *
 * @module
 */

import crypto from 'node:crypto';

/**
 * Verify an Ed25519 signature over `hashBuffer`.
 *
 * Never throws — returns `false` for any structurally invalid input
 * (wrong-length hash/signature, unparseable key, mismatched signature),
 * matching the server implementation's fail-closed, non-throwing contract.
 */
export function verifyEd25519(hashBuffer: Buffer, signatureBase64: string, pubDer: Buffer): boolean {
  try {
    if (!Buffer.isBuffer(hashBuffer) || hashBuffer.length !== 32) return false;
    if (typeof signatureBase64 !== 'string') return false;
    if (!Buffer.isBuffer(pubDer) || pubDer.length === 0) return false;

    const sigBuf = Buffer.from(signatureBase64, 'base64');
    if (sigBuf.length !== 64) return false;

    const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
    return crypto.verify(null, hashBuffer, pubKey, sigBuf);
  } catch {
    return false;
  }
}
