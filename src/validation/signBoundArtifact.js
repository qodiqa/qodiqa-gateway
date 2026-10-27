'use strict';

/**
 * QODIQA Bound Artifact Signer
 *
 * Extends signArtifact() with HTTP request binding and execution uniqueness.
 *
 * Signing flow:
 *   1. generateRequestId()                         → UUID v4 (128-bit random nonce)
 *   2. computeRequestHash(method, path, body)       → 64-char hex
 *   3. boundPayload = { ...payload, requestHash, requestId }
 *   4. signArtifact({ ...envelope, payload: boundPayload }, privDer)
 *
 * Both requestHash and requestId are injected into the payload BEFORE signing.
 * They are therefore covered by the full-envelope Ed25519 signature — any
 * post-signing modification to either field invalidates the signature.
 *
 * requestId guarantees each signed artifact is uniquely identifiable.
 * requestHash cryptographically binds the artifact to a specific (method, path, body).
 */

const { signArtifact }        = require('./signArtifact');
const { computeRequestHash }  = require('./requestHash');
const { generateRequestId }   = require('./requestId');
const { isPlainObject,
        hasUndefined }        = require('./canonicalize');

/**
 * Sign a QODIQA V2 artifact bound to an exact HTTP request with a unique identity.
 *
 * @param {{ method: string, path: string, body: object }} request
 *   The HTTP request being authorized.  All three fields are mandatory.
 *
 * @param {{ payload: object, timestamp: number, expiry: number, publicKeyId: string }} envelope
 *   Standard signArtifact envelope.  payload MUST NOT already contain
 *   requestHash or requestId — both are injected by this function.
 *
 * @param {Buffer} privDer  Ed25519 private key in PKCS8 DER format.
 *
 * @returns {Readonly<{ payload: object, signature: string, timestamp: number,
 *                      expiry: number, publicKeyId: string }>}
 * @throws {TypeError}  On any invalid input.
 */
function signBoundArtifact(request, envelope, privDer) {
  if (!isPlainObject(request)) {
    throw new TypeError('signBoundArtifact: request must be a plain object');
  }

  const { method, path: reqPath, body } = request;

  // Throws on invalid method / path / body — propagates directly to caller.
  const requestHash = computeRequestHash(method, reqPath, body);
  const requestId   = generateRequestId();

  const { payload } = envelope;

  if (!isPlainObject(payload)) {
    throw new TypeError('signBoundArtifact: envelope.payload must be a plain object');
  }
  if (hasUndefined(payload)) {
    throw new TypeError('signBoundArtifact: envelope.payload must not contain undefined values');
  }
  if ('requestHash' in payload) {
    throw new TypeError(
      'signBoundArtifact: payload must not already contain requestHash — ' +
      'pass the payload without it and let signBoundArtifact inject it'
    );
  }
  if ('requestId' in payload) {
    throw new TypeError(
      'signBoundArtifact: payload must not already contain requestId — ' +
      'pass the payload without it and let signBoundArtifact inject it'
    );
  }

  const boundPayload = { ...payload, requestHash, requestId };

  return signArtifact({ ...envelope, payload: boundPayload }, privDer);
}

module.exports = { signBoundArtifact };
