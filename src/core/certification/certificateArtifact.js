'use strict';

/**
 * QODIQA Signed Certificate Artifact — Component #29
 *
 * Generates, signs, and verifies immutable certificate artifacts for every
 * successful CERTIFIED decision.  Designed for offline, permanent verification.
 *
 * SIGNING SCHEME:
 *   Hash:      SHA-256("QODIQA::CERTIFICATE::V1" || stableStringify(certificate))
 *   Algorithm: Ed25519
 *   Encoding:  base64
 *
 * Domain separation ("QODIQA::CERTIFICATE::V1") prevents cross-protocol reuse
 * with artifact envelopes ("QODIQA::ARTIFACT::V1") and other signed objects.
 *
 * BUNDLE FORMAT (self-contained — requires no DB lookup to verify):
 *   {
 *     version:          1,
 *     certificate:      { ...immutable certification facts... },
 *     signature:        "<Ed25519 base64>",
 *     keyId:            "<clientId:key_vN>",
 *     signingAlgorithm: "Ed25519",
 *     signedAt:         "<ISO timestamp>",
 *     domain:           "QODIQA::CERTIFICATE::V1"
 *   }
 *
 * CERTIFICATE PAYLOAD (the exact object that is signed):
 *   {
 *     certificateId:   "<UUID>",
 *     certificationId: "<UUID>",
 *     tenantId:        "<string|null>",
 *     issuedAt:        "<ISO timestamp>",
 *     level:           "<certification level>",
 *     score:           <number>,
 *     status:          "CERTIFIED",
 *     policyVersion:   "<string>",
 *     artifactVersion: 1
 *   }
 *
 * OFFLINE VERIFICATION:
 *   Requires: bundle JSON + public key (via keyId).
 *   No database lookup, no API call, no network connectivity.
 *   verifyCertificateArtifact() never throws — always returns structured result.
 *
 * KEY ROTATION COMPATIBILITY:
 *   The keyId in the bundle is used to look up the correct public key.
 *   Retired (deprecated) keys remain verifiable indefinitely via getPublicKey().
 */

const { randomUUID }         = require('crypto');
const stableStringify        = require('../../utils/stableStringify');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
const { sign, verify }       = require('../../infra/crypto/ed25519');
const { emit }               = require('../../../services/logger');
// top-level — never a lazy require inside a verification call
const { checkHistorical }    = require('../../validation/keyLifecycle');
const keyStatusTimeline      = require('../signing/keyStatusTimeline');
const { isCanonicalSignature } = require('../../validation/validateArtifact');

// Certificate domain — MUST NOT change after first issuance
const CERTIFICATE_DOMAIN  = ARTIFACT_DOMAINS.CERTIFICATE;
const ARTIFACT_VERSION    = 1;
const SIGNING_ALGORITHM   = 'Ed25519';

// Default client ID for signing (same as /sign route)
function _clientId() {
  return process.env.QODIQA_CLIENT_ID || 'default';
}

// ── Key manager access — lazy to avoid circular deps at load time ─────────────

let _keyManager = null;
function _getKeyManager() {
  if (!_keyManager) _keyManager = require('../../../services/artifact/keyManager');
  return _keyManager;
}

// ── Canonical serialization ───────────────────────────────────────────────────

/**
 * Produce the deterministic canonical JSON string for a certificate payload.
 * stableStringify sorts keys lexicographically — output is stable regardless
 * of insertion order.
 *
 * @param {object} certificate
 * @returns {string}
 */
function canonicalizeCertificate(certificate) {
  return stableStringify(certificate);
}

/**
 * Compute the 32-byte domain-separated hash of a certificate payload.
 * SHA-256("QODIQA::CERTIFICATE::V1" || stableStringify(certificate))
 *
 * @param {object} certificate
 * @returns {Buffer}  32-byte raw hash
 */
function certificateHash(certificate) {
  const canonical = canonicalizeCertificate(certificate);
  return domainSeparatedHash(CERTIFICATE_DOMAIN, canonical);
}

// ── Certificate payload builder ───────────────────────────────────────────────

/**
 * Build the canonical certificate payload from a certification result.
 * Contains only immutable certification facts — no operational metadata.
 *
 * @param {object} certificationResult  From evaluationEngine.evaluate()
 * @param {object} opts
 * @param {string} [opts.certificateId]  Override (for deterministic testing)
 * @param {string} [opts.issuedAt]       Override (for deterministic testing)
 * @returns {object}  Canonical certificate payload
 */
function buildCertificatePayload(certificationResult, opts = {}) {
  const {
    certificationId,
    certificationLevel,
    certificationDecision,
    version,
    score,
  } = certificationResult;

  return {
    artifactVersion:  ARTIFACT_VERSION,
    certificateId:    opts.certificateId ?? randomUUID(),
    certificationId,
    issuedAt:         opts.issuedAt ?? new Date().toISOString(),
    level:            certificationLevel,
    policyVersion:    version ?? '1.0',
    score,
    status:           certificationDecision,
    tenantId:         certificationResult.metadata?.requestedBy ?? null,
  };
}

// ── Certificate issuance ──────────────────────────────────────────────────────

/**
 * Issue a signed certificate artifact for a successful certification.
 *
 * Signing uses the active key for QODIQA_CLIENT_ID.  The bundle is
 * self-contained: verification requires only the bundle and the public key
 * identified by keyId.
 *
 * @param {object} certificationResult  From evaluationEngine.evaluate()
 * @param {object} [opts]
 * @param {string} [opts.certificateId]  Override for testing
 * @param {string} [opts.issuedAt]       Override for testing
 * @returns {{ bundle: object, certificate: object }}
 * @throws {Error}  Only if no active signing key is configured
 */
function issueCertificateArtifact(certificationResult, opts = {}) {
  const certificate = buildCertificatePayload(certificationResult, opts);
  const signedAt    = opts.issuedAt ?? new Date().toISOString();

  // Acquire signing key — throws if none configured (startup should have caught this)
  const km          = _getKeyManager();
  const signingKey  = km.getSigningKey(_clientId());
  const { keyId, privDer } = signingKey;

  if (!privDer) {
    throw new Error('issueCertificateArtifact: native signing providers are not supported for certificate artifacts — privDer must be available');
  }

  // Sign the canonical certificate payload
  const hashBuf   = certificateHash(certificate);
  const signature = sign(hashBuf, privDer);

  const bundle = Object.freeze({
    version:          ARTIFACT_VERSION,
    certificate:      Object.freeze(certificate),
    signature,
    keyId,
    signingAlgorithm: SIGNING_ALGORITHM,
    signedAt,
    domain:           CERTIFICATE_DOMAIN,
  });

  emit('INFO', 'CERTIFICATE_ARTIFACT_ISSUED', {
    certificateId:   certificate.certificateId,
    certificationId: certificate.certificationId,
    level:           certificate.level,
    score:           certificate.score,
    keyId,
    signedAt,
  });

  return { bundle, certificate };
}

// ── Offline verification ──────────────────────────────────────────────────────

/**
 * Verify a signed certificate artifact bundle.
 *
 * Requires no database, no API call, no network connectivity.
 * Never throws — always returns a structured result.
 *
 * @param {unknown} bundle  The full bundle object (as parsed from JSON)
 * @returns {{
 *   valid:     boolean,
 *   reason:    string,
 *   details:   object,
 * }}
 */
function verifyCertificateArtifact(bundle) {
  // ── 1. Bundle must be a plain object ────────────────────────────────────────
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    return _invalid('MALFORMED_BUNDLE', { issue: 'bundle must be a plain object' });
  }

  // ── 2. Required top-level fields ─────────────────────────────────────────────
  const REQUIRED = ['version', 'certificate', 'signature', 'keyId', 'signingAlgorithm', 'signedAt', 'domain'];
  for (const field of REQUIRED) {
    if (!(field in bundle) || bundle[field] === undefined) {
      return _invalid('MALFORMED_BUNDLE', { missing: field });
    }
  }

  const { version, certificate, signature, keyId, signingAlgorithm, signedAt, domain } = bundle;

  // ── 3. Version check ─────────────────────────────────────────────────────────
  if (version !== ARTIFACT_VERSION) {
    return _invalid('UNSUPPORTED_VERSION', { version, expected: ARTIFACT_VERSION });
  }

  // ── 4. Domain check ──────────────────────────────────────────────────────────
  if (domain !== CERTIFICATE_DOMAIN) {
    return _invalid('WRONG_DOMAIN', { domain, expected: CERTIFICATE_DOMAIN });
  }

  // ── 5. Algorithm check ───────────────────────────────────────────────────────
  if (signingAlgorithm !== SIGNING_ALGORITHM) {
    return _invalid('UNSUPPORTED_ALGORITHM', { signingAlgorithm });
  }

  // ── 6. Certificate payload must be a plain object ────────────────────────────
  if (!certificate || typeof certificate !== 'object' || Array.isArray(certificate)) {
    return _invalid('MALFORMED_CERTIFICATE', { issue: 'certificate must be a plain object' });
  }

  // ── 7. Required certificate fields ───────────────────────────────────────────
  const CERT_REQUIRED = [
    'artifactVersion', 'certificateId', 'certificationId',
    'issuedAt', 'level', 'policyVersion', 'score', 'status',
  ];
  for (const field of CERT_REQUIRED) {
    if (!(field in certificate) || certificate[field] === undefined || certificate[field] === null) {
      if (field !== 'tenantId') { // tenantId is explicitly nullable
        return _invalid('MALFORMED_CERTIFICATE', { missing: field });
      }
    }
  }

  // ── 8. Signature must be a base64 string decoding to 64 bytes ────────────────
  if (typeof signature !== 'string' || !signature) {
    return _invalid('INVALID_SIGNATURE_ENCODING', { issue: 'signature must be a non-empty string' });
  }
  let sigBuf;
  try {
    sigBuf = Buffer.from(signature, 'base64');
  } catch {
    return _invalid('INVALID_SIGNATURE_ENCODING', { issue: 'signature base64 decode failed' });
  }
  if (sigBuf.length !== 64) {
    return _invalid('INVALID_SIGNATURE_ENCODING', {
      issue:    `signature must decode to 64 bytes`,
      got:      sigBuf.length,
    });
  }
  // one canonical spelling — padded standard base64, 88 chars, round-trip exact.
  if (!isCanonicalSignature(signature)) {
    return _invalid('INVALID_SIGNATURE_ENCODING', { issue: 'signature is not the canonical encoding (standard base64, padded, 88 characters)' });
  }

  // ── 9. keyId must be a non-empty string ──────────────────────────────────────
  if (typeof keyId !== 'string' || !keyId.trim()) {
    return _invalid('UNKNOWN_KEY', { issue: 'keyId must be a non-empty string' });
  }

  // ── 10. Key resolution (fail-closed, no fallback) ────────────────────────────
  let pubDer; let keyTimeline = null;
  try {
    const km     = _getKeyManager();
    const result = km.getVerificationKey(keyId);
    if (!result || !result.pubDer) {
      return _invalid('UNKNOWN_KEY', { keyId });
    }
    pubDer = result.pubDer;
    keyTimeline = result.timeline || { status: result.status };
  } catch (err) {
    return _invalid('UNKNOWN_KEY', { keyId, error: err.message });
  }

  // ── 11. Recompute hash and verify signature ───────────────────────────────────
  // The signed object is exactly the certificate payload field.
  // Any modification to certificate (payload tampering) produces a different hash.
  let hashBuf;
  try {
    hashBuf = certificateHash(certificate);
  } catch (err) {
    return _invalid('CANONICALIZATION_FAILED', { error: err.message });
  }

  const sigValid = verify(hashBuf, signature, pubDer);
  if (!sigValid) {
    return _invalid('INVALID_SIGNATURE', { keyId, issue: 'signature verification failed' });
  }

  // ── 11b. Historical key-lifecycle check ────────────────────
  // A certificate stays verifiable after its key is rotated out or archived —
  // but only if the key was ACTIVE when the certificate was issued. The time
  // used is certificate.issuedAt (inside the signed payload), never the
  // unsigned bundle.signedAt. Revoked keys never reach here (UNKNOWN_KEY).
  try {
    const timeline = keyStatusTimeline.effective(keyId, keyTimeline);
    const h = checkHistorical(timeline, Date.parse(certificate.issuedAt));
    if (!h.valid) return _invalid(h.reason, { keyId, ...h.details });
  } catch (err) {
    return _invalid(err && err.code ? err.code : 'KEY_STATUS_UNAVAILABLE', { keyId });
  }

  // ── 12. Verified ─────────────────────────────────────────────────────────────
  return {
    valid:   true,
    reason:  'SIGNATURE_VERIFIED',
    details: {
      certificateId:   certificate.certificateId,
      certificationId: certificate.certificationId,
      level:           certificate.level,
      score:           certificate.score,
      status:          certificate.status,
      keyId,
      signedAt,
      domain,
    },
  };
}

function _invalid(reason, details) {
  return { valid: false, reason, details: details ?? {} };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  issueCertificateArtifact,
  verifyCertificateArtifact,
  buildCertificatePayload,
  certificateHash,
  canonicalizeCertificate,
  CERTIFICATE_DOMAIN,
  ARTIFACT_VERSION,
  SIGNING_ALGORITHM,
};
