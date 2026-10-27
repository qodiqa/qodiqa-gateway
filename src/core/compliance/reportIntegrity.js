'use strict';

/**
 * QODIQA Compliance Report Integrity
 *
 * Provides cryptographic protection for compliance reports:
 *   - SHA-256 canonical hash of the JSON report payload
 *   - Ed25519 signature over the hash using the active QODIQA signing key
 *   - Independent verification: anyone with the public key can verify
 *
 * The signing envelope uses the same domain-separation prefix as artifact signing:
 *   SHA-256("QODIQA::COMPLIANCE_REPORT::V1" || canonicalJson)
 *
 * Reports are immutable once signed.  Any modification to the JSON payload
 * will cause verification to fail, detecting tampering.
 */

const crypto    = require('crypto');
const { emit }  = require('../../../services/logger');

const DOMAIN_PREFIX   = 'QODIQA::COMPLIANCE_REPORT::V1';
const ALGORITHM       = 'ed25519';
const HASH_ALGO       = 'sha256';

// ── Canonical serialisation ───────────────────────────────────────────────────

/**
 * Produce a stable, deterministic JSON string for hashing.
 * Keys are sorted recursively; arrays are preserved in order.
 * Excludes the `signature` field itself to avoid circular hashing.
 */
function canonicalise(reportPayload) {
  const clone = _deepClone(reportPayload);
  delete clone.signature;
  delete clone.signedAt;
  delete clone._hash;
  return JSON.stringify(clone, _sortedReplacer);
}

function _deepClone(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(_deepClone);
  // Null-prototype accumulator: assigning to a key literally named
  // "__proto__" on a normal {} object invokes the inherited
  // Object.prototype.__proto__ setter instead of creating an own property,
  // silently dropping the key. That would make a report tampered with an
  // injected "__proto__" field hash-identical to the untampered original —
  // a silent signature-verification bypass. Object.create(null) has no such
  // setter, so the key is always preserved and hashed.
  const out = Object.create(null);
  for (const k of Object.keys(obj)) out[k] = _deepClone(obj[k]);
  return out;
}

function _sortedReplacer(_key, value) {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    // Same null-prototype requirement as _deepClone above — this reconstructs
    // a fresh object for every nested value the JSON.stringify replacer
    // visits, so it needs the identical guard.
    const sorted = Object.create(null);
    for (const k of Object.keys(value).sort()) sorted[k] = value[k];
    return sorted;
  }
  return value;
}

// ── Hash computation ──────────────────────────────────────────────────────────

/**
 * Compute the SHA-256 domain-separated hash of the canonical report JSON.
 * @param {object} reportPayload
 * @returns {Buffer} 32-byte digest
 */
function computeHash(reportPayload) {
  const canonical = canonicalise(reportPayload);
  const prefixed  = Buffer.concat([
    Buffer.from(DOMAIN_PREFIX, 'utf8'),
    Buffer.from(canonical, 'utf8'),
  ]);
  return crypto.createHash(HASH_ALGO).update(prefixed).digest();
}

/**
 * Hex-encoded SHA-256 hash of the report payload.
 * @param {object} reportPayload
 * @returns {string} 64-char hex string
 */
function hashReport(reportPayload) {
  return computeHash(reportPayload).toString('hex');
}

// ── Signing ───────────────────────────────────────────────────────────────────

/**
 * Sign a compliance report using the active QODIQA Ed25519 signing key.
 * Returns a signature envelope that can be stored in compliance_report_signatures.
 *
 * @param {object} reportPayload   The complete report object (without signature fields)
 * @param {string} clientId        The QODIQA client/tenant ID for key selection
 * @returns {{ keyId, algorithm, signatureB64, reportHash, signedAt, signerId }}
 */
async function signReport(reportPayload, clientId) {
  if (!reportPayload || typeof reportPayload !== 'object') {
    throw new TypeError('signReport: reportPayload must be a non-null object');
  }
  if (typeof clientId !== 'string' || !clientId) {
    throw new TypeError('signReport: clientId must be a non-empty string');
  }

  const keyManager = require('../../../services/artifact/keyManager');

  const hash    = computeHash(reportPayload);
  const keyInfo = keyManager.getSigningKey(clientId);

  let sigBuf;
  if (keyInfo.nativeSigning) {
    sigBuf = await keyManager.nativeSign(keyInfo.keyId, hash);
  } else {
    const privKey = crypto.createPrivateKey({
      key:    keyInfo.privDer,
      format: 'der',
      type:   'pkcs8',
    });
    sigBuf = crypto.sign(null, hash, privKey);
  }

  const envelope = {
    keyId:        keyInfo.keyId,
    algorithm:    ALGORITHM,
    signatureB64: sigBuf.toString('base64'),
    reportHash:   hash.toString('hex'),
    signedAt:     new Date().toISOString(),
    signerId:     clientId,
  };

  emit('INFO', 'COMPLIANCE_REPORT_SIGNED', {
    keyId:      keyInfo.keyId,
    reportHash: envelope.reportHash,
    signerId:   clientId,
  });

  return envelope;
}

// ── Verification ──────────────────────────────────────────────────────────────

/**
 * Verify a compliance report's integrity and signature.
 *
 * @param {object} reportPayload       The report JSON (signature fields stripped or kept)
 * @param {object} signatureEnvelope   From compliance_report_signatures
 * @returns {{ verified: bool, hashMatch: bool, sigValid: bool, detail: string }}
 */
async function verifyReport(reportPayload, signatureEnvelope) {
  if (!reportPayload || !signatureEnvelope) {
    return { verified: false, hashMatch: false, sigValid: false, detail: 'Missing payload or signature envelope' };
  }

  const { keyId, signatureB64, reportHash: storedHash, algorithm } = signatureEnvelope;

  if (algorithm !== ALGORITHM) {
    return { verified: false, hashMatch: false, sigValid: false,
      detail: `Unsupported algorithm: ${algorithm}` };
  }

  // 1. Recompute hash
  const recomputedHash = hashReport(reportPayload);
  const hashMatch      = recomputedHash === storedHash;

  if (!hashMatch) {
    return {
      verified:  false,
      hashMatch: false,
      sigValid:  false,
      detail:    `Hash mismatch: stored=${storedHash?.slice(0, 16)}... recomputed=${recomputedHash.slice(0, 16)}...`,
    };
  }

  // 2. Verify Ed25519 signature using the public key from keyStore
  try {
    const keyManager = require('../../../services/artifact/keyManager');
    const { pubDer }  = keyManager.getVerificationKey(keyId);
    const pubKey      = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });

    const hashBuf = Buffer.from(storedHash, 'hex');
    const sigBuf  = Buffer.from(signatureB64, 'base64');
    const sigValid = crypto.verify(null, hashBuf, pubKey, sigBuf);

    emit('INFO', 'COMPLIANCE_REPORT_VERIFIED', {
      keyId,
      reportHash: storedHash,
      sigValid,
    });

    return {
      verified:  sigValid && hashMatch,
      hashMatch: true,
      sigValid,
      detail:    sigValid
        ? 'Report integrity verified: hash matches and signature is valid'
        : 'Signature invalid: report may have been tampered with',
    };
  } catch (err) {
    return {
      verified:  false,
      hashMatch: true,
      sigValid:  false,
      detail:    `Verification error: ${err.message}`,
    };
  }
}

module.exports = {
  canonicalise,
  hashReport,
  computeHash,
  signReport,
  verifyReport,
  DOMAIN_PREFIX,
};
