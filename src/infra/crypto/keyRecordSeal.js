'use strict';

/**
 * Authenticated key-store records — K1.
 *
 * WHY: every key-store file (services/artifact/keyStore.js — keys.json; src/core/transparency/ed25519KeyStore.js —
 * transparency-keys.json and checkpoint-keys.json) protected only the PRIVATE key (AES-256-GCM under the KEK). The
 * public half of each record — publicKeyDer, status, createdAt, retiredAt/revokedAt, lifecycle, purpose — was plain,
 * unauthenticated JSON. Anyone able to write the file WITHOUT the KEK could inject or edit a public record (for
 * example a 'deprecated' key with retiredAt≈now) and a running gateway adopted it on its next reload. The encrypted
 * private key itself carried no AAD, so its ciphertext was not bound to the record it sits in.
 *
 * WHAT (pure crypto — this module never reads the KEK, files or env itself; Infrastructure layer):
 *   - MAC KEY:  HKDF-SHA256(KEK, salt="", info=RECORD_MAC_INFO) — derived by keyEncryption.deriveKekSubkey(), so the
 *               raw KEK never leaves services/artifact/keyEncryption.js. Domain-separated from the KEK's other uses
 *               (AES-GCM key wrapping, the KEK fingerprint HMAC label).
 *   - RECORD MAC: HMAC-SHA256(macKey, canonical JSON of the record's public fields + where it sits in the file +
 *               the trust domain + a digest of its encrypted private key blob). Stored as entry.recordMac (hex).
 *   - FILE MARKER: payload.recordSeal = SEAL_DESCRIPTOR. A file carrying it is SEALED: every record must carry a
 *               valid recordMac, or the load is refused (fail closed, CRITICAL). A file without it is LEGACY.
 *   - AAD:      new private-key encryptions bind AES-GCM AAD = canonical record identity (domain, keyId, clientId,
 *               version, sha256(publicKeyDer)); the blob carries aad: AAD_LABEL. Legacy blobs (no `aad` field) still
 *               decrypt without AAD. Stripping `aad` from a bound blob makes GCM authentication fail.
 *
 * Canonicalisation is JSON with recursively sorted keys after a JSON round-trip (so undefined fields vanish exactly
 * as they do on disk). Absent and null fields are both encoded as null.
 */

const crypto = require('crypto');

const RECORD_MAC_INFO = 'qodiqa-keystore-record-mac-v1';
const AAD_LABEL       = 'qodiqa-keyrec-aad-v1';
const MAC_LABEL       = 'qodiqa-keyrec-mac-v1';
const SEAL_VERSION    = 1;
const SEAL_DESCRIPTOR = Object.freeze({
  version: SEAL_VERSION,
  mac:     'HMAC-SHA256',
  kdf:     `HKDF-SHA256(KEK, info=${RECORD_MAC_INFO})`,
  aad:     AAD_LABEL,
});

// The persisted record fields covered by the MAC. Anything that can change how a record loads must be here.
const MAC_FIELDS = Object.freeze([
  'keyId', 'clientId', 'version', 'algorithm', 'purpose', 'publicKeyDer', 'status', 'createdAt',
  'retiredAt', 'revokedAt', 'rotationDeadline', 'expiresAt', 'nativeKey', 'nativeRevocation',
]);

function _sortDeep(v) {
  if (Array.isArray(v)) return v.map(_sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = _sortDeep(v[k]);
    return out;
  }
  return v;
}

/** Deterministic JSON: JSON round-trip (drops undefined like the file does), then recursively sorted keys. */
function canonicalize(v) {
  const roundTripped = v === undefined ? null : JSON.parse(JSON.stringify(v));
  return JSON.stringify(_sortDeep(roundTripped));
}

function _sha256Hex(data) { return crypto.createHash('sha256').update(data).digest('hex'); }

/**
 * Canonical MAC input for one persisted record.
 * @param {string} domain           trust domain ('artifact' | 'transparency' | 'audit-checkpoint' | …)
 * @param {object} entry            the record exactly as persisted (pre-serialisation or parsed back)
 * @param {{ mapKey: string, bucket?: string|null }} where  the map key it is stored under (and client bucket, if any)
 */
function recordMacInput(domain, entry, where) {
  const fields = {};
  for (const f of MAC_FIELDS) fields[f] = entry[f] === undefined ? null : entry[f];
  const enc = entry.encryptedPrivateKeyDer;
  return canonicalize({
    label:   MAC_LABEL,
    domain,
    bucket:  (where && where.bucket !== undefined) ? where.bucket : null,
    mapKey:  where ? where.mapKey : null,
    fields,
    encryptedPrivateKeyDigest: enc === undefined || enc === null ? null : _sha256Hex(canonicalize(enc)),
    plaintextPrivateKeyPresent: entry.privateKeyDer !== undefined && entry.privateKeyDer !== null,
  });
}

function _assertMacKey(macKey) {
  if (!Buffer.isBuffer(macKey) || macKey.length < 32) throw new TypeError('keyRecordSeal: macKey must be a ≥32-byte Buffer');
}

/** @returns {string} hex HMAC-SHA256 */
function computeRecordMac(macKey, domain, entry, where) {
  _assertMacKey(macKey);
  return crypto.createHmac('sha256', macKey).update(recordMacInput(domain, entry, where), 'utf8').digest('hex');
}

/** @returns {'ok'|'missing'|'invalid'} */
function verifyRecordMac(macKey, domain, entry, where) {
  if (typeof entry.recordMac !== 'string' || entry.recordMac.length === 0) return 'missing';
  const expected = Buffer.from(computeRecordMac(macKey, domain, entry, where), 'hex');
  let got;
  try { got = Buffer.from(entry.recordMac, 'hex'); } catch { return 'invalid'; }
  if (got.length !== expected.length || !/^[0-9a-f]+$/i.test(entry.recordMac)) return 'invalid';
  return crypto.timingSafeEqual(got, expected) ? 'ok' : 'invalid';
}

/**
 * Is this parsed key file sealed? Throws on a recordSeal marker this code does not understand (fail closed — a newer
 * or forged format is never silently treated as legacy).
 */
function isSealedFile(data) {
  if (!data || data.recordSeal === undefined || data.recordSeal === null) return false;
  const s = data.recordSeal;
  if (typeof s !== 'object' || s.version !== SEAL_VERSION || s.aad !== AAD_LABEL || s.mac !== SEAL_DESCRIPTOR.mac) {
    /** @type {any} */ const e = new Error(`unsupported recordSeal marker ${JSON.stringify(s)} (expected version ${SEAL_VERSION})`);
    e.code = 'KEYSTORE_SEAL_UNSUPPORTED';
    throw e;
  }
  return true;
}

/**
 * Check every record of a parsed file.
 * @param {Buffer} macKey
 * @param {string} domain
 * @param {Array<{ entry: object, mapKey: string, bucket?: string|null }>} records
 * @returns {Array<{ keyId: string, reason: 'missing'|'invalid' }>} failures ([] = all authentic)
 */
function checkRecords(macKey, domain, records) {
  const failures = [];
  for (const { entry, mapKey, bucket } of records) {
    const r = (entry && typeof entry === 'object') ? verifyRecordMac(macKey, domain, entry, { mapKey, bucket }) : 'invalid';
    if (r !== 'ok') failures.push({ keyId: mapKey, ...(bucket !== undefined ? { bucket } : {}), reason: r });
  }
  return failures;
}

/** AES-GCM AAD binding an encrypted private key to its record identity. */
function recordAad(domain, { keyId, clientId, version, publicKeyDer }) {
  const pub = Buffer.isBuffer(publicKeyDer) ? publicKeyDer : Buffer.from(String(publicKeyDer || ''), 'base64');
  return Buffer.from(canonicalize([AAD_LABEL, domain, keyId, clientId, version, _sha256Hex(pub)]), 'utf8');
}

/**
 * (Re)seal a parsed key file in place, as a KEK holder would: set the marker and recompute every record's MAC.
 * Handles both layouts — { clients: { <bucket>: { <keyId>: entry } } } (artifact) and { keys: { <keyId>: entry } }.
 * Used by operator/test tooling that must change a file deliberately; the stores themselves seal on every save.
 * A sealed file must carry AAD-bound ciphertexts, so this never makes a legacy-ciphertext file loadable as sealed.
 */
function sealFileData(data, macKey, domain) {
  data.recordSeal = { ...SEAL_DESCRIPTOR };
  const seal1 = (entry, where) => { delete entry.recordMac; entry.recordMac = computeRecordMac(macKey, domain, entry, where); };
  if (data.clients && typeof data.clients === 'object') {
    for (const [bucket, cd] of Object.entries(data.clients)) for (const [mapKey, e] of Object.entries(cd || {})) seal1(e, { bucket, mapKey });
  }
  if (data.keys && typeof data.keys === 'object') {
    for (const [mapKey, e] of Object.entries(data.keys)) seal1(e, { mapKey });
  }
  return data;
}

/**
 * Refuse every unsealed key file, including the one-time TOFU migration?
 * OA-RC-2: REQUIRED BY DEFAULT IN PRODUCTION. NODE_ENV=production → true unless
 * QODIQA_KEYSTORE_REQUIRE_SEALED=false is set explicitly (the boot validator then reports it as a WARN); other
 * environments keep the previous default (true only when the variable is exactly 'true'). An existing unsealed file is
 * sealed offline before the upgrade: scripts/keys/seal-keystore.js (docs/operations/runbook — "Seal the key stores").
 */
function sealRequired(env = process.env) {
  const v = env.QODIQA_KEYSTORE_REQUIRE_SEALED;
  if (v === 'true') return true;
  if (v === 'false') return false;
  return env.NODE_ENV === 'production';
}

module.exports = {
  RECORD_MAC_INFO, AAD_LABEL, SEAL_VERSION, SEAL_DESCRIPTOR, MAC_FIELDS,
  canonicalize, recordMacInput, computeRecordMac, verifyRecordMac, isSealedFile, checkRecords, recordAad, sealFileData, sealRequired,
};
