'use strict';

/**
 * Evidence Chain keyFingerprint Conformance — QODIQA-PROTOCOL-SPEC.md §12.3
 *
 * Regression suite for the defect fixed in "Evidence Chain keyFingerprint
 * Remediation": computeKeyFingerprint previously base64-DECODED the input
 * before hashing (SHA-256 of DER bytes), producing a value that does not
 * match the protocol spec.
 *
 * Spec formula under test (§12.3, §25.9, §23.9):
 *   keyFingerprint = LowercaseHex(SHA-256(UTF8(publicKeyB64)))
 * where publicKeyB64 is Standard Base64 of SPKI DER bytes — the fingerprint
 * hashes the STRING, not the bytes it decodes to.
 */

const crypto = require('crypto');
const {
  computeKeyFingerprint,
  buildEvidenceRecord,
  verifyEvidenceRecord,
} = require('../chain');

// Independent re-implementation using raw crypto — does not call
// computeKeyFingerprint, so this cross-checks the actual formula rather than
// merely confirming the function agrees with itself.
function expectedFingerprint(publicKeyB64) {
  return crypto.createHash('sha256').update(publicKeyB64, 'utf8').digest('hex');
}

function freshKeyPair() {
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  return publicKey.export({ type: 'spki', format: 'der' });
}

describe('Evidence Chain keyFingerprint Conformance — §12.3', () => {

  test('KFP-01 matches the independently-computed spec formula for a real SPKI DER key', () => {
    const pubDer = freshKeyPair();
    const b64    = pubDer.toString('base64');
    expect(computeKeyFingerprint(b64)).toBe(expectedFingerprint(b64));
  });

  test('KFP-02 known-good test vector: fingerprint is SHA-256 of the base64 TEXT, not the decoded bytes', () => {
    const b64 = 'MCowBQYDK2VwAyEAaGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkaGk=';
    const expected = crypto.createHash('sha256').update(b64, 'utf8').digest('hex');
    expect(computeKeyFingerprint(b64)).toBe(expected);

    // Regression guard: must NOT equal the (incorrect) hash of the decoded DER bytes.
    const decodedBytesHash = crypto.createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex');
    expect(computeKeyFingerprint(b64)).not.toBe(decodedBytesHash);
  });

  test('KFP-03 output is 64-char lowercase hex', () => {
    const b64 = freshKeyPair().toString('base64');
    const fp = computeKeyFingerprint(b64);
    expect(fp).toHaveLength(64);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  test('KFP-04 deterministic — same input always produces the same fingerprint', () => {
    const b64 = freshKeyPair().toString('base64');
    expect(computeKeyFingerprint(b64)).toBe(computeKeyFingerprint(b64));
  });

  test('KFP-05 different keys produce different fingerprints', () => {
    const b64a = freshKeyPair().toString('base64');
    const b64b = freshKeyPair().toString('base64');
    expect(computeKeyFingerprint(b64a)).not.toBe(computeKeyFingerprint(b64b));
  });

  test('KFP-06 null input returns null', () => {
    expect(computeKeyFingerprint(null)).toBeNull();
  });

  test('KFP-07 undefined input returns null', () => {
    expect(computeKeyFingerprint(undefined)).toBeNull();
  });

  test('KFP-08 empty string returns null', () => {
    expect(computeKeyFingerprint('')).toBeNull();
  });

  test('KFP-09 non-string input (number, object, array) returns null', () => {
    expect(computeKeyFingerprint(42)).toBeNull();
    expect(computeKeyFingerprint({})).toBeNull();
    expect(computeKeyFingerprint([])).toBeNull();
  });

  test('KFP-10 malformed Base64 (invalid characters) is hashed as-is, not rejected', () => {
    // computeKeyFingerprint has no opinion on whether the string is valid Base64 —
    // per spec it hashes whatever UTF-8 string it is given. Validity of the
    // publicKeyB64 value is a concern for the caller, not this function.
    const malformed = 'not-valid-base64!!!***';
    expect(computeKeyFingerprint(malformed)).toBe(expectedFingerprint(malformed));
  });

  test('KFP-11 PEM-formatted input is hashed literally (no PEM parsing/normalization)', () => {
    const pem = '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----\n';
    expect(computeKeyFingerprint(pem)).toBe(expectedFingerprint(pem));
  });

  test('KFP-12 whitespace is significant — a value with embedded whitespace differs from one without', () => {
    const clean = 'MCowBQYDK2VwAyEAaGVsbG93b3JsZA==';
    const withSpace = clean + '\n';
    expect(computeKeyFingerprint(clean)).not.toBe(computeKeyFingerprint(withSpace));
  });

  test('KFP-13 Base64 padding differences produce different fingerprints (no normalization)', () => {
    const withPadding = 'MCowBQYDK2VwAyEAaGVsbG93b3JsZA==';
    const withoutPadding = withPadding.replace(/=+$/, '');
    expect(computeKeyFingerprint(withPadding)).not.toBe(computeKeyFingerprint(withoutPadding));
  });

  test('KFP-14 Unicode input hashes deterministically', () => {
    const withUnicode = 'MCowBQYDK2VwAyEA-héllo-🚀-wörld';
    expect(computeKeyFingerprint(withUnicode)).toBe(expectedFingerprint(withUnicode));
  });

  test('KFP-15 tampering with a single character of publicKeyB64 changes the fingerprint', () => {
    const b64 = freshKeyPair().toString('base64');
    const tampered = 'X' + b64.slice(1);
    expect(computeKeyFingerprint(b64)).not.toBe(computeKeyFingerprint(tampered));
  });

  test('KFP-16 cross-platform vector: matches raw SHA-256(UTF8(str)) computed without any base64 decode step', () => {
    // Vectors any independent (e.g. Python) implementation must reproduce.
    const vectors = [
      '',
      'QQ==',
      'MCowBQYDK2VwAyEAaGVsbG93b3JsZA==',
    ].filter(Boolean);
    for (const v of vectors) {
      expect(computeKeyFingerprint(v)).toBe(
        crypto.createHash('sha256').update(v, 'utf8').digest('hex')
      );
    }
  });

  // ── Integration: buildEvidenceRecord / verifyEvidenceRecord use the corrected fingerprint ──

  test('KFP-17 buildEvidenceRecord.keyFingerprint matches the spec formula for the given keyInfo', () => {
    const b64 = freshKeyPair().toString('base64');
    const auditEntry = {
      artifactId: 'art-1', inputHash: 'a'.repeat(64), policyHash: 'p'.repeat(64),
      hash: 'h'.repeat(64), decision: 'ALLOW', timestamp: new Date().toISOString(),
      executionContext: { publicKeyId: 'default:key_v1' },
    };
    const record = buildEvidenceRecord(auditEntry, { publicKeyB64: b64, version: 1 });
    expect(record.keyFingerprint).toBe(expectedFingerprint(b64));
  });

  test('KFP-18 verifyEvidenceRecord Step 3 KEY_FINGERPRINT passes when fingerprint matches keyInfo', () => {
    const b64 = freshKeyPair().toString('base64');
    const evidenceRecord = { key_fingerprint: expectedFingerprint(b64) };
    const result = verifyEvidenceRecord(evidenceRecord, { keyInfo: { publicKeyB64: b64 } });
    const step3 = result.steps.find(s => s.step === 'KEY_FINGERPRINT');
    expect(step3.result).toBe('PASS');
  });

  test('KFP-19 verifyEvidenceRecord Step 3 KEY_FINGERPRINT fails when the wrong key is presented', () => {
    const b64a = freshKeyPair().toString('base64');
    const b64b = freshKeyPair().toString('base64');
    const evidenceRecord = { key_fingerprint: expectedFingerprint(b64a) };
    const result = verifyEvidenceRecord(evidenceRecord, { keyInfo: { publicKeyB64: b64b } });
    const step3 = result.steps.find(s => s.step === 'KEY_FINGERPRINT');
    expect(step3.result).toBe('FAIL');
  });

  test('KFP-20 verifyEvidenceRecord Step 3 is SKIPPED (not failed) when keyInfo is unavailable', () => {
    const evidenceRecord = { key_fingerprint: 'c'.repeat(64) };
    const result = verifyEvidenceRecord(evidenceRecord, { keyInfo: null });
    const step3 = result.steps.find(s => s.step === 'KEY_FINGERPRINT');
    expect(step3.result).toBe('SKIP');
  });

  // ── remediation: buildEvidenceRecord prefers the new durable,
  // hash-protected top-level publicKeyId over the legacy unprotected
  // executionContext copy ──────────────────────────────────────────────────

  test('KFP-21 buildEvidenceRecord.keyId resolves from the new top-level publicKeyId field', () => {
    const auditEntry = {
      artifactId: 'art-2', inputHash: 'a'.repeat(64), policyHash: 'p'.repeat(64),
      hash: 'h'.repeat(64), decision: 'ALLOW', timestamp: new Date().toISOString(),
      publicKeyId: 'tenant-a:key_v1',
      schemaVersion: 2,
      // No executionContext at all — proves the fix does not depend on it.
    };
    const record = buildEvidenceRecord(auditEntry, null);
    expect(record.keyId).toBe('tenant-a:key_v1');
  });

  test('KFP-22 buildEvidenceRecord.keyId falls back to the legacy executionContext copy when the top-level field is absent (pre-fix entries stay readable)', () => {
    const auditEntry = {
      artifactId: 'art-3', inputHash: 'a'.repeat(64), policyHash: 'p'.repeat(64),
      hash: 'h'.repeat(64), decision: 'ALLOW', timestamp: new Date().toISOString(),
      executionContext: { publicKeyId: 'legacy-tenant:key_v1' },
    };
    const record = buildEvidenceRecord(auditEntry, null);
    expect(record.keyId).toBe('legacy-tenant:key_v1');
  });

  test('KFP-23 verifyEvidenceRecord Step 3 KEY_FINGERPRINT PASSes end-to-end for a NONREP-2-fixed entry (no more SKIP for live executions with a resolvable key)', () => {
    const b64 = freshKeyPair().toString('base64');
    const auditEntry = {
      artifactId: 'art-4', inputHash: 'a'.repeat(64), policyHash: 'p'.repeat(64),
      hash: 'h'.repeat(64), decision: 'ALLOW', timestamp: new Date().toISOString(),
      publicKeyId: 'tenant-a:key_v1',
      schemaVersion: 2,
    };
    const keyInfo = { publicKeyB64: b64, version: 1 };
    const record  = buildEvidenceRecord(auditEntry, keyInfo);
    expect(record.keyId).toBe('tenant-a:key_v1');
    expect(record.keyFingerprint).toBe(expectedFingerprint(b64));

    const evidenceRecord = { key_fingerprint: record.keyFingerprint };
    const result = verifyEvidenceRecord(evidenceRecord, { keyInfo });
    const step3 = result.steps.find(s => s.step === 'KEY_FINGERPRINT');
    expect(step3.result).toBe('PASS');
  });

});
