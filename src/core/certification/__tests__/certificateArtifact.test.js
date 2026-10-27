'use strict';

/**
 * Unit and integration tests for Component #29 — Signed Certificate Artifact
 *
 * CAT-01..CAT-10  Module exports and constants
 * CAT-11..CAT-20  canonicalizeCertificate / certificateHash
 * CAT-21..CAT-32  buildCertificatePayload
 * CAT-33..CAT-50  issueCertificateArtifact
 * CAT-51..CAT-80  verifyCertificateArtifact
 * CAT-81..CAT-90  certificateStore (pgPool integration)
 * CAT-91..CAT-100 Download endpoint GET /:certificationId/certificate
 */

const crypto = require('crypto');

// ── Generate a real Ed25519 key pair for signing tests ─────────────────────────

const { privateKey: _privKeyObj, publicKey: _pubKeyObj } =
  crypto.generateKeyPairSync('ed25519');

const _PRIV_DER = _privKeyObj.export({ type: 'pkcs8', format: 'der' });
const _PUB_DER  = _pubKeyObj.export({ type: 'spki',  format: 'der' });
const _KEY_ID   = 'test-client:key_v1';

// ── Mocks ──────────────────────────────────────────────────────────────────────

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: mockEmit }));

const mockGetSigningKey     = jest.fn();
const mockGetVerificationKey = jest.fn();
jest.mock('../../../../services/artifact/keyManager', () => ({
  getSigningKey:      mockGetSigningKey,
  getVerificationKey: mockGetVerificationKey,
}));

const mockPgQuery   = jest.fn();
const mockPgEnabled = jest.fn();
jest.mock('../../../infra/postgres/pool', () => ({
  isEnabled: mockPgEnabled,
  query:     mockPgQuery,
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

function _defaultSigningKey() {
  mockGetSigningKey.mockReturnValue({ keyId: _KEY_ID, privDer: _PRIV_DER, pubDer: _PUB_DER });
  mockGetVerificationKey.mockReturnValue({ keyId: _KEY_ID, pubDer: _PUB_DER, status: 'active' });
}

function _makeCertificationResult(overrides = {}) {
  return {
    certificationId:       'aaaa0000-0000-0000-0000-000000000001',
    certificationLevel:    'CERTIFIED',
    certificationDecision: 'CERTIFIED',
    version:               '1.0',
    score:                 80,
    metadata: { requestedBy: 'tenant-abc' },
    ...overrides,
  };
}

// ── Module imports (after mocks) ───────────────────────────────────────────────

const {
  issueCertificateArtifact,
  verifyCertificateArtifact,
  buildCertificatePayload,
  certificateHash,
  canonicalizeCertificate,
  CERTIFICATE_DOMAIN,
  ARTIFACT_VERSION,
  SIGNING_ALGORITHM,
} = require('../certificateArtifact');

const certificateStore = require('../certificateStore');

// ══════════════════════════════════════════════════════════════════════════════
// CAT-01..CAT-10  Module exports and constants
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-01..10 — module exports and constants', () => {
  test('CAT-01 CERTIFICATE_DOMAIN is the correct domain string', () => {
    expect(CERTIFICATE_DOMAIN).toBe('QODIQA::CERTIFICATE::V1');
  });

  test('CAT-02 ARTIFACT_VERSION is 1', () => {
    expect(ARTIFACT_VERSION).toBe(1);
  });

  test('CAT-03 SIGNING_ALGORITHM is Ed25519', () => {
    expect(SIGNING_ALGORITHM).toBe('Ed25519');
  });

  test('CAT-04 issueCertificateArtifact is exported as a function', () => {
    expect(typeof issueCertificateArtifact).toBe('function');
  });

  test('CAT-05 verifyCertificateArtifact is exported as a function', () => {
    expect(typeof verifyCertificateArtifact).toBe('function');
  });

  test('CAT-06 buildCertificatePayload is exported as a function', () => {
    expect(typeof buildCertificatePayload).toBe('function');
  });

  test('CAT-07 certificateHash is exported as a function', () => {
    expect(typeof certificateHash).toBe('function');
  });

  test('CAT-08 canonicalizeCertificate is exported as a function', () => {
    expect(typeof canonicalizeCertificate).toBe('function');
  });

  test('CAT-09 CERTIFICATE_DOMAIN is distinct from ARTIFACT domain', () => {
    expect(CERTIFICATE_DOMAIN).not.toBe('QODIQA::ARTIFACT::V1');
  });

  test('CAT-10 CERTIFICATE_DOMAIN is distinct from REQUEST domain', () => {
    expect(CERTIFICATE_DOMAIN).not.toBe('QODIQA::REQUEST::V1');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-11..CAT-20  canonicalizeCertificate / certificateHash
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-11..20 — canonicalizeCertificate and certificateHash', () => {
  const payload = {
    artifactVersion: 1,
    certificateId:   'cert-id-1',
    certificationId: 'certn-id-1',
    issuedAt:        '2026-01-01T00:00:00.000Z',
    level:           'CERTIFIED',
    policyVersion:   '1.0',
    score:           80,
    status:          'CERTIFIED',
    tenantId:        'tenant-abc',
  };

  test('CAT-11 canonicalizeCertificate returns a string', () => {
    expect(typeof canonicalizeCertificate(payload)).toBe('string');
  });

  test('CAT-12 canonical output is valid JSON', () => {
    expect(() => JSON.parse(canonicalizeCertificate(payload))).not.toThrow();
  });

  test('CAT-13 canonical output has keys in sorted order', () => {
    const canonical = canonicalizeCertificate(payload);
    const keys = Object.keys(JSON.parse(canonical));
    expect(keys).toEqual([...keys].sort());
  });

  test('CAT-14 canonical output is deterministic regardless of insertion order', () => {
    const shuffled = {
      tenantId:        payload.tenantId,
      status:          payload.status,
      score:           payload.score,
      policyVersion:   payload.policyVersion,
      level:           payload.level,
      issuedAt:        payload.issuedAt,
      certificationId: payload.certificationId,
      certificateId:   payload.certificateId,
      artifactVersion: payload.artifactVersion,
    };
    expect(canonicalizeCertificate(shuffled)).toBe(canonicalizeCertificate(payload));
  });

  test('CAT-15 certificateHash returns a Buffer', () => {
    const h = certificateHash(payload);
    expect(Buffer.isBuffer(h)).toBe(true);
  });

  test('CAT-16 certificateHash returns exactly 32 bytes', () => {
    const h = certificateHash(payload);
    expect(h.length).toBe(32);
  });

  test('CAT-17 certificateHash is deterministic for same input', () => {
    const h1 = certificateHash(payload);
    const h2 = certificateHash({ ...payload });
    expect(h1.toString('hex')).toBe(h2.toString('hex'));
  });

  test('CAT-18 certificateHash changes when payload changes', () => {
    const h1 = certificateHash(payload);
    const h2 = certificateHash({ ...payload, score: 99 });
    expect(h1.toString('hex')).not.toBe(h2.toString('hex'));
  });

  test('CAT-19 certificateHash is domain-separated (differs from raw SHA-256 of canonical JSON)', () => {
    const canonical = canonicalizeCertificate(payload);
    const rawHash   = crypto.createHash('sha256').update(canonical, 'utf8').digest();
    const domainHash = certificateHash(payload);
    expect(domainHash.toString('hex')).not.toBe(rawHash.toString('hex'));
  });

  test('CAT-20 certificateHash embeds CERTIFICATE_DOMAIN in hash input', () => {
    const canonical = canonicalizeCertificate(payload);
    const expectedHash = crypto.createHash('sha256')
      .update(CERTIFICATE_DOMAIN, 'utf8')
      .update(canonical, 'utf8')
      .digest();
    expect(certificateHash(payload).toString('hex')).toBe(expectedHash.toString('hex'));
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-21..CAT-32  buildCertificatePayload
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-21..32 — buildCertificatePayload', () => {
  const result = _makeCertificationResult();

  test('CAT-21 returns an object', () => {
    expect(typeof buildCertificatePayload(result)).toBe('object');
  });

  test('CAT-22 contains all required certificate fields', () => {
    const c = buildCertificatePayload(result);
    const required = ['artifactVersion', 'certificateId', 'certificationId', 'issuedAt', 'level', 'policyVersion', 'score', 'status', 'tenantId'];
    for (const f of required) {
      expect(c).toHaveProperty(f);
    }
  });

  test('CAT-23 artifactVersion is 1', () => {
    expect(buildCertificatePayload(result).artifactVersion).toBe(1);
  });

  test('CAT-24 certificationId matches input', () => {
    expect(buildCertificatePayload(result).certificationId).toBe(result.certificationId);
  });

  test('CAT-25 level matches certificationLevel', () => {
    expect(buildCertificatePayload(result).level).toBe('CERTIFIED');
  });

  test('CAT-26 score matches input', () => {
    expect(buildCertificatePayload(result).score).toBe(80);
  });

  test('CAT-27 status matches certificationDecision', () => {
    expect(buildCertificatePayload(result).status).toBe('CERTIFIED');
  });

  test('CAT-28 policyVersion matches result.version', () => {
    expect(buildCertificatePayload(result).policyVersion).toBe('1.0');
  });

  test('CAT-29 tenantId is taken from metadata.requestedBy', () => {
    expect(buildCertificatePayload(result).tenantId).toBe('tenant-abc');
  });

  test('CAT-30 tenantId is null when metadata is absent', () => {
    const r = _makeCertificationResult({ metadata: undefined });
    expect(buildCertificatePayload(r).tenantId).toBeNull();
  });

  test('CAT-31 certificateId can be overridden via opts', () => {
    const c = buildCertificatePayload(result, { certificateId: 'fixed-uuid' });
    expect(c.certificateId).toBe('fixed-uuid');
  });

  test('CAT-32 issuedAt can be overridden via opts', () => {
    const c = buildCertificatePayload(result, { issuedAt: '2026-01-01T00:00:00.000Z' });
    expect(c.issuedAt).toBe('2026-01-01T00:00:00.000Z');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-33..CAT-50  issueCertificateArtifact
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-33..50 — issueCertificateArtifact', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    _defaultSigningKey();
  });

  test('CAT-33 returns { bundle, certificate }', () => {
    const { bundle, certificate } = issueCertificateArtifact(_makeCertificationResult());
    expect(bundle).toBeDefined();
    expect(certificate).toBeDefined();
  });

  test('CAT-34 bundle.version is ARTIFACT_VERSION (1)', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(bundle.version).toBe(1);
  });

  test('CAT-35 bundle.domain is CERTIFICATE_DOMAIN', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(bundle.domain).toBe('QODIQA::CERTIFICATE::V1');
  });

  test('CAT-36 bundle.signingAlgorithm is Ed25519', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(bundle.signingAlgorithm).toBe('Ed25519');
  });

  test('CAT-37 bundle.keyId matches the signing key keyId', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(bundle.keyId).toBe(_KEY_ID);
  });

  test('CAT-38 bundle.signature is a non-empty string', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(typeof bundle.signature).toBe('string');
    expect(bundle.signature.length).toBeGreaterThan(0);
  });

  test('CAT-39 bundle.signature decodes to exactly 64 bytes (Ed25519)', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    const sig = Buffer.from(bundle.signature, 'base64');
    expect(sig.length).toBe(64);
  });

  test('CAT-40 bundle.certificate contains all required fields', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    const required = ['artifactVersion', 'certificateId', 'certificationId', 'issuedAt', 'level', 'policyVersion', 'score', 'status'];
    for (const f of required) {
      expect(bundle.certificate).toHaveProperty(f);
    }
  });

  test('CAT-41 bundle.signedAt is a valid ISO timestamp', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(() => new Date(bundle.signedAt).toISOString()).not.toThrow();
  });

  test('CAT-42 bundle is frozen (immutable)', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(Object.isFrozen(bundle)).toBe(true);
  });

  test('CAT-43 bundle.certificate is frozen (immutable)', () => {
    const { bundle } = issueCertificateArtifact(_makeCertificationResult());
    expect(Object.isFrozen(bundle.certificate)).toBe(true);
  });

  test('CAT-44 certificate returned equals bundle.certificate', () => {
    const { bundle, certificate } = issueCertificateArtifact(_makeCertificationResult());
    expect(certificate).toBe(bundle.certificate);
  });

  test('CAT-45 issuedAt override propagates to bundle.certificate.issuedAt', () => {
    const fixed = '2026-01-01T00:00:00.000Z';
    const { bundle } = issueCertificateArtifact(_makeCertificationResult(), { issuedAt: fixed });
    expect(bundle.certificate.issuedAt).toBe(fixed);
  });

  test('CAT-46 certificateId override propagates to bundle.certificate.certificateId', () => {
    const id = 'deadbeef-0000-0000-0000-000000000001';
    const { bundle } = issueCertificateArtifact(_makeCertificationResult(), { certificateId: id });
    expect(bundle.certificate.certificateId).toBe(id);
  });

  test('CAT-47 emits INFO CERTIFICATE_ARTIFACT_ISSUED', () => {
    issueCertificateArtifact(_makeCertificationResult());
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'CERTIFICATE_ARTIFACT_ISSUED', expect.objectContaining({
      certificationId: 'aaaa0000-0000-0000-0000-000000000001',
      keyId:           _KEY_ID,
    }));
  });

  test('CAT-48 throws when getSigningKey returns no privDer (native signing)', () => {
    mockGetSigningKey.mockReturnValue({ keyId: _KEY_ID, privDer: null, nativeSigning: true });
    expect(() => issueCertificateArtifact(_makeCertificationResult())).toThrow('privDer must be available');
  });

  test('CAT-49 two sequential issues produce different certificateIds (random UUID)', () => {
    const { bundle: b1 } = issueCertificateArtifact(_makeCertificationResult());
    const { bundle: b2 } = issueCertificateArtifact(_makeCertificationResult());
    expect(b1.certificate.certificateId).not.toBe(b2.certificate.certificateId);
  });

  test('CAT-50 two sequential issues with same opts produce identical signatures', () => {
    const opts = { certificateId: 'fixed-cert-id', issuedAt: '2026-01-01T00:00:00.000Z' };
    const { bundle: b1 } = issueCertificateArtifact(_makeCertificationResult(), opts);
    const { bundle: b2 } = issueCertificateArtifact(_makeCertificationResult(), opts);
    expect(b1.signature).toBe(b2.signature);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-51..CAT-80  verifyCertificateArtifact
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-51..80 — verifyCertificateArtifact', () => {
  let validBundle;

  beforeEach(() => {
    jest.clearAllMocks();
    _defaultSigningKey();
    const opts = { certificateId: 'fixed-cert-id', issuedAt: '2026-01-01T00:00:00.000Z' };
    validBundle = issueCertificateArtifact(_makeCertificationResult(), opts).bundle;
    // Unfreeze for individual field tampering in some tests
    validBundle = JSON.parse(JSON.stringify(validBundle));
  });

  test('CAT-51 valid bundle returns { valid: true }', () => {
    const r = verifyCertificateArtifact(validBundle);
    expect(r.valid).toBe(true);
  });

  test('CAT-52 valid bundle returns reason SIGNATURE_VERIFIED', () => {
    const r = verifyCertificateArtifact(validBundle);
    expect(r.reason).toBe('SIGNATURE_VERIFIED');
  });

  test('CAT-53 valid result details contains certificateId', () => {
    const r = verifyCertificateArtifact(validBundle);
    expect(r.details.certificateId).toBe('fixed-cert-id');
  });

  test('CAT-54 valid result details contains certificationId', () => {
    const r = verifyCertificateArtifact(validBundle);
    expect(r.details.certificationId).toBe('aaaa0000-0000-0000-0000-000000000001');
  });

  test('CAT-55 valid result details contains level, score, status, keyId, signedAt, domain', () => {
    const r = verifyCertificateArtifact(validBundle);
    expect(r.details).toMatchObject({
      level:   'CERTIFIED',
      score:   80,
      status:  'CERTIFIED',
      keyId:   _KEY_ID,
      domain:  'QODIQA::CERTIFICATE::V1',
    });
  });

  test('CAT-56 null input returns { valid: false, reason: MALFORMED_BUNDLE }', () => {
    const r = verifyCertificateArtifact(null);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
  });

  test('CAT-57 array input returns MALFORMED_BUNDLE', () => {
    const r = verifyCertificateArtifact([]);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
  });

  test('CAT-58 string input returns MALFORMED_BUNDLE', () => {
    const r = verifyCertificateArtifact('not-an-object');
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
  });

  test('CAT-59 missing version field returns MALFORMED_BUNDLE', () => {
    const { version: _, ...noVersion } = validBundle;
    const r = verifyCertificateArtifact(noVersion);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
    expect(r.details.missing).toBe('version');
  });

  test('CAT-60 wrong version returns UNSUPPORTED_VERSION', () => {
    const r = verifyCertificateArtifact({ ...validBundle, version: 99 });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNSUPPORTED_VERSION');
  });

  test('CAT-61 wrong domain returns WRONG_DOMAIN', () => {
    const r = verifyCertificateArtifact({ ...validBundle, domain: 'QODIQA::ARTIFACT::V1' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('WRONG_DOMAIN');
  });

  test('CAT-62 wrong signingAlgorithm returns UNSUPPORTED_ALGORITHM', () => {
    const r = verifyCertificateArtifact({ ...validBundle, signingAlgorithm: 'RSA256' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNSUPPORTED_ALGORITHM');
  });

  test('CAT-63 certificate is array returns MALFORMED_CERTIFICATE', () => {
    const r = verifyCertificateArtifact({ ...validBundle, certificate: [] });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_CERTIFICATE');
  });

  test('CAT-64 missing required certificate field (score) returns MALFORMED_CERTIFICATE', () => {
    const tampered = { ...validBundle, certificate: { ...validBundle.certificate } };
    delete tampered.certificate.score;
    const r = verifyCertificateArtifact(tampered);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_CERTIFICATE');
    expect(r.details.missing).toBe('score');
  });

  test('CAT-65 empty string signature returns INVALID_SIGNATURE_ENCODING', () => {
    const r = verifyCertificateArtifact({ ...validBundle, signature: '' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE_ENCODING');
  });

  test('CAT-66 signature that decodes to wrong byte length returns INVALID_SIGNATURE_ENCODING', () => {
    const short = Buffer.alloc(32).toString('base64');
    const r = verifyCertificateArtifact({ ...validBundle, signature: short });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE_ENCODING');
    expect(r.details.got).toBe(32);
  });

  test('CAT-67 empty keyId returns UNKNOWN_KEY', () => {
    const r = verifyCertificateArtifact({ ...validBundle, keyId: '   ' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNKNOWN_KEY');
  });

  test('CAT-68 unknown keyId returns UNKNOWN_KEY', () => {
    mockGetVerificationKey.mockReturnValue(null);
    const r = verifyCertificateArtifact({ ...validBundle, keyId: 'unknown:key_vX' });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNKNOWN_KEY');
  });

  test('CAT-69 getVerificationKey throwing returns UNKNOWN_KEY', () => {
    mockGetVerificationKey.mockImplementation(() => { throw new Error('key store unavailable'); });
    const r = verifyCertificateArtifact(validBundle);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNKNOWN_KEY');
    expect(r.details.error).toBe('key store unavailable');
  });

  test('CAT-70 verifyCertificateArtifact never throws', () => {
    expect(() => verifyCertificateArtifact(undefined)).not.toThrow();
    expect(() => verifyCertificateArtifact(null)).not.toThrow();
    expect(() => verifyCertificateArtifact({ broken: true })).not.toThrow();
  });

  test('CAT-71 payload tampering (score changed) fails signature', () => {
    const tampered = { ...validBundle, certificate: { ...validBundle.certificate, score: 99 } };
    const r = verifyCertificateArtifact(tampered);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('CAT-72 payload tampering (level changed) fails signature', () => {
    const tampered = { ...validBundle, certificate: { ...validBundle.certificate, level: 'CERTIFIED_PLUS' } };
    const r = verifyCertificateArtifact(tampered);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('CAT-73 payload tampering (certificationId changed) fails signature', () => {
    const tampered = {
      ...validBundle,
      certificate: { ...validBundle.certificate, certificationId: 'deadbeef-0000-0000-0000-000000000001' },
    };
    const r = verifyCertificateArtifact(tampered);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('CAT-74 corrupted signature bytes fails signature', () => {
    const sigBytes = Buffer.from(validBundle.signature, 'base64');
    sigBytes[0] ^= 0xff;
    const r = verifyCertificateArtifact({ ...validBundle, signature: sigBytes.toString('base64') });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('CAT-75 key rotation: deprecated key still verifies old bundle', () => {
    const { privateKey: oldPriv, publicKey: oldPub } = crypto.generateKeyPairSync('ed25519');
    const oldPrivDer = oldPriv.export({ type: 'pkcs8', format: 'der' });
    const oldPubDer  = oldPub.export({ type: 'spki',  format: 'der' });
    const oldKeyId   = 'test-client:key_v0';

    // Issue with the old key
    mockGetSigningKey.mockReturnValue({ keyId: oldKeyId, privDer: oldPrivDer, pubDer: oldPubDer });
    const { bundle: oldBundle } = issueCertificateArtifact(_makeCertificationResult(), {
      certificateId: 'old-cert-id',
      issuedAt:      '2025-01-01T00:00:00.000Z',
    });

    // Rotate — active key is now _KEY_ID, but old key is still resolvable
    mockGetSigningKey.mockReturnValue({ keyId: _KEY_ID, privDer: _PRIV_DER, pubDer: _PUB_DER });
    // the key's status timeline travels with it (keyStore.getPublicKey)
    const oldTimeline = { status: 'deprecated', activatedAt: '2024-06-01T00:00:00.000Z', deprecatedAt: '2025-06-01T00:00:00.000Z', archivedAt: null, revokedAt: null };
    mockGetVerificationKey.mockImplementation((kid) => {
      if (kid === oldKeyId) return { keyId: oldKeyId, pubDer: oldPubDer, status: 'deprecated', timeline: oldTimeline };
      if (kid === _KEY_ID)  return { keyId: _KEY_ID,  pubDer: _PUB_DER,  status: 'active' };
      return null;
    });

    const r = verifyCertificateArtifact(JSON.parse(JSON.stringify(oldBundle)));
    expect(r.valid).toBe(true);
    expect(r.details.keyId).toBe(oldKeyId);
  });

  test('CAT-75b a certificate issued AFTER its key was retired does not verify (historical rule)', () => {
    const { privateKey: oldPriv, publicKey: oldPub } = crypto.generateKeyPairSync('ed25519');
    const oldPrivDer = oldPriv.export({ type: 'pkcs8', format: 'der' });
    const oldPubDer  = oldPub.export({ type: 'spki',  format: 'der' });
    const oldKeyId   = 'test-client:key_v0';
    mockGetSigningKey.mockReturnValue({ keyId: oldKeyId, privDer: oldPrivDer, pubDer: oldPubDer });
    const { bundle } = issueCertificateArtifact(_makeCertificationResult(), { certificateId: 'late-cert-id', issuedAt: '2025-07-01T00:00:00.000Z' });
    mockGetVerificationKey.mockImplementation((kid) => (kid === oldKeyId
      ? { keyId: oldKeyId, pubDer: oldPubDer, status: 'deprecated', timeline: { status: 'deprecated', activatedAt: '2024-06-01T00:00:00.000Z', deprecatedAt: '2025-06-01T00:00:00.000Z' } }
      : null));
    const r = verifyCertificateArtifact(JSON.parse(JSON.stringify(bundle)));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('KEY_NOT_ACTIVE_AT_SIGNING_TIME');
  });

  test('CAT-76 bundle serialized to JSON and parsed back still verifies', () => {
    const serialized = JSON.stringify(validBundle);
    const parsed     = JSON.parse(serialized);
    const r = verifyCertificateArtifact(parsed);
    expect(r.valid).toBe(true);
  });

  test('CAT-77 bundle with extra top-level fields still verifies (signed object is certificate only)', () => {
    const extra = { ...validBundle, extraField: 'ignored' };
    const r = verifyCertificateArtifact(extra);
    expect(r.valid).toBe(true);
  });

  test('CAT-78 missing keyId field returns MALFORMED_BUNDLE', () => {
    const { keyId: _, ...noKey } = validBundle;
    const r = verifyCertificateArtifact(noKey);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
  });

  test('CAT-79 missing signedAt field returns MALFORMED_BUNDLE', () => {
    const { signedAt: _, ...noSignedAt } = validBundle;
    const r = verifyCertificateArtifact(noSignedAt);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('MALFORMED_BUNDLE');
  });

  test('CAT-80 getVerificationKey returning object without pubDer returns UNKNOWN_KEY', () => {
    mockGetVerificationKey.mockReturnValue({ keyId: _KEY_ID, pubDer: null });
    const r = verifyCertificateArtifact(validBundle);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('UNKNOWN_KEY');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-81..CAT-90  certificateStore
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-81..90 — certificateStore', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    _defaultSigningKey();
  });

  const _makeBundle = () => {
    const opts = { certificateId: 'cert-store-id', issuedAt: '2026-01-01T00:00:00.000Z' };
    return issueCertificateArtifact(_makeCertificationResult(), opts).bundle;
  };

  test('CAT-81 storeCertificate returns null when PG is disabled', async () => {
    mockPgEnabled.mockReturnValue(false);
    const result = await certificateStore.storeCertificate(_makeBundle());
    expect(result).toBeNull();
    expect(mockPgQuery).not.toHaveBeenCalled();
  });

  test('CAT-82 storeCertificate executes INSERT with ON CONFLICT when PG is enabled', async () => {
    mockPgEnabled.mockReturnValue(true);
    const row = { id: 1, certificate_id: 'cert-store-id', certification_id: 'aaaa0000-0000-0000-0000-000000000001' };
    mockPgQuery.mockResolvedValue({ rows: [row] });

    const result = await certificateStore.storeCertificate(_makeBundle());
    expect(result).toEqual(row);
    expect(mockPgQuery).toHaveBeenCalledTimes(1);
    const sql = mockPgQuery.mock.calls[0][0];
    expect(sql).toMatch(/INSERT INTO certificate_artifacts/);
    expect(sql).toMatch(/ON CONFLICT/);
    expect(sql).toMatch(/DO NOTHING/);
  });

  test('CAT-83 storeCertificate returns null when ON CONFLICT fires (no row returned)', async () => {
    mockPgEnabled.mockReturnValue(true);
    mockPgQuery.mockResolvedValue({ rows: [] });
    const result = await certificateStore.storeCertificate(_makeBundle());
    expect(result).toBeNull();
  });

  test('CAT-84 storeCertificate emits INFO CERTIFICATE_ARTIFACT_STORED on success', async () => {
    mockPgEnabled.mockReturnValue(true);
    const row = { id: 1, certificate_id: 'cert-store-id', certification_id: 'aaaa0000-0000-0000-0000-000000000001' };
    mockPgQuery.mockResolvedValue({ rows: [row] });
    await certificateStore.storeCertificate(_makeBundle());
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'CERTIFICATE_ARTIFACT_STORED', expect.objectContaining({
      certificateId:   'cert-store-id',
      certificationId: 'aaaa0000-0000-0000-0000-000000000001',
      stored:          true,
    }));
  });

  test('CAT-85 storeCertificate emits with stored=false when conflict fires', async () => {
    mockPgEnabled.mockReturnValue(true);
    mockPgQuery.mockResolvedValue({ rows: [] });
    await certificateStore.storeCertificate(_makeBundle());
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'CERTIFICATE_ARTIFACT_STORED', expect.objectContaining({
      stored: false,
    }));
  });

  test('CAT-86 storeCertificate emits ERROR and rethrows on PG error', async () => {
    mockPgEnabled.mockReturnValue(true);
    mockPgQuery.mockRejectedValue(new Error('PG connection refused'));
    await expect(certificateStore.storeCertificate(_makeBundle())).rejects.toThrow('PG connection refused');
    expect(mockEmit).toHaveBeenCalledWith('ERROR', 'CERTIFICATE_ARTIFACT_STORE_FAILED', expect.objectContaining({
      error: 'PG connection refused',
    }));
  });

  test('CAT-87 getByCertificateId returns null when PG is disabled', async () => {
    mockPgEnabled.mockReturnValue(false);
    expect(await certificateStore.getByCertificateId('any-id')).toBeNull();
    expect(mockPgQuery).not.toHaveBeenCalled();
  });

  test('CAT-88 getByCertificateId queries by certificate_id', async () => {
    mockPgEnabled.mockReturnValue(true);
    const row = { id: 1, certificate_id: 'cert-store-id' };
    mockPgQuery.mockResolvedValue({ rows: [row] });
    const result = await certificateStore.getByCertificateId('cert-store-id');
    expect(result).toEqual(row);
    const sql = mockPgQuery.mock.calls[0][0];
    expect(sql).toMatch(/certificate_id\s*=\s*\$1/);
  });

  test('CAT-89 getByCertificationId returns null when PG is disabled', async () => {
    mockPgEnabled.mockReturnValue(false);
    expect(await certificateStore.getByCertificationId('any-id')).toBeNull();
  });

  test('CAT-90 getByCertificationId queries by certification_id', async () => {
    mockPgEnabled.mockReturnValue(true);
    const row = { id: 1, certification_id: 'aaaa0000-0000-0000-0000-000000000001' };
    mockPgQuery.mockResolvedValue({ rows: [row] });
    const result = await certificateStore.getByCertificationId('aaaa0000-0000-0000-0000-000000000001');
    expect(result).toEqual(row);
    const sql = mockPgQuery.mock.calls[0][0];
    expect(sql).toMatch(/certification_id\s*=\s*\$1/);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CAT-91..CAT-100  Download endpoint GET /:certificationId/certificate
// ══════════════════════════════════════════════════════════════════════════════

describe('CAT-91..100 — GET /:certificationId/certificate', () => {
  const express     = require('express');
  const request     = require('supertest');

  // Mock the stores used by the certification router
  jest.mock('../certificationStore');
  jest.mock('../certificateStore');
  jest.mock('../../../core/rateLimit', () => ({
    createRateLimitMiddleware: () => (_req, _res, next) => next(),
  }));
  jest.mock('../../../core/certification/evaluationEngine', () => ({
    evaluate:                     jest.fn(),
    assembleCertificationEvidence: jest.fn(),
  }));

  const { createCertificationPublicRouter } = require('../../../api/routes/certification');
  const mockCertStore = require('../certificateStore');
  const CERT_ID = 'cccc0000-0000-0000-0000-000000000001';

  function _makeApp() {
    const app = express();
    app.use(express.json());
    app.use('/v1/certification', createCertificationPublicRouter());
    return app;
  }

  let _validBundle;

  beforeEach(() => {
    jest.clearAllMocks();
    _defaultSigningKey();
    const opts = { certificateId: 'dl-cert-id', issuedAt: '2026-01-01T00:00:00.000Z' };
    _validBundle = issueCertificateArtifact(_makeCertificationResult({ certificationId: CERT_ID }), opts).bundle;
    _validBundle = JSON.parse(JSON.stringify(_validBundle));
  });

  test('CAT-91 returns 200 with the stored bundle when certificate exists', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ version: 1, domain: 'QODIQA::CERTIFICATE::V1' });
  });

  test('CAT-92 Content-Type is application/json', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('CAT-93 downloaded bundle passes verifyCertificateArtifact', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    const result = verifyCertificateArtifact(res.body);
    expect(result.valid).toBe(true);
  });

  test('CAT-94 returns 404 when no certificate exists', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue(null);
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  });

  test('CAT-95 returns 400 for invalid UUID param', async () => {
    const res = await request(_makeApp()).get('/v1/certification/not-a-uuid/certificate');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('INVALID_PARAM');
  });

  test('CAT-96 returns 500 on unexpected store error', async () => {
    mockCertStore.getByCertificationId.mockRejectedValue(new Error('DB failure'));
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.status).toBe(500);
    expect(res.body.error.code).toBe('INTERNAL_ERROR');
  });

  test('CAT-97 emits CERTIFICATE_ARTIFACT_DOWNLOADED on success', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(mockEmit).toHaveBeenCalledWith('INFO', 'CERTIFICATE_ARTIFACT_DOWNLOADED', expect.objectContaining({
      certificationId: CERT_ID,
      certificateId:   'dl-cert-id',
    }));
  });

  test('CAT-98 bundle in response is identical to stored bundle (not a copy with extra fields)', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.body).toEqual(_validBundle);
  });

  test('CAT-99 does not return standard QODIQA response envelope (raw bundle, not wrapped)', async () => {
    mockCertStore.getByCertificationId.mockResolvedValue({
      certificate_id:   'dl-cert-id',
      certification_id: CERT_ID,
      bundle:           _validBundle,
    });
    const res = await request(_makeApp()).get(`/v1/certification/${CERT_ID}/certificate`);
    expect(res.body).not.toHaveProperty('status');
    expect(res.body).not.toHaveProperty('apiVersion');
    expect(res.body).not.toHaveProperty('data');
  });

  test('CAT-100 does not call getByCertificationId when param UUID is invalid', async () => {
    await request(_makeApp()).get('/v1/certification/invalid-id/certificate');
    expect(mockCertStore.getByCertificationId).not.toHaveBeenCalled();
  });
});
