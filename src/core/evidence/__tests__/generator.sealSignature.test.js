'use strict';

/**
 * Evidence Package Integrity Seal — regression coverage.
 *
 * flagged the evidence package integrity seal as "only a hash" — no
 * cryptographic signature, so anyone could recompute packageHash and forge a
 * package that looked internally consistent. generator.js's _signPackage()/
 * verifyEvidencePackage() already close this (Ed25519 signature over the
 * package content, full signature + public key + keyId exported), but there
 * was no test guarding that behavior from silently regressing back to a bare
 * hash. This file is that guard.
 */

const crypto = require('crypto');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

jest.mock('../../audit/audit-log.js');
jest.mock('../../../../services/artifact/keyManager');

const { generateEvidencePackage, verifyEvidencePackage } = require('../generator');
const auditLog    = require('../../audit/audit-log.js');
const keyManager   = require('../../../../services/artifact/keyManager');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB_DER  = publicKey.export({ type: 'spki', format: 'der' });
const PRIV_DER = privateKey.export({ type: 'pkcs8', format: 'der' });
const KEY_ID   = 'test-client:key_v1';

// The `canonical`/`hash` pair must be a real, mutually-consistent
// domain-separated hash — generator.js's chainHash check (Step 3 of
// verifyEvidencePackage) recomputes hash from canonical and would otherwise
// always fail, masking the packageHash/signature behavior this file targets.
const SAMPLE_CANONICAL = '{"placeholder":true}';
const SAMPLE_HASH = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, SAMPLE_CANONICAL).toString('hex');

const SAMPLE_ENTRY = Object.freeze({
  artifactId: 'art-evid3-1',
  decision: 'ALLOW',
  timestamp: new Date().toISOString(),
  inputHash: 'a'.repeat(64),
  requestHash: 'b'.repeat(64),
  policyHash: 'c'.repeat(64),
  signature: 'sig-placeholder',
  nonce: null,
  tenantId: null,
  highResTime: '123',
  executionContext: { stage: 'PROVIDER_EXECUTION' },
  hash: SAMPLE_HASH,
  prevHash: 'GENESIS',
  canonical: SAMPLE_CANONICAL,
  verificationResult: true,
  schemaVersion: 4,
  publicKeyId: KEY_ID,
});

beforeEach(() => {
  jest.clearAllMocks();
  auditLog.getAuditChain.mockReturnValue([SAMPLE_ENTRY]);
  auditLog.getArtifactById.mockReturnValue(SAMPLE_ENTRY);
  auditLog.getReplayLineage.mockReturnValue([]);
  auditLog.verifyAuditChainDetailed.mockReturnValue({
    valid: true, entriesVerified: 1, tamperingDetected: false, reason: null, head: 'd'.repeat(64), tail: 'd'.repeat(64),
  });
  // the generator now walks the chain with forEachChainEntry + createChainWalker; this double serves the same
  // chain and verdict as the getAuditChain / verifyAuditChainDetailed doubles above.
  auditLog.forEachChainEntry.mockImplementation(async (visit) => { const c = auditLog.getAuditChain(); c.forEach(visit); return c.length; });
  auditLog.createChainWalker.mockImplementation(() => ({ push: () => null, result: () => auditLog.verifyAuditChainDetailed() }));

  keyManager.getSigningKey.mockReturnValue({
    keyId: KEY_ID, privDer: PRIV_DER, pubDer: PUB_DER, clientId: 'test-client',
  });
  keyManager.getVerificationKey.mockReturnValue({ pubDer: PUB_DER, status: 'active' });
  keyManager.listPublicKeys.mockReturnValue([{
    keyId: KEY_ID, clientId: 'test-client', status: 'active', algorithm: 'Ed25519',
    version: 1, createdAt: new Date().toISOString(), publicKeyB64: PUB_DER.toString('base64'),
  }]);
});

describe('evidence package integrity seal is cryptographically signed', () => {
  test('SEAL-01 generateEvidencePackage() produces a real Ed25519 signature, not just a hash', async () => {
    const { found, package: pkg } = await generateEvidencePackage('art-evid3-1', [], null, null);
    expect(found).toBe(true);
    expect(pkg.integrity.algorithm).toBe('SHA-256');
    expect(pkg.integrity.packageHash).toMatch(/^[0-9a-f]{64}$/);

    // The seal itself — this is the part required and the earlier
    // implementation lacked.
    expect(pkg.integrity.signingAlgorithm).toBe('Ed25519');
    expect(pkg.integrity.keyId).toBe(KEY_ID);
    expect(pkg.integrity.sealError).toBeNull();
    expect(typeof pkg.integrity.signature).toBe('string');
    expect(Buffer.from(pkg.integrity.signature, 'base64').length).toBe(64); // real Ed25519 sig length
    expect(pkg.integrity.publicKey).toBe(PUB_DER.toString('base64'));
  });

  test('SEAL-02 verifyEvidencePackage() reports signatureValid: true for a genuinely signed package', async () => {
    const { package: pkg } = await generateEvidencePackage('art-evid3-1', [], null, null);
    const result = verifyEvidencePackage(pkg);
    expect(result.packageHashValid).toBe(true);
    expect(result.signatureValid).toBe(true);
    expect(result.valid).toBe(true);
  });

  test('SEAL-03 tampering with signed content flips packageHash validity to false', async () => {
    const { package: pkg } = await generateEvidencePackage('art-evid3-1', [], null, null);
    pkg.sections.artifact.decision = 'BLOCK'; // tamper after signing
    const result = verifyEvidencePackage(pkg);
    expect(result.packageHashValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  test('SEAL-04 a forged signature (correct hash, wrong signature bytes) is rejected — a bare hash alone is not sufficient proof', async () => {
    const { package: pkg } = await generateEvidencePackage('art-evid3-1', [], null, null);
    // Flip the signature to another validly-shaped but wrong 64-byte Ed25519 signature.
    const forged = Buffer.alloc(64, 0x42).toString('base64');
    pkg.integrity.signature = forged;
    const result = verifyEvidencePackage(pkg);
    expect(result.packageHashValid).toBe(true); // hash alone still "matches" — proves hash-only would have been forgeable
    expect(result.signatureValid).toBe(false);  // but the signature check catches it
    expect(result.valid).toBe(false);
  });

  test('SEAL-05 a signature from an unrelated keypair over the same content is rejected', async () => {
    const { package: pkg } = await generateEvidencePackage('art-evid3-1', [], null, null);
    const otherPair = crypto.generateKeyPairSync('ed25519');
    pkg.integrity.publicKey = otherPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    const result = verifyEvidencePackage(pkg);
    expect(result.signatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});
