'use strict';

/**
 * Self-contained offline evidence bundle — regression coverage.
 *
 * generateEvidenceBundle() wraps generateEvidencePackage()'s output together
 * with the artifact's Merkle transparency inclusion proof (via
 * src/core/transparency/proofLookup.js), sealed with one more Ed25519
 * signature over the combined content. Covers both the "root already
 * generated" and "no root yet" cases, and that verifyEvidenceBundle()
 * detects tampering with either half independently.
 */

const crypto = require('crypto');

jest.mock('../../audit/audit-log.js');
jest.mock('../../../../services/artifact/keyManager');
jest.mock('../../transparency/proofLookup');

const { generateEvidenceBundle, verifyEvidenceBundle } = require('../generator');
const auditLog    = require('../../audit/audit-log.js');
const keyManager   = require('../../../../services/artifact/keyManager');
const proofLookup  = require('../../transparency/proofLookup');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');
const merkle = require('../../transparency/merkle');

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB_DER  = publicKey.export({ type: 'spki', format: 'der' });
const PRIV_DER = privateKey.export({ type: 'pkcs8', format: 'der' });
const KEY_ID   = 'test-client:key_v1';

const SAMPLE_CANONICAL = '{"placeholder":true}';
const SAMPLE_HASH = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, SAMPLE_CANONICAL).toString('hex');

const SAMPLE_ENTRY = Object.freeze({
  artifactId: 'art-bundle-1', decision: 'ALLOW', timestamp: new Date().toISOString(),
  inputHash: 'a'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
  signature: 'sig-placeholder', nonce: null, tenantId: null, highResTime: '123',
  executionContext: { stage: 'PROVIDER_EXECUTION' },
  hash: SAMPLE_HASH, prevHash: 'GENESIS', canonical: SAMPLE_CANONICAL,
  verificationResult: true, schemaVersion: 5, publicKeyId: KEY_ID,
  provider: 'anthropic', model: 'claude-3-opus-20240229',
});

// A genuinely valid RFC6962 inclusion proof, built with the real merkle.js
// primitives — not hand-waved hash strings. Necessary because
// generator.js's verifyEvidenceBundle() (and the standalone
// tools/verify/verify.bundle.external.js) actually recompute and check the Merkle path,
// not merely check its shape.
// fixture correction: the server-side verifier now also checks the entry hash, the entry and
// root Ed25519 signatures against this instance's TRUSTED transparency keys, and the leaf <-> artifact binding
// (as tools/verify/verify.bundle.external.js always did). The previous fixture was an unsigned leaf with no artifactId, which
// "verified fully" only because those checks were missing — so the proof is now a real signed one: 10 entries
// signed with the (per-worker isolated) transparency key store's active key, leaf 4 = this artifact's leaf.
const _log = require('../../transparency/log');
const _tk  = require('../../transparency/transparencyKeyStore').getActiveKey();
const { sign: _edSign } = require('../../../infra/crypto/ed25519');
const _LEAF_INDEX    = 4;
const _ENTRIES = (() => {
  const out = []; let prev = null;
  for (let i = 0; i < 10; i++) {
    const e = {
      transparencyId: `t-${i}`, entryType: 'DECISION', artifactId: i === _LEAF_INDEX ? 'art-bundle-1' : `other-${i}`,
      evidenceChainId: null, verificationId: null,
      payloadHash: crypto.createHash('sha256').update(`entry-${i}`).digest('hex'),
      previousEntryHash: prev, signerKeyId: _tk.keyId,
    };
    e.entryHash = _log.computeEntryHash(e);
    e.signature = _edSign(Buffer.from(e.entryHash, 'hex'), _tk.privDer);
    prev = e.entryHash; out.push(e);
  }
  return out;
})();
const _ENTRY_HASHES  = _ENTRIES.map((e) => e.entryHash);
const _MERKLE_ROOT    = merkle.merkleRoot(_ENTRY_HASHES);
const _MERKLE_PATH    = merkle.inclusionPath(_ENTRY_HASHES, _LEAF_INDEX);
const _ROOT = { rootId: 'r-1', seqFrom: 1, seqTo: 10, entryCount: 10, rootHash: _MERKLE_ROOT, previousRootHash: null, signerKeyId: _tk.keyId };
_ROOT.signature = _edSign(_log.computeRootSigningBuffer(_ROOT), _tk.privDer);

const SAMPLE_INCLUSION_PROOF = Object.freeze({
  proofVersion: '2', proofType: 'TRANSPARENCY_INCLUSION', generatedAt: new Date().toISOString(),
  entry: { ..._ENTRIES[_LEAF_INDEX], id: _LEAF_INDEX + 1 },
  root: _ROOT,
  proof: { leafIndex: _LEAF_INDEX, treeSize: 10, merklePath: _MERKLE_PATH, merkleRoot: _MERKLE_ROOT },
  verifiable: true,
});

beforeEach(() => {
  jest.clearAllMocks();
  auditLog.getAuditChain.mockReturnValue([SAMPLE_ENTRY]);
  auditLog.getArtifactById.mockReturnValue(SAMPLE_ENTRY);
  auditLog.getReplayLineage.mockReturnValue([]);
  auditLog.verifyAuditChainDetailed.mockReturnValue({
    valid: true, entriesVerified: 1, tamperingDetected: false, reason: null, head: SAMPLE_HASH, tail: SAMPLE_HASH,
  });
  // the generator now walks the chain with forEachChainEntry + createChainWalker; this double serves the same
  // chain and verdict as the getAuditChain / verifyAuditChainDetailed doubles above.
  auditLog.forEachChainEntry.mockImplementation(async (visit) => { const c = auditLog.getAuditChain(); c.forEach(visit); return c.length; });
  auditLog.createChainWalker.mockImplementation(() => ({ push: () => null, result: () => auditLog.verifyAuditChainDetailed() }));

  keyManager.getSigningKey.mockReturnValue({ keyId: KEY_ID, privDer: PRIV_DER, pubDer: PUB_DER, clientId: 'test-client' });
  keyManager.getVerificationKey.mockReturnValue({ pubDer: PUB_DER, status: 'active' });
  keyManager.listPublicKeys.mockReturnValue([{
    keyId: KEY_ID, clientId: 'test-client', status: 'active', algorithm: 'Ed25519',
    version: 1, createdAt: new Date().toISOString(), publicKeyB64: PUB_DER.toString('base64'),
  }]);
});

describe('generateEvidenceBundle() / verifyEvidenceBundle()', () => {
  test('BUNDLE-01 with a published root: bundle carries the inclusion proof and verifies fully', async () => {
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({
      proof: SAMPLE_INCLUSION_PROOF, proofVerification: { valid: true }, message: null,
    });

    const { found, bundle } = await generateEvidenceBundle('art-bundle-1', [], null, null);
    expect(found).toBe(true);
    expect(bundle.schema).toBe('QODIQA::EVIDENCE_BUNDLE::V1');
    expect(bundle.transparency.available).toBe(true);
    expect(bundle.transparency.inclusionProof).toEqual(SAMPLE_INCLUSION_PROOF);
    expect(bundle.integrity.sealError).toBeNull();
    expect(Buffer.from(bundle.integrity.signature, 'base64').length).toBe(64);

    const result = verifyEvidenceBundle(bundle);
    expect(result.bundleHashValid).toBe(true);
    expect(result.bundleSignatureValid).toBe(true);
    expect(result.packageValid).toBe(true);
    expect(result.transparencyProofValid).toBe(true);
    expect(result.valid).toBe(true);
  });

  test('BUNDLE-02 with no root generated yet: bundle is still produced and still verifies (transparency section marked unavailable)', async () => {
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({
      proof: null, proofVerification: null, message: 'No root has been generated covering this entry yet.',
    });

    const { found, bundle } = await generateEvidenceBundle('art-bundle-1', [], null, null);
    expect(found).toBe(true);
    expect(bundle.transparency.available).toBe(false);
    expect(bundle.transparency.note).toMatch(/No root/);

    const result = verifyEvidenceBundle(bundle);
    // transparencyProofValid stays null (nothing to check) — must not fail
    // the bundle just because a root hasn't been published yet.
    expect(result.transparencyProofValid).toBeNull();
    expect(result.bundleHashValid).toBe(true);
    expect(result.bundleSignatureValid).toBe(true);
    expect(result.packageValid).toBe(true);
    expect(result.valid).toBe(true);
  });

  test('BUNDLE-03 artifact not found in audit chain: found:false, no bundle generated', async () => {
    auditLog.getArtifactById.mockReturnValue(null);
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({ proof: null, proofVerification: null, message: null });

    const { found, bundle } = await generateEvidenceBundle('nonexistent', [], null, null);
    expect(found).toBe(false);
    expect(bundle).toBeNull();
    // Transparency lookup should never even run for a not-found artifact.
    expect(proofLookup.getInclusionProofForArtifact).not.toHaveBeenCalled();
  });

  test('BUNDLE-04 tampering with the evidence package inside a valid bundle is detected', async () => {
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({
      proof: SAMPLE_INCLUSION_PROOF, proofVerification: { valid: true }, message: null,
    });
    const { bundle } = await generateEvidenceBundle('art-bundle-1', [], null, null);

    bundle.evidencePackage.sections.artifact.decision = 'BLOCK'; // tamper
    const result = verifyEvidenceBundle(bundle);
    // The bundle envelope hash itself now no longer matches either, since
    // evidencePackage is part of what the envelope hash covers.
    expect(result.bundleHashValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  test('BUNDLE-05 splicing in an inclusion proof for a different artifact is detected by the envelope seal', async () => {
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({
      proof: SAMPLE_INCLUSION_PROOF, proofVerification: { valid: true }, message: null,
    });
    const { bundle } = await generateEvidenceBundle('art-bundle-1', [], null, null);

    // Splice in a structurally-valid but different inclusion proof, without
    // re-sealing the envelope (exactly what an attacker without the private
    // key could do).
    bundle.transparency.inclusionProof = {
      ...SAMPLE_INCLUSION_PROOF,
      entry: { ...SAMPLE_INCLUSION_PROOF.entry, entryHash: '9'.repeat(64) },
    };
    const result = verifyEvidenceBundle(bundle);
    expect(result.bundleHashValid).toBe(false);
    expect(result.bundleSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  test('BUNDLE-06 a forged bundle signature (correct hash, wrong signature bytes) is rejected', async () => {
    proofLookup.getInclusionProofForArtifact.mockResolvedValue({
      proof: SAMPLE_INCLUSION_PROOF, proofVerification: { valid: true }, message: null,
    });
    const { bundle } = await generateEvidenceBundle('art-bundle-1', [], null, null);

    bundle.integrity.signature = Buffer.alloc(64, 0x42).toString('base64');
    const result = verifyEvidenceBundle(bundle);
    expect(result.bundleHashValid).toBe(true); // hash alone still "matches" — proves hash-only would be forgeable
    expect(result.bundleSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});
