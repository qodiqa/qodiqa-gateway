'use strict';

/**
 * the SERVER-SIDE evidence bundle verifier (generator.verifyEvidenceBundle) must verify the
 * transparency inclusion proof the same way the standalone tools/verify/verify.bundle.external.js does: not only the Merkle
 * structure (leaf range, tree size, path, root hash) but also
 *   - entryHash covers the entry's canonical fields,
 *   - the entry's Ed25519 signature and the root's Ed25519 signature, against TRUSTED transparency keys — this
 *     instance's own transparency key store PUBLIC keys (status active/deprecated, exactly the set served at
 *     GET /.well-known/qodiqa/transparency-keys), never key material carried by the proof,
 *   - the leaf ↔ artifact binding (the leaf names this bundle's artifactId, or a lifecycle suffix of it).
 *
 * Every bad bundle below is SEALED VALIDLY by the instance's evidence key (generateEvidenceBundle with a mocked
 * proof lookup) — i.e. the envelope seal cannot catch it; only the transparency checks can.
 * The real transparency key store is used (test/support/jest.setup.js isolates its file per worker); the "attacker" is a fresh
 * Ed25519 key the store does not hold.
 */

const crypto = require('crypto');

jest.mock('../../audit/audit-log.js');
jest.mock('../../../../services/artifact/keyManager');
jest.mock('../../transparency/proofLookup');

const { generateEvidenceBundle, verifyEvidenceBundle } = require('../generator');
const auditLog    = require('../../audit/audit-log.js');
const keyManager  = require('../../../../services/artifact/keyManager');
const proofLookup = require('../../transparency/proofLookup');
const log         = require('../../transparency/log');
const merkle      = require('../../transparency/merkle');
const transparencyKeyStore = require('../../transparency/transparencyKeyStore');
const { sign } = require('../../../infra/crypto/ed25519');
const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

const ARTIFACT_ID = 'art-dd112-1';

// Evidence/bundle seal key (artifact key store, mocked as in generator.bundle.test.js).
const seal = crypto.generateKeyPairSync('ed25519');
const SEAL_PUB  = seal.publicKey.export({ type: 'spki', format: 'der' });
const SEAL_PRIV = seal.privateKey.export({ type: 'pkcs8', format: 'der' });
const SEAL_KEY_ID = 'test-client:key_v1';

const attacker = crypto.generateKeyPairSync('ed25519');
const ATTACKER_PRIV = attacker.privateKey.export({ type: 'pkcs8', format: 'der' });

const SAMPLE_CANONICAL = '{"placeholder":true}';
const SAMPLE_HASH = domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, SAMPLE_CANONICAL).toString('hex');
const SAMPLE_ENTRY = Object.freeze({
  artifactId: ARTIFACT_ID, decision: 'ALLOW', timestamp: new Date().toISOString(),
  inputHash: 'a'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
  signature: 'sig-placeholder', nonce: null, tenantId: null, highResTime: '123',
  executionContext: { stage: 'PROVIDER_EXECUTION' },
  hash: SAMPLE_HASH, prevHash: 'GENESIS', canonical: SAMPLE_CANONICAL,
  verificationResult: true, schemaVersion: 5, publicKeyId: SEAL_KEY_ID,
});

/**
 * A genuine proofVersion-2 inclusion proof (shape of log.buildInclusionProof): 6 signed entries, leaf 3 is the
 * artifact's DECISION leaf, root over all 6 entry hashes, entries and root signed with `entryKey` / `rootKey`.
 */
function buildProof({ entryKey, rootKey, leafArtifactId = ARTIFACT_ID, mutateEntryAfterSign } = {}) {
  const tk = transparencyKeyStore.getActiveKey();
  const eKey = entryKey || { keyId: tk.keyId, privDer: tk.privDer };
  const rKey = rootKey  || { keyId: tk.keyId, privDer: tk.privDer };
  const LEAF = 3;
  const entries = [];
  let prev = null;
  for (let i = 0; i < 6; i++) {
    const e = {
      transparencyId: `t-${i}`, entryType: 'DECISION',
      artifactId: i === LEAF ? leafArtifactId : `other-${i}`,
      evidenceChainId: null, verificationId: null,
      payloadHash: crypto.createHash('sha256').update(`payload-${i}`).digest('hex'),
      previousEntryHash: prev, signerKeyId: eKey.keyId,
    };
    e.entryHash = log.computeEntryHash(e);
    e.signature = sign(Buffer.from(e.entryHash, 'hex'), eKey.privDer);
    prev = e.entryHash;
    entries.push(e);
  }
  const hashes = entries.map((e) => e.entryHash);
  const rootHash = merkle.merkleRoot(hashes);
  const root = { rootId: 'r-1', seqFrom: 1, seqTo: 6, entryCount: 6, rootHash, previousRootHash: null, signerKeyId: rKey.keyId };
  root.signature = sign(log.computeRootSigningBuffer(root), rKey.privDer);
  const entry = { ...entries[LEAF], id: LEAF + 1 };
  if (mutateEntryAfterSign) mutateEntryAfterSign(entry);
  return {
    proofVersion: '2', proofType: 'TRANSPARENCY_INCLUSION', generatedAt: new Date().toISOString(),
    entry, root,
    proof: { leafIndex: LEAF, treeSize: 6, merklePath: merkle.inclusionPath(hashes, LEAF), merkleRoot: rootHash },
    verifiable: true,
  };
}

async function sealedBundleWith(proof) {
  proofLookup.getInclusionProofForArtifact.mockResolvedValue({ proof, proofVerification: { valid: true }, message: null });
  const { found, bundle } = await generateEvidenceBundle(ARTIFACT_ID, [], null, null);
  expect(found).toBe(true);
  return bundle;
}

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
  keyManager.getSigningKey.mockReturnValue({ keyId: SEAL_KEY_ID, privDer: SEAL_PRIV, pubDer: SEAL_PUB, clientId: 'test-client' });
  keyManager.getVerificationKey.mockReturnValue({ pubDer: SEAL_PUB, status: 'active' });
  keyManager.listPublicKeys.mockReturnValue([{
    keyId: SEAL_KEY_ID, clientId: 'test-client', status: 'active', algorithm: 'Ed25519',
    version: 1, createdAt: new Date().toISOString(), publicKeyB64: SEAL_PUB.toString('base64'),
  }]);
});

describe('server-side bundle verification checks transparency signatures and leaf binding', () => {
  test('TT-01 control: a genuine proof signed by this instance\'s transparency key, bound to the artifact → valid', async () => {
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof()));
    expect(r.reasons).toEqual([]);
    expect(r.transparencyProofValid).toBe(true);
    expect(r.valid).toBe(true);
  });

  test('TT-02 entry signed by an UNTRUSTED key (not in the transparency key store) → invalid', async () => {
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ entryKey: { keyId: 'tr-attacker:key_v1', privDer: ATTACKER_PRIV } })));
    expect(r.bundleSignatureValid).toBe(true); // the envelope seal is fine — only the transparency check catches it
    expect(r.transparencyProofValid).toBe(false);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/TRANSPARENCY_ENTRY_KEY/);
  });

  test('TT-03 entry signature forged under the TRUSTED keyId (attacker bytes) → TRANSPARENCY_ENTRY_SIGNATURE_INVALID', async () => {
    const tk = transparencyKeyStore.getActiveKey();
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ entryKey: { keyId: tk.keyId, privDer: ATTACKER_PRIV } })));
    expect(r.transparencyProofValid).toBe(false);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/TRANSPARENCY_ENTRY_SIGNATURE_INVALID/);
  });

  test('TT-04 root signature forged under the TRUSTED keyId → TRANSPARENCY_ROOT_SIGNATURE_INVALID', async () => {
    const tk = transparencyKeyStore.getActiveKey();
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ rootKey: { keyId: tk.keyId, privDer: ATTACKER_PRIV } })));
    expect(r.transparencyProofValid).toBe(false);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/TRANSPARENCY_ROOT_SIGNATURE_INVALID/);
  });

  test('TT-05 a valid, signed proof for a DIFFERENT artifact → TRANSPARENCY_ENTRY_NOT_BOUND', async () => {
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ leafArtifactId: 'some-other-artifact' })));
    expect(r.transparencyProofValid).toBe(false);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/TRANSPARENCY_ENTRY_NOT_BOUND/);
  });

  test('TT-06 entry fields altered after signing (entryHash no longer covers them) → TRANSPARENCY_ENTRY_HASH_MISMATCH', async () => {
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ mutateEntryAfterSign: (e) => { e.entryType = 'LIFECYCLE'; } })));
    expect(r.transparencyProofValid).toBe(false);
    expect(r.valid).toBe(false);
    expect(r.reasons.join(' ')).toMatch(/TRANSPARENCY_ENTRY_HASH_MISMATCH/);
  });

  test('TT-07 lifecycle leaf under the artifact (artifactId:suffix) is bound → valid', async () => {
    const r = verifyEvidenceBundle(await sealedBundleWith(buildProof({ leafArtifactId: `${ARTIFACT_ID}:lifecycle` })));
    expect(r.transparencyProofValid).toBe(true);
    expect(r.valid).toBe(true);
  });

  test('TT-08 a REVOKED transparency key no longer authenticates the proof', async () => {
    const proof = buildProof();
    const bundle = await sealedBundleWith(proof);
    const spy = jest.spyOn(transparencyKeyStore, 'getPublicKey').mockImplementation(() => { throw new Error('revoked'); });
    try {
      const r = verifyEvidenceBundle(bundle);
      expect(r.transparencyProofValid).toBe(false);
      expect(r.valid).toBe(false);
    } finally { spy.mockRestore(); }
  });
});
