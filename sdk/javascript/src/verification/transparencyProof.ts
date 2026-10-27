/**
 * Local, offline verification of a QODIQA transparency-log inclusion proof —
 * SDK-side port of `src/core/transparency/log.js`'s `computeEntryHash`,
 * `computeRootSigningBuffer`, `verifyEntrySignature`/`verifyRootSignature`,
 * and `verifyInclusionProof`.
 *
 * Verifies, independently of the server's own verdict:
 *   1. The entry's `entryHash` truly derives from its own canonical fields
 *      (the server's own `verifyInclusionProof` doesn't check this — it
 *      trusts `entry.entryHash` as given — so this is a strictly stronger
 *      check than the server performs).
 *   2. The Merkle audit path reconstructs `root.rootHash` from `entry.entryHash`.
 *   3. `proof.merkleRoot` (if present) matches `root.rootHash`.
 *   4. `leafIndex` is within `[0, treeSize)`.
 *   5. The entry and root Ed25519 signatures verify against the configured
 *      transparency key provider — a completely separate trust domain from
 *      artifact-signing keys.
 *
 * @module
 */

import { domainSeparatedHash, DOMAINS } from './domainHash.js';
import { stableStringify } from './canonicalJson.js';
import { verifyEd25519 } from './ed25519.js';
import { verifyInclusionPath } from './merkle.js';
import type { KeyProvider } from './keyProviders.js';
import type { TransparencyInclusionProof, TransparencyVerificationDetail, TransparencyProofEntry, TransparencyProofRoot } from './types.js';

const CANONICAL_ENTRY_FIELDS = [
  'transparencyId',
  'entryType',
  'artifactId',
  'evidenceChainId',
  'verificationId',
  'payloadHash',
  'previousEntryHash',
  'signerKeyId',
] as const;

const CANONICAL_ROOT_FIELDS = ['rootId', 'seqFrom', 'seqTo', 'entryCount', 'rootHash', 'previousRootHash'] as const;

function pick(record: Record<string, unknown>, fields: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) out[f] = record[f] ?? null;
  return out;
}

function computeEntryHash(entry: TransparencyProofEntry): string {
  const canonical = pick(entry as unknown as Record<string, unknown>, CANONICAL_ENTRY_FIELDS);
  return domainSeparatedHash(DOMAINS.TRANSPARENCY_ENTRY, stableStringify(canonical)).toString('hex');
}

function computeRootSigningBuffer(root: TransparencyProofRoot): Buffer {
  const canonical = pick(root as unknown as Record<string, unknown>, CANONICAL_ROOT_FIELDS);
  return domainSeparatedHash(DOMAINS.TRANSPARENCY_ROOT, stableStringify(canonical));
}

function computeEntrySigningBuffer(entry: TransparencyProofEntry): Buffer {
  return Buffer.from(computeEntryHash(entry), 'hex');
}

/**
 * Verify a {@link TransparencyInclusionProof} entirely locally.
 *
 * Never throws — every failure mode is captured in the returned
 * {@link TransparencyVerificationDetail}.
 */
export async function verifyTransparencyProof(
  proof: TransparencyInclusionProof,
  transparencyKeys: KeyProvider,
): Promise<TransparencyVerificationDetail> {
  const detail: TransparencyVerificationDetail = {
    entryHashValid: false,
    merklePathValid: false,
    entrySignatureValid: false,
    rootSignatureValid: false,
    leafIndexValid: false,
    keyValid: false,
    keyStatus: null,
  };

  if (!proof || !proof.entry || !proof.root || !proof.proof) {
    return detail;
  }

  // Signature-format-version validation: this SDK understands proof format
  // '2' (the only version the server currently emits). An unrecognized
  // version has no defined verification semantics, so fail closed rather
  // than attempting to interpret unknown fields.
  if (proof.proofVersion !== '2' || proof.proofType !== 'TRANSPARENCY_INCLUSION') {
    return detail;
  }

  const { entry, root, proof: proofData } = proof;

  // 1. Entry hash truly derives from the entry's own canonical fields.
  try {
    detail.entryHashValid = computeEntryHash(entry) === entry.entryHash;
  } catch {
    detail.entryHashValid = false;
  }

  // 2. Leaf index range.
  const leafIndex = Number(proofData.leafIndex);
  const treeSize = Number(proofData.treeSize);
  detail.leafIndexValid = Number.isInteger(leafIndex) && Number.isInteger(treeSize) && leafIndex >= 0 && leafIndex < treeSize;

  // 3. Merkle path reconstructs root.rootHash, and proof.merkleRoot agrees.
  // position-bound (the path must be the one for this leaf in this tree), and the tree is the one the signed
  // root covers (proof.treeSize === root.entryCount).
  const treeSizeMatchesRoot = Number(root.entryCount) === treeSize;
  const pathValid = treeSizeMatchesRoot && verifyInclusionPath(entry.entryHash, proofData.merklePath, root.rootHash, leafIndex, treeSize);
  const rootHashAgrees =
    proofData.merkleRoot === null || proofData.merkleRoot === undefined ? false : proofData.merkleRoot === root.rootHash;
  detail.merklePathValid = pathValid && rootHashAgrees;

  // 4. Entry + root Ed25519 signatures, against the transparency trust domain.
  const resolved = await transparencyKeys.getPublicKey(entry.signerKeyId).catch(() => null);
  if (resolved) {
    detail.keyValid = resolved.status === 'active' || resolved.status === 'deprecated';
    detail.keyStatus = resolved.status;
    if (detail.keyValid) {
      detail.entrySignatureValid = verifyEd25519(computeEntrySigningBuffer(entry), entry.signature, resolved.pubDer);
    }
  }

  const rootResolved = await transparencyKeys.getPublicKey(root.signerKeyId).catch(() => null);
  if (rootResolved && (rootResolved.status === 'active' || rootResolved.status === 'deprecated')) {
    detail.rootSignatureValid = verifyEd25519(computeRootSigningBuffer(root), root.signature, rootResolved.pubDer);
  }

  return detail;
}

/** Whether every check in a {@link TransparencyVerificationDetail} passed. */
export function transparencyDetailAllPassed(detail: TransparencyVerificationDetail): boolean {
  return (
    detail.entryHashValid &&
    detail.merklePathValid &&
    detail.leafIndexValid &&
    detail.keyValid &&
    detail.entrySignatureValid &&
    detail.rootSignatureValid
  );
}
