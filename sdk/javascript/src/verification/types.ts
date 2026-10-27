import type { KeyStatus } from '../types.js';
import type { MerklePathStep } from './merkle.js';

// ---------------------------------------------------------------------------
// Transparency wire types
//
// These are new, correctly-shaped types scoped to local verification only —
// deliberately NOT a replacement for the pre-existing (and stale)
// TransparencyEntry/TransparencyRoot/InclusionProof in ../types.ts, which are
// used by other TransparencyResource methods whose real wire shape wasn't in
// scope for this change. This is the actual shape served by
// GET /v1/transparency/proof/:transparencyId.
// ---------------------------------------------------------------------------

export interface TransparencyProofEntry {
  transparencyId: string;
  id: number;
  entryType: string;
  artifactId: string | null;
  evidenceChainId: string | null;
  verificationId: string | null;
  payloadHash: string;
  previousEntryHash: string | null;
  entryHash: string;
  signerKeyId: string;
  signature: string;
  createdAt: string;
}

export interface TransparencyProofRoot {
  rootId: string;
  seqFrom: number;
  seqTo: number;
  entryCount: number;
  rootHash: string;
  previousRootHash: string | null;
  signerKeyId: string;
  signature: string;
  generatedAt: string;
}

export interface TransparencyInclusionProof {
  proofVersion: string;
  proofType: string;
  generatedAt: string;
  entry: TransparencyProofEntry;
  root: TransparencyProofRoot;
  proof: {
    leafIndex: number;
    treeSize: number;
    merklePath: MerklePathStep[];
    merkleRoot: string | null;
  };
  verifiable: boolean;
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

export type VerificationStatus = 'valid' | 'invalid' | 'error';

export type TransparencyVerifiedState = 'verified' | 'failed' | 'unavailable';

export type FailedStage =
  | 'STRUCTURE'
  | 'CANONICALIZATION'
  | 'KEY_RESOLUTION'
  | 'FUTURE_TIMESTAMP'
  | 'EXPIRED'
  | 'INVALID_SIGNATURE'
  | 'TRANSPARENCY'
  | null;

export interface TransparencyVerificationDetail {
  entryHashValid: boolean;
  merklePathValid: boolean;
  entrySignatureValid: boolean;
  rootSignatureValid: boolean;
  leafIndexValid: boolean;
  keyValid: boolean;
  keyStatus: KeyStatus | null;
}

/**
 * Structured result of a fully local, offline artifact verification.
 *
 * `payloadHashValid` / `canonicalizationValid` deliberately do NOT represent
 * an independent stored-hash comparison — the real QODIQA artifact envelope
 * has no separately-stored payload hash field; the recomputed hash only ever
 * serves as the Ed25519 verification message. These two fields instead mean
 * "canonicalization and envelope-hash computation completed without a
 * structural/protocol error" (no forbidden keys, no non-finite numbers, no
 * undefined, a plain-object payload, etc). `signatureValid` is the field that
 * actually detects tampering, since any change to the canonical payload
 * changes the Ed25519 message and the signature stops verifying.
 */
export interface ArtifactVerificationResult {
  verificationStatus: VerificationStatus;
  signatureValid: boolean;
  payloadHashValid: boolean;
  canonicalizationValid: boolean;
  keyValid: boolean;
  keyId: string | null;
  keyStatus: KeyStatus | null;
  /**
   * Which discovery tier resolved `keyId` — `'live'` (the ordinary case) or
   * `'archived'` when the key was only resolvable via the archived-key
   * fallback, i.e. it had already been purged from the live
   * keystore. `null` when no key was resolved at all. Purely diagnostic —
   * never affects `keyValid`.
   */
  keySource: 'live' | 'archived' | null;
  expiryValid: boolean;
  timestampValid: boolean;
  transparencyVerified: TransparencyVerifiedState;
  transparencyDetail: TransparencyVerificationDetail | null;
  verificationErrors: string[];
  verificationWarnings: string[];
  failedStage: FailedStage;
  verifiedAt: number;
}
