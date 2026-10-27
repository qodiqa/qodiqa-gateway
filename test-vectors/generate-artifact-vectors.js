#!/usr/bin/env node
'use strict';

/**
 * QODIQA Artifact & Transparency-Proof — Canonical Test Vector Generator
 *
 * Generates test-vectors/artifact-v1.json from the PRODUCTION server
 * signing/hashing implementation: `src/validation/signArtifact.js`,
 * `src/utils/stableStringify.js`, `src/infra/crypto/ed25519.js`,
 * `src/core/transparency/merkle.js`, and `src/core/transparency/log.js`.
 * Every signature and hash in the output file is computed by calling the
 * real production code — nothing here hand-writes a signature or a Merkle
 * root. Tampered ("negative") vectors are derived by deterministically
 * mutating a genuine vector *after* it was produced by the real signer,
 * never by fabricating one from scratch.
 *
 * Both `sdk/javascript` and `sdk/python`'s conformance test suites load this
 * exact file and must produce identical `verify()` outcomes per vector —
 * this is the cross-language consistency requirement.
 *
 * Uses a fixed, hardcoded, test-only Ed25519 keypair (not the file-backed
 * key stores in services/artifact/keyStore.js or
 * src/core/transparency/transparencyKeyStore.js) so that re-running this
 * generator with no protocol changes produces byte-identical output (module
 * the `generatedAt` timestamp) — random per-run key generation would defeat
 * that reproducibility property. These keys are test fixtures only and are
 * never used by any running QODIQA server.
 *
 * One scenario from the original plan — "non-finite number injected into
 * the payload" — is deliberately NOT represented as a shared JSON vector:
 * `JSON.stringify(Infinity)` serializes to `null`, so the actual non-finite
 * value cannot survive a round trip through this vector file at all. That
 * case is covered instead as a same-language unit test directly against
 * each SDK's canonical-JSON module (see `canonical-json.test.ts` /
 * `test_verification_canonical_json.py`), where the value never needs to
 * cross a JSON boundary.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const DEFAULT_OUTPUT_PATH = path.join(__dirname, 'artifact-v1.json');
const PROTOCOL_VERSION = 'v1';

const { signArtifact } = require(path.join(ROOT, 'src/validation/signArtifact.js'));
const ed25519 = require(path.join(ROOT, 'src/infra/crypto/ed25519.js'));
const merkle = require(path.join(ROOT, 'src/core/transparency/merkle.js'));
const log = require(path.join(ROOT, 'src/core/transparency/log.js'));

// ---------------------------------------------------------------------------
// Fixed test-only keypairs (see module doc above — never used in production)
// ---------------------------------------------------------------------------

const ARTIFACT_KEY_ID = 'test-vectors:key_v1';
const ARTIFACT_PRIV_DER = Buffer.from('MC4CAQAwBQYDK2VwBCIEIH6Q76IA3Tbf5dB+CqVCfj9nmiwCUIvyXitq3eHv+ryx', 'base64');
const ARTIFACT_PUB_DER = Buffer.from('MCowBQYDK2VwAyEArI9wKSGHg7Ig9ZtbOg+7d/QSddFvQ9xHSQxJ7ErydFs=', 'base64');

// A second, unrelated keypair — used only to build the "wrong public key"
// vector (a genuine artifact whose publicKeyId resolves, in the verifier's
// trust bundle, to a *different* key than the one that actually signed it).
const WRONG_PUB_DER = Buffer.from('MCowBQYDK2VwAyEAGj+ZQMJsr8wuTa8hNQLnxunF+LXkr2/2aZ9aNEAlOOw=', 'base64');

const TRANSPARENCY_KEY_ID = 'tr-test-vectors:key_v1';
const TRANSPARENCY_PRIV_DER = Buffer.from('MC4CAQAwBQYDK2VwBCIEIPWNry+pLxKOXC3vRgfI8qM3SfH9l0p2zmvMct4oBDs0', 'base64');
const TRANSPARENCY_PUB_DER = Buffer.from('MCowBQYDK2VwAyEAdSSemovV3S2/Vt1zspRyoHOijWSETC/Pg38gz7Yh0uk=', 'base64');

function keyEntry(keyId, pubDer, status) {
  return { keyId, algorithm: 'ed25519', publicKey: pubDer.toString('base64'), status };
}

// Fixed base timestamp so output is reproducible independent of wall-clock time.
const BASE_TS = Date.UTC(2026, 0, 1); // 2026-01-01T00:00:00.000Z

// ---------------------------------------------------------------------------
// Artifact vectors
// ---------------------------------------------------------------------------

function signValidArtifact() {
  const timestamp = BASE_TS;
  const expiry = BASE_TS + 3_600_000; // +1h
  const artifact = signArtifact(
    {
      payload: {
        requestId: 'req-conformance-001',
        requestHash: 'a'.repeat(64),
        policyHash: 'b'.repeat(64),
        tenantId: 'test-vectors',
      },
      publicKeyId: ARTIFACT_KEY_ID,
      timestamp,
      expiry,
    },
    ARTIFACT_PRIV_DER,
  );
  return { artifact, timestamp, expiry };
}

function flipLastBase64Char(b64) {
  const buf = Buffer.from(b64, 'base64');
  buf[buf.length - 1] ^= 0x01;
  return buf.toString('base64');
}

function buildArtifactVectors() {
  const { artifact: validArtifact, timestamp, expiry } = signValidArtifact();
  const verifyAtValid = timestamp + 1_000; // 1s after signing, well within validity
  const validKeySet = [keyEntry(ARTIFACT_KEY_ID, ARTIFACT_PUB_DER, 'active')];

  const vectors = [];

  vectors.push({
    id: 'valid-artifact',
    description: 'A genuine artifact signed by the production signer, verified with the correct trust bundle.',
    tags: ['positive'],
    artifact: validArtifact,
    keySet: validKeySet,
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'valid',
      signatureValid: true,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: true,
      expiryValid: true,
      failedStage: null,
    },
  });

  vectors.push({
    id: 'tampered-payload-field',
    description: 'Genuine artifact with one payload field mutated after signing; signature is now over the wrong bytes.',
    tags: ['negative', 'tamper'],
    artifact: { ...validArtifact, payload: { ...validArtifact.payload, tenantId: 'attacker-controlled' } },
    keySet: validKeySet,
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: true,
      expiryValid: true,
      failedStage: 'INVALID_SIGNATURE',
    },
  });

  vectors.push({
    id: 'tampered-signature-bytes',
    description: 'Genuine artifact whose signature has one bit flipped after signing.',
    tags: ['negative', 'tamper'],
    artifact: { ...validArtifact, signature: flipLastBase64Char(validArtifact.signature) },
    keySet: validKeySet,
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: true,
      expiryValid: true,
      failedStage: 'INVALID_SIGNATURE',
    },
  });

  vectors.push({
    id: 'wrong-public-key',
    description:
      'Genuine artifact, but the verifier\'s trust bundle maps publicKeyId to an unrelated public key — proves the SDK ' +
      'cryptographically verifies against the resolved key rather than trusting the publicKeyId label alone.',
    tags: ['negative', 'key'],
    artifact: validArtifact,
    keySet: [keyEntry(ARTIFACT_KEY_ID, WRONG_PUB_DER, 'active')],
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: true,
      expiryValid: true,
      failedStage: 'INVALID_SIGNATURE',
    },
  });

  vectors.push({
    id: 'unknown-key-id',
    description: 'Genuine artifact, but its publicKeyId is absent from the verifier\'s trust bundle entirely.',
    tags: ['negative', 'key'],
    artifact: validArtifact,
    keySet: [],
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: false,
      keyStatus: null,
      timestampValid: false,
      expiryValid: false,
      failedStage: 'KEY_RESOLUTION',
    },
  });

  vectors.push({
    id: 'revoked-key-id',
    description: 'Genuine artifact, but the resolved key\'s status is "revoked" in the verifier\'s trust bundle.',
    tags: ['negative', 'key'],
    artifact: validArtifact,
    keySet: [keyEntry(ARTIFACT_KEY_ID, ARTIFACT_PUB_DER, 'revoked')],
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: false,
      keyStatus: 'revoked',
      timestampValid: false,
      expiryValid: false,
      failedStage: 'KEY_RESOLUTION',
    },
  });

  // A short-lived artifact, verified after its own expiry.
  const { artifact: shortLivedArtifact, expiry: shortExpiry } = (() => {
    const ts = BASE_TS;
    const exp = BASE_TS + 1_000; // expires 1s after signing
    const art = signArtifact(
      {
        payload: { requestId: 'req-conformance-002', requestHash: 'c'.repeat(64), policyHash: 'd'.repeat(64), tenantId: 'test-vectors' },
        publicKeyId: ARTIFACT_KEY_ID,
        timestamp: ts,
        expiry: exp,
      },
      ARTIFACT_PRIV_DER,
    );
    return { artifact: art, expiry: exp };
  })();

  vectors.push({
    id: 'expired-artifact',
    description: 'Genuine artifact verified 4 seconds after its own expiry.',
    tags: ['negative', 'time'],
    artifact: shortLivedArtifact,
    keySet: validKeySet,
    verifyAt: shortExpiry + 4_000,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      // Verification is fail-closed and stops at the first failing stage —
      // EXPIRED is detected during the timestamp-check stage, which runs
      // BEFORE Ed25519 signature verification, so signatureValid is never
      // set to true even though this artifact's signature is genuine.
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: true,
      expiryValid: false,
      failedStage: 'EXPIRED',
    },
  });

  vectors.push({
    id: 'future-timestamped-artifact',
    description: 'Genuine artifact whose signing timestamp is, from the verifier\'s point of view, in the future.',
    tags: ['negative', 'time'],
    artifact: validArtifact,
    keySet: validKeySet,
    verifyAt: timestamp - 60_000, // verifying "before" the artifact was signed
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyStatus: 'active',
      timestampValid: false,
      expiryValid: false,
      failedStage: 'FUTURE_TIMESTAMP',
    },
  });

  const { expiry: _unused, ...missingExpiryArtifact } = validArtifact;
  vectors.push({
    id: 'malformed-missing-field',
    description: 'A structurally invalid artifact — the required "expiry" field has been removed entirely.',
    tags: ['negative', 'structure'],
    artifact: missingExpiryArtifact,
    keySet: validKeySet,
    verifyAt: verifyAtValid,
    clockToleranceMs: 0,
    transparencyProof: null,
    expected: {
      verificationStatus: 'invalid',
      signatureValid: false,
      payloadHashValid: false,
      canonicalizationValid: false,
      keyValid: false,
      keyStatus: null,
      timestampValid: false,
      expiryValid: false,
      failedStage: 'STRUCTURE',
    },
  });

  return vectors;
}

// ---------------------------------------------------------------------------
// Transparency proof vectors
// ---------------------------------------------------------------------------

function signEntry(record) {
  const entryHash = log.computeEntryHash(record);
  const signature = ed25519.sign(log.computeEntrySigningBuffer(record), TRANSPARENCY_PRIV_DER);
  return { ...record, entryHash, signature };
}

function signRoot(record) {
  const signature = ed25519.sign(log.computeRootSigningBuffer(record), TRANSPARENCY_PRIV_DER);
  return { ...record, signature };
}

function buildTransparencyFixture() {
  // A small 5-leaf tree; the artifact-bearing entry sits at index 2 so the
  // Merkle path is non-trivial (more than a single sibling hop) in both
  // directions.
  const baseRecord = (i) => ({
    transparencyId: `tv-entry-${i}`,
    entryType: 'ARTIFACT',
    artifactId: i === 2 ? 'tv-artifact-conformance' : null,
    evidenceChainId: null,
    verificationId: null,
    payloadHash: log.computePayloadHash({ note: `entry ${i}` }),
    previousEntryHash: null,
    signerKeyId: TRANSPARENCY_KEY_ID,
  });

  const entries = [0, 1, 2, 3, 4].map((i) => signEntry(baseRecord(i)));
  for (let i = 1; i < entries.length; i++) {
    entries[i] = signEntry({ ...baseRecord(i), previousEntryHash: entries[i - 1].entryHash });
  }

  const entryHashes = entries.map((e) => e.entryHash);
  const targetIndex = 2;
  const targetEntry = { ...entries[targetIndex], id: targetIndex + 1, createdAt: '2026-01-01T00:00:00.000Z' };

  const rootHash = log.computeRootHash(entryHashes);
  const rootRecordUnsigned = {
    rootId: 'tv-root-1',
    seqFrom: 1,
    seqTo: entries.length,
    entryCount: entries.length,
    rootHash,
    previousRootHash: null,
    signerKeyId: TRANSPARENCY_KEY_ID,
  };
  const signedRoot = signRoot(rootRecordUnsigned);
  const rootRecord = { ...signedRoot, generatedAt: '2026-01-01T00:05:00.000Z' };

  const proof = log.generateInclusionProof(targetEntry, entryHashes, rootRecord);

  return { proof, entryHashes, targetIndex };
}

function buildTransparencyVectors() {
  const { proof } = buildTransparencyFixture();
  const validTransparencyKeySet = [keyEntry(TRANSPARENCY_KEY_ID, TRANSPARENCY_PUB_DER, 'active')];

  const vectors = [];

  vectors.push({
    id: 'valid-merkle-proof',
    description: 'A genuine inclusion proof: real Merkle path plus real entry/root signatures.',
    tags: ['positive'],
    proof,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'verified',
      entryHashValid: true,
      merklePathValid: true,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  const wrongRoot = {
    ...proof,
    root: { ...proof.root, rootHash: 'f'.repeat(64) },
    proof: { ...proof.proof, merkleRoot: 'f'.repeat(64) },
  };
  vectors.push({
    id: 'wrong-merkle-root',
    description: 'proof.root.rootHash and proof.proof.merkleRoot both replaced with an unrelated (unsigned) hash.',
    tags: ['negative', 'merkle'],
    proof: wrongRoot,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: false,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: false,
    },
  });

  const truncatedPath = { ...proof, proof: { ...proof.proof, merklePath: proof.proof.merklePath.slice(1) } };
  vectors.push({
    id: 'truncated-merkle-path',
    description: 'One sibling hash removed from proof.proof.merklePath.',
    tags: ['negative', 'merkle'],
    proof: truncatedPath,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: false,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  const reorderedPath = {
    ...proof,
    proof: {
      ...proof.proof,
      merklePath:
        proof.proof.merklePath.length > 1
          ? [proof.proof.merklePath[1], proof.proof.merklePath[0], ...proof.proof.merklePath.slice(2)]
          : proof.proof.merklePath,
    },
  };
  vectors.push({
    id: 'reordered-merkle-path',
    description: 'The first two sibling-path elements swapped, breaking the leaf-to-root reconstruction.',
    tags: ['negative', 'merkle'],
    proof: reorderedPath,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: false,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  const wrongLeafIndex = { ...proof, proof: { ...proof.proof, leafIndex: proof.proof.treeSize } };
  vectors.push({
    id: 'wrong-leaf-index',
    description: 'proof.proof.leafIndex set equal to treeSize (out of the valid [0, treeSize) range).',
    tags: ['negative', 'merkle'],
    proof: wrongLeafIndex,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      // The Merkle path is position-bound — it is not the path of an out-of-range leaf.
      merklePathValid: false,
      leafIndexValid: false,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  // A genuine proof relabelled to ANOTHER in-range position. Previously every verifier accepted it (the
  // path's side flags alone drove the root computation); now the path must be exactly the RFC6962 path of the claimed
  // leaf, so the relabelled proof fails while the index itself is in range.
  const relabelledLeafIndex = { ...proof, proof: { ...proof.proof, leafIndex: (proof.proof.leafIndex + 1) % proof.proof.treeSize } };
  vectors.push({
    id: 'relabelled-leaf-index',
    description: 'proof.proof.leafIndex changed to another in-range position; the merklePath is the genuine path of the original leaf.',
    tags: ['negative', 'merkle', 'cry-16'],
    proof: relabelledLeafIndex,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: false,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  // A genuine proof whose treeSize no longer matches the signed root's entryCount.
  const wrongTreeSize = { ...proof, proof: { ...proof.proof, treeSize: proof.proof.treeSize + 1 } };
  vectors.push({
    id: 'tree-size-not-root-entry-count',
    description: 'proof.proof.treeSize changed so it no longer equals the signed root\'s entryCount (the leaf index stays in range).',
    tags: ['negative', 'merkle', 'cry-16'],
    proof: wrongTreeSize,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: false,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: true,
      rootSignatureValid: true,
    },
  });

  const unsupportedVersion = { ...proof, proofVersion: '99' };
  vectors.push({
    id: 'unsupported-proof-version',
    description: 'proof.proofVersion set to an unrecognized value; the SDK has no defined semantics for it.',
    tags: ['negative', 'metadata'],
    proof: unsupportedVersion,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: false,
      merklePathValid: false,
      leafIndexValid: false,
      keyValid: false,
      entrySignatureValid: false,
      rootSignatureValid: false,
    },
  });

  const truncatedEntrySig = {
    ...proof,
    entry: { ...proof.entry, signature: Buffer.from(Buffer.from(proof.entry.signature, 'base64').subarray(0, 32)).toString('base64') },
  };
  vectors.push({
    id: 'truncated-entry-signature',
    description: 'The entry\'s signature truncated to 32 bytes (half the required 64).',
    tags: ['negative', 'signature'],
    proof: truncatedEntrySig,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: true,
      leafIndexValid: true,
      keyValid: true,
      entrySignatureValid: false,
      rootSignatureValid: true,
    },
  });

  vectors.push({
    id: 'unknown-transparency-key',
    description: 'A genuine proof, but the verifier\'s transparency trust bundle does not contain the signing key at all.',
    tags: ['negative', 'key'],
    proof,
    transparencyKeySet: [],
    expected: {
      transparencyVerified: 'failed',
      entryHashValid: true,
      merklePathValid: true,
      leafIndexValid: true,
      keyValid: false,
      entrySignatureValid: false,
      rootSignatureValid: false,
    },
  });

  vectors.push({
    id: 'missing-transparency-proof',
    description:
      'No transparency proof supplied at all. With requireTransparency=false (the default), this must be reported ' +
      'as "unavailable" and must NOT affect the overall artifact verification outcome — never conflated with "failed".',
    tags: ['positive', 'unavailable'],
    proof: null,
    transparencyKeySet: validTransparencyKeySet,
    expected: {
      transparencyVerified: 'unavailable',
    },
  });

  return vectors;
}

// ---------------------------------------------------------------------------
// Public API — build the vector file in memory
// ---------------------------------------------------------------------------

function buildVectorFile() {
  const artifactVectors = buildArtifactVectors();
  const transparencyVectors = buildTransparencyVectors();

  return {
    $schema: './artifact-v1.schema.json',
    protocolVersion: PROTOCOL_VERSION,
    description:
      'Canonical, language-neutral conformance vectors for local (offline) QODIQA artifact and transparency-proof ' +
      'verification. Every signature, hash, and Merkle proof was generated by calling the production ' +
      'signing/hashing implementation directly — see "generatedBy" below and test-vectors/README-artifact.md for ' +
      'the full process and update procedure.',
    generatedBy: {
      generatorScript: 'test-vectors/generate-artifact-vectors.js',
      serverImplementation: [
        'src/validation/signArtifact.js',
        'src/utils/stableStringify.js',
        'src/infra/crypto/ed25519.js',
        'src/core/transparency/merkle.js',
        'src/core/transparency/log.js',
      ],
      generatedAt: new Date().toISOString(),
    },
    vectorCount: {
      artifact: artifactVectors.length,
      transparency: transparencyVectors.length,
    },
    artifactVectors,
    transparencyVectors,
  };
}

module.exports = { buildVectorFile, DEFAULT_OUTPUT_PATH };

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

if (require.main === module) {
  const args = process.argv.slice(2);
  let outputPath = DEFAULT_OUTPUT_PATH;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out' && args[i + 1]) {
      outputPath = path.resolve(args[++i]);
    }
  }

  const output = buildVectorFile();
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + '\n', 'utf8');

  console.log(
    `Wrote ${output.artifactVectors.length} artifact vectors and ${output.transparencyVectors.length} ` +
      `transparency vectors to ${outputPath}`,
  );
}
