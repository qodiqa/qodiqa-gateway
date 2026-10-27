/**
 * QODIQA Local Artifact & Transparency-Proof Verification —
 * JavaScript SDK Conformance Test
 *
 * Loads the shared, language-neutral vector file
 * (test-vectors/artifact-v1.json) and verifies every vector with the real,
 * unmodified JS SDK verifier. Every signature, hash, and Merkle proof in the
 * vector file was produced by the production server signing/hashing code
 * (see test-vectors/generate-artifact-vectors.js) — nothing is regenerated
 * here.
 *
 * `sdk/python`'s loads this exact same
 * file and must produce identical outcomes per vector — that is the
 * cross-language consistency requirement for.
 */

import fs from 'node:fs';
import path from 'node:path';
import { ArtifactVerifier, verifyTransparencyProof, transparencyDetailAllPassed, StaticKeyProvider } from '../src/index.js';
import type { TransparencyInclusionProof } from '../src/index.js';

const VECTORS_PATH = path.resolve(__dirname, '../../../test-vectors/artifact-v1.json');
const vectorFile = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));

describe('artifact/transparency conformance — shared vector file', () => {
  it('loads and is non-empty', () => {
    expect(Array.isArray(vectorFile.artifactVectors)).toBe(true);
    expect(Array.isArray(vectorFile.transparencyVectors)).toBe(true);
    expect(vectorFile.artifactVectors.length).toBeGreaterThan(0);
    expect(vectorFile.transparencyVectors.length).toBeGreaterThan(0);
  });

  it('vectorCount metadata matches the actual arrays', () => {
    expect(vectorFile.vectorCount.artifact).toBe(vectorFile.artifactVectors.length);
    expect(vectorFile.vectorCount.transparency).toBe(vectorFile.transparencyVectors.length);
  });
});

describe('artifact conformance vectors', () => {
  for (const v of vectorFile.artifactVectors) {
    test(`${v.id}: ${v.description}`, async () => {
      const verifier = new ArtifactVerifier({
        keys: new StaticKeyProvider(v.keySet),
        _now: v.verifyAt,
        clockToleranceMs: v.clockToleranceMs,
      });
      const result = await verifier.verify(v.artifact);
      for (const [key, expected] of Object.entries(v.expected)) {
        expect((result as unknown as Record<string, unknown>)[key]).toBe(expected);
      }
    });
  }
});

describe('transparency-proof conformance vectors', () => {
  for (const v of vectorFile.transparencyVectors) {
    test(`${v.id}: ${v.description}`, async () => {
      if (v.proof === null) {
        // The "no proof supplied" case is verified through the full
        // ArtifactVerifier pipeline instead, using an arbitrary valid vector.
        const artifactVector = vectorFile.artifactVectors[0];
        const verifier = new ArtifactVerifier({
          keys: new StaticKeyProvider(artifactVector.keySet),
          transparencyKeys: new StaticKeyProvider(v.transparencyKeySet),
          _now: artifactVector.verifyAt,
        });
        const result = await verifier.verify(artifactVector.artifact);
        expect(result.transparencyVerified).toBe(v.expected.transparencyVerified);
        return;
      }

      const detail = await verifyTransparencyProof(
        v.proof as TransparencyInclusionProof,
        new StaticKeyProvider(v.transparencyKeySet),
      );
      const verified = transparencyDetailAllPassed(detail) ? 'verified' : 'failed';
      for (const [key, expected] of Object.entries(v.expected)) {
        const actual = key === 'transparencyVerified' ? verified : (detail as unknown as Record<string, unknown>)[key];
        expect(actual).toBe(expected);
      }
    });
  }
});
