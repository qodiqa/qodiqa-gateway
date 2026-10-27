import { verifyTransparencyProof, transparencyDetailAllPassed } from '../../src/verification/transparencyProof.js';
import { StaticKeyProvider } from '../../src/verification/keyProviders.js';
import type { TransparencyInclusionProof } from '../../src/verification/types.js';
import vectors from '../../../../test-vectors/artifact-v1.json';

describe('verifyTransparencyProof — generated conformance vectors', () => {
  for (const v of vectors.transparencyVectors) {
    if (v.proof === null) continue; // "unavailable" case is covered via the full ArtifactVerifier pipeline instead.

    test(v.id, async () => {
      const detail = await verifyTransparencyProof(
        v.proof as unknown as TransparencyInclusionProof,
        new StaticKeyProvider(v.transparencyKeySet as never),
      );
      const verified = transparencyDetailAllPassed(detail) ? 'verified' : 'failed';
      expect(verified).toBe(v.expected.transparencyVerified);
      for (const [key, expected] of Object.entries(v.expected)) {
        if (key === 'transparencyVerified') continue;
        expect((detail as unknown as Record<string, unknown>)[key]).toBe(expected);
      }
    });
  }
});

describe('verifyTransparencyProof — structural edge cases', () => {
  test('never throws on a completely malformed proof object', async () => {
    const keys = new StaticKeyProvider([]);
    await expect(verifyTransparencyProof({} as TransparencyInclusionProof, keys)).resolves.toBeDefined();
    await expect(verifyTransparencyProof(null as unknown as TransparencyInclusionProof, keys)).resolves.toBeDefined();
  });

  test('an unknown transparency signing key resolves to keyValid=false, not a thrown error', async () => {
    const valid = vectors.transparencyVectors.find((v) => v.id === 'valid-merkle-proof')!;
    const detail = await verifyTransparencyProof(valid.proof as unknown as TransparencyInclusionProof, new StaticKeyProvider([]));
    expect(detail.keyValid).toBe(false);
    expect(detail.entrySignatureValid).toBe(false);
  });
});
