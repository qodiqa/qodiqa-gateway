import { ArtifactVerifier, verifyArtifact } from '../../src/verification/artifactVerifier.js';
import { StaticKeyProvider, createKeyProvider } from '../../src/verification/keyProviders.js';
import { ValidationError } from '../../src/errors.js';
import vectors from '../../../../test-vectors/artifact-v1.json';

const validVector = vectors.artifactVectors.find((v) => v.id === 'valid-artifact')!;

describe('ArtifactVerifier — constructor validation', () => {
  test('throws ValidationError when no keys provider is given', () => {
    // @ts-expect-error — intentionally omitting the required `keys` option
    expect(() => new ArtifactVerifier({})).toThrow(ValidationError);
  });

  test('throws ValidationError when requireTransparency is set with no transparencyKeys', () => {
    expect(
      () => new ArtifactVerifier({ keys: new StaticKeyProvider([]), requireTransparency: true }),
    ).toThrow(ValidationError);
  });
});

describe('ArtifactVerifier.verify — full result shape on a valid artifact', () => {
  test('reports every stage as passed', async () => {
    const verifier = new ArtifactVerifier({
      keys: new StaticKeyProvider(validVector.keySet as never),
      _now: validVector.verifyAt,
    });
    const result = await verifier.verify(validVector.artifact);
    expect(result).toMatchObject({
      verificationStatus: 'valid',
      signatureValid: true,
      payloadHashValid: true,
      canonicalizationValid: true,
      keyValid: true,
      keyId: 'test-vectors:key_v1',
      keyStatus: 'active',
      keySource: 'live',
      timestampValid: true,
      expiryValid: true,
      transparencyVerified: 'unavailable',
      failedStage: null,
    });
    expect(result.verificationErrors).toEqual([]);
  });
});

describe('ArtifactVerifier.verify — keySource', () => {
  test('defaults to "live" when the KeyProvider does not set source (e.g. StaticKeyProvider)', async () => {
    const verifier = new ArtifactVerifier({
      keys: new StaticKeyProvider(validVector.keySet as never),
      _now: validVector.verifyAt,
    });
    const result = await verifier.verify(validVector.artifact);
    expect(result.keySource).toBe('live');
  });

  test('reports "archived" when the KeyProvider resolves the key with source: "archived"', async () => {
    const entry = (validVector.keySet as { keyId: string; publicKey: string; status: string }[])[0]!;
    const provider = createKeyProvider(async (keyId) =>
      keyId === entry.keyId
        ? { pubDer: Buffer.from(entry.publicKey, 'base64'), status: 'deprecated', source: 'archived' }
        : null,
    );
    const verifier = new ArtifactVerifier({ keys: provider, _now: validVector.verifyAt });
    const result = await verifier.verify(validVector.artifact);
    expect(result.keySource).toBe('archived');
    // Purely diagnostic — the archived source never affects the validity outcome.
    expect(result.keyValid).toBe(true);
    expect(result.verificationStatus).toBe('valid');
  });

  test('keySource is null when no key was resolved at all', async () => {
    const verifier = new ArtifactVerifier({ keys: new StaticKeyProvider([]), _now: validVector.verifyAt });
    const result = await verifier.verify(validVector.artifact);
    expect(result.keySource).toBeNull();
    expect(result.failedStage).toBe('KEY_RESOLUTION');
  });
});

describe('verifyArtifact — one-shot convenience function', () => {
  test('matches ArtifactVerifier.verify for the same input', async () => {
    const result = await verifyArtifact(validVector.artifact, {
      keys: new StaticKeyProvider(validVector.keySet as never),
      _now: validVector.verifyAt,
    });
    expect(result.verificationStatus).toBe('valid');
  });
});

describe('ArtifactVerifier.verify — never throws for content problems', () => {
  const verifier = new ArtifactVerifier({ keys: new StaticKeyProvider(validVector.keySet as never) });

  test.each([
    null,
    undefined,
    'a string',
    42,
    [],
    {},
    { expiry: 1, payload: {}, publicKeyId: 'k', signature: 'x', timestamp: 1, extra: 'field' },
    { payload: { a: 1 } },
  ])('does not throw for garbage input: %p', async (garbage) => {
    await expect(verifier.verify(garbage)).resolves.toBeDefined();
  });

  test('a key provider that throws surfaces as verificationStatus="error", not a rejection', async () => {
    const throwingProvider = { getPublicKey: async () => { throw new Error('network down'); } };
    const v = new ArtifactVerifier({ keys: throwingProvider });
    const result = await v.verify(validVector.artifact);
    expect(result.verificationStatus).toBe('error');
    expect(result.failedStage).toBe('KEY_RESOLUTION');
    expect(result.verificationErrors.some((e) => e.includes('network down'))).toBe(true);
  });
});

describe('ArtifactVerifier — transparency proof wiring', () => {
  test('a supplied but unverifiable transparency proof fails the overall result', async () => {
    const badProof = vectors.transparencyVectors.find((v) => v.id === 'wrong-merkle-root')!;
    const verifier = new ArtifactVerifier({
      keys: new StaticKeyProvider(validVector.keySet as never),
      transparencyKeys: new StaticKeyProvider(badProof.transparencyKeySet as never),
      _now: validVector.verifyAt,
    });
    const result = await verifier.verify(validVector.artifact, { transparencyProof: badProof.proof as never });
    expect(result.transparencyVerified).toBe('failed');
    expect(result.verificationStatus).toBe('invalid');
    expect(result.failedStage).toBe('TRANSPARENCY');
  });

  test('requireTransparency=true fails when no proof is supplied', async () => {
    const verifier = new ArtifactVerifier({
      keys: new StaticKeyProvider(validVector.keySet as never),
      transparencyKeys: new StaticKeyProvider([]),
      requireTransparency: true,
      _now: validVector.verifyAt,
    });
    const result = await verifier.verify(validVector.artifact);
    expect(result.transparencyVerified).toBe('unavailable');
    expect(result.verificationStatus).toBe('invalid');
    expect(result.failedStage).toBe('TRANSPARENCY');
  });

  test('a proof supplied without a configured transparencyKeys provider is reported unavailable with a warning, not silently trusted', async () => {
    const goodProof = vectors.transparencyVectors.find((v) => v.id === 'valid-merkle-proof')!;
    const verifier = new ArtifactVerifier({ keys: new StaticKeyProvider(validVector.keySet as never), _now: validVector.verifyAt });
    const result = await verifier.verify(validVector.artifact, { transparencyProof: goodProof.proof as never });
    expect(result.transparencyVerified).toBe('unavailable');
    expect(result.verificationWarnings.length).toBeGreaterThan(0);
    // Absence of a transparency-key provider must never itself invalidate an
    // otherwise-valid artifact.
    expect(result.verificationStatus).toBe('valid');
  });
});

describe('ArtifactVerifier.verify — numeric strictness of timestamp / expiry', () => {
  const verifier = () => new ArtifactVerifier({ keys: new StaticKeyProvider(validVector.keySet as never), _now: validVector.verifyAt });
  const withTimes = (timestamp: number, expiry: number) => ({ ...validVector.artifact, timestamp, expiry });

  test.each([
    ['fractional timestamp', validVector.artifact.timestamp + 0.5, validVector.artifact.expiry],
    ['expiry above 2^53-1', validVector.artifact.timestamp, 2 ** 53 + 2],
    ['timestamp equal to expiry', validVector.artifact.timestamp, validVector.artifact.timestamp],
    ['timestamp after expiry', validVector.artifact.expiry + 1, validVector.artifact.expiry],
  ])('rejects %s at the STRUCTURE stage', async (_name, timestamp, expiry) => {
    const result = await verifier().verify(withTimes(timestamp, expiry) as never);
    expect(result.failedStage).toBe('STRUCTURE');
    expect(result.verificationStatus).not.toBe('valid');
  });
});
