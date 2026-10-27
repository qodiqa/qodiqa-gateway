'use strict';

/**
 * Cryptographic Regression Tests
 *
 * Fixed-vector tests that pin the output of every cryptographic primitive.
 * Any change to hashing, canonicalization, or signing that alters the output
 * for the same input will cause these tests to fail — intentional: this suite
 * guards against accidental algorithm changes or dependency upgrades that silently
 * alter crypto output.
 *
 * All expected values were computed from the real implementation at the time
 * the regression suite was written and must NOT be changed without a deliberate,
 * documented decision to alter the crypto implementation.
 */

const crypto = require('crypto');

const {
  sha256Hex,
  sha256Raw,
  sortedJSON,
  domainSeparatedHash,
  computeHash,
  generateNonce,
  generateArtifactId,
  timingSafeCompare,
  ARTIFACT_DOMAINS,
} = require('../src/infra/crypto/hashing');

const {
  envelopeHash,
  canonicalizeEnvelope,
  ENVELOPE_DOMAIN,
  SIGNED_ENVELOPE_KEYS,
} = require('../src/validation/canonicalize');

const { sign, verify } = require('../src/infra/crypto/ed25519');

// ── SHA-256 fixed vectors ─────────────────────────────────────────────────────

describe('SHA-256 fixed vectors', () => {
  test('sha256Hex("") equals RFC 4634 test vector', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  test('sha256Hex("abc") equals RFC 4634 test vector', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  test('sha256Hex("hello world") is deterministic across calls', () => {
    const expected = sha256Hex('hello world');
    expect(sha256Hex('hello world')).toBe(expected);
    expect(sha256Hex('hello world')).toBe(expected);
    // Pinned value
    expect(expected).toBe('b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9');
  });

  test('sha256Raw returns 32-byte Buffer', () => {
    const raw = sha256Raw('test');
    expect(Buffer.isBuffer(raw)).toBe(true);
    expect(raw.length).toBe(32);
  });

  test('sha256Raw hex matches sha256Hex', () => {
    const input = 'canonical test string';
    expect(sha256Raw(input).toString('hex')).toBe(sha256Hex(input));
  });

  test('sha256Hex matches Node.js crypto independently', () => {
    const input = 'qodiqa enforcement platform';
    const expected = crypto.createHash('sha256').update(input).digest('hex');
    expect(sha256Hex(input)).toBe(expected);
  });
});

// ── sortedJSON determinism ────────────────────────────────────────────────────

describe('sortedJSON determinism', () => {
  test('same object regardless of insertion order', () => {
    const a = sortedJSON({ z: 1, a: 2 });
    const b = sortedJSON({ a: 2, z: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"z":1}');
  });

  test('nested object keys are sorted', () => {
    const result = sortedJSON({ outer: { z: 9, a: 1 }, b: true });
    expect(result).toBe('{"b":true,"outer":{"a":1,"z":9}}');
  });

  test('produces the same JSON as a hand-sorted object', () => {
    const input    = { provider: 'openai', requestHash: 'abc', policyHash: 'def' };
    const expected = JSON.stringify({ policyHash: 'def', provider: 'openai', requestHash: 'abc' });
    expect(sortedJSON(input)).toBe(expected);
  });

  test('null values serialize correctly', () => {
    expect(sortedJSON({ a: null, b: 1 })).toBe('{"a":null,"b":1}');
  });
});

// ── Domain-separated hashing ──────────────────────────────────────────────────

describe('domainSeparatedHash', () => {
  test('returns 32-byte Buffer', () => {
    const h = domainSeparatedHash('CANONICAL', 'input');
    expect(Buffer.isBuffer(h)).toBe(true);
    expect(h.length).toBe(32);
  });

  test('different domains produce different hashes for same input', () => {
    const h1 = domainSeparatedHash(ARTIFACT_DOMAINS.CANONICAL, 'payload');
    const h2 = domainSeparatedHash(ARTIFACT_DOMAINS.ARTIFACT,  'payload');
    const h3 = domainSeparatedHash(ARTIFACT_DOMAINS.REQUEST,   'payload');
    expect(h1.equals(h2)).toBe(false);
    expect(h1.equals(h3)).toBe(false);
    expect(h2.equals(h3)).toBe(false);
  });

  test('same domain + same input always produces same hash', () => {
    const a = domainSeparatedHash('POLICY', 'fixed-input');
    const b = domainSeparatedHash('POLICY', 'fixed-input');
    expect(a.toString('hex')).toBe(b.toString('hex'));
  });

  test('different inputs with same domain produce different hashes', () => {
    const h1 = domainSeparatedHash('CANONICAL', 'input-A');
    const h2 = domainSeparatedHash('CANONICAL', 'input-B');
    expect(h1.equals(h2)).toBe(false);
  });
});

// ── ARTIFACT_DOMAINS constant ─────────────────────────────────────────────────

describe('ARTIFACT_DOMAINS', () => {
  const EXPECTED_KEYS = ['CANONICAL', 'ARTIFACT', 'REQUEST', 'POLICY', 'CERTIFICATE', 'EVIDENCE', 'AUDIT'];

  test('contains all required domain identifiers', () => {
    for (const key of EXPECTED_KEYS) {
      expect(ARTIFACT_DOMAINS).toHaveProperty(key);
      expect(typeof ARTIFACT_DOMAINS[key]).toBe('string');
    }
  });

  test('all domain values are unique strings', () => {
    const values = Object.values(ARTIFACT_DOMAINS);
    const unique  = new Set(values);
    expect(unique.size).toBe(values.length);
  });

  test('is frozen (immutable)', () => {
    expect(Object.isFrozen(ARTIFACT_DOMAINS)).toBe(true);
  });
});

// ── computeHash fixed vector ──────────────────────────────────────────────────

describe('computeHash fixed vector', () => {
  const FIXED_INPUT = {
    prompt:    'hi',
    consent:   'yes',
    purpose:   'test',
    timestamp: 1700000000,
    decision:  'ALLOW',
    ai_output: 'hello',
  };

  const PINNED_HASH = 'a9ff55f0ac9f66da432bb8960476cad30d2cfbd0dd32847d4d1a2bcf658ce11d';

  test('produces pinned hash for fixed inputs', () => {
    expect(computeHash(FIXED_INPUT)).toBe(PINNED_HASH);
  });

  test('is deterministic across multiple calls', () => {
    expect(computeHash(FIXED_INPUT)).toBe(computeHash(FIXED_INPUT));
  });

  test('different inputs produce different hashes', () => {
    const h1 = computeHash({ ...FIXED_INPUT, prompt: 'hello' });
    const h2 = computeHash({ ...FIXED_INPUT, prompt: 'world' });
    expect(h1).not.toBe(h2);
  });
});

// ── generateArtifactId ───────────────────────────────────────────────────────

describe('generateArtifactId', () => {
  test('returns a 32-character hex string', () => {
    const id = generateArtifactId('abc123hash', 1700000000);
    expect(typeof id).toBe('string');
    expect(id).toMatch(/^[a-f0-9]{32}$/);
  });

  test('is deterministic for same inputs', () => {
    const a = generateArtifactId('test-hash', 1700000000);
    const b = generateArtifactId('test-hash', 1700000000);
    expect(a).toBe(b);
  });

  test('different hash inputs produce different ids', () => {
    const a = generateArtifactId('hash-A', 1700000000);
    const b = generateArtifactId('hash-B', 1700000000);
    expect(a).not.toBe(b);
  });
});

// ── generateNonce ────────────────────────────────────────────────────────────

describe('generateNonce', () => {
  test('returns a 32-character hex string (16 bytes)', () => {
    const nonce = generateNonce();
    expect(typeof nonce).toBe('string');
    expect(nonce).toMatch(/^[a-f0-9]{32}$/);
  });

  test('each call returns a unique value', () => {
    const nonces = new Set(Array.from({ length: 50 }, () => generateNonce()));
    expect(nonces.size).toBe(50);
  });
});

// ── timingSafeCompare ────────────────────────────────────────────────────────

describe('timingSafeCompare', () => {
  test('returns true for identical buffers', () => {
    const buf = Buffer.from('deadbeef', 'hex');
    expect(timingSafeCompare(buf, Buffer.from('deadbeef', 'hex'))).toBe(true);
  });

  test('returns false for different buffers of same length', () => {
    const a = Buffer.from('deadbeef', 'hex');
    const b = Buffer.from('cafebabe', 'hex');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('returns false when lengths differ', () => {
    const a = Buffer.from('aabbcc', 'hex');
    const b = Buffer.from('aabb', 'hex');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('returns true for empty buffers', () => {
    expect(timingSafeCompare(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });
});

// ── envelopeHash fixed vector ────────────────────────────────────────────────

describe('envelopeHash fixed vector', () => {
  const FIXED_ENVELOPE = {
    payload:     { provider: 'openai' },
    timestamp:   1700000000,
    expiry:      1700300000,
    publicKeyId: 'test:key_v1',
  };

  const PINNED_HASH = 'c80ac6983385eccb5ed06cac4337029f92c1770f73ccaf721b9f8d9537d08def';

  test('produces pinned hash for fixed envelope', () => {
    const h = envelopeHash(FIXED_ENVELOPE);
    expect(h.toString('hex')).toBe(PINNED_HASH);
  });

  test('returns a 32-byte Buffer', () => {
    const h = envelopeHash(FIXED_ENVELOPE);
    expect(Buffer.isBuffer(h)).toBe(true);
    expect(h.length).toBe(32);
  });

  test('is deterministic: same envelope → same hash', () => {
    const h1 = envelopeHash(FIXED_ENVELOPE);
    const h2 = envelopeHash({ ...FIXED_ENVELOPE });
    expect(h1.toString('hex')).toBe(h2.toString('hex'));
  });

  test('different publicKeyId → different hash', () => {
    const h1 = envelopeHash(FIXED_ENVELOPE);
    const h2 = envelopeHash({ ...FIXED_ENVELOPE, publicKeyId: 'other:key_v1' });
    expect(h1.toString('hex')).not.toBe(h2.toString('hex'));
  });

  test('different timestamp → different hash', () => {
    const h1 = envelopeHash(FIXED_ENVELOPE);
    const h2 = envelopeHash({ ...FIXED_ENVELOPE, timestamp: 1700000001 });
    expect(h1.toString('hex')).not.toBe(h2.toString('hex'));
  });

  test('different payload → different hash', () => {
    const h1 = envelopeHash(FIXED_ENVELOPE);
    const h2 = envelopeHash({ ...FIXED_ENVELOPE, payload: { provider: 'anthropic' } });
    expect(h1.toString('hex')).not.toBe(h2.toString('hex'));
  });
});

// ── Ed25519 sign/verify roundtrip ────────────────────────────────────────────

describe('Ed25519 sign/verify roundtrip', () => {
  // Generate a fresh key pair for each test run
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const privDer = privateKey.export({ type: 'pkcs8',   format: 'der' });
  const pubDer  = publicKey.export({ type: 'spki', format: 'der' });

  const FIXED_HASH = sha256Raw('deterministic-test-message');

  test('sign returns a base64 string that decodes to 64 bytes', () => {
    const sig = sign(FIXED_HASH, privDer);
    expect(typeof sig).toBe('string');
    const decoded = Buffer.from(sig, 'base64');
    expect(decoded.length).toBe(64);
  });

  test('verify returns true for a valid signature', () => {
    const sig = sign(FIXED_HASH, privDer);
    expect(verify(FIXED_HASH, sig, pubDer)).toBe(true);
  });

  test('verify returns false when signature is corrupted', () => {
    const sig    = sign(FIXED_HASH, privDer);
    const sigBuf = Buffer.from(sig, 'base64');
    sigBuf[0]   ^= 0xff; // flip all bits in first byte
    const corrupted = sigBuf.toString('base64');
    expect(verify(FIXED_HASH, corrupted, pubDer)).toBe(false);
  });

  test('verify returns false for wrong message', () => {
    const sig      = sign(FIXED_HASH, privDer);
    const wrongMsg = sha256Raw('different-message');
    expect(verify(wrongMsg, sig, pubDer)).toBe(false);
  });

  test('verify returns false for wrong public key', () => {
    const { publicKey: wrongPub } = crypto.generateKeyPairSync('ed25519');
    const wrongPubDer = wrongPub.export({ type: 'spki', format: 'der' });
    const sig = sign(FIXED_HASH, privDer);
    expect(verify(FIXED_HASH, sig, wrongPubDer)).toBe(false);
  });

  test('signing same message twice produces valid signatures both times', () => {
    const sig1 = sign(FIXED_HASH, privDer);
    const sig2 = sign(FIXED_HASH, privDer);
    expect(verify(FIXED_HASH, sig1, pubDer)).toBe(true);
    expect(verify(FIXED_HASH, sig2, pubDer)).toBe(true);
  });

  test('verify returns false for invalid base64 signature string', () => {
    expect(verify(FIXED_HASH, 'not-valid-base64!!!', pubDer)).toBe(false);
  });

  test('verify returns false for empty signature', () => {
    expect(verify(FIXED_HASH, '', pubDer)).toBe(false);
  });
});

// ── canonicalizeEnvelope key set ─────────────────────────────────────────────

describe('canonicalizeEnvelope', () => {
  const ENVELOPE = {
    payload:     { provider: 'openai', requestHash: 'abc' },
    timestamp:   1700000000,
    expiry:      1700300000,
    publicKeyId: 'tenant:key_v1',
  };

  test('only includes SIGNED_ENVELOPE_KEYS fields', () => {
    const canonical = canonicalizeEnvelope(ENVELOPE);
    const parsed    = JSON.parse(canonical);
    const keys      = Object.keys(parsed);
    for (const k of keys) {
      expect(SIGNED_ENVELOPE_KEYS).toContain(k);
    }
  });

  test('extra fields are excluded from canonical form', () => {
    const withExtra = { ...ENVELOPE, extraField: 'should-be-ignored' };
    const canonical = canonicalizeEnvelope(withExtra);
    expect(canonical).not.toContain('extraField');
    expect(canonical).not.toContain('should-be-ignored');
  });

  test('output is valid JSON', () => {
    const canonical = canonicalizeEnvelope(ENVELOPE);
    expect(() => JSON.parse(canonical)).not.toThrow();
  });

  test('same envelope always produces same canonical form', () => {
    expect(canonicalizeEnvelope(ENVELOPE)).toBe(canonicalizeEnvelope({ ...ENVELOPE }));
  });

  test('ENVELOPE_DOMAIN is a non-empty string', () => {
    expect(typeof ENVELOPE_DOMAIN).toBe('string');
    expect(ENVELOPE_DOMAIN.length).toBeGreaterThan(0);
  });
});
