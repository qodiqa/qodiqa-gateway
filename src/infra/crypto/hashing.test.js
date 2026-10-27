'use strict';

const crypto = require('crypto');
const {
  sha256Hex,
  sha256Raw,
  sortedJSON,
  domainSeparatedHash,
  generateNonce,
  timingSafeCompare,
  computeHash,
  ARTIFACT_DOMAINS,
  generateArtifactId,
} = require('./hashing');

// ── sha256Hex ──────────────────────────────────────────────────────────────────

describe('sha256Hex', () => {
  test('empty string matches known SHA-256 value', () => {
    const expected = crypto.createHash('sha256').update('').digest('hex');
    expect(sha256Hex('')).toBe(expected);
  });

  test('string "abc" matches Node crypto SHA-256 output', () => {
    const expected = crypto.createHash('sha256').update('abc').digest('hex');
    expect(sha256Hex('abc')).toBe(expected);
  });

  test('string "abc" produces 64-char hex deterministically', () => {
    // Matches Node.js crypto — run twice to confirm determinism
    const expected = crypto.createHash('sha256').update('abc').digest('hex');
    expect(sha256Hex('abc')).toBe(expected);
    expect(sha256Hex('abc')).toBe(expected);
  });

  test('Buffer input produces same result as string input', () => {
    const str = 'hello world';
    const buf = Buffer.from(str, 'utf8');
    expect(sha256Hex(buf)).toBe(sha256Hex(str));
  });

  test('returns lowercase hex string of length 64', () => {
    const result = sha256Hex('test input');
    expect(typeof result).toBe('string');
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test('different inputs produce different outputs', () => {
    expect(sha256Hex('aaa')).not.toBe(sha256Hex('bbb'));
  });
});

// ── sha256Raw ──────────────────────────────────────────────────────────────────

describe('sha256Raw', () => {
  test('returns Buffer of length 32', () => {
    const result = sha256Raw('some data');
    expect(Buffer.isBuffer(result)).toBe(true);
    expect(result.length).toBe(32);
  });

  test('raw bytes match hex output', () => {
    const data = 'consistency check';
    const raw = sha256Raw(data);
    const hex = sha256Hex(data);
    expect(raw.toString('hex')).toBe(hex);
  });

  test('empty string returns 32-byte Buffer', () => {
    expect(sha256Raw('')).toHaveLength(32);
  });
});

// ── sortedJSON ─────────────────────────────────────────────────────────────────

describe('sortedJSON', () => {
  test('same output for different key orderings', () => {
    const a = sortedJSON({ z: 1, a: 2 });
    const b = sortedJSON({ a: 2, z: 1 });
    expect(a).toBe(b);
  });

  test('nested objects are also sorted deterministically', () => {
    const a = sortedJSON({ b: { y: 10, x: 20 }, a: 1 });
    const b = sortedJSON({ a: 1, b: { x: 20, y: 10 } });
    expect(a).toBe(b);
  });

  test('returns a valid JSON string', () => {
    const result = sortedJSON({ key: 'value', num: 42 });
    expect(() => JSON.parse(result)).not.toThrow();
  });

  test('null values serialize correctly', () => {
    const result = sortedJSON({ a: null });
    expect(result).toContain('null');
  });
});

// ── domainSeparatedHash ────────────────────────────────────────────────────────

describe('domainSeparatedHash', () => {
  test('returns a Buffer of length 32', () => {
    const result = domainSeparatedHash('DOMAIN::TEST::V1', 'canonical string');
    expect(Buffer.isBuffer(result)).toBe(true);
    expect(result.length).toBe(32);
  });

  test('different domains produce different hashes for same canonical', () => {
    const canonical = 'same content';
    const h1 = domainSeparatedHash('DOMAIN::A::V1', canonical);
    const h2 = domainSeparatedHash('DOMAIN::B::V1', canonical);
    expect(h1.toString('hex')).not.toBe(h2.toString('hex'));
  });

  test('same domain and canonical always produces same hash (deterministic)', () => {
    const h1 = domainSeparatedHash('DOMAIN::X::V1', 'data');
    const h2 = domainSeparatedHash('DOMAIN::X::V1', 'data');
    expect(h1.toString('hex')).toBe(h2.toString('hex'));
  });

  test('throws TypeError for empty domain', () => {
    expect(() => domainSeparatedHash('', 'canonical')).toThrow(TypeError);
  });

  test('throws TypeError for non-string domain', () => {
    expect(() => domainSeparatedHash(123, 'canonical')).toThrow(TypeError);
  });

  test('throws TypeError for non-string, non-Buffer canonical', () => {
    expect(() => domainSeparatedHash('DOMAIN::X::V1', 123)).toThrow(TypeError);
  });
});

// ── generateNonce ──────────────────────────────────────────────────────────────

describe('generateNonce', () => {
  test('returns a 32-character hex string (16 bytes)', () => {
    const nonce = generateNonce();
    expect(typeof nonce).toBe('string');
    expect(nonce).toHaveLength(32);
    expect(nonce).toMatch(/^[0-9a-f]{32}$/);
  });

  test('is random each call', () => {
    const a = generateNonce();
    const b = generateNonce();
    expect(a).not.toBe(b);
  });
});

// ── timingSafeCompare ──────────────────────────────────────────────────────────

describe('timingSafeCompare', () => {
  test('returns true for equal buffers', () => {
    const a = Buffer.from('deadbeef', 'hex');
    const b = Buffer.from('deadbeef', 'hex');
    expect(timingSafeCompare(a, b)).toBe(true);
  });

  test('returns false for different buffers of same length', () => {
    const a = Buffer.from('deadbeef', 'hex');
    const b = Buffer.from('cafebabe', 'hex');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('returns false for buffers of different lengths', () => {
    const a = Buffer.from('aabb', 'hex');
    const b = Buffer.from('aabbcc', 'hex');
    expect(timingSafeCompare(a, b)).toBe(false);
  });

  test('returns true for two empty buffers', () => {
    expect(timingSafeCompare(Buffer.alloc(0), Buffer.alloc(0))).toBe(true);
  });
});

// ── ARTIFACT_DOMAINS ───────────────────────────────────────────────────────────

describe('ARTIFACT_DOMAINS', () => {
  const expectedKeys = ['CANONICAL', 'ARTIFACT', 'REQUEST', 'POLICY', 'CERTIFICATE', 'EVIDENCE', 'AUDIT'];

  test('has all expected domain keys', () => {
    for (const key of expectedKeys) {
      expect(ARTIFACT_DOMAINS).toHaveProperty(key);
    }
  });

  test('all values are non-empty strings', () => {
    for (const key of expectedKeys) {
      expect(typeof ARTIFACT_DOMAINS[key]).toBe('string');
      expect(ARTIFACT_DOMAINS[key].length).toBeGreaterThan(0);
    }
  });

  test('is frozen (immutable)', () => {
    expect(Object.isFrozen(ARTIFACT_DOMAINS)).toBe(true);
  });

  test('all domain strings are unique', () => {
    const values = Object.values(ARTIFACT_DOMAINS);
    const unique = new Set(values);
    expect(unique.size).toBe(values.length);
  });
});

// ── generateArtifactId ─────────────────────────────────────────────────────────

describe('generateArtifactId', () => {
  test('returns a 32-character hex string', () => {
    const hash = 'abc123';
    const ts = 1700000000000;
    const result = generateArtifactId(hash, ts);
    expect(typeof result).toBe('string');
    expect(result).toHaveLength(32);
    expect(result).toMatch(/^[0-9a-f]{32}$/);
  });

  test('is deterministic for same inputs', () => {
    const hash = 'cafebabe';
    const ts = 9999999999;
    expect(generateArtifactId(hash, ts)).toBe(generateArtifactId(hash, ts));
  });

  test('different timestamps produce different IDs', () => {
    const hash = 'aabbcc';
    const id1 = generateArtifactId(hash, 1000);
    const id2 = generateArtifactId(hash, 2000);
    expect(id1).not.toBe(id2);
  });
});

// ── computeHash ───────────────────────────────────────────────────────────────

describe('computeHash', () => {
  const fixedInput = {
    prompt:    'test prompt',
    consent:   'consent-id-123',
    purpose:   'test-purpose',
    timestamp: '2024-01-01T00:00:00.000Z',
    decision:  'EXECUTE',
    ai_output: 'test output',
  };

  test('returns a 64-character hex string', () => {
    const result = computeHash(fixedInput);
    expect(typeof result).toBe('string');
    expect(result).toHaveLength(64);
    expect(result).toMatch(/^[0-9a-f]{64}$/);
  });

  test('is deterministic — same inputs produce same hash', () => {
    const h1 = computeHash(fixedInput);
    const h2 = computeHash({ ...fixedInput });
    expect(h1).toBe(h2);
  });

  test('is deterministic regardless of input key order', () => {
    const h1 = computeHash(fixedInput);
    const h2 = computeHash({
      ai_output: fixedInput.ai_output,
      consent:   fixedInput.consent,
      decision:  fixedInput.decision,
      prompt:    fixedInput.prompt,
      purpose:   fixedInput.purpose,
      timestamp: fixedInput.timestamp,
    });
    expect(h1).toBe(h2);
  });

  test('different prompt produces different hash', () => {
    const h1 = computeHash(fixedInput);
    const h2 = computeHash({ ...fixedInput, prompt: 'different prompt' });
    expect(h1).not.toBe(h2);
  });

  test('different decision produces different hash', () => {
    const h1 = computeHash({ ...fixedInput, decision: 'EXECUTE' });
    const h2 = computeHash({ ...fixedInput, decision: 'BLOCK' });
    expect(h1).not.toBe(h2);
  });
});
