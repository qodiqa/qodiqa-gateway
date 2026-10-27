'use strict';

/**
 * Property-Based / Fuzz Tests
 *
 * Uses fast-check to generate random/adversarial inputs and prove that
 * invariants always hold regardless of input for the QODIQA enforcement
 * pipeline's core validation primitives.
 *
 * Modules under test (real implementations — no mocking):
 *   1. src/validation/requestHash.js     — computeRequestHash()
 *   2. src/validation/timeCheck.js       — parseTimestamp(), checkTimestamp(),
 *                                          checkExpiry(), checkSkew()
 *   3. src/validation/registerNonce.js   — registerNonce()
 *   4. src/validation/verifyRequestBinding.js — verifyRequestBinding()
 *   5. src/infra/crypto/hashing.js       — sha256Hex(), sortedJSON(),
 *                                          domainSeparatedHash()
 */

// Mock consent so policy evaluation doesn't need live infrastructure
jest.mock('../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const fc = require('fast-check');
const crypto = require('crypto');

const { computeRequestHash }   = require('../src/validation/requestHash');
const { parseTimestamp,
        checkTimestamp,
        checkExpiry,
        checkSkew }            = require('../src/validation/timeCheck');
const { registerNonce }        = require('../src/validation/registerNonce');
const { verifyRequestBinding } = require('../src/validation/verifyRequestBinding');
const { sha256Hex,
        sortedJSON,
        domainSeparatedHash }  = require('../src/infra/crypto/hashing');

// ─────────────────────────────────────────────────────────────────────────────
// Arbitraries
// ─────────────────────────────────────────────────────────────────────────────

/** Non-empty string — covers unicode, control chars, long strings */
const nonEmptyString = fc.string({ minLength: 1, maxLength: 256 });

/** HTTP method — realistic variants including case mixing */
const httpMethod = fc.oneof(
  fc.constantFrom('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'),
  fc.string({ minLength: 1, maxLength: 20 }).filter(s => s.trim().length > 0),
);

/** Path — non-empty string (no normalization applied by impl) */
const httpPath = fc.string({ minLength: 1, maxLength: 512 });

/** Plain object with string keys and JSON-safe leaf values — no undefined */
const jsonSafeLeaf = fc.oneof(
  fc.string(),
  fc.integer(),
  fc.double({ noNaN: true, noDefaultInfinity: true }),
  fc.boolean(),
  fc.constant(null),
);

// fc.string() (used as an object key below) includes "__proto__",
// "constructor", and "prototype" in its adversarial-string corpus by design
// — great for a dedicated canonicalization-rejection test (see the
// stableStringify section below), but these tests are about general
// determinism/collision properties of otherwise-valid bodies, where such a
// key is now a deliberate, spec-mandated rejection (QODIQA-PROTOCOL-SPEC.md
// §6.1) rather than a body that should hash successfully. Filter them out
// here so "any valid body" generators stay within the domain these
// properties are about.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const safeObjectKey  = fc.string({ minLength: 1, maxLength: 32 }).filter(k => !FORBIDDEN_KEYS.has(k));

const plainBody = fc.dictionary(
  safeObjectKey,
  jsonSafeLeaf,
  { minKeys: 0, maxKeys: 10 },
);

/** Positive finite number — valid epoch-ms range */
const epochMs = fc.integer({ min: 1, max: 2_000_000_000_000 });

/** UUID v4 in canonical lowercase form */
// Strict UUID v4: version nibble must be 4, variant nibble must be [89ab]
const uuidV4 = fc.stringMatching(
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
);

/** Future expiry relative to a known now */
const futureExpiryPair = fc.integer({ min: 100, max: 1_000_000_000_000 }).chain(now =>
  fc.integer({ min: 1, max: 300_000 }).map(delta => ({ now, expiry: now + delta })),
);

/** Anything — for adversarial "should never throw" properties */
const anything = fc.anything();

// ─────────────────────────────────────────────────────────────────────────────
// 1. computeRequestHash — requestHash.js
// ─────────────────────────────────────────────────────────────────────────────

describe('computeRequestHash — property-based', () => {
  test('returns 64-char lowercase hex for any valid inputs', () => {
    fc.assert(
      fc.property(httpMethod, httpPath, plainBody, (method, path, body) => {
        const result = computeRequestHash(method, path, body);
        expect(typeof result).toBe('string');
        expect(result).toHaveLength(64);
        expect(result).toMatch(/^[0-9a-f]{64}$/);
      }),
      { numRuns: 200 },
    );
  });

  test('is deterministic — same inputs always produce same hash', () => {
    fc.assert(
      fc.property(httpMethod, httpPath, plainBody, (method, path, body) => {
        const h1 = computeRequestHash(method, path, body);
        const h2 = computeRequestHash(method, path, body);
        expect(h1).toBe(h2);
      }),
      { numRuns: 200 },
    );
  });

  test('method is case-insensitive — upper and lower produce same hash', () => {
    fc.assert(
      fc.property(httpMethod, httpPath, plainBody, (method, path, body) => {
        // Only test strings that survive toUpperCase/toLowerCase round-trips
        const upper = computeRequestHash(method.toUpperCase(), path, body);
        const lower = computeRequestHash(method.toLowerCase(), path, body);
        expect(upper).toBe(lower);
      }),
      { numRuns: 200 },
    );
  });

  test('throws TypeError for invalid method (non-string or empty)', () => {
    const invalidMethod = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(123),
      fc.constant({}),
      fc.constant([]),
      fc.constant(''),
      fc.constant('   '), // whitespace-only
    );
    fc.assert(
      fc.property(invalidMethod, httpPath, plainBody, (method, path, body) => {
        expect(() => computeRequestHash(method, path, body)).toThrow(TypeError);
      }),
      { numRuns: 100 },
    );
  });

  test('throws TypeError for invalid path (non-string or empty)', () => {
    const invalidPath = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(0),
      fc.constant(''),
    );
    fc.assert(
      fc.property(httpMethod, invalidPath, plainBody, (method, path, body) => {
        expect(() => computeRequestHash(method, path, body)).toThrow(TypeError);
      }),
      { numRuns: 100 },
    );
  });

  test('throws TypeError for non-plain-object body', () => {
    const nonPlainBody = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant('string'),
      fc.constant(42),
      fc.constant([1, 2, 3]),
      // class instances are not plain objects
      fc.constant(new Date()),
      fc.constant(new Map()),
    );
    fc.assert(
      fc.property(httpMethod, httpPath, nonPlainBody, (method, path, body) => {
        expect(() => computeRequestHash(method, path, body)).toThrow(TypeError);
      }),
      { numRuns: 100 },
    );
  });

  test('different paths produce different hashes (collision resistance)', () => {
    fc.assert(
      fc.property(
        httpMethod,
        httpPath,
        httpPath,
        plainBody,
        (method, path1, path2, body) => {
          fc.pre(path1 !== path2);
          const h1 = computeRequestHash(method, path1, body);
          const h2 = computeRequestHash(method, path2, body);
          expect(h1).not.toBe(h2);
        },
      ),
      { numRuns: 200 },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. timeCheck.js — parseTimestamp, checkTimestamp, checkExpiry, checkSkew
// ─────────────────────────────────────────────────────────────────────────────

describe('parseTimestamp — property-based', () => {
  test('never throws — always returns a number (possibly NaN)', () => {
    fc.assert(
      fc.property(anything, (raw) => {
        let result;
        expect(() => { result = parseTimestamp(raw); }).not.toThrow();
        expect(typeof result).toBe('number');
      }),
      { numRuns: 500 },
    );
  });

  test('returns a positive finite number for positive finite number input', () => {
    fc.assert(
      fc.property(
        fc.double({ min: 1, max: 2e12, noNaN: true, noDefaultInfinity: true }),
        (n) => {
          const result = parseTimestamp(n);
          expect(Number.isFinite(result)).toBe(true);
          expect(result).toBeGreaterThan(0);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns NaN for non-string non-number inputs', () => {
    const nonNumericNonString = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant({}),
      fc.constant([]),
      fc.constant(true),
      fc.constant(false),
    );
    fc.assert(
      fc.property(nonNumericNonString, (raw) => {
        expect(Number.isNaN(parseTimestamp(raw))).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});

describe('checkTimestamp — property-based', () => {
  // a 5 s future-skew tolerance.
  test('returns {valid:false} for any ts more than the 5 s tolerance ahead of now', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1_000_000_000_000 }).chain(now =>
          fc.integer({ min: 5_001, max: 1_000_000 }).map(delta => ({
            now,
            ts: now + delta,
          })),
        ),
        ({ ts, now }) => {
          const result = checkTimestamp(ts, now);
          expect(result.valid).toBe(false);
          expect(result.reason).toBe('FUTURE_TIMESTAMP');
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {valid:true} for any ts inside the tolerance (now < ts ≤ now + 5 s)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1_000_000_000_000 }).chain(now =>
          fc.integer({ min: 1, max: 5_000 }).map(delta => ({ now, ts: now + delta })),
        ),
        ({ ts, now }) => { expect(checkTimestamp(ts, now).valid).toBe(true); },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {valid:true} for ts <= now', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 1_000_000_000_000 }).chain(now =>
          fc.integer({ min: 1, max: now - 1 }).map(ts => ({ now, ts })),
        ),
        ({ ts, now }) => {
          const result = checkTimestamp(ts, now);
          expect(result.valid).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('result always has a boolean valid field — never throws', () => {
    fc.assert(
      fc.property(anything, epochMs, (ts, now) => {
        let result;
        expect(() => { result = checkTimestamp(ts, now); }).not.toThrow();
        expect(typeof result.valid).toBe('boolean');
      }),
      { numRuns: 300 },
    );
  });
});

describe('checkExpiry — property-based', () => {
  test('returns {valid:false} when now >= expiry', () => {
    fc.assert(
      fc.property(
        futureExpiryPair.map(({ now, expiry }) => ({ expiry, now: expiry })), // now == expiry → expired
        ({ expiry, now }) => {
          const result = checkExpiry(expiry, now);
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {valid:false} when now > expiry', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1_000_000_000_000 }).chain(expiry =>
          fc.integer({ min: 1, max: 1_000_000 }).map(delta => ({
            expiry,
            now: expiry + delta,
          })),
        ),
        ({ expiry, now }) => {
          const result = checkExpiry(expiry, now);
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {valid:true} when now < expiry', () => {
    fc.assert(
      fc.property(futureExpiryPair, ({ now, expiry }) => {
        const result = checkExpiry(expiry, now);
        expect(result.valid).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  test('never throws for arbitrary inputs', () => {
    fc.assert(
      fc.property(anything, epochMs, (expiry, now) => {
        expect(() => checkExpiry(expiry, now)).not.toThrow();
      }),
      { numRuns: 300 },
    );
  });
});

describe('checkSkew — property-based', () => {
  test('returns {valid:false} when backward drift exceeds maxSkewMs', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1_000, max: 1_000_000_000_000 }).chain(now =>
          fc.integer({ min: 1, max: 60_000 }).chain(maxSkewMs =>
            fc.integer({ min: 1, max: 1_000_000 }).map(extra => ({
              now,
              maxSkewMs,
              ts: now - maxSkewMs - extra, // drift > maxSkewMs
            })),
          ),
        ),
        ({ ts, now, maxSkewMs }) => {
          const result = checkSkew(ts, now, maxSkewMs);
          expect(result.valid).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {valid:true} when drift is within maxSkewMs', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1_000, max: 1_000_000_000_000 }).chain(now =>
          fc.integer({ min: 100, max: 60_000 }).chain(maxSkewMs =>
            // drift must be < maxSkewMs; ts = now - drift must be >= 1
            fc.integer({ min: 0, max: Math.min(maxSkewMs - 1, now - 1) }).map(drift => ({
              now,
              maxSkewMs,
              ts: now - drift,
            })),
          ),
        ),
        ({ ts, now, maxSkewMs }) => {
          const result = checkSkew(ts, now, maxSkewMs);
          expect(result.valid).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('never throws for arbitrary inputs', () => {
    fc.assert(
      fc.property(anything, epochMs, epochMs, (ts, now, maxSkewMs) => {
        expect(() => checkSkew(ts, now, maxSkewMs)).not.toThrow();
      }),
      { numRuns: 300 },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. registerNonce — registerNonce.js
// ─────────────────────────────────────────────────────────────────────────────

describe('registerNonce — property-based', () => {
  test('always returns {ok:false} for invalid requestId', async () => {
    const invalidId = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(''),
      fc.constant('not-a-uuid'),
      fc.constant('00000000-0000-0000-0000-000000000000'), // nil uuid
      fc.constant('ABCDEFAB-CDEF-4ABC-8ABC-ABCDEFABCDEF'), // uppercase
      fc.string({ minLength: 0, maxLength: 50 }).filter(s =>
        !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s),
      ),
    );

    await fc.assert(
      fc.asyncProperty(invalidId, epochMs, async (requestId, expiryMs) => {
        const futureExpiry = Date.now() + 60_000; // always future
        const store = { register: jest.fn().mockResolvedValue({ registered: true }) };
        const result = await registerNonce(requestId, futureExpiry, { _store: store });
        expect(result.ok).toBe(false);
        expect(result.reason).toBe('MALFORMED_REQUEST_ID');
      }),
      { numRuns: 150 },
    );
  });

  test('always returns {ok:false} when store throws (fail-closed)', async () => {
    await fc.assert(
      fc.asyncProperty(uuidV4, async (requestId) => {
        const futureExpiry = Date.now() + 60_000;
        const throwingStore = {
          register: jest.fn().mockRejectedValue(new Error('Redis connection refused')),
        };
        const result = await registerNonce(requestId, futureExpiry, { _store: throwingStore });
        expect(result.ok).toBe(false);
        expect(result.reason).toBe('NONCE_STORE_ERROR');
      }),
      { numRuns: 150 },
    );
  });

  test('always returns {ok:false} for invalid expiryMs', async () => {
    const invalidExpiry = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(''),
      fc.constant(0),
      fc.constant(-1),
      fc.constant(NaN),
      fc.constant(Infinity),
      fc.constant(-Infinity),
    );
    await fc.assert(
      fc.asyncProperty(uuidV4, invalidExpiry, async (requestId, expiryMs) => {
        const store = { register: jest.fn().mockResolvedValue({ registered: true }) };
        const result = await registerNonce(requestId, expiryMs, { _store: store });
        expect(result.ok).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  test('returns {ok:true} for valid fresh UUID + future expiry + fresh store', async () => {
    await fc.assert(
      fc.asyncProperty(uuidV4, async (requestId) => {
        const futureExpiry = Date.now() + 300_000;
        const freshStore = {
          register: jest.fn().mockResolvedValue({ registered: true }),
        };
        const result = await registerNonce(requestId, futureExpiry, { _store: freshStore });
        expect(result.ok).toBe(true);
        expect(result.requestId).toBe(requestId);
      }),
      { numRuns: 150 },
    );
  });

  test('returns {ok:false} for already-registered (replay detected)', async () => {
    await fc.assert(
      fc.asyncProperty(uuidV4, async (requestId) => {
        const futureExpiry = Date.now() + 300_000;
        const replayStore = {
          register: jest.fn().mockResolvedValue({ registered: false }),
        };
        const result = await registerNonce(requestId, futureExpiry, { _store: replayStore });
        expect(result.ok).toBe(false);
        expect(result.reason).toBe('REPLAY_DETECTED');
      }),
      { numRuns: 150 },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. verifyRequestBinding — verifyRequestBinding.js
// ─────────────────────────────────────────────────────────────────────────────

describe('verifyRequestBinding — property-based', () => {
  test('never throws — always returns an object with a boolean bound field', () => {
    fc.assert(
      fc.property(anything, anything, (artifact, request) => {
        let result;
        expect(() => { result = verifyRequestBinding(artifact, request); }).not.toThrow();
        expect(typeof result).toBe('object');
        expect(result).not.toBeNull();
        expect(typeof result.bound).toBe('boolean');
      }),
      { numRuns: 500 },
    );
  });

  test('returns {bound:false} for any structurally invalid artifact', () => {
    const invalidArtifact = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant('string'),
      fc.constant(42),
      fc.constant([]),
      fc.constant({}),                            // missing payload
      fc.record({ payload: fc.constant(null) }), // payload not plain object
      fc.record({ payload: fc.constant('x') }),
    );
    fc.assert(
      fc.property(invalidArtifact, anything, (artifact, request) => {
        const result = verifyRequestBinding(artifact, request);
        expect(result.bound).toBe(false);
      }),
      { numRuns: 200 },
    );
  });

  test('returns {bound:false} for artifact missing valid requestId', () => {
    const badRequestId = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(''),
      fc.constant('not-a-uuid'),
      fc.constant('UPPERCASE-UUID-4abc-8abc-abcdefabcdef'),
    );
    fc.assert(
      fc.property(badRequestId, httpMethod, httpPath, plainBody, (badId, method, path, body) => {
        const hash = computeRequestHash(method, path, body);
        const artifact = {
          payload: { requestId: badId, requestHash: hash },
        };
        const request = { method, path, body };
        const result = verifyRequestBinding(artifact, request);
        expect(result.bound).toBe(false);
      }),
      { numRuns: 150 },
    );
  });

  test('returns {bound:false} when requestHash does not match the actual request', () => {
    fc.assert(
      fc.property(
        uuidV4,
        httpMethod, httpPath, plainBody,
        httpMethod, httpPath, plainBody,
        (requestId, m1, p1, b1, m2, p2, b2) => {
          // Ensure the two requests are different
          fc.pre(
            m1.toUpperCase() !== m2.toUpperCase() ||
            p1 !== p2 ||
            JSON.stringify(b1) !== JSON.stringify(b2),
          );

          const hashForReq1 = computeRequestHash(m1, p1, b1);
          // Artifact claims hash for request 1, but we verify against request 2
          const artifact = {
            payload: { requestId, requestHash: hashForReq1 },
          };
          const request2 = { method: m2, path: p2, body: b2 };
          const result = verifyRequestBinding(artifact, request2);
          expect(result.bound).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  test('returns {bound:true} when artifact matches the actual request', () => {
    fc.assert(
      fc.property(uuidV4, httpMethod, httpPath, plainBody, (requestId, method, path, body) => {
        const hash = computeRequestHash(method, path, body);
        const artifact = {
          payload: { requestId, requestHash: hash },
        };
        const request = { method, path, body };
        const result = verifyRequestBinding(artifact, request);
        expect(result.bound).toBe(true);
        expect(result.requestId).toBe(requestId);
      }),
      { numRuns: 200 },
    );
  });

  test('is consistent — same artifact + same request always returns same result', () => {
    fc.assert(
      fc.property(uuidV4, httpMethod, httpPath, plainBody, (requestId, method, path, body) => {
        const hash = computeRequestHash(method, path, body);
        const artifact = Object.freeze({ payload: { requestId, requestHash: hash } });
        const request = Object.freeze({ method, path, body });
        const r1 = verifyRequestBinding(artifact, request);
        const r2 = verifyRequestBinding(artifact, request);
        expect(r1.bound).toBe(r2.bound);
      }),
      { numRuns: 200 },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. hashing.js — sha256Hex, sortedJSON, domainSeparatedHash
// ─────────────────────────────────────────────────────────────────────────────

describe('sha256Hex — property-based', () => {
  test('is total for any string input — never throws', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        let result;
        expect(() => { result = sha256Hex(s); }).not.toThrow();
        expect(typeof result).toBe('string');
        expect(result).toHaveLength(64);
        expect(result).toMatch(/^[0-9a-f]{64}$/);
      }),
      { numRuns: 300 },
    );
  });

  test('is deterministic for any string input', () => {
    fc.assert(
      fc.property(fc.string(), (s) => {
        expect(sha256Hex(s)).toBe(sha256Hex(s));
      }),
      { numRuns: 300 },
    );
  });

  test('different strings (almost) always produce different digests', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        fc.pre(a !== b);
        expect(sha256Hex(a)).not.toBe(sha256Hex(b));
      }),
      { numRuns: 200 },
    );
  });
});

describe('sortedJSON — property-based', () => {
  test('is deterministic regardless of key insertion order', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          safeObjectKey,
          jsonSafeLeaf,
          { minKeys: 1, maxKeys: 8 },
        ),
        (obj) => {
          // Build a permuted copy with keys in a different order.
          // Use a null-prototype accumulator: a key literally named
          // "__proto__" assigned onto a normal {} object literal invokes
          // Object.prototype's __proto__ *setter* instead of creating an own
          // property (and the setter silently no-ops for non-object values),
          // which would drop the key entirely and desync `reversed` from
          // `obj`. Object.create(null) has no such setter, so the assignment
          // always creates a real own property, regardless of key name.
          const keys = Object.keys(obj);
          const reversed = Object.create(null);
          for (const k of [...keys].reverse()) {
            reversed[k] = obj[k];
          }
          expect(sortedJSON(obj)).toBe(sortedJSON(reversed));
        },
      ),
      { numRuns: 300 },
    );
  });

  test('always returns a string', () => {
    fc.assert(
      fc.property(plainBody, (obj) => {
        const result = sortedJSON(obj);
        expect(typeof result).toBe('string');
      }),
      { numRuns: 200 },
    );
  });

  test('different objects produce different serializations', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          safeObjectKey,
          jsonSafeLeaf,
          { minKeys: 1, maxKeys: 5 },
        ),
        fc.dictionary(
          safeObjectKey,
          jsonSafeLeaf,
          { minKeys: 1, maxKeys: 5 },
        ),
        (a, b) => {
          // Only assert when they are semantically different
          fc.pre(JSON.stringify(a) !== JSON.stringify(b));
          fc.pre(sortedJSON(a) !== undefined && sortedJSON(b) !== undefined);
          expect(sortedJSON(a)).not.toBe(sortedJSON(b));
        },
      ),
      { numRuns: 200 },
    );
  });

  test('any object containing a forbidden key ("__proto__", "constructor", "prototype") is rejected', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('__proto__', 'constructor', 'prototype'),
        jsonSafeLeaf,
        fc.dictionary(safeObjectKey, jsonSafeLeaf, { minKeys: 0, maxKeys: 4 }),
        (forbiddenKey, value, rest) => {
          const poisoned = Object.assign(Object.create(null), rest);
          Object.defineProperty(poisoned, forbiddenKey, { value, enumerable: true, configurable: true, writable: true });
          expect(() => sortedJSON(poisoned)).toThrow(sortedJSON.CanonicalizationError);
        },
      ),
      { numRuns: 100 },
    );
  });

  test('any array or object containing NaN/Infinity/-Infinity is rejected', () => {
    const nonFinite = fc.constantFrom(NaN, Infinity, -Infinity);
    fc.assert(
      fc.property(nonFinite, safeObjectKey, (badNum, key) => {
        expect(() => sortedJSON({ [key]: badNum })).toThrow(sortedJSON.CanonicalizationError);
        expect(() => sortedJSON([badNum])).toThrow(sortedJSON.CanonicalizationError);
      }),
      { numRuns: 50 },
    );
  });
});

describe('domainSeparatedHash — property-based', () => {
  test('returns a 32-byte Buffer for any string domain and string input', () => {
    fc.assert(
      fc.property(nonEmptyString, fc.string(), (domain, input) => {
        const result = domainSeparatedHash(domain, input);
        expect(Buffer.isBuffer(result)).toBe(true);
        expect(result.length).toBe(32);
      }),
      { numRuns: 300 },
    );
  });

  test('is deterministic — same domain + input always produces same hash', () => {
    fc.assert(
      fc.property(nonEmptyString, fc.string(), (domain, input) => {
        const r1 = domainSeparatedHash(domain, input);
        const r2 = domainSeparatedHash(domain, input);
        expect(r1.equals(r2)).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  test('domain separation — same input with different domains produces different hashes', () => {
    fc.assert(
      fc.property(nonEmptyString, nonEmptyString, fc.string(), (d1, d2, input) => {
        fc.pre(d1 !== d2);
        const h1 = domainSeparatedHash(d1, input);
        const h2 = domainSeparatedHash(d2, input);
        expect(h1.equals(h2)).toBe(false);
      }),
      { numRuns: 200 },
    );
  });

  test('throws TypeError for empty domain', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        expect(() => domainSeparatedHash('', input)).toThrow(TypeError);
      }),
      { numRuns: 100 },
    );
  });

  test('throws TypeError for non-string domain', () => {
    const nonString = fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.constant(42),
      fc.constant({}),
      fc.constant([]),
    );
    fc.assert(
      fc.property(nonString, fc.string(), (domain, input) => {
        expect(() => domainSeparatedHash(domain, input)).toThrow(TypeError);
      }),
      { numRuns: 100 },
    );
  });
});
