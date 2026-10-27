'use strict';

/**
 * Component #17 — Stable Stringify Library
 *
 * Tests for src/utils/stableStringify.js (backed by fast-json-stable-stringify).
 *
 * Coverage:
 *   SS-01 … SS-10   Deterministic ordering
 *   SS-11 … SS-20   Nested objects and arrays
 *   SS-21 … SS-30   Hash stability and cryptographic consistency
 *   SS-31 … SS-40   Artifact signing stability
 *   SS-41 … SS-50   Legacy compatibility (undefined → null convention)
 *   SS-51 … SS-60   Library integration guards
 */

const crypto          = require('crypto');
const stableStringify = require('../stableStringify');
const legacyStringify = require('../../../services/utils/stableStringify');

// ── SS-01…10: Deterministic ordering ─────────────────────────────────────────

describe('SS-01…10 — Deterministic ordering', () => {

  test('SS-01 same input always produces same output', () => {
    const obj = { z: 'last', a: 'first', m: 'middle' };
    expect(stableStringify(obj)).toBe(stableStringify({ ...obj }));
  });

  test('SS-02 key insertion order does not affect output', () => {
    const a = { z: 'last', a: 'first', m: 'middle' };
    const b = { m: 'middle', z: 'last', a: 'first' };
    expect(stableStringify(a)).toBe(stableStringify(b));
  });

  test('SS-03 keys are sorted lexicographically ascending', () => {
    expect(stableStringify({ z: 1, a: 2, m: 3 })).toBe('{"a":2,"m":3,"z":1}');
  });

  test('SS-04 null serializes as literal null', () => {
    expect(stableStringify(null)).toBe('null');
    expect(stableStringify({ x: null })).toBe('{"x":null}');
  });

  test('SS-05 booleans serialize as literals', () => {
    expect(stableStringify(true)).toBe('true');
    expect(stableStringify(false)).toBe('false');
    expect(stableStringify({ flag: true })).toBe('{"flag":true}');
  });

  test('SS-06 numbers serialize correctly', () => {
    expect(stableStringify(42)).toBe('42');
    expect(stableStringify(1.5)).toBe('1.5');
    expect(stableStringify({ n: 0 })).toBe('{"n":0}');
  });

  test('SS-07 strings serialize with quotes and control-char escaping', () => {
    expect(stableStringify('hello')).toBe('"hello"');
    expect(stableStringify('say "hi"')).toBe('"say \\"hi\\""');
    expect(stableStringify('line\none')).toBe('"line\\none"');
  });

  test('SS-08 array element order is preserved', () => {
    expect(stableStringify([3, 1, 2])).toBe('[3,1,2]');
    expect(stableStringify([{ b: 2 }, { a: 1 }])).toBe('[{"b":2},{"a":1}]');
  });

  test('SS-09 empty object and empty array', () => {
    expect(stableStringify({})).toBe('{}');
    expect(stableStringify([])).toBe('[]');
  });

  test('SS-10 repeated calls on same input are stable', () => {
    const obj = { nonce: crypto.randomBytes(16).toString('hex'), ts: Date.now() };
    const s1  = stableStringify(obj);
    const s2  = stableStringify(obj);
    const s3  = stableStringify(obj);
    expect(s1).toBe(s2);
    expect(s2).toBe(s3);
  });

});

// ── SS-11…20: Nested objects and arrays ──────────────────────────────────────

describe('SS-11…20 — Nested objects and arrays', () => {

  test('SS-11 keys sorted at every depth', () => {
    const obj = { z: { b: 2, a: 1 }, a: { y: 'y', x: 'x' } };
    expect(stableStringify(obj)).toBe('{"a":{"x":"x","y":"y"},"z":{"a":1,"b":2}}');
  });

  test('SS-12 array of objects — each object keys sorted', () => {
    const arr = [{ z: 1, a: 2 }, { m: 3, b: 4 }];
    expect(stableStringify(arr)).toBe('[{"a":2,"z":1},{"b":4,"m":3}]');
  });

  test('SS-13 deeply nested objects are consistently ordered', () => {
    const obj = { c: { b: { a: 1 } }, a: { b: { c: 2 } } };
    expect(stableStringify(obj)).toBe('{"a":{"b":{"c":2}},"c":{"b":{"a":1}}}');
  });

  test('SS-14 mixed nesting: objects inside arrays inside objects', () => {
    const obj = { policies: [{ id: 'p2', rule: 'allow' }, { id: 'p1', rule: 'deny' }] };
    expect(stableStringify(obj)).toBe('{"policies":[{"id":"p2","rule":"allow"},{"id":"p1","rule":"deny"}]}');
  });

  test('SS-15 array order preserved within nested objects', () => {
    const a = { items: [3, 1, 2] };
    const b = { items: [3, 1, 2] };
    expect(stableStringify(a)).toBe(stableStringify(b));
  });

  test('SS-16 evidence-style payload with varied key order', () => {
    const v1 = { artifactId: 'a1', decision: 'ALLOW', policyHash: 'abc123', timestamp: '2026-01-01T00:00:00Z' };
    const v2 = { timestamp: '2026-01-01T00:00:00Z', policyHash: 'abc123', decision: 'ALLOW', artifactId: 'a1' };
    expect(stableStringify(v1)).toBe(stableStringify(v2));
  });

  test('SS-17 policy document with multiple rules', () => {
    const doc1 = { rules: [{ action: 'read', effect: 'allow', resource: '*' }], version: 2 };
    const doc2 = { version: 2, rules: [{ resource: '*', effect: 'allow', action: 'read' }] };
    expect(stableStringify(doc1)).toBe(stableStringify(doc2));
  });

  test('SS-18 transparency entry fields', () => {
    const e1 = { entryType: 'ARTIFACT', payloadHash: 'ph1', signerKeyId: 'k1', transparencyId: 't1' };
    const e2 = { transparencyId: 't1', signerKeyId: 'k1', payloadHash: 'ph1', entryType: 'ARTIFACT' };
    expect(stableStringify(e1)).toBe(stableStringify(e2));
  });

  test('SS-19 null values in nested objects', () => {
    expect(stableStringify({ a: { b: null, c: 1 } })).toBe('{"a":{"b":null,"c":1}}');
  });

  test('SS-20 array with mixed types', () => {
    expect(stableStringify([null, true, 42, 'str', { z: 1 }])).toBe('[null,true,42,"str",{"z":1}]');
  });

});

// ── SS-21…30: Hash stability and cryptographic consistency ───────────────────

describe('SS-21…30 — Hash stability and cryptographic consistency', () => {

  function sha256(str) {
    return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
  }

  test('SS-21 same logical object always produces same SHA-256', () => {
    const a = { z: 'last', b: 1, a: 2 };
    const b = { a: 2, b: 1, z: 'last' };
    expect(sha256(stableStringify(a))).toBe(sha256(stableStringify(b)));
  });

  test('SS-22 different objects produce different hashes', () => {
    const a = { x: 1 };
    const b = { x: 2 };
    expect(sha256(stableStringify(a))).not.toBe(sha256(stableStringify(b)));
  });

  test('SS-23 domain-separated hash is stable for equivalent objects', () => {
    const payload = { action: 'read', consent: true, userId: 'u1' };
    const alt     = { userId: 'u1', consent: true, action: 'read' };
    const domain  = 'QODIQA::TEST::V1';

    const h1 = crypto.createHash('sha256').update(domain).update(stableStringify(payload)).digest('hex');
    const h2 = crypto.createHash('sha256').update(domain).update(stableStringify(alt)).digest('hex');
    expect(h1).toBe(h2);
  });

  test('SS-24 hash output is a 64-character lowercase hex string', () => {
    const hash = sha256(stableStringify({ x: 1 }));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('SS-25 repeated serialization → same hash (determinism guard)', () => {
    const obj  = { nonce: crypto.randomBytes(16).toString('hex'), ts: '2026-01-01T00:00:00Z' };
    const hash = sha256(stableStringify(obj));
    for (let i = 0; i < 100; i++) {
      expect(sha256(stableStringify({ ...obj }))).toBe(hash);
    }
  });

  test('SS-26 evidence hash stability — canonical fields with null coalescing', () => {
    const fields = {
      evidenceId:          'ev-001',
      artifactId:          'art-001',
      artifactHash:        'a'.repeat(64),
      policyId:            'POLICY_SET',
      policyHash:          'b'.repeat(64),
      keyId:               'default:key_v1',
      keyFingerprint:      'c'.repeat(64),
      auditRecordId:       'd'.repeat(64),
      auditRecordHash:     'e'.repeat(64),
      previousEvidenceHash: null,
    };
    const h1 = sha256(stableStringify(fields));
    const h2 = sha256(stableStringify({ ...fields }));
    expect(crypto.timingSafeEqual(Buffer.from(h1, 'hex'), Buffer.from(h2, 'hex'))).toBe(true);
  });

  test('SS-27 policy fingerprint stability', () => {
    const policySet1 = [{ id: 'p1', effect: 'allow' }, { id: 'p2', effect: 'deny' }];
    const policySet2 = [{ effect: 'allow', id: 'p1' }, { effect: 'deny', id: 'p2' }];
    const h1 = sha256(stableStringify(policySet1));
    const h2 = sha256(stableStringify(policySet2));
    expect(h1).toBe(h2);
  });

  test('SS-28 request hash stability', () => {
    const body = { consent: true, purpose: 'analysis', userId: 'u1' };
    const r1   = { body, method: 'POST', path: '/v1/ai/chat' };
    const r2   = { path: '/v1/ai/chat', method: 'POST', body: { userId: 'u1', purpose: 'analysis', consent: true } };
    expect(sha256(stableStringify(r1))).toBe(sha256(stableStringify(r2)));
  });

  test('SS-29 transparency entry hash stability', () => {
    const e1 = { entryType: 'ARTIFACT', payloadHash: 'ph', previousEntryHash: null, signerKeyId: 'k1', transparencyId: 't1' };
    const e2 = { transparencyId: 't1', signerKeyId: 'k1', previousEntryHash: null, payloadHash: 'ph', entryType: 'ARTIFACT' };
    expect(sha256(stableStringify(e1))).toBe(sha256(stableStringify(e2)));
  });

  test('SS-30 null vs missing field produce different hashes (collision resistance)', () => {
    const withNull    = { x: null, y: 1 };
    const withoutNull = { y: 1 };
    expect(sha256(stableStringify(withNull))).not.toBe(sha256(stableStringify(withoutNull)));
  });

});

// ── SS-31…40: Artifact signing stability ─────────────────────────────────────

describe('SS-31…40 — Artifact signing stability', () => {

  test('SS-31 envelope fields produce identical canonical form regardless of insertion order', () => {
    const now    = new Date().toISOString();
    const expiry = new Date(Date.now() + 3_600_000).toISOString();

    const env1 = { expiry, payload: { consent: true, userId: 'u1' }, publicKeyId: 'k1', timestamp: now };
    const env2 = { timestamp: now, publicKeyId: 'k1', payload: { userId: 'u1', consent: true }, expiry };

    expect(stableStringify(env1)).toBe(stableStringify(env2));
  });

  test('SS-32 nested payload objects in envelopes are key-sorted', () => {
    const payload1 = { z: 'last', a: 1, m: true };
    const payload2 = { a: 1, m: true, z: 'last' };
    expect(stableStringify({ payload: payload1 })).toBe(stableStringify({ payload: payload2 }));
  });

  test('SS-33 hex hash strings are not re-encoded or modified', () => {
    const hexStr = 'a'.repeat(64);
    expect(stableStringify({ hash: hexStr })).toBe(`{"hash":"${'a'.repeat(64)}"}`);
  });

  test('SS-34 ISO timestamp strings are not modified', () => {
    const ts = '2026-01-01T00:00:00.000Z';
    expect(stableStringify({ timestamp: ts })).toBe(`{"timestamp":"${ts}"}`);
  });

  test('SS-35 UUID strings are not modified', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    expect(stableStringify({ id: uuid })).toBe(`{"id":"${uuid}"}`);
  });

  test('SS-36 base64 strings (public key DER) are not modified', () => {
    const b64 = Buffer.from('test key material').toString('base64');
    expect(stableStringify({ key: b64 })).toBe(`{"key":"${b64}"}`);
  });

  test('SS-37 signing produces same hash from either field ordering', () => {
    function sha256(str) { return crypto.createHash('sha256').update(str, 'utf8').digest(); }

    const payload1 = { consent: true, purpose: 'analysis', userId: 'u1' };
    const payload2 = { userId: 'u1', consent: true, purpose: 'analysis' };

    const h1 = sha256(stableStringify(payload1));
    const h2 = sha256(stableStringify(payload2));
    expect(crypto.timingSafeEqual(h1, h2)).toBe(true);
  });

  test('SS-38 audit record with execution context produces stable output', () => {
    const rec1 = {
      decision: 'ALLOW',
      executionContext: { publicKeyId: 'k1', requestId: 'r1' },
      hash: 'h1',
      policyHash: 'ph1',
      timestamp: '2026-01-01T00:00:00Z',
    };
    const rec2 = {
      timestamp: '2026-01-01T00:00:00Z',
      policyHash: 'ph1',
      hash: 'h1',
      decision: 'ALLOW',
      executionContext: { requestId: 'r1', publicKeyId: 'k1' },
    };
    expect(stableStringify(rec1)).toBe(stableStringify(rec2));
  });

});

// ── SS-41…50: Legacy compatibility — undefined → null convention ─────────────

describe('SS-41…50 — Legacy compatibility (undefined → null)', () => {

  test('SS-41 undefined at top level serializes as null', () => {
    expect(stableStringify(undefined)).toBe('null');
  });

  test('SS-42 undefined object values serialize as null (not omitted)', () => {
    expect(stableStringify({ x: undefined })).toBe('{"x":null}');
  });

  test('SS-43 multiple undefined values all become null', () => {
    expect(stableStringify({ a: undefined, b: 1, c: undefined })).toBe('{"a":null,"b":1,"c":null}');
  });

  test('SS-44 undefined in nested objects becomes null', () => {
    expect(stableStringify({ outer: { inner: undefined } })).toBe('{"outer":{"inner":null}}');
  });

  test('SS-45 produces same output as legacy services/utils/stableStringify for all real QODIQA data types', () => {
    const realDataExamples = [
      { evidenceId: 'ev-001', artifactHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) },
      { timestamp: '2026-01-01T00:00:00Z', decision: 'ALLOW', keyId: 'default:key_v1' },
      [{ id: 'p1', effect: 'allow' }, { id: 'p2', effect: 'deny' }],
      { a: 1, b: null, c: true, d: 'string' },
    ];

    for (const example of realDataExamples) {
      expect(stableStringify(example)).toBe(legacyStringify(example));
    }
  });

  test('SS-46 same function reference is exported from both paths', () => {
    // services/utils/stableStringify.js is a re-export of src/utils/stableStringify.js
    expect(legacyStringify).toBe(stableStringify);
  });

  test('SS-47 hashing with new and legacy path produce identical SHA-256', () => {
    const obj = { action: 'read', consent: true, nonce: crypto.randomBytes(16).toString('hex') };
    const h1  = crypto.createHash('sha256').update(stableStringify(obj)).digest('hex');
    const h2  = crypto.createHash('sha256').update(legacyStringify(obj)).digest('hex');
    expect(h1).toBe(h2);
  });

});

// ── SS-51…60: Library integration guards ─────────────────────────────────────

describe('SS-51…60 — Library integration guards', () => {

  test('SS-51 src/utils/stableStringify.js uses fast-json-stable-stringify', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../stableStringify.js'),
      'utf8',
    );
    expect(src).toMatch(/require\(['"']fast-json-stable-stringify['"']\)/);
  });

  test('SS-52 src/utils/stableStringify.js does not define a custom sort loop', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../stableStringify.js'),
      'utf8',
    );
    expect(src).not.toMatch(/Object\.keys.*\.sort\(\).*\.map/);
  });

  test('SS-53 services/utils/stableStringify.js does not contain a custom implementation', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../../services/utils/stableStringify.js'),
      'utf8',
    );
    expect(src).not.toMatch(/function stableStringify/);
    expect(src).not.toMatch(/function _encodeString/);
    expect(src).toMatch(/require.*stableStringify/);
  });

  test('SS-54 chain.js does not define a local _canonicalJson', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../core/evidence/chain.js'),
      'utf8',
    );
    expect(src).not.toMatch(/function _canonicalJson/);
    expect(src).toMatch(/require.*stableStringify/);
  });

  test('SS-55 log.js does not define a local _canonicalJson', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../../core/transparency/log.js'),
      'utf8',
    );
    expect(src).not.toMatch(/function _canonicalJson/);
    expect(src).toMatch(/require.*stableStringify/);
  });

  test('SS-56 fast-json-stable-stringify is resolvable', () => {
    expect(() => require('fast-json-stable-stringify')).not.toThrow();
  });

  test('SS-57 stableStringify produces no whitespace in output', () => {
    const obj = { z: 1, a: { b: 2 } };
    const out = stableStringify(obj);
    expect(out).not.toMatch(/\s/);
  });

  test('SS-58 no custom encodeString or sortedJSON defined in src/utils/stableStringify.js', () => {
    const src = require('fs').readFileSync(
      require('path').join(__dirname, '../stableStringify.js'),
      'utf8',
    );
    expect(src).not.toMatch(/function _encodeString/);
    expect(src).not.toMatch(/function sortedJSON/);
  });

});

// ── SS-61…70: Numeric edge cases (QODIQA-PROTOCOL-SPEC.md §6.1) ──────────────

describe('SS-61…70 — Numeric edge cases', () => {

  test('SS-61 NaN is rejected (spec §6.1: "if NaN or Infinity: ERROR")', () => {
    expect(() => stableStringify(NaN)).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify({ x: NaN })).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-62 Infinity and -Infinity are rejected', () => {
    expect(() => stableStringify(Infinity)).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify(-Infinity)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-63 rejection errors carry a stable error code', () => {
    try {
      stableStringify(NaN);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.code).toBe('NON_FINITE_NUMBER');
      expect(e.name).toBe('CanonicalizationError');
    }
  });

  test('SS-64 -0 serializes identically to 0', () => {
    expect(stableStringify(-0)).toBe(stableStringify(0));
    expect(stableStringify(-0)).toBe('0');
  });

  test('SS-65 Number.MAX_VALUE and MIN_VALUE serialize without error', () => {
    expect(() => stableStringify(Number.MAX_VALUE)).not.toThrow();
    expect(() => stableStringify(Number.MIN_VALUE)).not.toThrow();
  });

  test('SS-66 Number.MAX_SAFE_INTEGER and MIN_SAFE_INTEGER serialize as plain decimal', () => {
    expect(stableStringify(Number.MAX_SAFE_INTEGER)).toBe('9007199254740991');
    expect(stableStringify(Number.MIN_SAFE_INTEGER)).toBe('-9007199254740991');
  });

  test('SS-67 bigint is rejected with an explicit CanonicalizationError', () => {
    expect(() => stableStringify(10n)).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify({ x: 10n })).toThrow(stableStringify.CanonicalizationError);
  });

});

// ── SS-71…80: Forbidden keys and unsupported value types (spec §6.1) ─────────

describe('SS-71…80 — Forbidden keys and unsupported value types', () => {

  test('SS-71 __proto__ own key is rejected, not silently stripped or admitted', () => {
    const poisoned = JSON.parse('{"__proto__":{"isAdmin":true},"userId":"alice"}');
    expect(Object.keys(poisoned)).toContain('__proto__');
    expect(() => stableStringify(poisoned)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-72 constructor and prototype own keys are rejected', () => {
    expect(() => stableStringify({ constructor: 5 })).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify({ prototype: 5 })).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-73 forbidden keys are rejected at any nesting depth', () => {
    // Note: `{ __proto__: 1 }` as an *object literal* is special-cased by the
    // JS spec to set [[Prototype]] directly (a no-op here since 1 isn't an
    // object/null) rather than creating an own property — so nesting must
    // use JSON.parse or a computed key to actually produce an own
    // "__proto__" property to test against.
    const nested = JSON.parse('{"a":{"b":{"__proto__":1}}}');
    expect(() => stableStringify(nested)).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify([{ constructor: 1 }])).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-74 rejection error code for forbidden keys is FORBIDDEN_KEY', () => {
    try {
      stableStringify(JSON.parse('{"__proto__":1}'));
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.code).toBe('FORBIDDEN_KEY');
    }
  });

  test('SS-75 function values are rejected', () => {
    expect(() => stableStringify({ a: function foo() {} })).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-76 symbol values are rejected', () => {
    expect(() => stableStringify({ a: Symbol('x') })).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-77 symbol-keyed properties are silently excluded (not own string keys)', () => {
    const obj = { a: 1 };
    obj[Symbol('hidden')] = 'ignored';
    expect(stableStringify(obj)).toBe('{"a":1}');
  });

  test('SS-78 non-enumerable properties are excluded from canonical form', () => {
    const obj = { visible: 1 };
    Object.defineProperty(obj, 'hidden', { value: 2, enumerable: false });
    expect(stableStringify(obj)).toBe('{"visible":1}');
  });

  test('SS-79 objects with a non-standard prototype chain (e.g. class instances) are rejected outright', () => {
    // The only way to have inherited-but-invisible-to-Object.keys properties
    // is a non-Object.prototype/non-null prototype chain — and that is
    // exactly what _isPlainObject rejects. This is a stronger guarantee than
    // "inherited properties are silently excluded": such objects never reach
    // key enumeration at all. Matches src/validation/canonicalize.js's own
    // isPlainObject() policy (see redteam.adversarial.test.js [1.E-1]).
    class Base { constructor() { this.own = 1; } }
    Base.prototype.inherited = 99;
    expect(() => stableStringify(new Base())).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-80 Object.create(null) objects are fully supported', () => {
    const obj = Object.create(null);
    obj.b = 2;
    obj.a = 1;
    expect(stableStringify(obj)).toBe('{"a":1,"b":2}');
  });

});

// ── SS-81…90: Exotic object types (Date, RegExp, Map, Set, Buffer, ...) ──────

describe('SS-81…90 — Exotic object types are rejected, not silently lossy', () => {

  // Rationale: none of these have own enumerable string keys reflecting their
  // actual value, so the pre-fix behavior silently serialized all of them to
  // "{}" — meaning e.g. two different Dates, or a Map with entries vs. an
  // empty Map, hashed identically. Rejecting them outright prevents this
  // class of collision; QODIQA-PROTOCOL-SPEC.md §6.1 only defines a
  // canonical form for null/boolean/number/string/array/plain-object.

  test('SS-81 Date objects are rejected (would otherwise collapse to "{}")', () => {
    expect(() => stableStringify(new Date())).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify(new Date('invalid'))).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-82 RegExp objects are rejected', () => {
    expect(() => stableStringify(/abc/gi)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-83 Error objects are rejected', () => {
    expect(() => stableStringify(new Error('boom'))).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-84 Map objects are rejected', () => {
    expect(() => stableStringify(new Map([['a', 1]]))).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-85 Set objects are rejected', () => {
    expect(() => stableStringify(new Set([1, 2, 3]))).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-86 ArrayBuffer, Buffer, and TypedArray values are rejected', () => {
    expect(() => stableStringify(new ArrayBuffer(4))).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify(Buffer.from('hi'))).toThrow(stableStringify.CanonicalizationError);
    expect(() => stableStringify(new Uint8Array([1, 2, 3]))).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-87 two different Dates previously collided post-fix they both reject rather than match', () => {
    let a, b;
    try { stableStringify(new Date('2020-01-01')); } catch (e) { a = e; }
    try { stableStringify(new Date('2030-01-01')); } catch (e) { b = e; }
    expect(a).toBeInstanceOf(stableStringify.CanonicalizationError);
    expect(b).toBeInstanceOf(stableStringify.CanonicalizationError);
  });

  test('SS-88 exotic-type rejection error code is UNSUPPORTED_TYPE', () => {
    try {
      stableStringify(new Date());
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.code).toBe('UNSUPPORTED_TYPE');
    }
  });

});

// ── SS-91…100: Circular references and depth limits ──────────────────────────

describe('SS-91…100 — Circular references and depth limits', () => {

  test('SS-91 direct self-reference is rejected deterministically (no stack overflow)', () => {
    const obj = { a: 1 };
    obj.self  = obj;
    expect(() => stableStringify(obj)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-92 indirect (multi-hop) cycle is rejected', () => {
    const a = {}; const b = { a };
    a.b = b;
    expect(() => stableStringify(a)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-93 cyclic array is rejected', () => {
    const arr = [1, 2];
    arr.push(arr);
    expect(() => stableStringify(arr)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-94 circular reference error code is CIRCULAR_REFERENCE', () => {
    const obj = {}; obj.self = obj;
    try {
      stableStringify(obj);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.code).toBe('CIRCULAR_REFERENCE');
    }
  });

  test('SS-95 shared (non-circular) sub-object referenced twice serializes fine', () => {
    const shared = { x: 1 };
    expect(() => stableStringify({ a: shared, b: shared })).not.toThrow();
    expect(stableStringify({ a: shared, b: shared })).toBe('{"a":{"x":1},"b":{"x":1}}');
  });

  test('SS-96 pathologically deep nesting is rejected without a stack overflow', () => {
    let deep = { v: 1 };
    for (let i = 0; i < 2000; i++) deep = { n: deep };
    expect(() => stableStringify(deep)).toThrow(stableStringify.CanonicalizationError);
  });

  test('SS-97 deep-nesting error code is MAX_DEPTH_EXCEEDED', () => {
    let deep = { v: 1 };
    for (let i = 0; i < 2000; i++) deep = { n: deep };
    try {
      stableStringify(deep);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e.code).toBe('MAX_DEPTH_EXCEEDED');
    }
  });

  test('SS-98 legitimate deep nesting (200 levels) still validates successfully', () => {
    // Matches the depth exercised by the adversarial suite
    // (redteam.adversarial.test.js [3.E-1]) — must not regress.
    let deep = { leaf: true };
    for (let i = 0; i < 200; i++) deep = { n: deep };
    expect(() => stableStringify(deep)).not.toThrow();
  });

});

// ── SS-101…110: Arrays, sparse elements, and unicode ──────────────────────────

describe('SS-101…110 — Arrays, sparse elements, and unicode', () => {

  test('SS-101 sparse array holes serialize as null', () => {
    expect(stableStringify([1, , 3])).toBe('[1,null,3]');
  });

  test('SS-102 explicit undefined array elements serialize as null', () => {
    expect(stableStringify([1, undefined, 3])).toBe('[1,null,3]');
  });

  test('SS-103 deeply nested arrays preserve structure and order', () => {
    expect(stableStringify([[1, 2], [3, [4, 5]]])).toBe('[[1,2],[3,[4,5]]]');
  });

  test('SS-104 emoji and astral characters round-trip correctly', () => {
    expect(stableStringify({ a: '😀' })).toBe('{"a":"😀"}');
  });

  test('SS-105 lone surrogate halves are escaped, not thrown', () => {
    expect(() => stableStringify('\ud800')).not.toThrow();
    expect(stableStringify('\ud800')).toBe('"\\ud800"');
  });

  test('SS-106 combining-character strings serialize as opaque byte sequences (no NFC/NFD normalization)', () => {
    const nfc = 'é';        // U+00E9
    const nfd = 'é';  // e + combining acute accent
    expect(stableStringify(nfc)).not.toBe(stableStringify(nfd));
  });

  test('SS-107 empty string and empty containers serialize distinctly', () => {
    expect(stableStringify('')).toBe('""');
    expect(stableStringify({})).toBe('{}');
    expect(stableStringify([])).toBe('[]');
    expect(new Set([stableStringify(''), stableStringify({}), stableStringify([])]).size).toBe(3);
  });

});

// ── sortedJSON identity (hashing.js re-exports stableStringify) ───────────────
//
// Merged from the former (Register
// #111 — that file otherwise duplicated everything above via the legacy
// import path; this is the one piece of coverage it had that this file
// didn't: src/infra/crypto/hashing.js's sortedJSON/domainSeparatedHash
// integration).

describe('sortedJSON from hashing.js is the canonical stableStringify', () => {
  const { domainSeparatedHash, ARTIFACT_DOMAINS, sortedJSON } = require('../../infra/crypto/hashing.js');

  test('hashing.js does not define a local sortedJSON — delegates to stableStringify', () => {
    const hashingSrc = require('fs').readFileSync(
      require('path').join(__dirname, '../../infra/crypto/hashing.js'),
      'utf8',
    );
    expect(hashingSrc).not.toMatch(/^function sortedJSON/m);
    expect(hashingSrc).not.toMatch(/^function encodeString/m);
    expect(hashingSrc).toMatch(/require.*stableStringify/);
  });

  test('sortedJSON is the same function reference as stableStringify', () => {
    expect(sortedJSON).toBe(stableStringify);
  });

  test('sortedJSON and stableStringify produce identical output for objects', () => {
    const obj = { z: 'last', a: 1, m: true, n: null };
    expect(sortedJSON(obj)).toBe(stableStringify(obj));
  });

  test('sortedJSON and stableStringify produce identical output for arrays', () => {
    const arr = [{ b: 2 }, { a: 1 }];
    expect(sortedJSON(arr)).toBe(stableStringify(arr));
  });

  test('sortedJSON and stableStringify produce identical output for primitives', () => {
    for (const v of [null, true, false, 42, 'hello\nworld']) {
      expect(sortedJSON(v)).toBe(stableStringify(v));
    }
  });

  test('domain-separated hash is stable across call sites', () => {
    const fields = { a: 1, z: 'last', m: true };
    const h1 = domainSeparatedHash(ARTIFACT_DOMAINS.ARTIFACT, stableStringify(fields));
    const h2 = domainSeparatedHash(ARTIFACT_DOMAINS.ARTIFACT, sortedJSON(fields));
    expect(crypto.timingSafeEqual(h1, h2)).toBe(true);
  });

  test('produces byte-level identical output for the same signed fields at all call sites', () => {
    const fields = {
      artifactId: 'test-id',
      keyId:      'test:key_v1',
      nonce:      crypto.randomBytes(16).toString('hex'),
      requestHash: crypto.randomBytes(32).toString('hex'),
      timestamp:  new Date().toISOString(),
    };

    const fromDirect = stableStringify(fields);
    const fromSorted = sortedJSON(fields);
    expect(fromDirect).toBe(fromSorted);

    const h1 = crypto.createHash('sha256').update(fromDirect, 'utf8').digest();
    const h2 = crypto.createHash('sha256').update(fromSorted, 'utf8').digest();
    expect(crypto.timingSafeEqual(h1, h2)).toBe(true);
  });
});
