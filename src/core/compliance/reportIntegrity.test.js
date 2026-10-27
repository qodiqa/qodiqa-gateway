'use strict';

/**
 * Task #12 — canonical serializer edge cases.
 *
 * Targeted regression coverage for the fix applied to
 * src/core/compliance/reportIntegrity.js's `canonicalise()`: its `_deepClone`
 * and `_sortedReplacer` helpers previously rebuilt objects via a plain `{}`
 * accumulator, which silently drops a key literally named "__proto__"
 * (assigning to it on a normal object invokes the inherited
 * Object.prototype.__proto__ setter instead of creating an own property).
 * That let a tampered report — with an injected "__proto__" field — hash
 * identical to the untampered original, defeating the whole point of a
 * signed integrity hash. Both helpers now use Object.create(null).
 */

const { canonicalise, hashReport } = require('./reportIntegrity');

describe('reportIntegrity.canonicalise — __proto__ key handling', () => {
  test('RI-01  a "__proto__" own key is preserved in the canonical form, not stripped', () => {
    const tampered = JSON.parse('{"__proto__":{"evil":true},"amount":100}');
    expect(canonicalise(tampered)).toContain('__proto__');
  });

  test('RI-02  a tampered report with an injected "__proto__" key no longer hashes identically to the original', () => {
    const original = { amount: 100 };
    const tampered = JSON.parse('{"__proto__":{"evil":true},"amount":100}');
    expect(hashReport(tampered)).not.toBe(hashReport(original));
  });

  test('RI-03  the same collision guard holds for a nested "__proto__" key inside the report', () => {
    const original = { section: { amount: 100 } };
    const tampered = { section: JSON.parse('{"__proto__":{"evil":true},"amount":100}') };
    expect(hashReport(tampered)).not.toBe(hashReport(original));
  });

  test('RI-04  normal reports without any forbidden key still canonicalize and hash deterministically', () => {
    const a = { b: 2, a: 1, nested: { y: 2, x: 1 } };
    const b = { a: 1, nested: { x: 1, y: 2 }, b: 2 };
    expect(canonicalise(a)).toBe(canonicalise(b));
    expect(hashReport(a)).toBe(hashReport(b));
  });

  test('RI-05  signature/signedAt/_hash fields are still excluded from the canonical form', () => {
    const report = { amount: 100, signature: 'sig', signedAt: '2026-01-01', _hash: 'h' };
    const canon  = canonicalise(report);
    expect(canon).not.toMatch(/signature|signedAt|_hash/);
  });
});
