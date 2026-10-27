'use strict';

/**
 * Task #12 — canonical serializer edge cases.
 *
 * Targeted regression coverage for the fix applied to
 * src/core/policy/provenance.js's `canonicalJson()`/`computePolicyHash()`:
 * it previously rolled its own recursive JSON.stringify-based canonicalizer
 * instead of delegating to the shared src/utils/stableStringify.js — the
 * codebase's own stated invariant ("All ... policy fingerprints MUST import
 * this module. No duplicate serializers elsewhere.") that this violated.
 *
 * The local implementation also had a real correctness bug: for an
 * undefined-valued property, `JSON.stringify(undefined)` returns the actual
 * JS value `undefined` (not a string), which string-concatenation coerces
 * to the literal text "undefined" — producing syntactically invalid "JSON"
 * output — instead of the spec-correct `null` substitution stableStringify
 * provides.
 */

const { computePolicyHash, versionsToCSV } = require('./provenance');

describe('provenance.computePolicyHash — canonical serializer migration', () => {
  test('PROV-01  key order does not affect the hash', () => {
    const a = { rules: [{ effect: 'allow', id: 'p1' }], version: 2 };
    const b = { version: 2, rules: [{ id: 'p1', effect: 'allow' }] };
    expect(computePolicyHash(a)).toBe(computePolicyHash(b));
  });

  test('PROV-02  different content produces different hashes', () => {
    const a = { version: 1 };
    const b = { version: 2 };
    expect(computePolicyHash(a)).not.toBe(computePolicyHash(b));
  });

  test('PROV-03  output is a 64-char lowercase hex SHA-256 digest', () => {
    expect(computePolicyHash({ version: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });

  test('PROV-04  undefined-valued fields no longer produce invalid "JSON" output', () => {
    // Pre-fix, the local implementation's canonicalJson({x: undefined})
    // embedded the literal unquoted text "undefined" via string
    // concatenation. Now it correctly substitutes null (spec §6.1) and
    // returns a real digest rather than throwing/hashing garbage.
    expect(() => computePolicyHash({ x: undefined, y: 1 })).not.toThrow();
    expect(computePolicyHash({ x: undefined, y: 1 })).toBe(computePolicyHash({ x: null, y: 1 }));
  });

  test('PROV-05  a "__proto__" own key is now rejected rather than silently mishandled', () => {
    const poisoned = JSON.parse('{"__proto__":1,"amount":100}');
    expect(() => computePolicyHash(poisoned)).toThrow();
  });

  test('PROV-06  NaN/Infinity fields are now rejected rather than silently coerced', () => {
    expect(() => computePolicyHash({ score: NaN })).toThrow();
    expect(() => computePolicyHash({ score: Infinity })).toThrow();
  });
});

// ── INJ-7: versionsToCSV formula-injection protection ────────────────────────

describe('provenance.versionsToCSV — INJ-7 formula injection protection', () => {
  test('a change_reason starting with "=" is neutralized with a leading quote', () => {
    const csv = versionsToCSV([{
      version_number: 1, event_type: 'UPDATE', occurred_at: '2024-01-01T00:00:00Z',
      actor_id: 'a1', actor_username: 'alice', actor_role: 'admin', source_ip: '127.0.0.1',
      change_reason: '=cmd|\'/C calc\'!A0', policy_hash: 'h1', previous_policy_hash: null,
    }]);
    const dataRow = csv.split('\n')[1];
    expect(dataRow).toContain('"\'=cmd');
  });

  test('an ordinary change_reason is unaffected', () => {
    const csv = versionsToCSV([{
      version_number: 1, event_type: 'UPDATE', occurred_at: '2024-01-01T00:00:00Z',
      actor_id: 'a1', actor_username: 'alice', actor_role: 'admin', source_ip: '127.0.0.1',
      change_reason: 'quarterly policy update', policy_hash: 'h1', previous_policy_hash: null,
    }]);
    expect(csv).toContain('quarterly policy update');
  });
});
