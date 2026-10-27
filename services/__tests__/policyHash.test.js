'use strict';

const { computePolicyHash, policyHashesEqual } = require('../policyHash');

const POLICY_A = [{ id: 'POL-001', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, config: { requireValidArtifact: true } }];
const POLICY_B = [{ id: 'POL-002', type: 'BLOCK_IP', priority: 20, enabled: true, config: { blocklist: ['1.2.3.4'], cidrs: [] } }];

// Keys in different order — stableStringify must normalise to the same digest.
const POLICY_A_REORDERED = [{ config: { requireValidArtifact: true }, enabled: true, id: 'POL-001', priority: 10, type: 'REQUIRE_CONSENT' }];

describe('computePolicyHash', () => {
  test('PHASH-CANON-01  identical policies → same hash', () => {
    expect(computePolicyHash(POLICY_A)).toBe(computePolicyHash(POLICY_A));
  });

  test('PHASH-CANON-02  reordered object keys → same hash', () => {
    expect(computePolicyHash(POLICY_A)).toBe(computePolicyHash(POLICY_A_REORDERED));
  });

  test('PHASH-CANON-03  different policy content → different hash', () => {
    expect(computePolicyHash(POLICY_A)).not.toBe(computePolicyHash(POLICY_B));
  });

  test('PHASH-CANON-04  multi-policy array reordered keys → same hash', () => {
    const forward  = [POLICY_A[0], POLICY_B[0]];
    const reordered = [
      { config: POLICY_A[0].config, enabled: POLICY_A[0].enabled, id: POLICY_A[0].id, priority: POLICY_A[0].priority, type: POLICY_A[0].type },
      { config: POLICY_B[0].config, enabled: POLICY_B[0].enabled, id: POLICY_B[0].id, priority: POLICY_B[0].priority, type: POLICY_B[0].type },
    ];
    expect(computePolicyHash(forward)).toBe(computePolicyHash(reordered));
  });

  test('PHASH-CANON-05  output is 64-char lowercase hex', () => {
    expect(computePolicyHash(POLICY_A)).toMatch(/^[a-f0-9]{64}$/);
  });

  test('PHASH-CANON-06  domain-separated — differs from plain SHA-256 of same input', () => {
    const crypto          = require('crypto');
    const stableStringify = require('../utils/stableStringify');
    const plainHash = crypto.createHash('sha256')
      .update(stableStringify(POLICY_A), 'utf8')
      .digest('hex');
    // The domain prefix changes the digest — must NOT be equal.
    expect(computePolicyHash(POLICY_A)).not.toBe(plainHash);
  });

  test('PHASH-CANON-07  empty array throws', () => {
    expect(() => computePolicyHash([])).toThrow();
  });

  test('PHASH-CANON-08  non-array throws', () => {
    expect(() => computePolicyHash(null)).toThrow();
    expect(() => computePolicyHash({})).toThrow();
    expect(() => computePolicyHash('string')).toThrow();
  });

  test('PHASH-CANON-09  stable across repeated calls (no random component)', () => {
    const h1 = computePolicyHash(POLICY_A);
    const h2 = computePolicyHash(POLICY_A);
    const h3 = computePolicyHash(POLICY_A);
    expect(h1).toBe(h2);
    expect(h2).toBe(h3);
  });
});

describe('policyHashesEqual — audit/forensic use only', () => {
  test('PHASH-EQ-01  same hash string → true', () => {
    const h = computePolicyHash(POLICY_A);
    expect(policyHashesEqual(h, h)).toBe(true);
  });

  test('PHASH-EQ-02  hashes of identical policies → true', () => {
    const h1 = computePolicyHash(POLICY_A);
    const h2 = computePolicyHash(POLICY_A_REORDERED);
    expect(policyHashesEqual(h1, h2)).toBe(true);
  });

  test('PHASH-EQ-03  hashes of different policies → false', () => {
    const h1 = computePolicyHash(POLICY_A);
    const h2 = computePolicyHash(POLICY_B);
    expect(policyHashesEqual(h1, h2)).toBe(false);
  });

  test('PHASH-EQ-04  non-string inputs → false (no throw)', () => {
    const h = computePolicyHash(POLICY_A);
    expect(policyHashesEqual(h, null)).toBe(false);
    expect(policyHashesEqual(null, h)).toBe(false);
    expect(policyHashesEqual(null, null)).toBe(false);
  });

  test('PHASH-EQ-05  wrong-length inputs → false (no throw)', () => {
    const h = computePolicyHash(POLICY_A);
    expect(policyHashesEqual(h, h.slice(0, 32))).toBe(false);
    expect(policyHashesEqual('', h)).toBe(false);
  });

  test('PHASH-EQ-06  runtime/test parity — both paths use same algorithm', () => {
    // Simulate signing path: compute hash at signing time
    const signingHash = computePolicyHash(POLICY_A);
    // Simulate enforcement path: compute hash at execution time (same policies)
    const enforcementHash = computePolicyHash(POLICY_A_REORDERED);
    // Forensic comparison must confirm no drift
    expect(policyHashesEqual(signingHash, enforcementHash)).toBe(true);
  });
});

// ── Derived/cache fields (Task #12): loader.js's evaluator.preprocess() step ──
// injects internal, underscore-prefixed cache fields (blockIp.js's
// `_blocklistSet: new Set(...)`, timeWindow.js's `_windows: [{days: new
// Set(...)}]`) alongside the canonical config, for O(1) runtime lookups.
// computePolicyHash is called on this preprocessed form on the live
// enforcement hot path (middleware/enforcePolicy.js). A Set has no defined
// canonical representation (src/utils/stableStringify.js), so these fields
// must be stripped before hashing — otherwise every policy set hashes
// identically regardless of blocklist/window content, defeating the
// fingerprint's entire purpose as a forensic record.

describe('computePolicyHash — derived/cache field handling', () => {
  const blockIp = require('../policy/evaluators/blockIp');

  test('PHASH-DERIVED-01  preprocessed config (with _blocklistSet) does not throw', () => {
    const cfg = blockIp.preprocess({ blocklist: ['1.2.3.4'], cidrs: [] });
    const policies = [{ id: 'P1', type: 'BLOCK_IP', priority: 10, enabled: true, config: cfg }];
    expect(() => computePolicyHash(policies)).not.toThrow();
  });

  test('PHASH-DERIVED-02  different blocklist contents produce different hashes (collision guard)', () => {
    const cfgA = blockIp.preprocess({ blocklist: ['1.2.3.4'], cidrs: [] });
    const cfgB = blockIp.preprocess({ blocklist: ['5.6.7.8'], cidrs: [] });
    const policiesA = [{ id: 'P1', type: 'BLOCK_IP', priority: 10, enabled: true, config: cfgA }];
    const policiesB = [{ id: 'P1', type: 'BLOCK_IP', priority: 10, enabled: true, config: cfgB }];
    expect(computePolicyHash(policiesA)).not.toBe(computePolicyHash(policiesB));
  });

  test('PHASH-DERIVED-03  raw (pre-preprocess) and preprocessed forms of the same config hash identically', () => {
    const raw = { blocklist: ['1.2.3.4'], cidrs: [] };
    const preprocessed = blockIp.preprocess(raw);
    const rawPolicies    = [{ id: 'P1', type: 'BLOCK_IP', priority: 10, enabled: true, config: raw }];
    const preppedPolicies = [{ id: 'P1', type: 'BLOCK_IP', priority: 10, enabled: true, config: preprocessed }];
    expect(computePolicyHash(rawPolicies)).toBe(computePolicyHash(preppedPolicies));
  });

  test('PHASH-DERIVED-04  underscore-prefixed fields are excluded even without a Set (plain derived data)', () => {
    const withDerived   = [{ id: 'P1', type: 'X', priority: 1, enabled: true, config: { a: 1, _cache: 'anything' } }];
    const withoutDerived = [{ id: 'P1', type: 'X', priority: 1, enabled: true, config: { a: 1 } }];
    expect(computePolicyHash(withDerived)).toBe(computePolicyHash(withoutDerived));
  });

  test('PHASH-DERIVED-05  a __proto__-keyed config still throws (defense in depth, not silently stripped)', () => {
    const poisoned = [{ id: 'P1', type: 'X', priority: 1, enabled: true, config: JSON.parse('{"__proto__":1,"a":2}') }];
    expect(() => computePolicyHash(poisoned)).toThrow();
  });
});
