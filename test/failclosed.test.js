'use strict';

/**
 * Fail-closed enforcement tests.
 *
 * Verifies that EVERY uncertainty or failure path in the policy evaluation
 * stack produces an explicit BLOCK — never an implicit or accidental ALLOW.
 *
 * Policy Engine consolidation note: this suite previously exercised a second,
 * unused policy evaluator (`policy/engine.js` + `policy/evaluator.js`) that
 * was never wired into any live request path. That duplicate engine has been
 * removed; `services/policy/engine.js` is the single canonical Policy Engine
 * (see `docs/guides/policy-simulation.md` §"Single evaluator"). This suite exercises
 * the canonical engine directly. It previously also exercised
 * `middleware/enforcePolicy.js`, believed at the time to be the real
 * production HTTP path — code-hygiene batch confirmed
 * `enforcePolicy.js` was itself dead (required only by its own tests; every
 * real route resolves through `src/validation/checkPolicy.js` instead), and
 * removed it along with those tests here.
 *
 * Coverage:
 *   1.  Canonical engine: empty/invalid policy set → BLOCK
 *   2.  Canonical engine: invalid context           → BLOCK
 *   3.  Canonical engine: evaluator error            → BLOCK
 *   4.  Canonical engine: valid policy set           → EXECUTE
 *   5.  Canonical engine: decision is always a defined EXECUTE/BLOCK string
 */

// Mock the consent registry so REQUIRE_CONSENT resolves synchronously without
// a live Redis/PostgreSQL connection — mirrors services/policy/policyEngine.test.js.
jest.mock('../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { evaluate }   = require('../services/policy/engine');

// ── Fixtures — canonical engine ───────────────────────────────────────────────

const VALID_CONTEXT = Object.freeze({
  artifact: { valid: true },
  userId:   'user-1',
  action:   'inference',
});

const CONSENT_POLICY = Object.freeze({
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
});

// ── 1–5. services/policy/engine — fail-closed contract (canonical engine) ────

describe('services/policy/engine#evaluate — fail-closed contract', () => {
  test('valid context + enabled REQUIRE_CONSENT policy → decision EXECUTE', async () => {
    const d = await evaluate(VALID_CONTEXT, [CONSENT_POLICY], {});
    expect(d.decision).toBe('EXECUTE');
  });

  test('invalid context (non-object) → decision BLOCK', async () => {
    const d = await evaluate(null, [CONSENT_POLICY], {});
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('INVALID_CONTEXT');
  });

  test('empty policy array → decision BLOCK NO_POLICIES_LOADED', async () => {
    const d = await evaluate(VALID_CONTEXT, [], {});
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('NO_POLICIES_LOADED');
  });

  test('non-array policies → decision BLOCK NO_POLICIES_LOADED', async () => {
    const d = await evaluate(VALID_CONTEXT, null, {});
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('NO_POLICIES_LOADED');
  });

  test('all policies disabled → decision BLOCK NO_ENABLED_POLICIES', async () => {
    const disabled = { ...CONSENT_POLICY, enabled: false };
    const d = await evaluate(VALID_CONTEXT, [disabled], {});
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('NO_ENABLED_POLICIES');
  });

  test('unknown policy type → decision BLOCK EVALUATOR_MISSING', async () => {
    const unknown = { id: 'POL-X', type: 'NOT_A_REAL_TYPE', priority: 0, enabled: true, config: {} };
    const d = await evaluate(VALID_CONTEXT, [unknown], {});
    expect(d.decision).toBe('BLOCK');
    expect(d.reason).toBe('EVALUATOR_MISSING');
  });

  test('artifact.valid = false → decision BLOCK (REQUIRE_CONSENT denies)', async () => {
    const invalidArtifactCtx = { ...VALID_CONTEXT, artifact: { valid: false } };
    const d = await evaluate(invalidArtifactCtx, [CONSENT_POLICY], {});
    expect(d.decision).toBe('BLOCK');
  });

  test('result always has a decision field of EXECUTE or BLOCK — never boolean, never undefined', async () => {
    const cases = await Promise.all([
      evaluate(VALID_CONTEXT, [CONSENT_POLICY], {}),
      evaluate(VALID_CONTEXT, [], {}),
      evaluate(null, [CONSENT_POLICY], {}),
      evaluate(VALID_CONTEXT, [{ ...CONSENT_POLICY, enabled: false }], {}),
    ]);
    for (const d of cases) {
      expect(typeof d.decision).toBe('string');
      expect(['EXECUTE', 'BLOCK']).toContain(d.decision);
      expect(d).not.toHaveProperty('allowed');
    }
  });
});
