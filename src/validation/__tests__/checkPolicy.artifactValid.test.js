'use strict';

/**
 * (Part 3) remediation — checkPolicy() no longer hardcodes
 * artifactValid: true internally. It is now a required, explicit boolean
 * parameter the caller must supply themselves.
 *
 * Register finding: "checkPolicy() hardcodes valid:true — latent bypass if
 * independently called." Previously, any future/alternate caller of
 * checkPolicy() got an implicit ALLOW-eligible artifactValid=true for free,
 * with no way to opt out, even without ever running validateBoundRequest().
 * Making it an explicit required parameter means a new caller must
 * consciously decide what to pass — they can no longer get it silently.
 */

// A REQUIRE_CONSENT policy is mandatory in every policy set (policyLoader
// fail-closed check) — mock the consent registry so evaluation always passes,
// keeping this suite focused purely on the artifactValid parameter contract
// rather than on consent evaluation itself.
jest.mock('../../core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED' }),
}));

const { checkPolicy } = require('../checkPolicy');
const { validateAndPrepare } = require('../../../services/policy/loader');
const { createStore }        = require('../../../services/policy/store');

const PERMISSIVE_POLICIES = validateAndPrepare({ policies: [{
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true,
  config: { requireValidArtifact: true },
}] });

function makeArtifact() {
  return { payload: { provider: 'openai', callerContext: null } };
}

describe('checkPolicy() requires an explicit artifactValid boolean', () => {
  test('throws a TypeError when artifactValid is omitted entirely', async () => {
    await expect(
      checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-1', makeArtifact(), /* artifactValid omitted */ 'key1', '127.0.0.1', null),
    ).rejects.toThrow(TypeError);
  });

  test('throws when artifactValid is undefined', async () => {
    await expect(
      checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-2', makeArtifact(), undefined, 'key1', '127.0.0.1', null),
    ).rejects.toThrow(/artifactValid must be explicitly passed as a boolean/);
  });

  test('throws when artifactValid is a truthy non-boolean (e.g. the string "true")', async () => {
    await expect(
      checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-3', makeArtifact(), 'true', 'key1', '127.0.0.1', null),
    ).rejects.toThrow(TypeError);
  });

  test('throws when artifactValid is null', async () => {
    await expect(
      checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-4', makeArtifact(), null, 'key1', '127.0.0.1', null),
    ).rejects.toThrow(TypeError);
  });

  test('accepts artifactValid: true and evaluates normally', async () => {
    const result = await checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-5', makeArtifact(), true, 'key1', '127.0.0.1', null);
    expect(result.allowed).toBe(true);
  });

  test('accepts artifactValid: false as a legitimate explicit value — and it actually changes the decision', async () => {
    // This is the core of the fix: artifactValid must be a real,
    // load-bearing signal, not accepted-and-ignored. REQUIRE_CONSENT's
    // requireValidArtifact config means an explicit false here must BLOCK,
    // proving the parameter genuinely reaches policy evaluation rather than
    // being silently coerced to true internally (the original bug).
    const result = await checkPolicy(() => PERMISSIVE_POLICIES, createStore(), 'req-6', makeArtifact(), false, 'key1', '127.0.0.1', null);
    expect(result.allowed).toBe(false);
  });
});
