'use strict';

/**
 * Caller-substitution prevention — remediation, core proof.
 *
 * Before this remediation, consent's actor_id was always publicKeyId — the
 * shared tenant signing key. Any two callers holding a valid signing
 * credential for the same tenant were therefore indistinguishable to the
 * consent registry: a consent grant issued to "whoever holds this key"
 * authorized every caller of that key, not a specific one.
 *
 * services/policy/evaluators/requireConsent.js now resolves actor_id from
 * context.callerId (the authenticated caller identity bound into the
 * artifact at /sign time) whenever it is present, and does NOT fall back to
 * the shared key when it is — the exact fix for caller substitution. This
 * suite proves that fix directly against the evaluator, with a mocked
 * consent registry standing in for ConsentVerifier (which is unit-tested on
 * its own merits in src/core/consent/consent.test.js — this suite is about
 * requireConsent.js's actor_id RESOLUTION logic, not the registry's lookup
 * mechanics).
 */

const mockVerify = jest.fn();
jest.mock('../src/core/consent', () => ({ verify: (...args) => mockVerify(...args) }));

const { evaluate, validate } = require('../services/policy/evaluators/requireConsent');

const CONFIG = { requireValidArtifact: true, requiredScope: null };

function ctx(overrides = {}) {
  return {
    artifact: { valid: true },
    userId:   'tenant-a:key_v1', // shared tenant signing key — same for every caller below
    action:   'openai',
    tenantId: 'tenant-a',
    requestId: 'req-1',
    ...overrides,
  };
}

beforeEach(() => {
  mockVerify.mockReset();
});

describe('caller-substitution prevention in requireConsent.evaluate()', () => {
  test('validate() still requires requireValidArtifact === true (unchanged)', () => {
    expect(() => validate({ requireValidArtifact: true })).not.toThrow();
    expect(() => validate({ requireValidArtifact: false })).toThrow();
  });

  test('CA-CONSENT-01 successful caller attribution: actor_id resolves to context.callerId, not the shared key', async () => {
    mockVerify.mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED', consentProvenance: { consentId: 'c-A' } });

    const result = await evaluate(ctx({ callerId: 'caller-A' }), CONFIG, {});

    expect(result.pass).toBe(true);
    expect(mockVerify).toHaveBeenCalledWith(expect.objectContaining({ actor_id: 'caller-A' }));
    expect(mockVerify).not.toHaveBeenCalledWith(expect.objectContaining({ actor_id: 'tenant-a:key_v1' }));
  });

  test('CA-CONSENT-02 THE CORE PROOF: a consent grant to caller A does not authorize caller B sharing the same tenant key', async () => {
    // Simulate a real keyed store: only 'caller-A' has an active grant.
    const grants = new Map([['caller-A:openai:tenant-a', { pass: true, reason: 'CONSENT_VERIFIED', consentProvenance: { consentId: 'c-A' } }]]);
    mockVerify.mockImplementation(async ({ actor_id, action, tenant_id }) => {
      const key = `${actor_id}:${action}:${tenant_id}`;
      return grants.get(key) ?? { pass: false, reason: 'CONSENT_NOT_FOUND' };
    });

    // Caller A (has a grant) — passes.
    const resultA = await evaluate(ctx({ callerId: 'caller-A' }), CONFIG, {});
    expect(resultA.pass).toBe(true);

    // Caller B — same tenant, same shared signing key (context.userId), same
    // action, but a DIFFERENT authenticated caller with no grant of its own.
    // this would have resolved actor_id to the shared key
    // and silently ridden on caller A's grant. It must now fail.
    const resultB = await evaluate(ctx({ callerId: 'caller-B' }), CONFIG, {});
    expect(resultB.pass).toBe(false);
    expect(resultB.reason).toBe('CONSENT_NOT_FOUND');
    expect(mockVerify).toHaveBeenLastCalledWith(expect.objectContaining({ actor_id: 'caller-B' }));
  });

  test('CA-CONSENT-03 legacy fallback: an artifact with no callerId (pre-NONREP-1) still resolves actor_id to the shared key', async () => {
    mockVerify.mockResolvedValue({ pass: true, reason: 'CONSENT_VERIFIED', consentProvenance: { consentId: 'c-legacy' } });

    // callerId entirely absent — only possible for an artifact signed
    // before this remediation shipped (self-expires within the max TTL).
    const result = await evaluate(ctx({ callerId: undefined }), CONFIG, {});

    expect(result.pass).toBe(true);
    expect(mockVerify).toHaveBeenCalledWith(expect.objectContaining({ actor_id: 'tenant-a:key_v1' }));
  });

  test('CA-CONSENT-04 CONSENT_CONTEXT_INCOMPLETE when action is missing, regardless of callerId presence', async () => {
    const result = await evaluate(ctx({ callerId: 'caller-A', action: null }), CONFIG, {});
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_CONTEXT_INCOMPLETE');
    expect(mockVerify).not.toHaveBeenCalled();
  });

  test('CA-CONSENT-05 CONSENT_MISSING when the artifact is not valid, before any actor_id resolution', async () => {
    const result = await evaluate({ artifact: { valid: false }, callerId: 'caller-A' }, CONFIG, {});
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_MISSING');
    expect(mockVerify).not.toHaveBeenCalled();
  });

  test('CA-CONSENT-06 CONSENT_EVALUATION_ERROR is fail-closed when the registry throws', async () => {
    mockVerify.mockRejectedValue(new Error('boom'));
    const result = await evaluate(ctx({ callerId: 'caller-A' }), CONFIG, {});
    expect(result.pass).toBe(false);
    expect(result.reason).toBe('CONSENT_EVALUATION_ERROR');
  });
});
