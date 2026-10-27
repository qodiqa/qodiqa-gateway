'use strict';

/**
 * end-to-end proof that a real context, real engine, and real
 * requireConsent evaluator resolve the consent lookup against callerId,
 * not the shared key-identity (userId).
 *
 * This is the disambiguation case live-reproduced against a real PG-backed
 * boot before this fix (:355-365, and this
 * session's own current-HEAD re-witness): a consent grant issued to a
 * distinct caller identity was ignored, and the lookup resolved against the
 * tenant's shared signing-key identity instead — permitting caller
 * substitution.
 *
 * It is also the exact class of regression the pre-existing
 * evaluatePolicyDecision.test.js could never catch: that suite mocks
 * ../engine entirely (`jest.mock('../engine', ...)`), so validateContext()'s
 * silent callerId-stripping (the actual root cause) never had a chance to
 * surface there — engine.evaluate() itself was never called for real. Here
 * only src/core/consent (the actual DB/cache boundary) is mocked; engine.js,
 * context.js, and requireConsent.js all run unmocked.
 */

const mockVerify = jest.fn();
jest.mock('../../../src/core/consent', () => ({ verify: (...args) => mockVerify(...args) }));

const { evaluate } = require('../engine');

const REQUIRE_CONSENT_POLICY = Object.freeze({
  id: 'POL-CONSENT', type: 'REQUIRE_CONSENT', priority: 10, enabled: true, currentVersion: 1,
  config: { requireValidArtifact: true },
});

// Mirrors the live probe: one shared tenant signing-key identity, and a
// genuinely distinct caller identity that signs artifacts under that same key.
const KEY_IDENTITY    = 'dev-local:key_v1';
const CALLER_IDENTITY = 'aac53069-9ad2-4f02-8313-915b4b5617e2';

function makeContext(overrides = {}) {
  return {
    artifact:  { valid: true },
    userId:    KEY_IDENTITY,
    callerId:  CALLER_IDENTITY,
    action:    'openai',
    tenantId:  'dev-local',
    requestId: 'req-f2-test',
    ip:        '203.0.113.4',
    timestamp: 1_700_000_000,
    ...overrides,
  };
}

beforeEach(() => jest.clearAllMocks());

describe('real engine + real requireConsent resolve consent against callerId', () => {
  test('disambiguation case: a grant issued to callerId is found — the lookup uses callerId, not the shared key-identity', async () => {
    // Simulates a consent grant that exists ONLY for the distinct caller
    // identity — the key-identity has no grant of its own, exactly like
    // the live probe (a fresh disambiguation identity, grant issued
    // specifically to its UUID).
    mockVerify.mockImplementation(async ({ actor_id }) => {
      if (actor_id === CALLER_IDENTITY) return { pass: true, reason: 'CONSENT_VERIFIED' };
      return { pass: false, reason: 'CONSENT_NOT_FOUND' };
    });

    const decision = await evaluate(makeContext(), [REQUIRE_CONSENT_POLICY], {}, { requestId: 'req-f2-test' });

    expect(mockVerify).toHaveBeenCalledWith(expect.objectContaining({ actor_id: CALLER_IDENTITY }));
    expect(mockVerify).not.toHaveBeenCalledWith(expect.objectContaining({ actor_id: KEY_IDENTITY }));
    expect(decision.decision).toBe('EXECUTE');
  });

  test('the reverse proves the point: a grant issued only to the key-identity does not satisfy a distinct caller', async () => {
    // If the lookup were still (bug-consistent) resolving against userId,
    // this would incorrectly pass. It must BLOCK.
    mockVerify.mockImplementation(async ({ actor_id }) => {
      if (actor_id === KEY_IDENTITY) return { pass: true, reason: 'CONSENT_VERIFIED' };
      return { pass: false, reason: 'CONSENT_NOT_FOUND' };
    });

    const decision = await evaluate(makeContext(), [REQUIRE_CONSENT_POLICY], {}, { requestId: 'req-f2-test' });

    expect(mockVerify).toHaveBeenCalledWith(expect.objectContaining({ actor_id: CALLER_IDENTITY }));
    expect(decision.decision).toBe('BLOCK');
    expect(decision.reason).toBe('CONSENT_NOT_FOUND');
  });

  test('falls back to userId only when callerId is genuinely absent (legacy pre-NONREP-1 artifact)', async () => {
    mockVerify.mockImplementation(async ({ actor_id }) => {
      if (actor_id === KEY_IDENTITY) return { pass: true, reason: 'CONSENT_VERIFIED' };
      return { pass: false, reason: 'CONSENT_NOT_FOUND' };
    });

    const decision = await evaluate(makeContext({ callerId: undefined }), [REQUIRE_CONSENT_POLICY], {}, { requestId: 'req-f2-test' });

    expect(mockVerify).toHaveBeenCalledWith(expect.objectContaining({ actor_id: KEY_IDENTITY }));
    expect(decision.decision).toBe('EXECUTE');
  });
});
