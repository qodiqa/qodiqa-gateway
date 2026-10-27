'use strict';

/**
 * validateContext() — coverage for the callerId whitelist gap.
 *
 *this function's returned object silently dropped callerId
 * (never in the whitelist, never in the returned object literal) even
 * though evaluatePolicyDecision.js already built it into rawContext —
 * every evaluator downstream, including requireConsent.js, saw a context
 * with no callerId key at all. See services/policy/__tests__/
 * requireConsentCallerId.test.js for the end-to-end proof through the real
 * engine + evaluator; this file covers validateContext() in isolation.
 */

const { validateContext, PolicyContextError } = require('../context');

const VALID_RAW = Object.freeze({
  artifact:  { valid: true },
  userId:    'default:key_v1',
  callerId:  'aac53069-9ad2-4f02-8313-915b4b5617e2',
  action:    'openai',
  tenantId:  'default',
  requestId: 'req-1',
  ip:        '203.0.113.4',
  timestamp: 1_700_000_000,
});

describe('validateContext — callerId', () => {
  test('callerId is present in the returned object when supplied', () => {
    const context = validateContext(VALID_RAW);
    expect(context.callerId).toBe('aac53069-9ad2-4f02-8313-915b4b5617e2');
    expect(Object.keys(context)).toContain('callerId');
  });

  test('callerId is null (not dropped, not undefined) when absent', () => {
    const { callerId, ...rest } = VALID_RAW;
    const context = validateContext(rest);
    expect(context.callerId).toBeNull();
    expect(Object.keys(context)).toContain('callerId');
  });

  test('callerId is null when explicitly null', () => {
    const context = validateContext({ ...VALID_RAW, callerId: null });
    expect(context.callerId).toBeNull();
  });

  test('non-string callerId throws PolicyContextError', () => {
    expect(() => validateContext({ ...VALID_RAW, callerId: 12345 }))
      .toThrow(PolicyContextError);
    expect(() => validateContext({ ...VALID_RAW, callerId: 12345 }))
      .toThrow(/context\.callerId must be a string/);
  });

  test('callerId exceeding the max length throws PolicyContextError', () => {
    expect(() => validateContext({ ...VALID_RAW, callerId: 'x'.repeat(257) }))
      .toThrow(/context\.callerId exceeds maximum length/);
  });

  test('callerId at exactly the max length (256) is accepted', () => {
    const context = validateContext({ ...VALID_RAW, callerId: 'x'.repeat(256) });
    expect(context.callerId).toHaveLength(256);
  });

  test('other fields are unaffected by the callerId addition', () => {
    const context = validateContext(VALID_RAW);
    expect(context).toEqual({
      artifact:  { valid: true },
      userId:    'default:key_v1',
      callerId:  'aac53069-9ad2-4f02-8313-915b4b5617e2',
      action:    'openai',
      tenantId:  'default',
      requestId: 'req-1',
      ip:        '203.0.113.4',
      timestamp: 1_700_000_000,
    });
  });
});
