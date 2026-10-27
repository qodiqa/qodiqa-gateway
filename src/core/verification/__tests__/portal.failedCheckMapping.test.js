'use strict';

/** every block reason validateArtifact() emits maps to its own portal check, never SCHEMA by default. */

jest.mock('../../../validation/validateArtifact', () => ({ validateArtifact: jest.fn() }));

const { validateArtifact } = require('../../../validation/validateArtifact');
const portal = require('../portal');

const CASES = [
  ['TIME_SKEW_EXCEEDED', 'CLOCK_SKEW'],
  ['EXPIRED', 'NOT_EXPIRED'],
  ['FUTURE_TIMESTAMP', 'TIMESTAMP'],
  ['KEY_REVOKED', 'KEY_VALID'],
  ['KEY_DEPRECATED', 'KEY_VALID'],
  ['KEY_ARCHIVED', 'KEY_VALID'],
  ['KEY_NOT_YET_ACTIVE', 'KEY_VALID'],
  ['KEY_NOT_ACTIVE_AT_SIGNING_TIME', 'KEY_VALID'],
  ['KEY_STATUS_UNKNOWN', 'KEY_VALID'],
  ['SIGNING_TIME_UNKNOWN', 'KEY_VALID'],
  ['KEY_NOT_FOUND', 'KEY_VALID'],
  ['INVALID_SIGNATURE', 'SIGNATURE'],
  ['INVALID_ARTIFACT', 'SCHEMA'],
];

describe('runPortalChecks — failedCheck mapping', () => {
  test.each(CASES)('FC-%s -> %s', (reason, expected) => {
    validateArtifact.mockReturnValueOnce({ decision: 'BLOCK', reason, details: {} });
    const out = portal.runPortalChecks({ payload: {} });
    expect(out.valid).toBe(false);
    expect(out.failedCheck).toBe(expected);
  });
});
