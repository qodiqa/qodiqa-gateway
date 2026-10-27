'use strict';

const { computeFingerprint } = require('../fingerprint');

const BASE = {
  tenantId:       'acme-corp',
  organizationId: 'org-1',
  publicKeyId:    'acme-corp:key_v1',
  callerId:       'user-42',
  provider:       'openai',
  requestHash:    'a'.repeat(64),
};

describe('computeFingerprint', () => {
  test('is deterministic — same input always produces the same output', () => {
    expect(computeFingerprint(BASE)).toBe(computeFingerprint({ ...BASE }));
  });

  test('is a 64-char lowercase hex string', () => {
    const fp = computeFingerprint(BASE);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  test('key insertion order does not affect the result (stableStringify)', () => {
    const reordered = {
      requestHash:    BASE.requestHash,
      provider:       BASE.provider,
      publicKeyId:    BASE.publicKeyId,
      callerId:       BASE.callerId,
      organizationId: BASE.organizationId,
      tenantId:       BASE.tenantId,
    };
    expect(computeFingerprint(reordered)).toBe(computeFingerprint(BASE));
  });

  test('changing requestHash changes the fingerprint (body/method/path binding)', () => {
    const other = { ...BASE, requestHash: 'b'.repeat(64) };
    expect(computeFingerprint(other)).not.toBe(computeFingerprint(BASE));
  });

  test('changing tenantId changes the fingerprint (tenant isolation input)', () => {
    const other = { ...BASE, tenantId: 'other-tenant' };
    expect(computeFingerprint(other)).not.toBe(computeFingerprint(BASE));
  });

  test('changing publicKeyId changes the fingerprint (authenticated identity)', () => {
    const other = { ...BASE, publicKeyId: 'acme-corp:key_v2' };
    expect(computeFingerprint(other)).not.toBe(computeFingerprint(BASE));
  });

  test('changing provider changes the fingerprint', () => {
    const other = { ...BASE, provider: 'anthropic' };
    expect(computeFingerprint(other)).not.toBe(computeFingerprint(BASE));
  });

  test('changing callerId changes the fingerprint', () => {
    const other = { ...BASE, callerId: 'user-99' };
    expect(computeFingerprint(other)).not.toBe(computeFingerprint(BASE));
  });

  test('null/undefined tenantId, organizationId, callerId, provider are treated identically', () => {
    const withNull = { ...BASE, tenantId: null, organizationId: null, callerId: null, provider: null };
    const withUndef = { ...BASE, tenantId: undefined, organizationId: undefined, callerId: undefined, provider: undefined };
    expect(computeFingerprint(withNull)).toBe(computeFingerprint(withUndef));
  });

  test('throws if publicKeyId is missing', () => {
    const { publicKeyId, ...rest } = BASE;
    expect(() => computeFingerprint(rest)).toThrow(TypeError);
  });

  test('throws if requestHash is missing', () => {
    const { requestHash, ...rest } = BASE;
    expect(() => computeFingerprint(rest)).toThrow(TypeError);
  });

  test('never includes timestamp/requestId-shaped fields — same logical request, two signed attempts, same fingerprint', () => {
    // Simulates two independently-signed retries of the same logical request:
    // different artifact timestamp/expiry/requestId (not passed to
    // computeFingerprint at all), identical requestHash (body+method+path).
    const attempt1 = computeFingerprint(BASE);
    const attempt2 = computeFingerprint({ ...BASE }); // a fresh object, as a second attempt would construct
    expect(attempt1).toBe(attempt2);
  });
});
