'use strict';

/** /sign's caller `payload` may not carry server-owned claims and is bounded. */

const { signBodySchema, RESERVED_PAYLOAD_KEYS, MAX_PAYLOAD_BYTES } = require('../sign.schema');

const base = (payload) => ({ request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hi' } }, ...(payload === undefined ? {} : { payload }) });

describe('signBodySchema — payload', () => {
  test('SP-01 free-form application context (documented: e.g. userId) is still accepted', () => {
    expect(signBodySchema.safeParse(base({ userId: 'u-1', provider: 'local', note: 'x' })).success).toBe(true);
    expect(signBodySchema.safeParse(base()).success).toBe(true);
  });

  test('SP-02 server-owned claim names are listed (they are overridden by /sign, with a WARN, not accepted)', () => {
    expect([...RESERVED_PAYLOAD_KEYS].sort()).toEqual(['callerContext', 'policyHash', 'requestHash', 'requestId', 'tenantId']);
  });

  test('SP-03 an oversized payload is refused', () => {
    expect(signBodySchema.safeParse(base({ blob: 'a'.repeat(MAX_PAYLOAD_BYTES + 1) })).success).toBe(false);
    expect(signBodySchema.safeParse(base({ blob: 'a'.repeat(100) })).success).toBe(true);
  });

  test('SP-04 a too-deeply nested payload is refused', () => {
    let deep = {}; let cur = deep;
    for (let i = 0; i < 12; i++) { cur.n = {}; cur = cur.n; }
    expect(signBodySchema.safeParse(base(deep)).success).toBe(false);
  });
});
