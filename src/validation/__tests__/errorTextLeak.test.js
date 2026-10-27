'use strict';

/**
 * internal error text never reaches a BLOCK body; it stays in the server log.
 * (Also pins's blockHttpStatus addition: CONSENT_STORE_ERROR is a dependency_unavailable reason.)
 *
 *   EL-01  registerNonce: a throwing store → NONCE_STORE_ERROR, details.error = 'NONCE_STORE_UNAVAILABLE', raw text logged
 *   EL-02  registerNonceAndCheckAnomaly: same
 *   EL-03  idempotencyGate.gate: a throwing store → IDEMPOTENCY_STORE_UNAVAILABLE with a stable details.error
 *   EL-04  verifyRequestBinding: a canonicalization error → REQUEST_MISMATCH, issue 'request canonicalization failed'
 *          with no canonicalizer text (fail-closed unchanged)
 *   EL-05  blockHttpStatus: CONSENT_STORE_ERROR → 503 in 'status' mode, still 200 in the default 'decision' mode
 */

jest.mock('../../../services/logger', () => ({ emit: jest.fn() }));
const { emit } = require('../../../services/logger');
const { registerNonce } = require('../registerNonce');
const { registerNonceAndCheckAnomaly } = require('../registerNonceAndCheckAnomaly');
const { verifyRequestBinding } = require('../verifyRequestBinding');
const idempotencyGate = require('../../core/idempotency/idempotencyGate');
const { blockHttpStatus, blockClass } = require('../../api/blockHttpStatus');

const SECRET = 'connect ECONNREFUSED 10.9.8.7:6380 NOSCRIPT sha=deadbeef';
const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const boom = () => { throw new Error(SECRET); };

beforeEach(() => emit.mockClear());
const logged = () => JSON.stringify(emit.mock.calls);

test('EL-01 registerNonce', async () => {
  const r = await registerNonce(RID, Date.now() + 60_000, { _store: { register: boom, registerNonce: boom, set: boom } });
  expect(r).toMatchObject({ ok: false, reason: 'NONCE_STORE_ERROR', details: { error: 'NONCE_STORE_UNAVAILABLE' } });
  expect(JSON.stringify(r)).not.toContain('ECONNREFUSED');
  expect(logged()).toContain('ECONNREFUSED');
});

test('EL-02 registerNonceAndCheckAnomaly', async () => {
  const r = await registerNonceAndCheckAnomaly(RID, Date.now() + 60_000, 'tenant1:key_v1', { _store: { registerAndCheckAnomaly: async () => boom() } });
  expect(r.nonceResult).toMatchObject({ ok: false, reason: 'NONCE_STORE_ERROR', details: { error: 'NONCE_STORE_UNAVAILABLE' } });
  expect(JSON.stringify(r)).not.toContain('ECONNREFUSED');
  expect(logged()).toContain('ECONNREFUSED');
});

test('EL-03 idempotencyGate', async () => {
  const r = await idempotencyGate.gate({
    idempotencyKey: 'k-1', tenantId: 't1', organizationId: null, publicKeyId: 't1:key_v1', callerId: null, provider: 'openai',
    requestHash: 'a'.repeat(64), reservationTtlMs: 1000, _store: { reserve: async () => boom() },
  });
  expect(r).toMatchObject({ outcome: 'store_unavailable', reason: 'IDEMPOTENCY_STORE_UNAVAILABLE', details: { error: 'IDEMPOTENCY_STORE_UNAVAILABLE' } });
  expect(JSON.stringify(r)).not.toContain('ECONNREFUSED');
  expect(logged()).toContain('ECONNREFUSED');
});

test('EL-04 verifyRequestBinding canonicalization failure', () => {
  const artifact = { payload: { requestId: RID, requestHash: 'a'.repeat(64) } };
  // a body containing undefined is rejected by the canonicalizer (computeRequestHash throws)
  const r = verifyRequestBinding(artifact, { method: 'POST', path: '/ai/chat', body: { x: undefined } });
  expect(r.bound).toBe(false);
  expect(r.reason).toBe('REQUEST_MISMATCH');
  expect(r.details).toEqual({ issue: 'request canonicalization failed' });
  expect(emit.mock.calls.map((c) => c[1])).toContain('REQUEST_CANONICALIZATION_FAILED');
});

test('EL-05 CONSENT_STORE_ERROR is a dependency_unavailable reason', () => {
  expect(blockClass('CONSENT_STORE_ERROR')).toBe('dependency_unavailable');
  expect(blockHttpStatus('CONSENT_STORE_ERROR', { QODIQA_BLOCK_HTTP_MODE: 'status' })).toBe(503);
  expect(blockHttpStatus('CONSENT_STORE_ERROR', {})).toBe(200);
});
