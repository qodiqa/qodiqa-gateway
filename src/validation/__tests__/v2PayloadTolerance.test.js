'use strict';

/**
 * (tolerance spike, pinned): an artifact whose payload carries the proposed protocol-V2 claims (v, bind, model, limits) is accepted by the
 * current gateway validator exactly like a V1 artifact, and the new claims are covered by the signature (changing one breaks it). This is what lets
 * V2 be introduced additively: old verifiers keep working on V2 artifacts, they just do not enforce the new claims.
 * Cross-language counterparts (JS SDK, Python SDK): (verify-js.js, verify.py).
 */

const { validateArtifact } = require('../validateArtifact');
const { signArtifact } = require('../signArtifact');
const { getActiveKey } = require('../../../services/artifact/keyStore');

let key;
beforeAll(() => { key = getActiveKey('default'); });

const v2Payload = () => ({
  v: 2,
  requestId: 'tol-1', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64),
  model: 'stub-model',
  bind: { query: [['x', '1']], headers: ['content-type'] },
  limits: { maxTokens: 256, maxCostMicros: 1000 },
});

function sign(payload) {
  const now = Date.now();
  return signArtifact({ payload, timestamp: now, expiry: now + 60_000, publicKeyId: key.keyId }, key.privDer);
}

describe('V2-shaped payload claims against the current validator', () => {
  test('F3-TOL-01 a payload with v/bind/model/limits validates (EXECUTE) like a V1 payload', () => {
    expect(validateArtifact(sign(v2Payload())).decision).toBe('EXECUTE');
    expect(validateArtifact(sign({ requestId: 'tol-0', requestHash: 'a'.repeat(64), policyHash: 'b'.repeat(64) })).decision).toBe('EXECUTE');
  });

  test.each([
    ['v', (p) => { p.v = 1; }],
    ['model', (p) => { p.model = 'other-model'; }],
    ['limits.maxTokens', (p) => { p.limits.maxTokens = 999999; }],
    ['bind.headers', (p) => { p.bind.headers.push('authorization'); }],
    ['bind.query', (p) => { p.bind.query = []; }],
  ])('F3-TOL-02 changing %s after signing breaks the signature', (_n, mutate) => {
    const art = sign(v2Payload());
    const forged = JSON.parse(JSON.stringify(art));
    mutate(forged.payload);
    expect(validateArtifact(forged)).toMatchObject({ decision: 'BLOCK', reason: 'INVALID_SIGNATURE' });
  });
});
