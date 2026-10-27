'use strict';

/**
 * Request-binding test suite — QODIQA V2
 *
 * Covers every attack vector listed in the security brief plus additional
 * adversarial cases.  Every test that must BLOCK must produce
 * { bound: false, reason: 'REQUEST_MISMATCH' } or an explicit error throw.
 *
 * Test categories:
 *   1.  Core binding (TC-01 … TC-07)
 *   2.  Canonicalization correctness (TC-08 … TC-10)
 *   3.  Adversarial (ADV-01 … ADV-08)
 *   4.  computeRequestHash — input validation
 *   5.  signBoundArtifact — input validation
 *   6.  verifyRequestBinding — edge cases
 *   7.  Full-pipeline: validateArtifact + verifyRequestBinding
 */

const crypto = require('crypto');

const { computeRequestHash, REQUEST_DOMAIN } = require('../requestHash');
const { signBoundArtifact }                  = require('../signBoundArtifact');
const { verifyRequestBinding }               = require('../verifyRequestBinding');
const { validateArtifact }                   = require('../validateArtifact');
const { signArtifact }                       = require('../signArtifact');
const { canonicalizeEnvelope }               = require('../canonicalize');
const { getActiveKey }                       = require('../../../services/artifact/keyStore');

// ── Helpers ───────────────────────────────────────────────────────────────────

let KEY;

beforeAll(() => {
  KEY = getActiveKey('default');
});

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return {
    payload,
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
  };
}

function buildBound(request, extraPayload = {}) {
  return signBoundArtifact(request, freshEnvelope(extraPayload), KEY.privDer);
}

// ── 1. Core binding tests ──────────────────────────────────────────────────────

describe('request binding — core', () => {

  // TC-01: full happy path
  test('TC-01  valid request → ALLOW and bound', () => {
    const req      = { method: 'POST', path: '/api/query', body: { userId: 'alice', resource: 'ds-42' } };
    const artifact = buildBound(req);

    const validation = validateArtifact(artifact);
    expect(validation.decision).toBe('EXECUTE');
    expect(validation.reason).toBe('ALL_CHECKS_PASSED');

    const binding = verifyRequestBinding(artifact, req);
    expect(binding.bound).toBe(true);
  });

  // TC-02: body modification
  test('TC-02  body modified after signing → not bound', () => {
    const req      = { method: 'POST', path: '/api/query', body: { userId: 'alice', resource: 'ds-42' } };
    const tampered = { method: 'POST', path: '/api/query', body: { userId: 'alice', resource: 'ds-99' } };
    const artifact = buildBound(req);

    const result = verifyRequestBinding(artifact, tampered);
    expect(result.bound).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
  });

  // TC-03: path modification
  test('TC-03  path modified after signing → not bound', () => {
    const req      = { method: 'POST', path: '/api/query',  body: { op: 'read' } };
    const tampered = { method: 'POST', path: '/api/admin',  body: { op: 'read' } };
    const artifact = buildBound(req);

    const result = verifyRequestBinding(artifact, tampered);
    expect(result.bound).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
  });

  // TC-04: method modification
  test('TC-04  method modified after signing → not bound', () => {
    const req      = { method: 'GET',  path: '/api/data', body: {} };
    const tampered = { method: 'POST', path: '/api/data', body: {} };
    const artifact = buildBound(req);

    const result = verifyRequestBinding(artifact, tampered);
    expect(result.bound).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
  });

  // TC-05: replay to different endpoint
  test('TC-05  same artifact replayed on different endpoint → not bound', () => {
    const original = { method: 'POST', path: '/api/data/read',   body: { userId: 'bob' } };
    const other    = { method: 'POST', path: '/api/data/delete', body: { userId: 'bob' } };
    const artifact = buildBound(original);

    expect(verifyRequestBinding(artifact, original).bound).toBe(true);
    expect(verifyRequestBinding(artifact, other).bound).toBe(false);
    expect(verifyRequestBinding(artifact, other).reason).toBe('REQUEST_MISMATCH');
  });

  // TC-06: replay with different method
  test('TC-06  same artifact replayed with different HTTP method → not bound', () => {
    const original = { method: 'GET',    path: '/api/resource', body: {} };
    const replay   = { method: 'DELETE', path: '/api/resource', body: {} };
    const artifact = buildBound(original);

    expect(verifyRequestBinding(artifact, original).bound).toBe(true);
    expect(verifyRequestBinding(artifact, replay).bound).toBe(false);
  });

  // TC-07: missing requestHash
  test('TC-07  missing requestHash in payload → not bound', () => {
    const req = { method: 'POST', path: '/api/query', body: { userId: 'carol' } };
    const now = Date.now();
    // Build a valid artifact WITHOUT requestHash in payload (using signArtifact directly)
    const artifact = signArtifact({
      payload:     { userId: 'carol' },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    const result = verifyRequestBinding(artifact, req);
    expect(result.bound).toBe(false);
    expect(result.reason).toBe('REQUEST_MISMATCH');
  });

});

// ── 2. Canonicalization correctness ───────────────────────────────────────────

describe('request binding — canonicalization', () => {

  // TC-08: key order in body does not affect hash
  test('TC-08  different body key order → same hash → bound', () => {
    const body1 = { action: 'read', userId: 'alice' };
    const body2 = { userId: 'alice', action: 'read' };

    const h1 = computeRequestHash('POST', '/api/q', body1);
    const h2 = computeRequestHash('POST', '/api/q', body2);
    expect(h1).toBe(h2);

    // An artifact signed with body1 must verify against body2 request.
    const artifact = buildBound({ method: 'POST', path: '/api/q', body: body1 });
    expect(verifyRequestBinding(artifact, { method: 'POST', path: '/api/q', body: body2 }).bound).toBe(true);
  });

  // TC-09: whitespace in JSON wire format is irrelevant after parsing
  test('TC-09  body parsed from JSON with different whitespace → same hash', () => {
    const compact = JSON.parse('{"userId":"alice","action":"read"}');
    const pretty  = JSON.parse('{ "userId": "alice", "action": "read" }');

    const h1 = computeRequestHash('POST', '/api/q', compact);
    const h2 = computeRequestHash('POST', '/api/q', pretty);
    expect(h1).toBe(h2);
  });

  // TC-10: method is case-normalized
  test('TC-10  method case is normalized — lowercase = uppercase', () => {
    const lowerH = computeRequestHash('post', '/api/q', { x: 1 });
    const upperH = computeRequestHash('POST', '/api/q', { x: 1 });
    expect(lowerH).toBe(upperH);

    const artifact = buildBound({ method: 'post', path: '/api/q', body: { x: 1 } });
    expect(verifyRequestBinding(artifact, { method: 'POST', path: '/api/q', body: { x: 1 } }).bound).toBe(true);
  });

});

// ── 3. Adversarial cases ───────────────────────────────────────────────────────

describe('request binding — adversarial', () => {

  // ADV-01: Unicode NFC vs NFD in path
  test('ADV-01  NFC vs NFD in path → not bound (exact bytes enforced)', () => {
    // NFC: U+00E9 (single codepoint é)
    // NFD: U+0065 U+0301 (e + combining acute accent)
    const pathNFC = '/api/café';
    const pathNFD = '/api/café';
    expect(pathNFC).not.toBe(pathNFD); // confirm distinct JS strings

    const artifact = buildBound({ method: 'GET', path: pathNFC, body: {} });
    expect(verifyRequestBinding(artifact, { method: 'GET', path: pathNFC, body: {} }).bound).toBe(true);
    expect(verifyRequestBinding(artifact, { method: 'GET', path: pathNFD, body: {} }).bound).toBe(false);
  });

  // ADV-02: Unicode NFC vs NFD in body value
  test('ADV-02  NFC vs NFD in body string value → not bound', () => {
    const bodyNFC = { name: 'café' };
    const bodyNFD = { name: 'café' };
    expect(computeRequestHash('POST', '/api/q', bodyNFC)).not.toBe(
      computeRequestHash('POST', '/api/q', bodyNFD)
    );

    const artifact = buildBound({ method: 'POST', path: '/api/q', body: bodyNFC });
    expect(verifyRequestBinding(artifact, { method: 'POST', path: '/api/q', body: bodyNFD }).bound).toBe(false);
  });

  // ADV-03: nested object mutation
  test('ADV-03  nested object mutation after signing → not bound', () => {
    const original = { method: 'POST', path: '/api/exec', body: { user: { id: 'alice', role: 'viewer' }, op: 'read' } };
    const mutated  = { method: 'POST', path: '/api/exec', body: { user: { id: 'alice', role: 'admin'  }, op: 'read' } };
    const artifact = buildBound(original);

    expect(verifyRequestBinding(artifact, mutated).bound).toBe(false);
  });

  // ADV-04: array element mutation
  test('ADV-04  array element mutation in body → not bound', () => {
    const original = { method: 'POST', path: '/api/batch', body: { ids: [1, 2, 3] } };
    const mutated  = { method: 'POST', path: '/api/batch', body: { ids: [1, 2, 99] } };
    const artifact = buildBound(original);

    expect(verifyRequestBinding(artifact, mutated).bound).toBe(false);
  });

  // ADV-05: replay across multiple endpoints
  test('ADV-05  artifact bound to /api/read is blocked at all other endpoints', () => {
    const origin    = '/api/read';
    const endpoints = ['/api/write', '/api/delete', '/api/admin', '/api/read/extra', '/api'];
    const req       = { method: 'POST', path: origin, body: { userId: 'dave' } };
    const artifact  = buildBound(req);

    expect(verifyRequestBinding(artifact, req).bound).toBe(true);
    for (const ep of endpoints) {
      const r = verifyRequestBinding(artifact, { method: 'POST', path: ep, body: { userId: 'dave' } });
      expect(r.bound).toBe(false);
      expect(r.reason).toBe('REQUEST_MISMATCH');
    }
  });

  // ADV-06: query string appended to path
  test('ADV-06  query string appended to path → not bound (no normalization)', () => {
    const artifact = buildBound({ method: 'GET', path: '/api/data', body: {} });
    expect(verifyRequestBinding(artifact, { method: 'GET', path: '/api/data?admin=true', body: {} }).bound).toBe(false);
    expect(verifyRequestBinding(artifact, { method: 'GET', path: '/api/data', body: {} }).bound).toBe(true);
  });

  // ADV-07: body field injection
  test('ADV-07  extra field injected into body → not bound', () => {
    const body     = { userId: 'alice', action: 'read' };
    const injected = { userId: 'alice', action: 'read', admin: true };
    const artifact = buildBound({ method: 'POST', path: '/api/q', body });

    expect(verifyRequestBinding(artifact, { method: 'POST', path: '/api/q', body: injected }).bound).toBe(false);
  });

  // ADV-08: modifying requestHash inside artifact payload breaks signature
  test('ADV-08  tampered requestHash in artifact payload → INVALID_SIGNATURE via validateArtifact', () => {
    const req      = { method: 'POST', path: '/api/q', body: { userId: 'alice' } };
    const artifact = buildBound(req);

    // Attacker replaces requestHash with hash for a different request.
    const fakeHash = computeRequestHash('DELETE', '/api/admin', {});
    const tampered = {
      ...artifact,
      payload: { ...artifact.payload, requestHash: fakeHash },
    };

    // The artifact signature no longer covers the tampered payload.
    const validation = validateArtifact(tampered);
    expect(validation.decision).toBe('BLOCK');
    expect(validation.reason).toBe('INVALID_SIGNATURE');
  });

  // ADV-09: path traversal variant
  test('ADV-09  path traversal string → not bound (no normalization)', () => {
    const artifact = buildBound({ method: 'GET', path: '/api/data', body: {} });
    expect(verifyRequestBinding(artifact, { method: 'GET', path: '/api/../api/data', body: {} }).bound).toBe(false);
  });

  // ADV-10: trailing slash difference
  test('ADV-10  trailing slash on path → not bound (exact bytes)', () => {
    const artifact = buildBound({ method: 'GET', path: '/api/data', body: {} });
    expect(verifyRequestBinding(artifact, { method: 'GET', path: '/api/data/', body: {} }).bound).toBe(false);
  });

});

// ── 4. computeRequestHash — input validation ──────────────────────────────────

describe('computeRequestHash — input validation', () => {

  test('throws on empty method',           () => expect(() => computeRequestHash('',    '/api', {})).toThrow(TypeError));
  test('throws on whitespace-only method', () => expect(() => computeRequestHash('   ', '/api', {})).toThrow(TypeError));
  test('throws on null method',            () => expect(() => computeRequestHash(null,  '/api', {})).toThrow(TypeError));
  test('throws on numeric method',         () => expect(() => computeRequestHash(42,    '/api', {})).toThrow(TypeError));
  test('throws on empty path',             () => expect(() => computeRequestHash('GET', '',    {})).toThrow(TypeError));
  test('throws on null path',              () => expect(() => computeRequestHash('GET', null,  {})).toThrow(TypeError));
  test('throws on numeric path',           () => expect(() => computeRequestHash('GET', 42,    {})).toThrow(TypeError));
  test('throws on null body',              () => expect(() => computeRequestHash('GET', '/api', null)).toThrow(TypeError));
  test('throws on array body',             () => expect(() => computeRequestHash('GET', '/api', [])).toThrow(TypeError));
  test('throws on Date body',              () => expect(() => computeRequestHash('GET', '/api', new Date())).toThrow(TypeError));
  test('throws on undefined in body',      () => expect(() => computeRequestHash('GET', '/api', { x: undefined })).toThrow(TypeError));
  test('throws on nested undefined',       () => expect(() => computeRequestHash('GET', '/api', { a: { b: undefined } })).toThrow(TypeError));

  test('returns 64-char lowercase hex',    () => {
    const h = computeRequestHash('POST', '/api/q', { x: 1 });
    expect(typeof h).toBe('string');
    expect(h).toHaveLength(64);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  test('is deterministic across calls', () => {
    const h1 = computeRequestHash('POST', '/api/q', { z: 9, a: 1 });
    const h2 = computeRequestHash('POST', '/api/q', { z: 9, a: 1 });
    expect(h1).toBe(h2);
  });

  test('empty body {} is valid and deterministic', () => {
    const h1 = computeRequestHash('GET', '/api', {});
    const h2 = computeRequestHash('GET', '/api', {});
    expect(h1).toBe(h2);
    expect(h1).toHaveLength(64);
  });

  test('uses correct domain', () => {
    expect(REQUEST_DOMAIN).toBe('QODIQA::REQUEST::V1');
  });

  test('domain isolation — differs from envelopeHash domain', () => {
    const { ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
    expect(REQUEST_DOMAIN).not.toBe(ARTIFACT_DOMAINS.CANONICAL);
    expect(REQUEST_DOMAIN).not.toBe(ARTIFACT_DOMAINS.ARTIFACT);
  });

});

// ── 5. signBoundArtifact — input validation ───────────────────────────────────

describe('signBoundArtifact — input validation', () => {

  test('throws on null request',              () => expect(() => signBoundArtifact(null,              freshEnvelope(), KEY.privDer)).toThrow(TypeError));
  test('throws on array as request',          () => expect(() => signBoundArtifact([],                freshEnvelope(), KEY.privDer)).toThrow(TypeError));
  test('throws on invalid method in request', () => expect(() => signBoundArtifact({ method: '', path: '/api', body: {} }, freshEnvelope(), KEY.privDer)).toThrow(TypeError));
  test('throws on missing path in request',   () => expect(() => signBoundArtifact({ method: 'POST', path: '',   body: {} }, freshEnvelope(), KEY.privDer)).toThrow(TypeError));
  test('throws on non-object body',           () => expect(() => signBoundArtifact({ method: 'POST', path: '/a', body: null }, freshEnvelope(), KEY.privDer)).toThrow(TypeError));
  test('throws if requestHash already in payload', () => {
    const req = { method: 'GET', path: '/api', body: {} };
    expect(() => signBoundArtifact(req, freshEnvelope({ requestHash: 'abc' }), KEY.privDer)).toThrow(TypeError);
  });

  test('injects requestHash into payload', () => {
    const req      = { method: 'POST', path: '/api/q', body: { userId: 'alice' } };
    const artifact = buildBound(req);
    expect(typeof artifact.payload.requestHash).toBe('string');
    expect(artifact.payload.requestHash).toHaveLength(64);
    expect(artifact.payload.requestHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('injected requestHash equals computeRequestHash(method, path, body)', () => {
    const req      = { method: 'POST', path: '/api/q', body: { x: 1 } };
    const artifact = buildBound(req);
    const expected = computeRequestHash(req.method, req.path, req.body);
    expect(artifact.payload.requestHash).toBe(expected);
  });

});

// ── 6. verifyRequestBinding — edge cases ─────────────────────────────────────

describe('verifyRequestBinding — edge cases', () => {

  test('null artifact → not bound', () => {
    const r = verifyRequestBinding(null, { method: 'GET', path: '/api', body: {} });
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('null request → not bound', () => {
    const artifact = buildBound({ method: 'GET', path: '/api', body: {} });
    const r = verifyRequestBinding(artifact, null);
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('requestHash set to empty string → not bound', () => {
    const now      = Date.now();
    const artifact = signArtifact({
      payload:     { requestHash: '' },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    const r = verifyRequestBinding(artifact, { method: 'GET', path: '/api', body: {} });
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('requestHash set to non-hex string → not bound', () => {
    const now      = Date.now();
    const artifact = signArtifact({
      payload:     { requestHash: 'not-a-valid-hex-string-at-all!!' },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    const r = verifyRequestBinding(artifact, { method: 'GET', path: '/api', body: {} });
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('requestHash set to uppercase hex (63 chars) → not bound', () => {
    const now      = Date.now();
    const artifact = signArtifact({
      payload:     { requestHash: 'A'.repeat(63) },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);
    const r = verifyRequestBinding(artifact, { method: 'GET', path: '/api', body: {} });
    expect(r.bound).toBe(false);
  });

  test('invalid method in request → not bound (computeRequestHash throws → block)', () => {
    const artifact = buildBound({ method: 'GET', path: '/api', body: {} });
    const r = verifyRequestBinding(artifact, { method: '', path: '/api', body: {} });
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('invalid body in request → not bound', () => {
    const artifact = buildBound({ method: 'GET', path: '/api', body: {} });
    const r = verifyRequestBinding(artifact, { method: 'GET', path: '/api', body: null });
    expect(r.bound).toBe(false);
  });

});

// ── 7. Full pipeline: validateArtifact + verifyRequestBinding ─────────────────

describe('full pipeline — validateArtifact then verifyRequestBinding', () => {

  test('valid artifact + matching request → ALLOW and bound', () => {
    const req      = { method: 'POST', path: '/api/execute', body: { userId: 'alice', resource: 'ds-1' } };
    const artifact = buildBound(req, { action: 'query' });

    const v = validateArtifact(artifact);
    expect(v.decision).toBe('EXECUTE');

    const b = verifyRequestBinding(artifact, req);
    expect(b.bound).toBe(true);
  });

  test('valid signature but wrong request → ALLOW then not bound', () => {
    const req      = { method: 'POST', path: '/api/read',  body: { userId: 'alice' } };
    const wrong    = { method: 'POST', path: '/api/admin', body: { userId: 'alice' } };
    const artifact = buildBound(req);

    // Signature is valid — validateArtifact passes.
    expect(validateArtifact(artifact).decision).toBe('EXECUTE');
    // But binding check fails — request doesn't match.
    expect(verifyRequestBinding(artifact, wrong).bound).toBe(false);
  });

  test('tampered payload → BLOCK at validateArtifact before binding is checked', () => {
    const req      = { method: 'POST', path: '/api/q', body: { userId: 'alice' } };
    const artifact = buildBound(req);

    const tampered = {
      ...artifact,
      payload: { ...artifact.payload, userId: 'attacker' },
    };

    expect(validateArtifact(tampered).decision).toBe('BLOCK');
    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('extra fields on artifact envelope → BLOCK at validateArtifact', () => {
    const req      = { method: 'GET', path: '/api', body: {} };
    const artifact = buildBound(req);
    const injected = { ...artifact, admin: true };

    expect(validateArtifact(injected).decision).toBe('BLOCK');
    expect(validateArtifact(injected).reason).toBe('INVALID_ARTIFACT');
  });

  test('GET request with empty body → ALLOW and bound', () => {
    const req      = { method: 'GET', path: '/api/status', body: {} };
    const artifact = buildBound(req);

    expect(validateArtifact(artifact).decision).toBe('EXECUTE');
    expect(verifyRequestBinding(artifact, req).bound).toBe(true);
  });

  test('deeply nested body → bound correctly', () => {
    const body     = { a: { b: { c: { d: 'value' } } }, arr: [1, [2, 3], { x: 4 }] };
    const req      = { method: 'POST', path: '/api/nested', body };
    const artifact = buildBound(req);

    expect(validateArtifact(artifact).decision).toBe('EXECUTE');
    expect(verifyRequestBinding(artifact, req).bound).toBe(true);

    // Any mutation anywhere in the nested structure breaks binding.
    const mutated = { method: 'POST', path: '/api/nested', body: { a: { b: { c: { d: 'HACKED' } } }, arr: [1, [2, 3], { x: 4 }] } };
    expect(verifyRequestBinding(artifact, mutated).bound).toBe(false);
  });

});
