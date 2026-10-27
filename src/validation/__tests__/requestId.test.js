'use strict';

/**
 * requestId (execution nonce) test suite — QODIQA V2
 *
 * Verifies that every bound artifact carries a cryptographically random,
 * uniquely identifiable, and signature-covered requestId.
 *
 * Test categories:
 *   1.  Core required cases (TC-01 … TC-05)
 *   2.  generateRequestId properties
 *   3.  isValidRequestId format gate
 *   4.  signBoundArtifact — requestId injection rules
 *   5.  verifyRequestBinding — requestId enforcement
 *   6.  Full pipeline with requestId
 *   7.  Adversarial tampering
 */

const crypto = require('crypto');

const { generateRequestId,
        isValidRequestId,
        UUID_V4_RE }           = require('../requestId');
const { signBoundArtifact }    = require('../signBoundArtifact');
const { verifyRequestBinding } = require('../verifyRequestBinding');
const { validateArtifact }     = require('../validateArtifact');
const { signArtifact }         = require('../signArtifact');
const { getActiveKey }         = require('../../../services/artifact/keyStore');

// ── Helpers ───────────────────────────────────────────────────────────────────

let KEY;

beforeAll(() => { KEY = getActiveKey('default'); });

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

const BASE_REQ = { method: 'POST', path: '/api/query', body: { userId: 'alice' } };

function buildBound(req = BASE_REQ, extraPayload = {}) {
  return signBoundArtifact(req, freshEnvelope(extraPayload), KEY.privDer);
}

// ── 1. Core required cases ────────────────────────────────────────────────────

describe('requestId — core required cases', () => {

  // TC-01: valid request with requestId → ALLOW and bound
  test('TC-01  valid artifact with requestId → validateArtifact ALLOW + bound: true', () => {
    const artifact = buildBound();

    const v = validateArtifact(artifact);
    expect(v.decision).toBe('EXECUTE');

    const b = verifyRequestBinding(artifact, BASE_REQ);
    expect(b.bound).toBe(true);
    expect(typeof b.requestId).toBe('string');
    expect(isValidRequestId(b.requestId)).toBe(true);
    expect(b.requestId).toBe(artifact.payload.requestId);
  });

  // TC-02: missing requestId → not bound
  test('TC-02  missing requestId in payload → not bound', () => {
    const now = Date.now();
    // Build valid artifact via signArtifact — no requestId in payload
    const artifact = signArtifact({
      payload:     { userId: 'alice', requestHash: 'a'.repeat(64) },
      timestamp:   now,
      expiry:      now + 300_000,
      publicKeyId: KEY.keyId,
    }, KEY.privDer);

    const r = verifyRequestBinding(artifact, BASE_REQ);
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  // TC-03: malformed requestId → not bound
  test('TC-03  malformed requestId in payload → not bound', () => {
    const artifact = buildBound();
    // Craft artifact with invalid requestId in payload; this bypasses signBoundArtifact
    // validation to reach verifyRequestBinding directly (simulate injection attack).
    const crafted = {
      ...artifact,
      payload: { ...artifact.payload, requestId: 'not-a-uuid' },
    };
    // validateArtifact will catch tampering — but also check verifyRequestBinding directly.
    expect(validateArtifact(crafted).decision).toBe('BLOCK'); // signature now invalid
    const r = verifyRequestBinding(crafted, BASE_REQ);
    expect(r.bound).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  // TC-04: requestId tampered after signing → BLOCK at signature verification
  test('TC-04  requestId tampered after signing → INVALID_SIGNATURE', () => {
    const artifact = buildBound();
    const tampered = {
      ...artifact,
      payload: { ...artifact.payload, requestId: generateRequestId() },
    };

    const v = validateArtifact(tampered);
    expect(v.decision).toBe('BLOCK');
    expect(v.reason).toBe('INVALID_SIGNATURE');
  });

  // TC-05: requestHash valid but requestId changed → BLOCK
  test('TC-05  requestHash intact but requestId changed → INVALID_SIGNATURE', () => {
    const artifact = buildBound();
    // Swap requestId for a freshly generated (but different) one — keeps requestHash
    const tampered = {
      ...artifact,
      payload: {
        ...artifact.payload,
        requestId: generateRequestId(), // different valid UUID — but changes signed envelope
      },
    };

    // Signature covers the entire payload including requestId.
    // Any change to requestId invalidates the Ed25519 signature — blocked here.
    expect(validateArtifact(tampered).decision).toBe('BLOCK');
    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');

    // verifyRequestBinding is called AFTER validateArtifact in production.
    // On its own it cannot distinguish a tampered-but-well-formed requestId from
    // a legitimate one — that invariant is enforced by the signature above.
    // The correct gate is: NEVER call verifyRequestBinding unless validateArtifact → ALLOW.
  });

});

// ── 2. generateRequestId properties ──────────────────────────────────────────

describe('generateRequestId — properties', () => {

  test('returns a string', () => {
    expect(typeof generateRequestId()).toBe('string');
  });

  test('returns UUID v4 format (canonical lowercase)', () => {
    const id = generateRequestId();
    expect(UUID_V4_RE.test(id)).toBe(true);
  });

  test('version nibble is always 4', () => {
    for (let i = 0; i < 20; i++) {
      const id = generateRequestId();
      expect(id[14]).toBe('4');
    }
  });

  test('variant nibble is always 8, 9, a, or b', () => {
    for (let i = 0; i < 20; i++) {
      const id = generateRequestId();
      expect(['8', '9', 'a', 'b']).toContain(id[19]);
    }
  });

  test('every call produces a unique value', () => {
    const ids = new Set();
    for (let i = 0; i < 1000; i++) ids.add(generateRequestId());
    expect(ids.size).toBe(1000);
  });

  test('two successive artifacts carry different requestIds', () => {
    const a1 = buildBound();
    const a2 = buildBound();
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);
  });

});

// ── 3. isValidRequestId format gate ──────────────────────────────────────────

describe('isValidRequestId — format validation', () => {

  test('accepts a freshly generated requestId',         () => expect(isValidRequestId(generateRequestId())).toBe(true));
  test('rejects null',                                  () => expect(isValidRequestId(null)).toBe(false));
  test('rejects undefined',                             () => expect(isValidRequestId(undefined)).toBe(false));
  test('rejects empty string',                          () => expect(isValidRequestId('')).toBe(false));
  test('rejects arbitrary string',                      () => expect(isValidRequestId('not-a-uuid')).toBe(false));
  test('rejects number',                                () => expect(isValidRequestId(42)).toBe(false));
  test('rejects UUID v1 (version nibble ≠ 4)',          () => expect(isValidRequestId('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).toBe(false));
  test('rejects UUID with uppercase hex',               () => expect(isValidRequestId('550E8400-E29B-41D4-A716-446655440000')).toBe(false));
  test('rejects UUID missing hyphens',                  () => expect(isValidRequestId('550e8400e29b41d4a716446655440000')).toBe(false));
  test('rejects UUID too short',                        () => expect(isValidRequestId('550e8400-e29b-4')).toBe(false));
  test('rejects UUID with wrong variant nibble',        () => expect(isValidRequestId('550e8400-e29b-4d4a-f716-446655440000')).toBe(false));
  test('rejects 64-char hex string (requestHash form)', () => expect(isValidRequestId('a'.repeat(64))).toBe(false));

});

// ── 4. signBoundArtifact — requestId injection rules ─────────────────────────

describe('signBoundArtifact — requestId injection', () => {

  test('injects requestId into payload automatically', () => {
    const artifact = buildBound();
    expect(typeof artifact.payload.requestId).toBe('string');
    expect(isValidRequestId(artifact.payload.requestId)).toBe(true);
  });

  test('throws if requestId already present in payload', () => {
    const existingId = generateRequestId();
    expect(() => signBoundArtifact(
      BASE_REQ,
      freshEnvelope({ requestId: existingId }),
      KEY.privDer,
    )).toThrow(TypeError);
  });

  test('throws if both requestHash and requestId already present', () => {
    expect(() => signBoundArtifact(
      BASE_REQ,
      freshEnvelope({ requestHash: 'a'.repeat(64), requestId: generateRequestId() }),
      KEY.privDer,
    )).toThrow(TypeError);
  });

  test('injects both requestHash and requestId', () => {
    const artifact = buildBound();
    expect(typeof artifact.payload.requestHash).toBe('string');
    expect(artifact.payload.requestHash).toHaveLength(64);
    expect(typeof artifact.payload.requestId).toBe('string');
    expect(isValidRequestId(artifact.payload.requestId)).toBe(true);
  });

  test('requestId differs across two calls for identical requests', () => {
    const a1 = buildBound(BASE_REQ);
    const a2 = buildBound(BASE_REQ);
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);
    // requestHash must be identical — same request
    expect(a1.payload.requestHash).toBe(a2.payload.requestHash);
  });

});

// ── 5. verifyRequestBinding — requestId enforcement ──────────────────────────

describe('verifyRequestBinding — requestId enforcement', () => {

  test('bound: true result exposes requestId for replay-guard layer', () => {
    const artifact = buildBound();
    const r = verifyRequestBinding(artifact, BASE_REQ);
    expect(r.bound).toBe(true);
    expect(r.requestId).toBe(artifact.payload.requestId);
  });

  test('bound: false result does not expose requestId', () => {
    const artifact = buildBound();
    const r = verifyRequestBinding(artifact, { ...BASE_REQ, path: '/api/other' });
    expect(r.bound).toBe(false);
    expect(r.requestId).toBeUndefined();
  });

  test('null requestId in payload → not bound', () => {
    const now = Date.now();
    const artifact = signArtifact({
      payload: { requestHash: 'a'.repeat(64), requestId: null },
      timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);
    expect(verifyRequestBinding(artifact, BASE_REQ).bound).toBe(false);
  });

  test('numeric requestId in payload → not bound', () => {
    const now = Date.now();
    const artifact = signArtifact({
      payload: { requestHash: 'a'.repeat(64), requestId: 12345 },
      timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);
    expect(verifyRequestBinding(artifact, BASE_REQ).bound).toBe(false);
  });

  test('missing requestId but valid requestHash → not bound', () => {
    const req  = { method: 'POST', path: '/api/q', body: { x: 1 } };
    const now  = Date.now();
    const { computeRequestHash } = require('../requestHash');
    const rh = computeRequestHash(req.method, req.path, req.body);
    const artifact = signArtifact({
      payload: { requestHash: rh },  // no requestId
      timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);
    expect(verifyRequestBinding(artifact, req).bound).toBe(false);
    expect(verifyRequestBinding(artifact, req).reason).toBe('REQUEST_MISMATCH');
  });

  test('requestId present but requestHash missing → not bound', () => {
    const now = Date.now();
    const artifact = signArtifact({
      payload: { requestId: generateRequestId() },  // no requestHash
      timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId,
    }, KEY.privDer);
    expect(verifyRequestBinding(artifact, BASE_REQ).bound).toBe(false);
  });

});

// ── 6. Full pipeline with requestId ──────────────────────────────────────────

describe('full pipeline — validateArtifact + verifyRequestBinding + requestId', () => {

  test('complete flow: sign → validate → bind → extract requestId', () => {
    const req      = { method: 'POST', path: '/api/exec', body: { userId: 'bob', action: 'read' } };
    const artifact = buildBound(req, { sessionId: 'sess-123' });

    expect(validateArtifact(artifact).decision).toBe('EXECUTE');

    const b = verifyRequestBinding(artifact, req);
    expect(b.bound).toBe(true);
    expect(isValidRequestId(b.requestId)).toBe(true);

    // requestId can be passed to replay guard
    const idForStorage = b.requestId;
    expect(idForStorage).toBe(artifact.payload.requestId);
  });

  test('two artifacts for identical requests have same requestHash but different requestId', () => {
    const req = { method: 'GET', path: '/api/data', body: {} };
    const a1  = buildBound(req);
    const a2  = buildBound(req);

    expect(a1.payload.requestHash).toBe(a2.payload.requestHash);
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);

    const b1 = verifyRequestBinding(a1, req);
    const b2 = verifyRequestBinding(a2, req);
    expect(b1.bound).toBe(true);
    expect(b2.bound).toBe(true);
    expect(b1.requestId).not.toBe(b2.requestId);
  });

  test('artifact is not transferable to a different request even with valid requestId', () => {
    const original = { method: 'POST', path: '/api/read',  body: { userId: 'alice' } };
    const other    = { method: 'POST', path: '/api/admin', body: { userId: 'alice' } };
    const artifact = buildBound(original);

    expect(verifyRequestBinding(artifact, original).bound).toBe(true);
    expect(verifyRequestBinding(artifact, other).bound).toBe(false);
  });

});

// ── 7. Adversarial tampering ──────────────────────────────────────────────────

describe('requestId — adversarial tampering', () => {

  test('removing requestId from payload → INVALID_SIGNATURE (signature covers it)', () => {
    const artifact = buildBound();
    const { requestId: _removed, ...payloadWithout } = artifact.payload;
    const tampered = { ...artifact, payload: payloadWithout };
    expect(validateArtifact(tampered).decision).toBe('BLOCK');
    expect(validateArtifact(tampered).reason).toBe('INVALID_SIGNATURE');
  });

  test('swapping requestId between two valid artifacts → INVALID_SIGNATURE on both', () => {
    const a1 = buildBound({ method: 'POST', path: '/api/q', body: { x: 1 } });
    const a2 = buildBound({ method: 'POST', path: '/api/q', body: { x: 1 } });

    const swapped1 = { ...a1, payload: { ...a1.payload, requestId: a2.payload.requestId } };
    const swapped2 = { ...a2, payload: { ...a2.payload, requestId: a1.payload.requestId } };

    expect(validateArtifact(swapped1).reason).toBe('INVALID_SIGNATURE');
    expect(validateArtifact(swapped2).reason).toBe('INVALID_SIGNATURE');
  });

  test('duplicating artifact object does not produce a new requestId', () => {
    const artifact = buildBound();
    const copy     = { ...artifact, payload: { ...artifact.payload } };

    // Both have identical requestIds — replay guard layer must catch this
    expect(copy.payload.requestId).toBe(artifact.payload.requestId);
    // Both verify correctly — uniqueness enforcement is the replay guard's job
    expect(validateArtifact(copy).decision).toBe('EXECUTE');
    expect(verifyRequestBinding(copy, BASE_REQ).bound).toBe(true);
    expect(verifyRequestBinding(copy, BASE_REQ).requestId).toBe(artifact.payload.requestId);
  });

  test('reusing requestId across different payloads is blocked by signature mismatch', () => {
    const a1 = buildBound({ method: 'POST', path: '/api/read',  body: {} });
    const a2 = buildBound({ method: 'POST', path: '/api/write', body: {} });

    // Try grafting a1's requestId into a2's payload
    const grafted = {
      ...a2,
      payload: { ...a2.payload, requestId: a1.payload.requestId },
    };
    expect(validateArtifact(grafted).reason).toBe('INVALID_SIGNATURE');
  });

  test('setting requestId to valid-looking but all-zeros UUID → accepted as format (unique check is replay guard)', () => {
    // All-zeros UUID-like string passes format check but would signal a broken RNG.
    // Format validation cannot distinguish this from a legitimately unlucky UUID.
    // Entropy enforcement is outside the scope of isValidRequestId.
    const allZeros = '00000000-0000-4000-8000-000000000000';
    expect(isValidRequestId(allZeros)).toBe(true); // format is valid UUID v4
    // In production: replay guard would catch reuse; key rotation handles compromised RNG.
  });

});
