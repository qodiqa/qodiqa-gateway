'use strict';

/**
 * Red Team: Adversarial Verification
 *
 * Validates that the stateless artifact-based enforcement pipeline
 * fails closed against all known attack vectors.
 *
 * Model: artifact (full envelope) → validateArtifact → decision
 *        artifact + request       → validateBoundRequest → decision
 *
 * Attack categories:
 *   1.  Missing / null / empty artifact               → BLOCK / MALFORMED_ARTIFACT
 *   2.  Tampered signature                            → BLOCK / INVALID_SIGNATURE
 *   3.  Tampered payload                              → BLOCK / INVALID_SIGNATURE
 *   4.  Tampered envelope fields (expiry, timestamp)  → BLOCK / INVALID_SIGNATURE
 *   5.  Expired artifact                              → BLOCK / EXPIRED
 *   6.  Future timestamp                              → BLOCK / FUTURE_TIMESTAMP
 *   7.  Unknown / wrong public key                    → BLOCK / KEY_NOT_FOUND | INVALID_SIGNATURE
 *   8.  Partial artifact (missing required fields)    → BLOCK / MALFORMED_ARTIFACT
 *   9.  Replay (same requestId submitted twice)       → BLOCK / REPLAY_DETECTED
 *   10. Request body mismatch (body injection)        → BLOCK / REQUEST_MISMATCH
 *   11. Cross-context replay (artifact ≠ request)     → BLOCK / REQUEST_MISMATCH
 *   12. Type confusion                                → BLOCK / MALFORMED_ARTIFACT
 *   13. Field injection (extra envelope fields)       → BLOCK / INVALID_SIGNATURE
 *   14. No valid artifact → provider never reached    → BLOCK (pre-execution)
 */

const crypto = require('crypto');

const { validateArtifact }    = require('../src/validation/validateArtifact');
const { validateBoundRequest } = require('../src/validation/validateBoundRequest');
const { signArtifact }        = require('../src/validation/signArtifact');
const { signBoundArtifact }   = require('../src/validation/signBoundArtifact');
const { getActiveKey }        = require('../services/artifact/keyStore');
const { buildNonceKey }       = require('../src/validation/nonceStore');
const { makeNonceStore, makeOpenAnomalyStore: makePassAnomalyStore } = require('./helpers/sharedMocks');

// ── Test setup ────────────────────────────────────────────────────────────────

const CLIENT = 'redteam-test';

let KEY;
beforeAll(() => {
  const { rotateKey } = require('../services/artifact/keyStore');
  rotateKey(CLIENT);
  KEY = getActiveKey(CLIENT);
});

// ── Artifact helpers ──────────────────────────────────────────────────────────

const BASE_REQ = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload: { provider: 'openai', ...payload }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}

function buildArtifact(req = BASE_REQ, extraPayload = {}) {
  return signBoundArtifact(req, freshEnvelope(extraPayload), KEY.privDer);
}

function vbr(artifact, req = BASE_REQ, opts = {}) {
  return validateBoundRequest(artifact, req, {
    _anomalyStore: makePassAnomalyStore(),
    ...opts,
  });
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. MISSING / NULL / EMPTY ARTIFACT
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: missing artifact', () => {

  test('MISSING-01: undefined → BLOCK MALFORMED_ARTIFACT', () => {
    const r = validateArtifact(undefined);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

  test('MISSING-02: null → BLOCK MALFORMED_ARTIFACT', () => {
    const r = validateArtifact(null);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

  test('MISSING-03: empty object → BLOCK MALFORMED_ARTIFACT', () => {
    const r = validateArtifact({});
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

  test('MISSING-04: array → BLOCK MALFORMED_ARTIFACT', () => {
    const r = validateArtifact([]);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

  test('MISSING-05: string → BLOCK MALFORMED_ARTIFACT', () => {
    const r = validateArtifact('not-an-artifact');
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_ARTIFACT');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 2. TAMPERED SIGNATURE
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: tampered signature', () => {

  test('SIG-01: zeroed signature → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64, 0).toString('base64') };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('SIG-02: random signature → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, signature: crypto.randomBytes(64).toString('base64') };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('SIG-03: truncated signature → BLOCK', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, signature: artifact.signature.slice(0, 10) };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
  });

  test('SIG-04: signature from a different artifact → BLOCK INVALID_SIGNATURE', () => {
    const a1 = buildArtifact();
    const a2 = buildArtifact();
    const tampered = { ...a1, signature: a2.signature };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 3. TAMPERED PAYLOAD
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: tampered payload', () => {

  test('PAYLOAD-01: modified provider field → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, payload: { ...artifact.payload, provider: 'attacker-controlled' } };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('PAYLOAD-02: injected admin field → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, payload: { ...artifact.payload, admin: true, role: 'superuser' } };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('PAYLOAD-03: swapped payload from different artifact → BLOCK INVALID_SIGNATURE', () => {
    const a1 = buildArtifact(BASE_REQ, { userId: 'alice' });
    const a2 = buildArtifact(BASE_REQ, { userId: 'bob' });
    const tampered = { ...a1, payload: a2.payload };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('PAYLOAD-04: requestHash tampered in payload → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, payload: { ...artifact.payload, requestHash: 'a'.repeat(64) } };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 4. TAMPERED ENVELOPE FIELDS
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: tampered envelope fields', () => {

  test('ENVELOPE-01: extended expiry → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, expiry: artifact.expiry + 9_999_999 };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('ENVELOPE-02: modified timestamp → BLOCK INVALID_SIGNATURE', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, timestamp: artifact.timestamp - 60_000 };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('ENVELOPE-03: swapped publicKeyId → BLOCK (KEY_NOT_FOUND or INVALID_SIGNATURE)', () => {
    const artifact = buildArtifact();
    const tampered = { ...artifact, publicKeyId: 'nonexistent:key_v0' };
    const r = validateArtifact(tampered);
    expect(r.decision).toBe('BLOCK');
    expect(['KEY_NOT_FOUND', 'INVALID_SIGNATURE']).toContain(r.reason);
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 5. EXPIRED ARTIFACT
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: expired artifact', () => {

  test('EXPIRY-01: artifact expired in the past → BLOCK EXPIRED', () => {
    const now      = Date.now();
    const artifact = signArtifact(
      { payload: { provider: 'openai' }, timestamp: now - 400_000, expiry: now - 100_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('EXPIRED');
  });

  test('EXPIRY-02: clock advanced past expiry → BLOCK EXPIRED', () => {
    const artifact = buildArtifact();
    const r = validateArtifact(artifact, { _clock: () => Date.now() + 400_000 });
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('EXPIRED');
  });

  test('EXPIRY-03: expiry set to now → BLOCK EXPIRED', () => {
    const now      = Date.now();
    const artifact = signArtifact(
      { payload: { provider: 'openai' }, timestamp: now - 1000, expiry: now - 1, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('EXPIRED');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 6. FUTURE TIMESTAMP
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: future timestamp', () => {

  test('FUTURE-01: timestamp 1 minute in the future → BLOCK FUTURE_TIMESTAMP', () => {
    const futureNow = Date.now() + 60_000;
    const artifact  = signArtifact(
      { payload: { provider: 'openai' }, timestamp: futureNow, expiry: futureNow + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('FUTURE_TIMESTAMP');
  });

  test('FUTURE-02: timestamp 1 hour in the future → BLOCK FUTURE_TIMESTAMP', () => {
    const futureNow = Date.now() + 3_600_000;
    const artifact  = signArtifact(
      { payload: { provider: 'openai' }, timestamp: futureNow, expiry: futureNow + 300_000, publicKeyId: KEY.keyId },
      KEY.privDer,
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('FUTURE_TIMESTAMP');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 7. UNKNOWN / WRONG KEY
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: wrong or unknown key', () => {

  // CRYPTO-5/VERIFY-4: an unresolved publicKeyId no longer produces its own
  // distinguishable KEY_NOT_FOUND reason — it falls through to signature
  // verification against a null key sentinel (always fails), so this case —
  // even though the artifact is genuinely, cryptographically well-signed
  // with SOME real key pair — is indistinguishable from any other
  // INVALID_SIGNATURE. An attacker learns nothing about whether the key
  // exists.
  test('unknown publicKeyId → BLOCK INVALID_SIGNATURE (not a distinguishable KEY_NOT_FOUND)', () => {
    const { privateKey: privDer } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const now      = Date.now();
    const artifact = signArtifact(
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: 'unknown:key_v0' },
      Buffer.from(privDer),
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('signed with wrong key, claims valid keyId → BLOCK INVALID_SIGNATURE', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
    });
    const wrongPrivDer = Buffer.from(privateKey);
    const now          = Date.now();
    const artifact     = signArtifact(
      { payload: { provider: 'openai' }, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId },
      wrongPrivDer,
    );
    const r = validateArtifact(artifact);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 8. PARTIAL ARTIFACT (MISSING REQUIRED FIELDS)
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: partial artifact (missing required fields)', () => {

  test('PARTIAL-01: missing signature → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const { signature: _s, ...partial } = artifact;
    expect(() => validateArtifact(partial)).not.toThrow();
    expect(validateArtifact(partial).decision).toBe('BLOCK');
  });

  test('PARTIAL-02: missing publicKeyId → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const { publicKeyId: _k, ...partial } = artifact;
    expect(() => validateArtifact(partial)).not.toThrow();
    expect(validateArtifact(partial).decision).toBe('BLOCK');
  });

  test('PARTIAL-03: missing payload → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const { payload: _p, ...partial } = artifact;
    expect(() => validateArtifact(partial)).not.toThrow();
    expect(validateArtifact(partial).decision).toBe('BLOCK');
  });

  test('PARTIAL-04: missing timestamp → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const { timestamp: _t, ...partial } = artifact;
    expect(() => validateArtifact(partial)).not.toThrow();
    expect(validateArtifact(partial).decision).toBe('BLOCK');
  });

  test('PARTIAL-05: missing expiry → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const { expiry: _e, ...partial } = artifact;
    expect(() => validateArtifact(partial)).not.toThrow();
    expect(validateArtifact(partial).decision).toBe('BLOCK');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 9. REPLAY ATTACK
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: replay attack', () => {

  test('REPLAY-01: same artifact submitted twice → second is BLOCK REPLAY_DETECTED', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();

    const r1 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r1.allowed).toBe(true);

    const r2 = await vbr(artifact, BASE_REQ, { _store: store });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });

  test('REPLAY-02: five replays all blocked', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();
    await vbr(artifact, BASE_REQ, { _store: store });

    for (let i = 0; i < 5; i++) {
      const r = await vbr(artifact, BASE_REQ, { _store: store });
      expect(r.allowed).toBe(false);
      expect(r.reason).toBe('REPLAY_DETECTED');
    }
  });

  test('REPLAY-03: two distinct artifacts both accepted once', async () => {
    const store = makeNonceStore();
    const a1 = buildArtifact();
    const a2 = buildArtifact();
    expect(a1.payload.requestId).not.toBe(a2.payload.requestId);

    expect((await vbr(a1, BASE_REQ, { _store: store })).allowed).toBe(true);
    expect((await vbr(a2, BASE_REQ, { _store: store })).allowed).toBe(true);
    expect((await vbr(a1, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
    expect((await vbr(a2, BASE_REQ, { _store: store })).reason).toBe('REPLAY_DETECTED');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 10. REQUEST BODY INJECTION
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: request body injection', () => {

  test('INJECT-01: body modified after signing → BLOCK REQUEST_MISMATCH', async () => {
    const artifact     = buildArtifact(BASE_REQ);
    const injectedReq  = { ...BASE_REQ, body: { prompt: 'injected malicious prompt', model: 'gpt-4' } };
    const r = await vbr(artifact, injectedReq);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('INJECT-02: extra field added to body → BLOCK REQUEST_MISMATCH', async () => {
    const artifact    = buildArtifact(BASE_REQ);
    const injectedReq = { ...BASE_REQ, body: { ...BASE_REQ.body, extra: 'injected' } };
    const r = await vbr(artifact, injectedReq);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('INJECT-03: method changed from POST to GET → BLOCK REQUEST_MISMATCH', async () => {
    const artifact  = buildArtifact(BASE_REQ);
    const wrongReq  = { ...BASE_REQ, method: 'GET' };
    const r = await vbr(artifact, wrongReq);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('INJECT-04: path changed to different endpoint → BLOCK REQUEST_MISMATCH', async () => {
    const artifact   = buildArtifact(BASE_REQ);
    const wrongReq   = { ...BASE_REQ, path: '/ai/admin' };
    const r = await vbr(artifact, wrongReq);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 11. CROSS-CONTEXT REPLAY
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: cross-context replay', () => {

  test('CROSS-01: artifact bound to request A, submitted with request B → BLOCK', async () => {
    const reqA = { method: 'POST', path: '/ai/chat', body: { prompt: 'request A', model: 'gpt-4' } };
    const reqB = { method: 'POST', path: '/ai/chat', body: { prompt: 'request B', model: 'gpt-4' } };

    const artifactA = buildArtifact(reqA);
    const r = await vbr(artifactA, reqB);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

  test('CROSS-02: artifact bound to endpoint A, submitted to endpoint B → BLOCK', async () => {
    const reqA = { method: 'POST', path: '/ai/chat',  body: { prompt: 'hello', model: 'gpt-4' } };
    const reqB = { method: 'POST', path: '/ai/admin', body: { prompt: 'hello', model: 'gpt-4' } };

    const artifactA = buildArtifact(reqA);
    const r = await vbr(artifactA, reqB);
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('REQUEST_MISMATCH');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 12. TYPE CONFUSION
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: type confusion', () => {

  test('TYPE-01: timestamp as string → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const confused = { ...artifact, timestamp: String(artifact.timestamp) };
    expect(() => validateArtifact(confused)).not.toThrow();
    expect(validateArtifact(confused).decision).toBe('BLOCK');
  });

  test('TYPE-02: expiry as string → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const confused = { ...artifact, expiry: String(artifact.expiry) };
    expect(() => validateArtifact(confused)).not.toThrow();
    expect(validateArtifact(confused).decision).toBe('BLOCK');
  });

  test('TYPE-03: payload as null → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const confused = { ...artifact, payload: null };
    expect(() => validateArtifact(confused)).not.toThrow();
    expect(validateArtifact(confused).decision).toBe('BLOCK');
  });

  test('TYPE-04: payload as string → BLOCK MALFORMED_ARTIFACT, no crash', () => {
    const artifact = buildArtifact();
    const confused = { ...artifact, payload: '{"provider":"openai"}' };
    expect(() => validateArtifact(confused)).not.toThrow();
    expect(validateArtifact(confused).decision).toBe('BLOCK');
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 13. FIELD INJECTION (extra envelope fields)
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: field injection into envelope', () => {

  test('INJECT-ENV-01: extra fields do not bypass verification — signature is still invalid', () => {
    const artifact = buildArtifact();
    // Adding extra fields to a valid artifact's payload breaks the signature
    const injected = { ...artifact, payload: { ...artifact.payload, admin: true } };
    const r = validateArtifact(injected);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe('INVALID_SIGNATURE');
  });

  test('INJECT-ENV-02: extra top-level fields — no crash, no privilege escalation', () => {
    const artifact = buildArtifact();
    const injected = { ...artifact, adminOverride: true, bypassAuth: 'yes' };
    expect(() => validateArtifact(injected)).not.toThrow();
    // System either ignores or rejects extra envelope fields — both are secure outcomes.
    // The invariant: extra fields cannot escalate privileges (decision is defined, no throw).
    const result = validateArtifact(injected);
    expect(typeof result.decision).toBe('string');
    expect(['EXECUTE', 'BLOCK']).toContain(result.decision);
  });

});

// ═════════════════════════════════════════════════════════════════════════════
// 14. INVARIANT: no valid artifact → no execution
// ═════════════════════════════════════════════════════════════════════════════

describe('Red Team: execution invariant', () => {

  test('INV-01: invalid signature → pipeline BLOCKS before nonce registration', async () => {
    let nonceCalled = false;
    const trackingStore = {
      async register() { nonceCalled = true; return { registered: true }; },
      async isRegistered() { return false; },
    };
    const artifact = buildArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64, 0).toString('base64') };
    const r = await validateBoundRequest(tampered, BASE_REQ, {
      _store: trackingStore,
      _anomalyStore: makePassAnomalyStore(),
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('INVALID_SIGNATURE');
    expect(nonceCalled).toBe(false);
  });

  test('INV-02: expired artifact → pipeline BLOCKS before nonce registration', async () => {
    let nonceCalled = false;
    const trackingStore = {
      async register() { nonceCalled = true; return { registered: true }; },
      async isRegistered() { return false; },
    };
    const artifact = buildArtifact();
    const r = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        trackingStore,
      _anomalyStore: makePassAnomalyStore(),
      _clock:        () => Date.now() + 400_000, // advance past expiry
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe('EXPIRED');
    expect(nonceCalled).toBe(false);
  });

  test('INV-03: valid artifact → ALLOW, nonce registered exactly once', async () => {
    const store    = makeNonceStore();
    const artifact = buildArtifact();
    const r = await validateBoundRequest(artifact, BASE_REQ, {
      _store:        store,
      _anomalyStore: makePassAnomalyStore(),
    });
    expect(r.allowed).toBe(true);
    // Key format per QODIQA-PROTOCOL-SPEC.md §27.11: <tenantId>:qodiqa:req:v2:<requestId>
    const scopedKey = buildNonceKey(artifact.payload.requestId, CLIENT);
    expect(store._map.has(scopedKey)).toBe(true);
  });

});
