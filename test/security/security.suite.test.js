'use strict';

/**
 * Security Tests
 *
 * Proves security invariants that the enforcement pipeline must maintain:
 *   1. Cross-artifact signature uniqueness — two different artifacts always
 *      produce different signatures (no signature reuse across artifacts).
 *   2. Key isolation — a key for one tenant cannot verify artifacts signed
 *      by another tenant's key.
 *   3. Constant-time comparison used for sensitive buffer comparisons.
 *   4. Signature non-malleability — altering any byte of the artifact changes
 *      the signature verification outcome.
 *   5. Request binding integrity — an artifact signed for request A cannot
 *      be used to authorize request B.
 */

jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const crypto = require('crypto');

const { signBoundArtifact }    = require('../../src/validation/signBoundArtifact');
const { validateBoundRequest } = require('../../src/validation/validateBoundRequest');
const { getActiveKey, rotateKey } = require('../../services/artifact/keyStore');
const { timingSafeCompare }    = require('../../src/infra/crypto/hashing');
const { envelopeHash }         = require('../../src/validation/canonicalize');
const { sign, verify }         = require('../../src/infra/crypto/ed25519');
const { makeNonceStore,
        makeOpenAnomalyStore } = require('../../src/testing/stores');

// ── Fixtures ──────────────────────────────────────────────────────────────────

let KEY;
beforeAll(() => {
  try   { KEY = getActiveKey('default'); }
  catch { rotateKey('default'); KEY = getActiveKey('default'); }
});

const BASE_REQ  = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };
const BASE_PAYLOAD = { provider: 'openai' };

function freshEnvelope(payloadOverrides = {}) {
  const now = Date.now();
  return {
    payload:     { ...BASE_PAYLOAD, ...payloadOverrides },
    timestamp:   now,
    expiry:      now + 300_000,
    publicKeyId: KEY.keyId,
  };
}

function buildArtifact(req = BASE_REQ, envOverrides = {}) {
  return signBoundArtifact(req, { ...freshEnvelope(), ...envOverrides }, KEY.privDer);
}

// ── 1. Cross-artifact signature uniqueness ────────────────────────────────────

describe('Cross-artifact signature uniqueness', () => {

  test('two identical requests produce different signatures (unique requestId in each)', async () => {
    const a1 = buildArtifact();
    const a2 = buildArtifact();
    // Signatures embed the requestId (nonce) which is generated fresh each time
    expect(a1.signature).not.toBe(a2.signature);
  });

  test('100 consecutive artifact signatures are all unique', () => {
    const sigs = new Set();
    for (let i = 0; i < 100; i++) {
      const art = buildArtifact();
      sigs.add(art.signature);
    }
    expect(sigs.size).toBe(100);
  });

  test('artifact signatures include request binding (requestHash in payload)', () => {
    const a1 = buildArtifact(BASE_REQ);
    const a2 = buildArtifact({ ...BASE_REQ, body: { prompt: 'different', model: 'gpt-4' } });
    // requestHash in payload differs → signatures differ
    expect(a1.payload.requestHash).not.toBe(a2.payload.requestHash);
    expect(a1.signature).not.toBe(a2.signature);
  });
});

// ── 2. Key isolation ──────────────────────────────────────────────────────────

describe('Key isolation — tenant key cross-verification', () => {

  test('artifact signed by key A cannot be verified by key B', () => {
    // Generate a fresh key pair (simulates different tenant key)
    const { privateKey: privB, publicKey: pubB } = crypto.generateKeyPairSync('ed25519');
    const privBDer = privB.export({ type: 'pkcs8', format: 'der' });
    const pubBDer  = pubB.export({ type: 'spki',  format: 'der' });

    // Hash from the fixed envelope
    const hash = envelopeHash(freshEnvelope());

    // Sign with key A (KEY.privDer), try to verify with key B's public key
    const sigA = sign(hash, KEY.privDer);
    expect(verify(hash, sigA, pubBDer)).toBe(false);

    // Sign with key B, try to verify with key A's public key
    const sigB = sign(hash, privBDer);
    expect(verify(hash, sigB, Buffer.from(KEY.pubDer, 'hex'))).toBe(false);
  });

  test('correct key verifies its own signature', () => {
    const hash = envelopeHash(freshEnvelope());
    const sig  = sign(hash, KEY.privDer);
    const pubDer = Buffer.from(KEY.pubDer, 'hex');
    expect(verify(hash, sig, pubDer)).toBe(true);
  });
});

// ── 3. Signature non-malleability ─────────────────────────────────────────────

describe('Signature non-malleability', () => {

  test('flipping any bit of the payload invalidates the signature', async () => {
    const store = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const artifact = buildArtifact();

    // Modify the requestHash in the payload (which is part of the signed content)
    const tampered = {
      ...artifact,
      payload: {
        ...artifact.payload,
        requestHash: artifact.payload.requestHash.replace(/^./, c =>
          c === '0' ? '1' : '0'),
      },
    };
    const result = await validateBoundRequest(tampered, BASE_REQ, { _store: store, _anomalyStore: anomaly });
    expect(result.allowed).toBe(false);
    expect(result.reason).toMatch(/INVALID_SIGNATURE|BINDING/);
  });

  test('altering the timestamp invalidates the signature', async () => {
    const store = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const artifact = buildArtifact();
    const tampered = { ...artifact, timestamp: artifact.timestamp + 1 };

    const result = await validateBoundRequest(tampered, BASE_REQ, { _store: store, _anomalyStore: anomaly });
    expect(result.allowed).toBe(false);
  });

  test('swapping publicKeyId invalidates the signature', async () => {
    const store = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const artifact = buildArtifact();
    const tampered = { ...artifact, publicKeyId: 'attacker:key_v1' };

    const result = await validateBoundRequest(tampered, BASE_REQ, { _store: store, _anomalyStore: anomaly });
    expect(result.allowed).toBe(false);
  });
});

// ── 4. Request binding integrity ──────────────────────────────────────────────

describe('Request binding integrity', () => {

  test('artifact signed for request A cannot authorize request B', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();

    const reqA = { method: 'POST', path: '/ai/chat', body: { prompt: 'legitimate', model: 'gpt-4' } };
    const reqB = { method: 'POST', path: '/ai/chat', body: { prompt: 'attackers-content', model: 'gpt-4' } };

    const artifact = buildArtifact(reqA);

    // Attempt to use the artifact (signed for reqA) to authorize reqB
    const result = await validateBoundRequest(artifact, reqB, { _store: store, _anomalyStore: anomaly });
    expect(result.allowed).toBe(false);
  });

  test('artifact signed for path /ai/chat cannot authorize /admin', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();

    const reqA = { method: 'POST', path: '/ai/chat', body: { prompt: 'hello', model: 'gpt-4' } };
    const reqB = { method: 'POST', path: '/admin',   body: { prompt: 'hello', model: 'gpt-4' } };

    const artifact = buildArtifact(reqA);
    const result = await validateBoundRequest(artifact, reqB, { _store: store, _anomalyStore: anomaly });
    expect(result.allowed).toBe(false);
  });

  test('same artifact cannot be used twice (replay protection)', async () => {
    const store   = makeNonceStore();
    const anomaly = makeOpenAnomalyStore();
    const artifact = buildArtifact();

    const r1 = await validateBoundRequest(artifact, BASE_REQ, { _store: store, _anomalyStore: anomaly });
    expect(r1.allowed).toBe(true);

    const r2 = await validateBoundRequest(artifact, BASE_REQ, { _store: store, _anomalyStore: anomaly });
    expect(r2.allowed).toBe(false);
    expect(r2.reason).toBe('REPLAY_DETECTED');
  });
});

// ── 5. timingSafeCompare security properties ──────────────────────────────────

describe('Constant-time comparison', () => {

  test('equal buffers return true regardless of length', () => {
    for (const len of [1, 16, 32, 64, 256]) {
      const buf = crypto.randomBytes(len);
      expect(timingSafeCompare(buf, Buffer.from(buf))).toBe(true);
    }
  });

  test('buffers differing by one bit return false', () => {
    const buf = crypto.randomBytes(32);
    const mod = Buffer.from(buf);
    mod[0] ^= 0x01;
    expect(timingSafeCompare(buf, mod)).toBe(false);
  });

  test('length mismatch always returns false (prevents length oracle)', () => {
    const a = crypto.randomBytes(32);
    const b = crypto.randomBytes(31);
    expect(timingSafeCompare(a, b)).toBe(false);
    expect(timingSafeCompare(b, a)).toBe(false);
  });
});

// ── 6. Envelope hash domain separation ────────────────────────────────────────

describe('Domain separation prevents cross-context signature reuse', () => {

  test('envelopeHash uses domain separation (hash differs from raw sha256)', () => {
    const { sha256Raw } = require('../../src/infra/crypto/hashing');
    const { canonicalizeEnvelope } = require('../../src/validation/canonicalize');

    const envelope    = freshEnvelope();
    const canonical   = canonicalizeEnvelope(envelope);
    const rawHash     = sha256Raw(canonical);
    const domainHash  = envelopeHash(envelope);

    // Domain-separated hash must differ from plain hash of canonical form
    expect(rawHash.toString('hex')).not.toBe(domainHash.toString('hex'));
  });

  test('envelopeHash is deterministic for same envelope', () => {
    const env = freshEnvelope({ requestHash: 'fixed-rh' });
    const h1  = envelopeHash(env);
    const h2  = envelopeHash({ ...env });
    expect(h1.toString('hex')).toBe(h2.toString('hex'));
  });
});
