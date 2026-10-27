'use strict';

/**
 * Canonical Reason Code Contract Tests
 *
 * Verifies that the runtime, /verify, and pipeline all emit codes
 * from the single canonical vocabulary — no legacy strings, no prose,
 * no near-synonyms.
 */

// Mock consent registry — policies.json uses REQUIRE_CONSENT; these tests
// validate the reason CODE vocabulary, not the consent evaluation logic.
jest.mock('../../src/core/consent', () => ({
  verify: jest.fn().mockResolvedValue({ pass: true, reason: 'ACTIVE' }),
}));

const { REASONS } = require('../reasons');

const path   = require('path');
const crypto = require('crypto');
const { validateArtifact }      = require('../validation/validateArtifact');
const { validateBoundRequest }  = require('../validation/validateBoundRequest');
const { signBoundArtifact }     = require('../validation/signBoundArtifact');
const { rotateKey, getActiveKey } = require('../../services/artifact/keyStore');
const { evaluate }              = require('../../services/policy/engine');
const { loadPolicies }          = require('../../services/policy/loader');
const { createStore }           = require('../../services/policy/store');
const { makeNonceStore, makeOpenAnomalyStore } = require('../testing/stores');

// ── Helpers ───────────────────────────────────────────────────────────────────

function freshNonceStore() { return makeNonceStore(); }
function freshAnomalyStore() { return makeOpenAnomalyStore(); }

let _key;
function ensureKey() {
  if (!_key) {
    rotateKey('reasons-test');
    _key = getActiveKey('reasons-test');
  }
  return _key;
}

function signedArtifact(overrides = {}, reqOverrides = {}) {
  const req = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' }, ...reqOverrides };
  const key = ensureKey();
  const now = Date.now();
  const base = signBoundArtifact(
    req,
    { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 60_000, publicKeyId: key.keyId },
    key.privDer,
  );
  return { artifact: { ...base, ...overrides }, request: req };
}

const POLICIES = loadPolicies(path.join(__dirname, '../../policies.json'));
// The canonical in-memory rate-limit store (services/policy/store.js's
// createStore()) — deterministic, sync, no Redis dependency, built exactly
// for test injection. Replaces a stale ad-hoc stub that only implemented
// the legacy getCount()/increment() pair; the RATE_LIMIT evaluator
// (services/policy/evaluators/rateLimit.js) now calls checkAndIncrement()
// atomically instead, which that stub never implemented — every call threw
// and was caught by the evaluator's fail-closed handling, always returning
// RATE_LIMIT_EXCEEDED regardless of actual request count.
//
// One shared instance for the whole file is sufficient, not a hidden
// coupling risk: every rate-limited key below (POL-004:<userId>) is touched
// by exactly one evaluate() call across this entire file — REASON-05c and
// REASON-06b's later calls reuse the same userIds but pass an empty/invalid
// context or policy list, which the engine rejects before the RATE_LIMIT
// evaluator ever runs. If a future test starts reusing a userId that
// already went through the evaluator, give it its own createStore().
const STORE    = createStore();

// ── REASON-01: canonical set is non-empty and all-uppercase-snake-case ─────────

describe('canonical reason set', () => {
  test('REASON-01  all entries are non-empty UPPERCASE_SNAKE_CASE strings', () => {
    const RE = /^[A-Z][A-Z0-9_]+$/;
    for (const [k, v] of Object.entries(REASONS)) {
      expect(typeof v).toBe('string');
      expect(v).toMatch(RE);
      expect(k).toBe(v);   // key === value — self-documenting
    }
  });

  test('REASON-02  no two entries share the same string value', () => {
    const values = Object.values(REASONS);
    const unique  = new Set(values);
    expect(unique.size).toBe(values.length);
  });
});

// ── REASON-03: validateArtifact emits canonical codes ─────────────────────────

describe('validateArtifact reason codes', () => {
  test('REASON-03a  missing artifact → INVALID_ARTIFACT', () => {
    expect(validateArtifact(null).reason).toBe(REASONS.INVALID_ARTIFACT);
    expect(validateArtifact([]).reason).toBe(REASONS.INVALID_ARTIFACT);
    expect(validateArtifact('str').reason).toBe(REASONS.INVALID_ARTIFACT);
  });

  test('REASON-03b  missing field → INVALID_ARTIFACT', () => {
    const { artifact } = signedArtifact();
    const { expiry: _, ...noExpiry } = artifact;
    expect(validateArtifact(noExpiry).reason).toBe(REASONS.INVALID_ARTIFACT);
  });

  test('REASON-03c  tampered signature → INVALID_SIGNATURE', () => {
    const { artifact } = signedArtifact();
    const tampered = { ...artifact, signature: Buffer.alloc(64).toString('base64') };
    expect(validateArtifact(tampered).reason).toBe(REASONS.INVALID_SIGNATURE);
  });

  // CRYPTO-5/VERIFY-4: expiry/timestamp are covered by the envelope
  // signature — mutating either AFTER signing (the previous version of these
  // two tests) breaks the signature itself, so validateArtifact now correctly
  // reports INVALID_SIGNATURE first (see fullEnvelopeSigning.test.js TC-3 for
  // the dedicated tamper-detection regression). To exercise EXPIRED/
  // FUTURE_TIMESTAMP in isolation — a genuinely, validly signed artifact,
  // never tampered — these sign the target expiry/timestamp value directly
  // instead of mutating it afterward.

  test('REASON-03d  expired artifact (validly signed, clock moved past expiry) → EXPIRED', () => {
    const req = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' } };
    const key = ensureKey();
    const now = Date.now();
    const artifact = signBoundArtifact(
      req,
      { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: now, expiry: now + 100, publicKeyId: key.keyId },
      key.privDer,
    );
    expect(validateArtifact(artifact, { _clock: () => now + 999999 }).reason).toBe(REASONS.EXPIRED);
  });

  test('REASON-03e  future timestamp (validly signed with a future timestamp) → FUTURE_TIMESTAMP', () => {
    const req = { method: 'POST', path: '/ai/chat', body: { prompt: 'hi', model: 'gpt-4' } };
    const key = ensureKey();
    const now = Date.now();
    const future = now + 999999;
    const artifact = signBoundArtifact(
      req,
      { payload: { provider: 'openai', policyHash: 'a'.repeat(64) }, timestamp: future, expiry: future + 60_000, publicKeyId: key.keyId },
      key.privDer,
    );
    expect(validateArtifact(artifact, { _clock: () => now }).reason).toBe(REASONS.FUTURE_TIMESTAMP);
  });

  test('REASON-03f  success → ALL_CHECKS_PASSED', () => {
    const { artifact } = signedArtifact();
    expect(validateArtifact(artifact).reason).toBe(REASONS.ALL_CHECKS_PASSED);
  });
});

// ── REASON-04: validateBoundRequest pipeline emits canonical codes ─────────────

describe('validateBoundRequest reason codes', () => {
  test('REASON-04a  no artifact → INVALID_ARTIFACT', async () => {
    const r = await validateBoundRequest(null, { method: 'POST', path: '/ai/chat', body: {} }, {
      _store: freshNonceStore(), _anomalyStore: freshAnomalyStore(),
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(REASONS.INVALID_ARTIFACT);
  });

  test('REASON-04b  request mismatch → REQUEST_MISMATCH', async () => {
    const { artifact } = signedArtifact();
    const otherReq = { method: 'POST', path: '/ai/chat', body: { prompt: 'different', model: 'gpt-4' } };
    const r = await validateBoundRequest(artifact, otherReq, {
      _store: freshNonceStore(), _anomalyStore: freshAnomalyStore(),
    });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(REASONS.REQUEST_MISMATCH);
  });

  test('REASON-04c  replay → REPLAY_DETECTED', async () => {
    const { artifact, request } = signedArtifact();
    const store = freshNonceStore();
    await validateBoundRequest(artifact, request, { _store: store, _anomalyStore: freshAnomalyStore() });
    const r = await validateBoundRequest(artifact, request, { _store: store, _anomalyStore: freshAnomalyStore() });
    expect(r.allowed).toBe(false);
    expect(r.reason).toBe(REASONS.REPLAY_DETECTED);
  });

  test('REASON-04d  success → allowed true (no public reason code in internal result)', async () => {
    const { artifact, request } = signedArtifact();
    const r = await validateBoundRequest(artifact, request, {
      _store: freshNonceStore(), _anomalyStore: freshAnomalyStore(),
    });
    expect(r.allowed).toBe(true);
  });
});

// ── REASON-05: policy engine emits canonical codes ────────────────────────────

describe('policy engine reason codes', () => {
  function ctx(overrides = {}) {
    return { artifact: { valid: true }, userId: 'u1', action: 'ai-chat', ip: '127.0.0.1', timestamp: Math.floor(Date.now() / 1000), ...overrides };
  }

  test('REASON-05a  success → ALL_CHECKS_PASSED', async () => {
    const r = await evaluate(ctx(), POLICIES, STORE);
    expect(r.decision).toBe('EXECUTE');
    expect(r.reason).toBe(REASONS.ALL_CHECKS_PASSED);
  });

  test('REASON-05b  null context → INVALID_CONTEXT (policy internal code)', async () => {
    const r = await evaluate(null, POLICIES, STORE);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe(REASONS.INVALID_CONTEXT);
  });

  test('REASON-05c  no policies → NO_POLICIES_LOADED (policy internal code)', async () => {
    const r = await evaluate(ctx(), [], STORE);
    expect(r.decision).toBe('BLOCK');
    expect(r.reason).toBe(REASONS.NO_POLICIES_LOADED);
  });
});

// ── REASON-06: no legacy codes emitted anywhere ────────────────────────────────

describe('legacy code elimination', () => {
  const FORBIDDEN = [
    'MALFORMED_ARTIFACT', 'INVALID_ARTIFACT_STRUCTURE', 'EXPIRED_ARTIFACT',
    'ARTIFACT_EXPIRED', 'TIMESTAMP_IN_FUTURE', 'SIGNATURE_INVALID',
    'INVALID_SIGNATURE_FORMAT', 'UNKNOWN_KEY_ID', 'POLICY_DENIED',
    'ALL_POLICIES_PASSED', 'PASS', 'VALID', 'OK', 'verified',
    'no artifact', 'verification failed', 'blocked',
    'missing_artifact', 'invalid_artifact', 'invalid_signature',
    'context_mismatch', 'artifact_reuse', 'verification_error',
  ];

  test('REASON-06a  validateArtifact never emits forbidden codes', () => {
    const cases = [null, [], 'str', {}, { ...signedArtifact().artifact, signature: Buffer.alloc(64).toString('base64') }];
    for (const c of cases) {
      const r = validateArtifact(c);
      expect(FORBIDDEN).not.toContain(r.reason);
    }
  });

  test('REASON-06b  policy engine never emits forbidden codes', () => {
    const evals = [
      evaluate(null, POLICIES, STORE),
      evaluate({ artifact: { valid: true }, userId: 'u', action: 'ai-chat', ip: '1.2.3.4', timestamp: Math.floor(Date.now() / 1000) }, POLICIES, STORE),
      evaluate({ artifact: { valid: true }, userId: 'u', action: 'ai-chat', ip: '1.2.3.4', timestamp: Math.floor(Date.now() / 1000) }, [], STORE),
    ];
    for (const r of evals) {
      expect(FORBIDDEN).not.toContain(r.reason);
    }
  });
});
