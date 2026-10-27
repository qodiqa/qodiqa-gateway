'use strict';

/**
 * Item 17 — combined vs. sequential path ROUTING.
 *
 * Isolates validateBoundRequest.js's routing decision (combined-Lua vs. the
 * original sequential registerNonce()+checkAnomaly() calls) from both Redis
 * and Lua specifics, by mocking nonceStore.js/anomalyStore.js at the module
 * boundary and asserting which functions got called. No Redis connection is
 * ever attempted — the routing tests need to safely exercise the
 * "no _store/_anomalyStore override" (real-store) code path, which the rest
 * of the suite deliberately avoids (see aiChat.test.js: "All stores are
 * injected — no Redis required").
 */

jest.mock('../nonceStore', () => ({
  register:               jest.fn(async () => ({ registered: true })),
  registerAndCheckAnomaly: jest.fn(async () => ({ phase: 'ALLOWED', perKeyCount: 1, globalCount: 1 })),
}));
jest.mock('../anomalyStore', () => ({
  record: jest.fn(async () => ({ count: 1 })),
  buildAnomalyKeys: jest.fn((publicKeyId, tenantId) => ({
    perKeyKey: `${tenantId ? `tenant:${tenantId}:` : ''}key:${publicKeyId}`,
    globalKey: `${tenantId ? `tenant:${tenantId}:` : ''}global`,
  })),
}));

const nonceStoreMock   = require('../nonceStore');
const anomalyStoreMock = require('../anomalyStore');
const { validateBoundRequest } = require('../validateBoundRequest');
const { signBoundArtifact }    = require('../signBoundArtifact');
const { getActiveKey }         = require('../../../services/artifact/keyStore');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });

function freshEnvelope(payload = {}) {
  const now = Date.now();
  return { payload, timestamp: now, expiry: now + 300_000, publicKeyId: KEY.keyId };
}
const BASE_REQ = { method: 'POST', path: '/api/run', body: { q: 1 } };
function buildBound(request, extraPayload = {}) {
  return signBoundArtifact(request, freshEnvelope(extraPayload), KEY.privDer);
}

beforeEach(() => {
  jest.clearAllMocks();
  nonceStoreMock.register.mockResolvedValue({ registered: true });
  nonceStoreMock.registerAndCheckAnomaly.mockResolvedValue({ phase: 'ALLOWED', perKeyCount: 1, globalCount: 1 });
  anomalyStoreMock.record.mockResolvedValue({ count: 1 });
});

describe('validateBoundRequest — item 17 combined/sequential routing', () => {

  test('default (no _haMode override, no store overrides) -> combined path used', async () => {
    const artifact = buildBound(BASE_REQ);
    const result = await validateBoundRequest(artifact, BASE_REQ, {});
    expect(result.allowed).toBe(true);

    expect(nonceStoreMock.registerAndCheckAnomaly).toHaveBeenCalledTimes(1);
    expect(nonceStoreMock.register).not.toHaveBeenCalled();
    expect(anomalyStoreMock.record).not.toHaveBeenCalled();
  });

  test('_haMode: "cluster" with no store overrides -> falls back to sequential path automatically', async () => {
    const artifact = buildBound(BASE_REQ);
    const result = await validateBoundRequest(artifact, BASE_REQ, { _haMode: 'cluster' });
    expect(result.allowed).toBe(true);

    // Sequential path: register() once, then record() twice (per-key + global).
    expect(nonceStoreMock.register).toHaveBeenCalledTimes(1);
    expect(anomalyStoreMock.record).toHaveBeenCalledTimes(2);
    expect(nonceStoreMock.registerAndCheckAnomaly).not.toHaveBeenCalled();
  });

  test('_haMode: "sentinel" with no store overrides -> combined path still used (sentinel has one logical dataset, no CROSSSLOT risk)', async () => {
    const artifact = buildBound(BASE_REQ);
    const result = await validateBoundRequest(artifact, BASE_REQ, { _haMode: 'sentinel' });
    expect(result.allowed).toBe(true);
    expect(nonceStoreMock.registerAndCheckAnomaly).toHaveBeenCalledTimes(1);
    expect(nonceStoreMock.register).not.toHaveBeenCalled();
  });

  test('_haMode: "single" explicitly -> combined path used', async () => {
    const artifact = buildBound(BASE_REQ);
    const result = await validateBoundRequest(artifact, BASE_REQ, { _haMode: 'single' });
    expect(result.allowed).toBe(true);
    expect(nonceStoreMock.registerAndCheckAnomaly).toHaveBeenCalledTimes(1);
  });

  test('explicit _store/_anomalyStore test doubles -> sequential path, real modules never touched, regardless of _haMode', async () => {
    const nonceDouble = { async register() { return { registered: true }; } };
    const anomalyDouble = { async record() { return { count: 1 }; } };
    const artifact = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _store: nonceDouble, _anomalyStore: anomalyDouble, _haMode: 'single',
    });
    expect(result.allowed).toBe(true);

    expect(nonceStoreMock.register).not.toHaveBeenCalled();
    expect(nonceStoreMock.registerAndCheckAnomaly).not.toHaveBeenCalled();
    expect(anomalyStoreMock.record).not.toHaveBeenCalled();
  });

  test('_combined override forces the combined path even under _haMode: "cluster"', async () => {
    const combinedDouble = {
      async registerAndCheckAnomaly() { return { phase: 'ALLOWED', perKeyCount: 1, globalCount: 1 }; },
    };
    const artifact = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {
      _combined: combinedDouble, _haMode: 'cluster',
    });
    expect(result.allowed).toBe(true);
    expect(nonceStoreMock.register).not.toHaveBeenCalled();
    expect(nonceStoreMock.registerAndCheckAnomaly).not.toHaveBeenCalled();
  });

  test('cluster fallback still blocks on replay — REPLAY_DETECTED surfaces identically via the sequential path', async () => {
    nonceStoreMock.register.mockResolvedValueOnce({ registered: false });
    const artifact = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, { _haMode: 'cluster' });
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('REPLAY_DETECTED');
    expect(anomalyStoreMock.record).not.toHaveBeenCalled();
  });

  test('combined path replay -> REPLAY_DETECTED, anomaly never invoked', async () => {
    nonceStoreMock.registerAndCheckAnomaly.mockResolvedValueOnce({ phase: 'REPLAY' });
    const artifact = buildBound(BASE_REQ);

    const result = await validateBoundRequest(artifact, BASE_REQ, {});
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('REPLAY_DETECTED');
  });

});
