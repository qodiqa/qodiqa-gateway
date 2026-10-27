'use strict';

// this suite exercises the embedding gate with a stand-in classifier
process.env.QODIQA_SEM_EMBEDDING_ENABLED = 'true';

/**
 * SEM-C session 3 — embeddingGate.js unit tests. Mocks ../embeddingSimilarity
 * entirely so every branch (ALLOW, DENY match, infra failure, unexpected
 * throw) is deterministic — this suite is about the gate's own
 * result-shape/evidence mapping, not about the embedding backend itself
 * (see ../embeddingSimilarity/__tests__/ for that).
 */

const { SEMANTIC_ENGINE_UNAVAILABLE_REASON, SEMANTIC_REASONS } = require('../reasons');

function freshGate(classifyImpl) {
  jest.resetModules();
  jest.doMock('../embeddingSimilarity', () => ({ classify: classifyImpl }));
  return require('../embeddingGate');
}

afterEach(() => {
  jest.dontMock('../embeddingSimilarity');
  jest.resetModules();
});

const CTX = { requestId: 'req-1', tenantId: 'tenant-1', provider: 'openai', surface: 'REQUEST' };

describe('embeddingGate.checkText', () => {
  test('ALLOW: does not block, evidence reflects ALLOW', async () => {
    const gate = freshGate(jest.fn().mockResolvedValue({
      decision: 'ALLOW', score: 0.1, threshold: 0.52, matchedAnchorId: null,
      engineStatus: 'READY', failureReason: null,
    }));

    const result = await gate.checkText('benign text', CTX);
    expect(result.blocks).toBe(false);
    expect(result.decision).toBe('ALLOW');
    expect(result.reason).toBeNull();
    expect(result.evidence.decision).toBe('ALLOW');
    expect(result.evidence.requestId).toBe('req-1');
  });

  test('DENY match: blocks, reason is EMBEDDING_SIMILARITY_MATCH, evidence carries the score', async () => {
    const gate = freshGate(jest.fn().mockResolvedValue({
      decision: 'DENY', score: 0.71, threshold: 0.52, matchedAnchorId: 'AC-0191',
      engineStatus: 'READY', failureReason: null,
    }));

    const result = await gate.checkText('paraphrased bypass attempt', CTX);
    expect(result.blocks).toBe(true);
    expect(result.decision).toBe('DENY');
    expect(result.reason).toBe(SEMANTIC_REASONS.EMBEDDING_SIMILARITY_MATCH);
    expect(result.evidence.decision).toBe('DENY');
    expect(result.evidence.score).toBeCloseTo(0.71, 4);
    expect(result.evidence.matchedPolicies).toHaveLength(1);
    expect(result.evidence.matchedPolicies[0].classifierId).toBe('embeddingSimilarity');
  });

  test('infra failure (embeddingSimilarity fails closed internally): blocks, generic client-facing reason, granular reason in evidence', async () => {
    const gate = freshGate(jest.fn().mockResolvedValue({
      decision: 'DENY', score: null, threshold: 0.52, matchedAnchorId: null,
      engineStatus: 'UNAVAILABLE', failureReason: 'EMBEDDING_INFERENCE_FAILED',
    }));

    const result = await gate.checkText('anything', CTX);
    expect(result.blocks).toBe(true);
    expect(result.reason).toBe(SEMANTIC_ENGINE_UNAVAILABLE_REASON);
    expect(result.evidence.failureReason).toBe('EMBEDDING_INFERENCE_FAILED');
    expect(result.evidence.engineStatus).toBe('UNAVAILABLE');
  });

  test('unexpected throw from embeddingSimilarity.classify(): still blocks, never propagates', async () => {
    const gate = freshGate(jest.fn().mockRejectedValue(new Error('boom')));

    const result = await gate.checkText('anything', CTX);
    expect(result.blocks).toBe(true);
    expect(result.reason).toBe(SEMANTIC_ENGINE_UNAVAILABLE_REASON);
    expect(result.evidence.failureReason).toBe('EMBEDDING_GATE_UNEXPECTED_ERROR');
  });

  test('works with no ctx supplied (defaults applied, never throws)', async () => {
    const gate = freshGate(jest.fn().mockResolvedValue({
      decision: 'ALLOW', score: 0, threshold: 0.52, matchedAnchorId: null,
      engineStatus: 'READY', failureReason: null,
    }));
    const result = await gate.checkText('text');
    expect(result.blocks).toBe(false);
  });
});
