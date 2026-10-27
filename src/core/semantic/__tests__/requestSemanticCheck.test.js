'use strict';

// requestSemanticCheck.js had NO dedicated unit test —
// it was only exercised transitively through aiChat.js/verify.js route
// tests (see verifySemanticParity.test.js), which cover the end-to-end
// wiring but never isolate this module's own branch logic. Stryker's
// score), all on the two decision points this file has — the short-circuit
// on `semantic.blocks` and the ternary choosing between `embeddingResult`
// and `semantic`. This suite targets exactly those two branches plus the
// exact shape of the embeddingGate.checkText() call.

jest.mock('../index', () => ({
  runSemanticPolicyEngine: jest.fn(),
}));
jest.mock('../embeddingGate', () => ({
  checkText: jest.fn(),
}));

const { runSemanticPolicyEngine } = require('../index');
const embeddingGate = require('../embeddingGate');
const { evaluateRequestSemantic } = require('../requestSemanticCheck');

describe('evaluateRequestSemantic', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('returns the keyword-engine verdict as-is and never consults the embedding gate when it already blocks', async () => {
    const semanticVerdict = { blocks: true, decision: 'DENY', reason: 'keyword-match', evidence: { matched: 'x' } };
    runSemanticPolicyEngine.mockReturnValue(semanticVerdict);

    const result = await evaluateRequestSemantic({ prompt: 'p', provider: 'openai', tenantId: 't1', requestId: 'r1' });

    expect(result).toBe(semanticVerdict);
    expect(embeddingGate.checkText).not.toHaveBeenCalled();
  });

  test('consults the embedding gate when the keyword engine allows, and returns its verdict when IT blocks', async () => {
    const semanticVerdict = { blocks: false, decision: 'ALLOW', reason: null, evidence: {} };
    const embeddingVerdict = { blocks: true, decision: 'DENY', reason: 'embedding-match', evidence: { score: 0.9 } };
    runSemanticPolicyEngine.mockReturnValue(semanticVerdict);
    embeddingGate.checkText.mockResolvedValue(embeddingVerdict);

    const result = await evaluateRequestSemantic({ prompt: 'hello', provider: 'anthropic', tenantId: 't2', requestId: 'r2' });

    expect(result).toBe(embeddingVerdict);
  });

  test('returns the keyword-engine ALLOW verdict, not the embedding gate result, when the embedding gate also allows', async () => {
    const semanticVerdict = { blocks: false, decision: 'ALLOW', reason: null, evidence: {} };
    const embeddingVerdict = { blocks: false, decision: 'ALLOW', reason: null, evidence: {} };
    runSemanticPolicyEngine.mockReturnValue(semanticVerdict);
    embeddingGate.checkText.mockResolvedValue(embeddingVerdict);

    const result = await evaluateRequestSemantic({ prompt: 'hello', provider: 'anthropic', tenantId: 't2', requestId: 'r2' });

    expect(result).toBe(semanticVerdict);
    expect(result).not.toBe(embeddingVerdict);
  });

  test('calls embeddingGate.checkText with the prompt and the exact REQUEST-surface options object', async () => {
    runSemanticPolicyEngine.mockReturnValue({ blocks: false, decision: 'ALLOW', reason: null, evidence: {} });
    embeddingGate.checkText.mockResolvedValue({ blocks: false, decision: 'ALLOW', reason: null, evidence: {} });

    await evaluateRequestSemantic({ prompt: 'the exact prompt', provider: 'openai', tenantId: 'tenant-9', requestId: 'req-9' });

    expect(embeddingGate.checkText).toHaveBeenCalledWith('the exact prompt', {
      requestId: 'req-9',
      tenantId: 'tenant-9',
      provider: 'openai',
      surface: 'REQUEST',
    });
  });
});
