'use strict';

// Isolated pure-function tests (Register #167) — the policy engine, hashing,
// and logging are mocked so this file exercises evaluatePolicyDecision()'s
// own orchestration/shaping logic in isolation, with explicit inputs and no
// Express req/res anywhere.

jest.mock('../engine', () => ({ evaluate: jest.fn() }));
jest.mock('../log', () => ({ logHashBound: jest.fn(), logError: jest.fn() }));
jest.mock('../../logger', () => ({ blocked: jest.fn(), emit: jest.fn() }));
jest.mock('../../policyHash', () => ({ computePolicyHash: jest.fn() }));

const { evaluate }          = require('../engine');
const { logHashBound, logError } = require('../log');
const { blocked, emit }     = require('../../logger');
const { computePolicyHash } = require('../../policyHash');
const { evaluatePolicyDecision } = require('../evaluatePolicyDecision');

const BASE_PARAMS = Object.freeze({
  getPolicies: () => [{ id: 'p1' }],
  policyStore: { getCount: jest.fn(), increment: jest.fn() },
  requestId:   'req-001',
  artifactId:  'artifact-001',
  artifactValid: true,
  userId:      'default:key_v1',
  callerId:    'caller-1',
  action:      'openai',
  tenantId:    'default',
  ip:          '203.0.113.4',
  timestamp:   1_700_000_000,
});

beforeEach(() => {
  jest.clearAllMocks();
});

describe('evaluatePolicyDecision — pure function contract', () => {
  test('takes only explicit parameters — no req/res in its call signature', () => {
    expect(evaluatePolicyDecision.length).toBe(1); // single destructured params object
  });

  test('ALLOW — returns decision EXECUTE with policyHash computed and logged', async () => {
    evaluate.mockResolvedValue({
      decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM',
      policyVersion: 3, engineVersion: 'v2', evaluatedAt: '2026-01-01T00:00:00Z',
      evaluationPath: [{ rule: 'r1' }], consentProvenance: { source: 'registry' },
    });
    computePolicyHash.mockReturnValue('hash123');

    const result = await evaluatePolicyDecision(BASE_PARAMS);

    expect(result.decision).toBe('EXECUTE');
    expect(result.policyHash).toBe('hash123');
    expect(result.policyId).toBe('SYSTEM');
    expect(result.policyVersion).toBe(3);
    expect(result.engineVersion).toBe('v2');
    expect(result.evaluatedAt).toBe('2026-01-01T00:00:00Z');
    expect(result.evaluationPath).toEqual([{ rule: 'r1' }]);
    expect(result.consentProvenance).toEqual({ source: 'registry' });
    expect(logHashBound).toHaveBeenCalledWith('hash123', { requestId: 'req-001' });
    expect(blocked).not.toHaveBeenCalled();
  });

  test('ALLOW — passes a properly-shaped context to evaluate()', async () => {
    evaluate.mockResolvedValue({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM' });
    computePolicyHash.mockReturnValue('h');

    await evaluatePolicyDecision(BASE_PARAMS);

    expect(evaluate).toHaveBeenCalledTimes(1);
    const [context, policies, store, opts] = evaluate.mock.calls[0];
    expect(context).toEqual({
      artifact:  { valid: true },
      userId:    'default:key_v1',
      callerId:  'caller-1',
      action:    'openai',
      tenantId:  'default',
      requestId: 'req-001',
      ip:        '203.0.113.4',
      timestamp: 1_700_000_000,
    });
    expect(policies).toEqual([{ id: 'p1' }]);
    expect(store).toBe(BASE_PARAMS.policyStore);
    expect(opts).toEqual({ requestId: 'req-001' });
  });

  test('normalizes an IPv4-mapped IPv6 address before passing it to evaluate()', async () => {
    evaluate.mockResolvedValue({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM' });
    computePolicyHash.mockReturnValue('h');

    await evaluatePolicyDecision({ ...BASE_PARAMS, ip: '::ffff:127.0.0.1' });

    const [context] = evaluate.mock.calls[0];
    expect(context.ip).toBe('127.0.0.1');
  });

  test('defaults a missing/null ip to 0.0.0.0', async () => {
    evaluate.mockResolvedValue({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM' });
    computePolicyHash.mockReturnValue('h');

    await evaluatePolicyDecision({ ...BASE_PARAMS, ip: null });

    const [context] = evaluate.mock.calls[0];
    expect(context.ip).toBe('0.0.0.0');
  });

  test('artifactValid !== true is reflected in the context passed to evaluate()', async () => {
    evaluate.mockResolvedValue({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM' });
    computePolicyHash.mockReturnValue('h');

    await evaluatePolicyDecision({ ...BASE_PARAMS, artifactValid: false });

    const [context] = evaluate.mock.calls[0];
    expect(context.artifact.valid).toBe(false);
  });

  test('DENY — returns the engine reason, logs the denial, emits ANOMALY_POLICY_DENIAL, and does not compute a policyHash', async () => {
    evaluate.mockResolvedValue({
      decision: 'BLOCK', reason: 'RATE_LIMIT_EXCEEDED', policyId: 'p1',
      policyVersion: 1, engineVersion: 'v2', evaluatedAt: '2026-01-01T00:00:00Z',
      evaluationPath: [], consentProvenance: null,
    });

    const result = await evaluatePolicyDecision({ ...BASE_PARAMS, keyId: 'tenant:key_v1' });

    expect(result.decision).toBe('BLOCK');
    expect(result.reason).toBe('RATE_LIMIT_EXCEEDED');
    expect(result.policyId).toBe('p1');
    expect(result.policyHash).toBeNull();
    expect(computePolicyHash).not.toHaveBeenCalled();
    expect(emit).toHaveBeenCalledWith('WARN', 'ANOMALY_POLICY_DENIAL', { source: 'tenant:key_v1', reason: 'POLICY_BLOCKED' });
    expect(blocked).toHaveBeenCalledWith('req-001', 'artifact-001', 'RATE_LIMIT_EXCEEDED', null);
  });

  test('DENY — keyId defaults to "unknown" when not supplied', async () => {
    evaluate.mockResolvedValue({ decision: 'BLOCK', reason: 'POLICY_DENIED', policyId: 'p1' });

    await evaluatePolicyDecision(BASE_PARAMS);

    expect(emit).toHaveBeenCalledWith('WARN', 'ANOMALY_POLICY_DENIAL', { source: 'unknown', reason: 'POLICY_BLOCKED' });
  });

  test('getPolicies() throwing → ENFORCEMENT_ERROR with reason POLICY_LOAD_ERROR, evaluate() never called', async () => {
    const err = new Error('policies.json corrupted');
    const params = { ...BASE_PARAMS, getPolicies: () => { throw err; } };

    const result = await evaluatePolicyDecision(params);

    expect(result.decision).toBe('ENFORCEMENT_ERROR');
    expect(result.reason).toBe('POLICY_LOAD_ERROR');
    expect(result.policyId).toBeNull();
    expect(result.policyHash).toBeNull();
    expect(evaluate).not.toHaveBeenCalled();
    expect(logError).toHaveBeenCalledWith('POLICY_LOAD_ERROR', { requestId: 'req-001', error: err.message });
    expect(blocked).toHaveBeenCalledWith('req-001', 'artifact-001', 'POLICY_LOAD_ERROR', null);
  });

  test('evaluate() throwing → ENFORCEMENT_ERROR with reason POLICY_ENGINE_ERROR', async () => {
    const err = new Error('engine crashed');
    evaluate.mockRejectedValue(err);

    const result = await evaluatePolicyDecision(BASE_PARAMS);

    expect(result.decision).toBe('ENFORCEMENT_ERROR');
    expect(result.reason).toBe('POLICY_ENGINE_ERROR');
    expect(logError).toHaveBeenCalledWith('POLICY_ENGINE_ERROR', { requestId: 'req-001', error: err.message });
    expect(blocked).toHaveBeenCalledWith('req-001', 'artifact-001', 'POLICY_ENGINE_ERROR', null);
  });

  test('artifactId defaults to requestId when not supplied', async () => {
    const err = new Error('boom');
    const { artifactId, ...withoutArtifactId } = BASE_PARAMS;
    const params = { ...withoutArtifactId, getPolicies: () => { throw err; } };

    await evaluatePolicyDecision(params);

    expect(blocked).toHaveBeenCalledWith('req-001', 'req-001', 'POLICY_LOAD_ERROR', null);
  });

  test('result object is frozen (immutable)', async () => {
    evaluate.mockResolvedValue({ decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', policyId: 'SYSTEM' });
    computePolicyHash.mockReturnValue('h');

    const result = await evaluatePolicyDecision(BASE_PARAMS);
    expect(Object.isFrozen(result)).toBe(true);
  });
});
