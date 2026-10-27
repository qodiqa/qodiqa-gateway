'use strict';

const path = require('path');

const POLICY_PATH = path.join(__dirname, '..', 'semanticPolicy.js');
const ENV_VAR = 'QODIQA_SEM_WARN_ESCALATE';

describe('loadSemanticPolicy — warnEscalate parsing', () => {
  beforeEach(() => {
    jest.resetModules();
    delete process.env[ENV_VAR];
  });

  afterEach(() => {
    delete process.env[ENV_VAR];
    jest.resetModules();
  });

  it('audit 2026-10-20 unset => the two measured prompt-injection reasons are escalated by default', () => {
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect(policy.warnEscalate).toBeInstanceOf(Set);
    expect([...policy.warnEscalate].sort()).toEqual(['PROMPT_INJECTION_ATTEMPT', 'SYSTEM_PROMPT_EXTRACTION']);
    expect(policy.warnEscalate.has('POLICY_BYPASS_ATTEMPT')).toBe(false);
  });

  it('set-but-empty restores the previous inert behaviour (operator kill-switch)', () => {
    process.env[ENV_VAR] = '';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    expect(loadSemanticPolicy().warnEscalate.size).toBe(0);
  });

  it('parses a single reason', () => {
    process.env[ENV_VAR] = 'SYSTEM_PROMPT_EXTRACTION';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect([...policy.warnEscalate]).toEqual(['SYSTEM_PROMPT_EXTRACTION']);
  });

  it('parses a comma-separated list, trimming whitespace', () => {
    process.env[ENV_VAR] = ' SYSTEM_PROMPT_EXTRACTION, PROMPT_INJECTION_ATTEMPT ,POLICY_BYPASS_ATTEMPT';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect(policy.warnEscalate.has('SYSTEM_PROMPT_EXTRACTION')).toBe(true);
    expect(policy.warnEscalate.has('PROMPT_INJECTION_ATTEMPT')).toBe(true);
    expect(policy.warnEscalate.has('POLICY_BYPASS_ATTEMPT')).toBe(true);
    expect(policy.warnEscalate.size).toBe(3);
  });

  it('drops empty entries from a trailing/doubled comma without throwing', () => {
    process.env[ENV_VAR] = 'SYSTEM_PROMPT_EXTRACTION,,';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect([...policy.warnEscalate]).toEqual(['SYSTEM_PROMPT_EXTRACTION']);
  });

  it('an unknown/misspelled reason name is accepted at parse time (never matches any real reason, never throws)', () => {
    process.env[ENV_VAR] = 'NOT_A_REAL_REASON_CODE';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    expect(() => loadSemanticPolicy()).not.toThrow();
    const policy = loadSemanticPolicy();
    expect(policy.warnEscalate.has('NOT_A_REAL_REASON_CODE')).toBe(true);
    expect(policy.warnEscalate.has('SYSTEM_PROMPT_EXTRACTION')).toBe(false);
  });

  it('the returned Set is effectively read-only via the frozen policy object (no accidental cross-request mutation path)', () => {
    process.env[ENV_VAR] = 'SYSTEM_PROMPT_EXTRACTION';
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect(Object.isFrozen(policy)).toBe(true);
  });

  it('does not disturb the existing WARN_BLOCKS/REVIEW_BLOCKS defaults', () => {
    const { loadSemanticPolicy } = require(POLICY_PATH);
    const policy = loadSemanticPolicy();
    expect(policy.enforcement.WARN_BLOCKS).toBe(false);
    expect(policy.enforcement.REVIEW_BLOCKS).toBe(true);
  });
});
