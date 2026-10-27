'use strict';

const { resolveAction } = require('../semanticActions');
const { DECISION } = require('../../reasons');

describe('resolveAction — tier defaults (pre-existing behavior, unchanged)', () => {
  it('DENY always blocks, no enforcement flag can change it', () => {
    expect(resolveAction({ decision: DECISION.DENY, reason: 'X' }, {}).blocks).toBe(true);
    expect(resolveAction({ decision: DECISION.DENY, reason: 'X' }, { enforcement: { REVIEW_BLOCKS: false } }).blocks).toBe(true);
  });

  it('REVIEW blocks by default, opts out only via REVIEW_BLOCKS:false', () => {
    expect(resolveAction({ decision: DECISION.REVIEW, reason: 'X' }, {}).blocks).toBe(true);
    expect(resolveAction({ decision: DECISION.REVIEW, reason: 'X' }, { enforcement: { REVIEW_BLOCKS: false } }).blocks).toBe(false);
  });

  it('WARN does not block by default', () => {
    expect(resolveAction({ decision: DECISION.WARN, reason: 'X' }, {}).blocks).toBe(false);
  });

  it('WARN blocks when WARN_BLOCKS is globally true', () => {
    expect(resolveAction({ decision: DECISION.WARN, reason: 'X' }, { enforcement: { WARN_BLOCKS: true } }).blocks).toBe(true);
  });

  it('ALLOW never blocks', () => {
    expect(resolveAction({ decision: DECISION.ALLOW, reason: null }, {}).blocks).toBe(false);
  });

  it('handles a missing/undefined policy object without throwing', () => {
    expect(() => resolveAction({ decision: DECISION.WARN, reason: 'X' })).not.toThrow();
    expect(resolveAction({ decision: DECISION.WARN, reason: 'X' }).blocks).toBe(false);
  });
});

describe('resolveAction — per-reason WARN escalation', () => {
  it('blocks a WARN whose reason is in warnEscalate, even with WARN_BLOCKS false', () => {
    const policy = { enforcement: { WARN_BLOCKS: false }, warnEscalate: new Set(['SYSTEM_PROMPT_EXTRACTION']) };
    expect(resolveAction({ decision: DECISION.WARN, reason: 'SYSTEM_PROMPT_EXTRACTION' }, policy).blocks).toBe(true);
  });

  it('does NOT block a WARN whose reason is absent from warnEscalate', () => {
    const policy = { enforcement: { WARN_BLOCKS: false }, warnEscalate: new Set(['SYSTEM_PROMPT_EXTRACTION']) };
    expect(resolveAction({ decision: DECISION.WARN, reason: 'PROMPT_INJECTION_ATTEMPT' }, policy).blocks).toBe(false);
  });

  it('escalation and the global switch are independent ORs, neither replaces the other', () => {
    // WARN_BLOCKS true, warnEscalate empty -> still blocks (global switch alone is sufficient)
    expect(resolveAction(
      { decision: DECISION.WARN, reason: 'ANYTHING' },
      { enforcement: { WARN_BLOCKS: true }, warnEscalate: new Set() },
    ).blocks).toBe(true);
    // WARN_BLOCKS false, warnEscalate has the reason -> still blocks (escalation alone is sufficient)
    expect(resolveAction(
      { decision: DECISION.WARN, reason: 'FILE_SYSTEM_ENUMERATION' },
      { enforcement: { WARN_BLOCKS: false }, warnEscalate: new Set(['FILE_SYSTEM_ENUMERATION']) },
    ).blocks).toBe(true);
  });

  it('empty/missing warnEscalate never blocks anything on its own (default/inert state)', () => {
    expect(resolveAction({ decision: DECISION.WARN, reason: 'X' }, { enforcement: {}, warnEscalate: new Set() }).blocks).toBe(false);
    expect(resolveAction({ decision: DECISION.WARN, reason: 'X' }, { enforcement: {} }).blocks).toBe(false);
  });

  it('never escalates a non-WARN decision (escalation is scoped to the WARN tier only)', () => {
    const policy = { enforcement: {}, warnEscalate: new Set(['SYSTEM_PROMPT_EXTRACTION']) };
    expect(resolveAction({ decision: DECISION.ALLOW, reason: 'SYSTEM_PROMPT_EXTRACTION' }, policy).blocks).toBe(false);
    // REVIEW already blocks by default, but confirm escalation doesn't change REVIEW's OWN opt-out path
    expect(resolveAction(
      { decision: DECISION.REVIEW, reason: 'SYSTEM_PROMPT_EXTRACTION' },
      { enforcement: { REVIEW_BLOCKS: false }, warnEscalate: new Set(['SYSTEM_PROMPT_EXTRACTION']) },
    ).blocks).toBe(false);
  });

  it('a null reason on a WARN decision never matches escalation (guards the Set lookup)', () => {
    const policy = { enforcement: {}, warnEscalate: new Set(['SYSTEM_PROMPT_EXTRACTION']) };
    expect(() => resolveAction({ decision: DECISION.WARN, reason: null }, policy)).not.toThrow();
    expect(resolveAction({ decision: DECISION.WARN, reason: null }, policy).blocks).toBe(false);
  });
});
