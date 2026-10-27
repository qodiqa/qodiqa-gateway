'use strict';

/**
 * AUDIT-V8-FREEZE Amendment 2: the sequence of the approval entries of one approvalRef is checked by BOTH verifiers (production walker == independent walker).
 *
 *   AS-01  the good sequences: granted then spent by one ACTION_INTENT; granted then expired; denied; expired unanswered; two independent approvals interleaved
 *   AS-02  each violation is APPROVAL_SEQUENCE_VIOLATION in both: out of order, repeated, another actionHash, spent twice, spent after expiry / denial, intent without approval
 *   AS-03  bounded walks accept an approval first seen mid-way; GENESIS walks do not
 *   AS-04  nothing else changes: entries without an approvalRef are not affected
 */

jest.mock('../../../infra/postgres/pg-audit-backend', () => ({ persistEntry: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

const eb = require('../entryBuilder');
const contract = require('../../../../scripts/audit-repro/verify/auditContract');
const audit = require('../audit-log');

const H = (c) => c.repeat(64);
const savedFlag = process.env.QODIQA_AUDIT_SCHEMA_V8;
beforeEach(() => { process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; });
afterAll(() => { if (savedFlag === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = savedFlag; });

const actionCtx = { action: { tool: { server: 'srv', name: 'tool', schemaHash: H('e') }, parentRequestHash: null, prevActionHash: null } };
const sess = '44444444-4444-4444-8444-444444444444';
const agent = '55555555-5555-4555-8555-555555555555';
const REQ = (ref, hash = H('d')) => ({ artifactId: `${ref}:approval_requested`, entryType: 'APPROVAL_REQUESTED', decision: 'BLOCK', reason: 'APPROVAL_REQUIRED', tenantId: 't1', approvalRef: ref, actionHash: hash, executionContext: { approval: { requesterId: 'identity:i', policyRuleId: 'tool:requiresApproval' } } });
const DEC = (ref, hash = H('d'), ok = true) => ({ artifactId: `${ref}:approval_decided`, entryType: 'APPROVAL_DECIDED', decision: ok ? 'ALLOW' : 'BLOCK', reason: ok ? 'APPROVED' : 'DENIED', tenantId: 't1', approvalRef: ref, actionHash: hash,
  executionContext: { approval: { requesterId: 'identity:i', approverId: 'bob', decision: ok ? 'APPROVED' : 'DENIED', notBefore: '2026-10-22T08:00:00.000Z', expiresAt: '2026-10-22T08:10:00.000Z', mfa: 'step-up' } } });
const EXP = (ref, hash = H('d')) => ({ artifactId: `${ref}:approval_expired`, entryType: 'APPROVAL_EXPIRED', decision: 'BLOCK', reason: 'APPROVAL_EXPIRED', tenantId: 't1', approvalRef: ref, actionHash: hash, executionContext: { approval: { requesterId: 'identity:i' } } });
let n = 0;
const INT = (ref, hash = H('d'), seq = 1) => ({ artifactId: `req${++n}:action_intent`, entryType: 'ACTION_INTENT', decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', signature: 'sig', tenantId: 't1', agentId: agent, sessionId: sess, actionSeq: seq, actionHash: hash,
  ...(ref ? { approvalRef: ref } : {}), executionContext: actionCtx });
const chain = (specs, prev = 'GENESIS') => specs.map((s0, idx) => { const s = { ...s0, artifactId: s0.artifactId.replace(':', `-${idx}:`) }; const e = JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(s), prev))); prev = e.hash; return e; });
const both = (entries, start = 'GENESIS') => {
  const p = audit.verifyAuditChainDetailed(entries, start);
  const i = contract.walkChain(entries, { startPrevHash: start });
  expect({ valid: i.valid, detail: i.failure ? i.failure.detail : null }).toEqual({ valid: p.valid, detail: p.valid ? null : p.detail });
  return i;
};
const A = 'a1111111-1111-4111-8111-111111111111'; const B = 'b2222222-2222-4222-8222-222222222222';

describe('approval sequence in the audit chain', () => {
  test('AS-01 good sequences', () => {
    expect(both(chain([REQ(A), DEC(A), INT(A)]))).toMatchObject({ valid: true });
    expect(both(chain([REQ(A), DEC(A), EXP(A)]))).toMatchObject({ valid: true });
    expect(both(chain([REQ(A), DEC(A, H('d'), false)]))).toMatchObject({ valid: true });
    expect(both(chain([REQ(A), EXP(A)]))).toMatchObject({ valid: true });
    expect(both(chain([REQ(A), REQ(B, H('c')), DEC(B, H('c')), DEC(A), INT(A, H('d'), 1), INT(B, H('c'), 2)]))).toMatchObject({ valid: true });
    expect(both(chain([INT(null)]))).toMatchObject({ valid: true });                                                    // an action that needed no approval
  });

  test('AS-02 violations', () => {
    const detail = (specs) => both(chain(specs)).failure;
    const V = 'APPROVAL_SEQUENCE_VIOLATION';
    for (const [name, specs] of Object.entries({
      'decided before requested': [DEC(A), REQ(A)],
      'decided without a request': [DEC(A)],
      'expired without a request': [EXP(A)],
      'requested twice': [REQ(A), REQ(A)],
      'decided twice': [REQ(A), DEC(A), DEC(A)],
      'denied then approved': [REQ(A), DEC(A, H('d'), false), DEC(A)],
      'another actionHash in the decision': [REQ(A), DEC(A, H('9'))],
      'another actionHash in the expiry': [REQ(A), EXP(A, H('9'))],
      'expired then decided': [REQ(A), EXP(A), DEC(A)],
      'spent after it expired': [REQ(A), DEC(A), EXP(A), INT(A)],
      'spent after it was denied': [REQ(A), DEC(A, H('d'), false), INT(A)],
      'spent without a decision': [REQ(A), INT(A)],
      'spent without any approval': [INT(A)],
      'spent twice': [REQ(A), DEC(A), INT(A), INT(A, H('d'), 2)],
      'spent for another action': [REQ(A), DEC(A), INT(A, H('9'))],
      'expired after it was spent': [REQ(A), DEC(A), INT(A), EXP(A)],
    })) expect([name, (detail(specs) || {}).detail]).toEqual([name, V]);
  });

  test('AS-03 bounded walks accept an approval first seen mid-way; GENESIS walks do not', () => {
    const bounded = chain([DEC(A), INT(A)], H('7'));
    expect(both(bounded, H('7'))).toMatchObject({ valid: true });
    expect(both(chain([EXP(B, H('c'))], H('7')), H('7'))).toMatchObject({ valid: true });
    expect(both(chain([INT(A)], H('7')), H('7'))).toMatchObject({ valid: true });
    // ... but what IS seen must still be in order: spent twice inside a bounded walk
    expect(both(chain([DEC(A), INT(A), INT(A, H('d'), 2)], H('7')), H('7')).failure.detail).toBe('APPROVAL_SEQUENCE_VIOLATION');
    expect(both(chain([DEC(A), INT(A)])).failure.detail).toBe('APPROVAL_SEQUENCE_VIOLATION');
  });

  test('AS-04 entries without an approvalRef are untouched', () => {
    const r = both(chain([INT(null, H('1'), 1), INT(null, H('2'), 2), REQ(A), DEC(A), INT(A, H('d'), 3)]));
    expect(r).toMatchObject({ valid: true });
  });
});
