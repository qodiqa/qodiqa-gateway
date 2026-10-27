'use strict';

/**
 * Audit schema v8.
 *
 *   V8-01  field set (v7 + 10), writer default (7), the flag, refusal of v8 values while the flag is off
 *   V8-02  every entry type builds, verifies, and is judged identically by the production and the independent verifier
 *   V8-03  negative shape table: each violation fails both verifiers with the same detail (differential)
 *   V8-04  chain walks: COMMIT / ACTION / downgrade / orphan rules, production walker == independent walker
 *   V8-05  the one-way flag: a writer whose chain head is v8 refuses to append v7
 *   V8-06  PostgreSQL boundary: v8 columns decode (BIGINT strings → numbers), lower versions carry no v8 keys
 */

jest.mock('../../../infra/postgres/pg-audit-backend', () => ({ persistEntry: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../dsr/subjectPseudonym', () => require('../../../../test/helpers/subjectPseudonymMock'));

const fs = require('fs');
const os = require('os');
const path = require('path');
const eb = require('../entryBuilder');
const { createLifecycleTracker } = require('../v7Lifecycle');
const contract = require('../../../../scripts/audit-repro/verify/auditContract');
const { decodeMirrorRow } = require('../../../infra/postgres/mirrorProjection');
const { v8InsertValues } = require('../../../infra/postgres/v8Columns');
const { sortedJSON, domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../../infra/crypto/hashing');

const H = (c) => c.repeat(64);
const RID = '22222222-2222-4222-8222-222222222222';
const ISSUED = 1760000000000;
const savedFlag = process.env.QODIQA_AUDIT_SCHEMA_V8;
const v8On = () => { process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; };
const v8Off = () => { delete process.env.QODIQA_AUDIT_SCHEMA_V8; };
afterAll(() => { if (savedFlag === undefined) delete process.env.QODIQA_AUDIT_SCHEMA_V8; else process.env.QODIQA_AUDIT_SCHEMA_V8 = savedFlag; });
beforeEach(v8On);

const base = (over = {}) => ({ inputHash: H('a'), signature: 'sig', requestHash: H('a'), policyHash: H('b'), verificationResult: true, tenantId: 't1', ...over });
const actionCtx = { action: { tool: { server: 'srv', name: 'tool', schemaHash: H('e') }, parentRequestHash: H('f'), prevActionHash: null } };

// one valid spec per entry type (fields as the callers will state them)
const SPECS = {
  DECISION: () => base({ artifactId: RID, decision: 'ALLOW', stage: 'PROVIDER_EXECUTION', outputHash: eb.outputHashOf('hi'), requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2 }),
  INTENT: () => base({ artifactId: eb.lifecycleArtifactId(RID, 'INTENT'), entryType: 'INTENT', decision: 'ALLOW', stage: 'PROVIDER_DISPATCH', requestId: RID, executingProvider: 'local', issuedAt: ISSUED, protocolVersion: 2 }),
  STREAM_OPENED: () => base({ artifactId: eb.lifecycleArtifactId(RID, 'STREAM_OPENED'), entryType: 'STREAM_OPENED', decision: 'ALLOW', stage: 'STREAM_OPENED', requestId: RID, executingProvider: 'local', responseId: 'r1', issuedAt: ISSUED, protocolVersion: 1 }),
  COMMIT: () => ({ artifactId: RID + ':commit', entryType: 'COMMIT', decision: 'ALLOW', reason: 'RESPONSE_DELIVERED', signature: 'sig', requestId: RID, tenantId: 't1', outputHash: H('c'), bytesDelivered: 12, completionStatus: 'COMPLETE', issuedAt: ISSUED, protocolVersion: 2 }),
  ACTION_INTENT: () => ({ artifactId: 'ar1:action_intent', entryType: 'ACTION_INTENT', decision: 'ALLOW', reason: 'ACTION_AUTHORIZED', signature: 'sig', tenantId: 't1', agentId: 'agent-1', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), executionContext: actionCtx }),
  ACTION_COMMIT: () => ({ artifactId: 'ar1:action_commit', entryType: 'ACTION_COMMIT', decision: 'ALLOW', reason: 'ACTION_COMPLETED', signature: 'sig', tenantId: 't1', agentId: 'agent-1', sessionId: 'sess-1', actionSeq: 1, actionHash: H('d'), outputHash: H('c'), completionStatus: 'COMPLETE', executionContext: actionCtx }),
  APPROVAL_REQUESTED: () => ({ artifactId: 'ap1:approval_requested', entryType: 'APPROVAL_REQUESTED', decision: 'BLOCK', reason: 'APPROVAL_REQUIRED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', policyRuleId: 'r1' } } }),
  APPROVAL_DECIDED: () => ({ artifactId: 'ap1:approval_decided', entryType: 'APPROVAL_DECIDED', decision: 'ALLOW', reason: 'APPROVED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1', approverId: 'u2', decision: 'APPROVED', notBefore: 1, expiresAt: 2, mfa: true } } }),
  APPROVAL_EXPIRED: () => ({ artifactId: 'ap1:approval_expired', entryType: 'APPROVAL_EXPIRED', decision: 'BLOCK', reason: 'APPROVAL_EXPIRED', tenantId: 't1', approvalRef: 'ap1', actionHash: H('d'), executionContext: { approval: { requesterId: 'u1' } } }),
  KILL_SWITCH: () => ({ artifactId: 'ev1:kill_switch', entryType: 'KILL_SWITCH', decision: 'BLOCK', reason: 'KILL_SWITCH_ON', tenantId: '*', executionContext: { killSwitch: { operatorId: 'op1', scope: 'global', stateHash: H('1') } } }),
  DLP_TRANSFORM: () => ({ artifactId: RID + ':dlp_in_1', entryType: 'DLP_TRANSFORM', decision: 'ALLOW', reason: 'DLP_REDACT', tenantId: 't1', requestId: RID, dlp: { rules: ['email'], action: 'REDACT', inputHashBefore: H('a'), inputHashAfter: H('b') } }),
  DELEGATION_ISSUED: () => ({ artifactId: 'dg1:delegation_issued', entryType: 'DELEGATION_ISSUED', decision: 'ALLOW', reason: 'DELEGATION_ISSUED', tenantId: 't1', executionContext: { delegation: { chainHash: H('9'), depth: 1, rootAgentId: 'agent-1', parentId: null } } }),
  DELEGATION_REVOKED: () => ({ artifactId: 'dg1:delegation_revoked', entryType: 'DELEGATION_REVOKED', decision: 'ALLOW', reason: 'DELEGATION_REVOKED', tenantId: 't1', executionContext: { delegation: { chainHash: H('9'), depth: 1, rootAgentId: 'agent-1', parentId: null } } }),
};
const build = (spec, prev = 'GENESIS') => JSON.parse(JSON.stringify(eb.buildEntry(eb.normalizeFields(spec), prev)));
const reseal = (e) => {
  const canonical = sortedJSON(eb.coreFieldsOf(e));
  return { ...e, canonical, hash: domainSeparatedHash(ARTIFACT_DOMAINS.AUDIT, canonical).toString('hex') };
};
function chain(specs, prev = 'GENESIS') {
  const out = [];
  for (const s of specs) { const e = build(s, prev); out.push(e); prev = e.hash; }
  return out;
}
const codes = (ws) => (ws || []).map((w) => w.code).sort();

describe('V8-01 — field set, writer default, the flag', () => {
  test('v8 = v7 + exactly the ten frozen fields; 8 is supported; every v8 entry hashes exactly 38 fields', () => {
    expect(eb.CORE_HASH_FIELDS_V8).toEqual([...eb.CORE_HASH_FIELDS_V7, 'issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'dlp', 'bytesDelivered', 'completionStatus']);
    expect(eb.CORE_HASH_FIELDS_V8).toHaveLength(38);
    expect(eb.SUPPORTED_SCHEMA_VERSIONS).toContain(8);
    const e = build(SPECS.DECISION());
    expect(e.schemaVersion).toBe(8);
    expect(Object.keys(JSON.parse(e.canonical)).sort()).toEqual([...eb.CORE_HASH_FIELDS_V8].sort());
  });

  test('with the flag off (the default) the writer stamps 7, the canonical has the 28 v7 fields, and no v8 key exists', () => {
    v8Off();
    expect(eb.currentSchemaVersion()).toBe(7);
    const e = build(base({ artifactId: RID, decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: RID }));
    expect(e.schemaVersion).toBe(7);
    expect(Object.keys(JSON.parse(e.canonical))).toHaveLength(28);
    for (const f of eb.V8_NEW_FIELDS) expect(e).not.toHaveProperty(f);
  });

  test('with the flag off a v8 field or a v8-only entry type is refused (nothing can be written ahead of the readers)', () => {
    v8Off();
    expect(() => eb.normalizeFields({ ...SPECS.DECISION(), issuedAt: ISSUED })).toThrow(/invalid_v8_field/);
    expect(() => eb.normalizeFields(SPECS.COMMIT())).toThrow(/invalid_v8_field/);   // COMMIT states bytesDelivered
    expect(() => eb.normalizeFields(SPECS.KILL_SWITCH())).toThrow(/invalid_entryType.*v8/);
  });

  test('the flag reads only the literal "true"', () => {
    for (const v of ['1', 'TRUE', 'yes', 'false', '']) { process.env.QODIQA_AUDIT_SCHEMA_V8 = v; expect(eb.currentSchemaVersion()).toBe(7); }
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true'; expect(eb.currentSchemaVersion()).toBe(8);
  });

  test('a malformed v8 value is refused by the writer before anything is built', () => {
    for (const [f, v] of [['issuedAt', -1], ['issuedAt', 1.5], ['issuedAt', '1'], ['protocolVersion', 0], ['actionSeq', 0], ['actionHash', 'zz'], ['bytesDelivered', -3], ['completionStatus', 'DONE'], ['dlp', { rules: [], action: 'NOPE' }]]) {
      expect(() => eb.normalizeFields({ ...SPECS.DECISION(), [f]: v })).toThrow(/invalid_v8_field/);
    }
  });
});

describe('V8-02 — every entry type builds and verifies identically in both verifiers', () => {
  test.each(Object.keys(SPECS))('%s', (type) => {
    const e = build(SPECS[type]());
    expect(e.schemaVersion).toBe(8);
    expect(e.entryType ?? 'DECISION').toBe(type);
    expect(eb.verifyCanonicalHash(e)).toBe(true);
    expect(eb.v8ShapeViolation(e)).toBeNull();
    expect(contract.checkEntryHash(e)).toMatchObject({ ok: true, version: 8 });
    expect(contract.v8Shape(e)).toBeNull();
    // the three fields every system entry states "UNAVAILABLE" are strings, so no verifier mistakes the entry for a legacy line
    expect(typeof e.inputHash).toBe('string');
    expect(contract.isLegacyShaped(e)).toBe(false);
  });

  test('every new field is always present in a v8 canonical (null when not stated)', () => {
    const c = JSON.parse(build(SPECS.KILL_SWITCH()).canonical);
    for (const f of eb.V8_NEW_FIELDS) expect(c).toHaveProperty(f, null);
  });

  test('a mixed chain of every type verifies in both walkers (from GENESIS, lifecycle-complete)', () => {
    const specs = [SPECS.INTENT(), SPECS.DECISION(), SPECS.COMMIT(), SPECS.KILL_SWITCH(), SPECS.APPROVAL_REQUESTED(), SPECS.APPROVAL_DECIDED(), SPECS.ACTION_INTENT(), SPECS.ACTION_COMMIT(), SPECS.DLP_TRANSFORM(), SPECS.DELEGATION_ISSUED(), SPECS.DELEGATION_REVOKED(), SPECS.APPROVAL_EXPIRED()];
    const entries = chain(specs);
    const ind = contract.walkChain(entries);
    expect(ind).toMatchObject({ valid: true, entriesVerified: entries.length, lifecycleComplete: true });
    expect(ind.warnings).toEqual([]);
  });
});

describe('V8-03 — negative shape table (differential, entries re-sealed so only the shape is wrong)', () => {
  const mutations = {
    COMMIT: [['decision BLOCK', { decision: 'BLOCK' }], ['reason', { reason: 'DONE' }], ['artifactId suffix', { artifactId: RID + ':commitx' }], ['no outputHash', { outputHash: null }], ['bytesDelivered missing', { bytesDelivered: null }], ['completionStatus missing', { completionStatus: null }],
      ['system signature on an artifact-driven entry is allowed only as SYSTEM: verificationResult false', { verificationResult: false }], ['forbidden dlp', { dlp: { rules: ['a'], action: 'MASK', inputHashBefore: H('a'), inputHashAfter: H('b') } }], ['forbidden agentId', { agentId: 'a' }], ['provider set', { provider: 'openai' }], ['inputHash a real hash', { inputHash: H('a') }], ['executionContext set', { executionContext: { x: 1 } }]],
    ACTION_INTENT: [['no agentId', { agentId: null }], ['actionSeq 0', { actionSeq: 0 }], ['bad actionHash', { actionHash: 'abc' }], ['stage', { stage: 'COMMIT' }], ['outputHash set', { outputHash: H('c') }], ['context key missing', { executionContext: { other: {} } }], ['context null', { executionContext: null }]],
    ACTION_COMMIT: [['outputHash missing', { outputHash: null }], ['completionStatus missing', { completionStatus: null }], ['reason', { reason: 'ACTION_AUTHORIZED' }]],
    APPROVAL_REQUESTED: [['decision ALLOW', { decision: 'ALLOW' }], ['signature not SYSTEM', { signature: 'sig' }], ['verificationResult true', { verificationResult: true }], ['approvalRef missing', { approvalRef: null }], ['context key', { executionContext: { killSwitch: {} } }]],
    APPROVAL_DECIDED: [['ALLOW with DENIED', { reason: 'DENIED' }], ['BLOCK with APPROVED', { decision: 'BLOCK' }]],
    APPROVAL_EXPIRED: [['decision ALLOW', { decision: 'ALLOW' }]],
    KILL_SWITCH: [['ON with ALLOW', { decision: 'ALLOW' }], ['OFF with BLOCK', { reason: 'KILL_SWITCH_OFF' }], ['stage', { stage: 'COMMIT' }], ['tenantId not needed but approvalRef set', { approvalRef: 'x' }]],
    DLP_TRANSFORM: [['no dlp', { dlp: null }], ['reason not matching action', { reason: 'DLP_MASK' }], ['BLOCK action with ALLOW decision', { dlp: { rules: ['a'], action: 'BLOCK', inputHashBefore: H('a'), inputHashAfter: H('b') } }], ['artifactId without direction', { artifactId: RID + ':dlp_1' }], ['hash not hex', { dlp: { rules: ['a'], action: 'REDACT', inputHashBefore: 'x', inputHashAfter: H('b') } }], ['context set', { executionContext: { a: 1 } }]],
    DELEGATION_ISSUED: [['reason', { reason: 'DELEGATION_REVOKED' }], ['context key', { executionContext: { approval: {} } }]],
    DELEGATION_REVOKED: [['suffix', { artifactId: 'dg1:delegation_issued' }]],
    DECISION: [['v8 field outside its list', { bytesDelivered: 4 }], ['agentId on a decision', { agentId: 'a' }], ['completionStatus bad', { completionStatus: 'DONE' }]],
    INTENT: [['completionStatus on an intent', { completionStatus: 'COMPLETE' }], ['outputHash on an intent', { outputHash: H('c') }]],
    STREAM_OPENED: [['stage', { stage: 'PROVIDER_DISPATCH' }]],
  };
  const cases = [];
  for (const [type, list] of Object.entries(mutations)) for (const [name, patch] of list) cases.push([type, name, patch]);
  test.each(cases)('%s — %s fails both verifiers with the same detail', (type, name, patch) => {
    const good = build(SPECS[type]());
    const bad = reseal({ ...good, ...patch });
    expect(eb.verifyCanonicalHash(bad)).toBe(false);
    const prodDetail = eb.v8ShapeViolation(bad);
    expect(prodDetail).toEqual(expect.any(String));
    const ind = contract.checkEntryHash(bad);
    expect(ind.ok).toBe(false);
    expect(ind.code).toBe(prodDetail);
    expect(eb.v7IntegrityDetail(bad)).toBe(prodDetail);
  });

  test('an unknown v8 entry type is INVALID_ENTRY_TYPE in both', () => {
    const bad = reseal({ ...build(SPECS.COMMIT()), entryType: 'STREAM_CLOSED' });
    expect(eb.v8ShapeViolation(bad)).toBe('INVALID_ENTRY_TYPE');
    expect(contract.checkEntryHash(bad).code).toBe('INVALID_ENTRY_TYPE');
  });

  test('an unsealed tampered field is a canonical mismatch, reported before any shape detail (the v7 ordering)', () => {
    const good = build(SPECS.COMMIT());
    const tampered = { ...good, bytesDelivered: 999 };
    expect(eb.verifyCanonicalHash(tampered)).toBe(false);
    expect(eb.v7IntegrityDetail(tampered)).toBeNull();
    expect(contract.checkEntryHash(tampered).code).toBe('CANONICAL_FIELD_MISMATCH');
  });

  test('the writer refuses to build a new-type entry its own verifier would refuse', () => {
    expect(() => eb.normalizeFields({ ...SPECS.COMMIT(), completionStatus: null })).toThrow(/invalid_entry_shape/);
    expect(() => eb.normalizeFields({ ...SPECS.KILL_SWITCH(), reason: 'NOPE' })).toThrow(/invalid_entry_shape/);
    expect(() => eb.normalizeFields({ ...SPECS.KILL_SWITCH(), decision: 'ALLOW' })).toThrow(/invalid_entry_shape/);
    expect(() => eb.normalizeFields({ ...SPECS.KILL_SWITCH(), artifactId: undefined })).toThrow(/invalid_artifactId/);
    expect(() => eb.normalizeFields({ ...SPECS.COMMIT(), signature: undefined })).toThrow(/invalid_signature/);
  });
});

describe('V8-04 — chain walks (production walker == independent walker)', () => {
  const audit = require('../audit-log');
  const both = (entries, start = 'GENESIS') => {
    const p = audit.verifyAuditChainDetailed(entries, start);
    const i = contract.walkChain(entries, { startPrevHash: start });
    expect({ valid: i.valid, detail: i.failure ? i.failure.detail : null, warnings: codes(i.warnings), lc: i.valid ? i.lifecycleComplete : null })
      .toEqual({ valid: p.valid, detail: p.valid ? null : p.detail, warnings: codes(p.warnings), lc: p.valid ? p.lifecycleComplete : null });
    return i;
  };
  const rid = (n) => `33333333-3333-4333-8333-${String(n).padStart(12, '0')}`;
  const trio = (n) => [
    { ...SPECS.INTENT(), artifactId: eb.lifecycleArtifactId(rid(n), 'INTENT'), requestId: rid(n) },
    { ...SPECS.DECISION(), artifactId: rid(n), requestId: rid(n) },
    { ...SPECS.COMMIT(), artifactId: rid(n) + ':commit', requestId: rid(n) },
  ];

  test('INTENT → DECISION → COMMIT is clean', () => {
    expect(both(chain(trio(1)))).toMatchObject({ valid: true, warnings: [] });
  });

  test('a COMMIT without its DECISION fails a GENESIS walk and is a warning in a bounded walk', () => {
    const lone = chain([SPECS.COMMIT()]);
    expect(both(lone).failure.detail).toBe('COMMIT_WITHOUT_DECISION');
    const bounded = chain([SPECS.COMMIT()], H('7'));
    expect(codes(both(bounded, H('7')).warnings)).toEqual(['COMMIT_BEFORE_START']);
  });

  test('a COMMIT for another request than the DECISION is COMMIT_WITHOUT_DECISION', () => {
    const t = trio(2);
    t[2] = { ...t[2], artifactId: rid(9) + ':commit', requestId: rid(9) };
    expect(both(chain(t)).failure.detail).toBe('COMMIT_WITHOUT_DECISION');
  });

  test('a v7 entry after a v8 entry is SCHEMA_DOWNGRADE', () => {
    const first = build(SPECS.KILL_SWITCH());
    v8Off();
    const v7 = build(base({ artifactId: 'later-v7', decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: 'later-v7' }), first.hash);
    expect(v7.schemaVersion).toBe(7);
    expect(both([first, v7]).failure.detail).toBe('SCHEMA_DOWNGRADE');
  });

  test('a v7 chain followed by v8 entries is valid (the flag may be turned on over an existing chain)', () => {
    v8Off();
    const a = build(base({ artifactId: 'v7-a', decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: 'v7-a' }));
    v8On();
    const k = build(SPECS.KILL_SWITCH(), a.hash);
    expect(both([a, k])).toMatchObject({ valid: true });
  });

  test('ACTION_INTENT sequence: 1,2 is valid; 1,3 and a GENESIS walk starting at 2 are ACTION_ORDER_VIOLATION', () => {
    const at = (seq, sess = 'sess-1') => ({ ...SPECS.ACTION_INTENT(), artifactId: `ar${sess}${seq}:action_intent`, sessionId: sess, actionSeq: seq });
    const ac = (seq, sess = 'sess-1') => ({ ...SPECS.ACTION_COMMIT(), artifactId: `ar${sess}${seq}:action_commit`, sessionId: sess, actionSeq: seq });
    expect(both(chain([at(1), ac(1), at(2), ac(2), at(1, 'sess-2'), ac(1, 'sess-2')]))).toMatchObject({ valid: true, warnings: [] });
    expect(both(chain([at(1), at(3)])).failure.detail).toBe('ACTION_ORDER_VIOLATION');
    expect(both(chain([at(2)])).failure.detail).toBe('ACTION_ORDER_VIOLATION');
    expect(both(chain([at(2)], H('7')), H('7'))).toMatchObject({ valid: true });   // a bounded walk may meet a session mid-way
  });

  test('an ACTION_INTENT without an ACTION_COMMIT is an ORPHAN_ACTION_INTENT warning, not a failure', () => {
    expect(codes(both(chain([SPECS.ACTION_INTENT()])).warnings)).toEqual(['ORPHAN_ACTION_INTENT']);
  });

  test('ORPHAN_DECISION: only a v8 ALLOW decision with an executing provider, after the first COMMIT, older than the grace period', () => {
    const entries = chain([...trio(1), { ...SPECS.INTENT(), artifactId: eb.lifecycleArtifactId(rid(2), 'INTENT'), requestId: rid(2) }, { ...SPECS.DECISION(), artifactId: rid(2), requestId: rid(2) }]);
    const now = Date.now();
    expect(codes(both(entries).warnings)).toEqual([]);                                        // no clock: the last entry's own timestamp, so inside the grace period
    expect(codes(contract.walkChain(entries, { nowMs: now }).warnings)).toEqual([]);
    expect(codes(contract.walkChain(entries, { nowMs: now + 11 * 60 * 1000 }).warnings)).toEqual(['ORPHAN_DECISION']);
    const t = createLifecycleTracker({ lifecycleComplete: true, nowMs: now + 11 * 60 * 1000 });
    for (const e of entries) expect(t.step(e)).toBeNull();
    expect(codes(t.finish())).toEqual(['ORPHAN_DECISION']);
    // a decision before the chain's first COMMIT (early v8) and a BLOCK decision never warn
    const early = chain([...trio(3).slice(0, 2), { ...SPECS.DECISION(), artifactId: rid(4), requestId: rid(4), decision: 'BLOCK', outputHash: undefined, executingProvider: undefined }]);
    const t2 = createLifecycleTracker({ lifecycleComplete: false, nowMs: now + 60 * 60 * 1000 });
    for (const e of early) t2.step(e);
    expect(codes(t2.finish())).not.toContain('ORPHAN_DECISION');
  });

  test('the tracker caps its decided-request memory and then turns an unknown COMMIT into a warning, never a failure', () => {
    const { DECIDED_CAP } = require('../v7Lifecycle');
    expect(DECIDED_CAP).toBeGreaterThan(1000);
  });

  test('system entries (KILL_SWITCH, APPROVAL_*, DLP, DELEGATION) never disturb the request lifecycle', () => {
    const entries = chain([SPECS.INTENT(), SPECS.KILL_SWITCH(), SPECS.APPROVAL_REQUESTED(), SPECS.DLP_TRANSFORM(), SPECS.DECISION(), SPECS.DELEGATION_ISSUED(), SPECS.COMMIT()]);
    expect(both(entries)).toMatchObject({ valid: true, warnings: [] });
  });
});

describe('V8-05 — the flag is one-directional on the writer', () => {
  const tmp = [];
  afterAll(() => { for (const d of tmp) fs.rmSync(d, { recursive: true, force: true }); });
  function fresh() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-v8-'));
    tmp.push(dir);
    const saved = process.env.QODIQA_AUDIT_LOG;
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    let audit;
    try { jest.isolateModules(() => { audit = require('../audit-log'); }); } finally { if (saved === undefined) delete process.env.QODIQA_AUDIT_LOG; else process.env.QODIQA_AUDIT_LOG = saved; }
    return audit;
  }
  const v7Fields = (id) => base({ artifactId: id, decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: id });

  test('a v7 writer appends v7; after a v8 append a v7 append is refused (nothing written), and v8 appends continue', async () => {
    v8Off();
    const audit = fresh();
    expect((await audit.append(v7Fields('one'))).schemaVersion).toBe(7);
    v8On();
    expect((await audit.append({ ...v7Fields('two'), issuedAt: ISSUED, protocolVersion: 1 })).schemaVersion).toBe(8);
    expect((await audit.append(SPECS.KILL_SWITCH())).entryType).toBe('KILL_SWITCH');
    const before = audit.getChainStats().modernLength;
    v8Off();
    await expect(audit.append(v7Fields('three'))).rejects.toMatchObject({ code: 'AUDIT_SCHEMA_DOWNGRADE_REFUSED', message: expect.stringMatching(/^invalid_schema_downgrade/) });
    expect(audit.getChainStats().modernLength).toBe(before);
    v8On();
    expect((await audit.append({ ...v7Fields('four'), issuedAt: ISSUED, protocolVersion: 2 })).schemaVersion).toBe(8);
    expect(audit.verifyAuditChainDetailed(audit.getChain ? audit.getChain() : [], 'GENESIS').valid).toBe(true);
  });
});

describe('V8-06 — PostgreSQL boundary (migration 083)', () => {
  test('a v8 row decodes: BIGINT strings become numbers, text fields are un-projected, dlp is restored; every field is present', () => {
    const row = { schemaVersion: 8, mirrorEncoding: 1, issuedAt: String(ISSUED), protocolVersion: 2, agentId: 'agent\\u0041', sessionId: null, actionSeq: '3', actionHash: H('d'), approvalRef: null, dlp: { rules: ['r'], action: 'MASK', inputHashBefore: H('a'), inputHashAfter: H('b') }, bytesDelivered: '12', completionStatus: 'COMPLETE' };
    const out = decodeMirrorRow(row, 'test');
    expect(out).toMatchObject({ issuedAt: ISSUED, protocolVersion: 2, agentId: 'agentA', sessionId: null, actionSeq: 3, bytesDelivered: 12, completionStatus: 'COMPLETE' });
    expect(out.dlp.action).toBe('MASK');
    for (const f of eb.V8_NEW_FIELDS) expect(out).toHaveProperty(f);
  });

  test('a row below v8 carries no v8 key (hydrated entries keep exactly the shape the builder produced)', () => {
    const out = decodeMirrorRow({ schemaVersion: 7, mirrorEncoding: 1, issuedAt: null, agentId: null, dlp: null, completionStatus: null }, 'test');
    for (const f of eb.V8_NEW_FIELDS) expect(out).not.toHaveProperty(f);
  });

  test('v8InsertValues: ten values in column order, JSON-encoded dlp, all NULL below v8', () => {
    const e = build(SPECS.DLP_TRANSFORM());
    const v = v8InsertValues(e);
    expect(v).toHaveLength(10);
    expect(JSON.parse(v[7])).toEqual(e.dlp);
    expect(v8InsertValues({ schemaVersion: 7, issuedAt: 5 })).toEqual(Array(10).fill(null));
  });

  test('an entry rebuilt from a stored row verifies (the round trip the verifier\'s PG path depends on)', () => {
    const e = build(SPECS.COMMIT());
    const row = { ...e, schemaVersion: 8, mirrorEncoding: 0, issuedAt: String(e.issuedAt), bytesDelivered: String(e.bytesDelivered), actionSeq: null };
    const back = decodeMirrorRow(row, 'test');
    expect(eb.verifyCanonicalHash(back)).toBe(true);
    const pgRow = { hash: e.hash, prev_hash: e.prevHash, canonical: e.canonical, artifact_id: e.artifactId, decision: e.decision, high_res_time: e.highResTime, input_hash: e.inputHash, signature: e.signature, request_hash: e.requestHash, policy_hash: e.policyHash, verification_result: e.verificationResult, schema_version: 8, entry_type: e.entryType, output_hash: e.outputHash, request_id: e.requestId, organization_id: null, tenant_id: e.tenantId, stage: e.stage, reason: e.reason, mirror_encoding: 0, issued_at: String(e.issuedAt), protocol_version: e.protocolVersion, bytes_delivered: String(e.bytesDelivered), completion_status: e.completionStatus, execution_context: null };
    expect(contract.checkEntryHash(contract.entryFromPgRow(pgRow))).toMatchObject({ ok: true, version: 8 });
  });
});

describe('V8-07 — the request context supplies issuedAt / protocolVersion to the request\'s own entries only', () => {
  const rac = require('../requestAuditContext');
  const inRequest = (fn) => new Promise((resolve, reject) => rac.requestAuditContextMiddleware({}, {}, () => { try { resolve(fn()); } catch (e) { reject(e); } }));
  const dec = (rid) => base({ artifactId: rid, decision: 'ALLOW', outputHash: eb.outputHashOf('x'), requestId: rid });

  test('an entry of the bound request carries the facts; an entry of another request, a system entry and an unbound request carry null', async () => {
    const out = await inRequest(() => {
      const unbound = eb.normalizeFields(dec(RID));
      rac.bindArtifactFacts({ requestId: RID, issuedAt: ISSUED, protocolVersion: 2 });
      return {
        unbound: [unbound.issuedAt, unbound.protocolVersion],
        same: eb.normalizeFields(dec(RID)),
        commit: eb.normalizeFields({ ...SPECS.COMMIT(), issuedAt: undefined, protocolVersion: undefined }),
        intent: eb.normalizeFields(SPECS.INTENT()),
        other: eb.normalizeFields(dec('44444444-4444-4444-8444-444444444444')),
        killSwitch: eb.normalizeFields(SPECS.KILL_SWITCH()),
        dlp: eb.normalizeFields(SPECS.DLP_TRANSFORM()),
      };
    });
    expect(out.unbound).toEqual([null, null]);
    expect([out.same.issuedAt, out.same.protocolVersion]).toEqual([ISSUED, 2]);
    expect([out.commit.issuedAt, out.commit.protocolVersion]).toEqual([ISSUED, 2]);
    expect([out.intent.issuedAt, out.intent.protocolVersion]).toEqual([ISSUED, 2]);
    expect([out.other.issuedAt, out.other.protocolVersion]).toEqual([null, null]);
    expect([out.killSwitch.issuedAt, out.killSwitch.protocolVersion]).toEqual([null, null]);
    expect([out.dlp.issuedAt, out.dlp.protocolVersion]).toEqual([null, null]);
  });

  test('outside a request there is no context; an explicit value is never overwritten; garbage facts are dropped', async () => {
    expect(rac.currentArtifactFacts()).toBeNull();
    expect(() => rac.bindArtifactFacts({ requestId: RID, issuedAt: 1 })).not.toThrow();
    const n = eb.normalizeFields(dec(RID));
    expect([n.issuedAt, n.protocolVersion]).toEqual([null, null]);
    const out = await inRequest(() => {
      rac.bindArtifactFacts({ requestId: RID, issuedAt: ISSUED, protocolVersion: 2 });
      const explicit = eb.normalizeFields({ ...dec(RID), issuedAt: 5, protocolVersion: 1 });
      rac.bindArtifactFacts({ requestId: RID, issuedAt: 'x', protocolVersion: 0 });
      return { explicit, garbage: eb.normalizeFields(dec(RID)) };
    });
    expect([out.explicit.issuedAt, out.explicit.protocolVersion]).toEqual([5, 1]);
    expect([out.garbage.issuedAt, out.garbage.protocolVersion]).toEqual([null, null]);
  });

  test('with the flag off the context is ignored (the entry stays a v7 entry)', async () => {
    v8Off();
    const n = await inRequest(() => { rac.bindArtifactFacts({ requestId: RID, issuedAt: ISSUED, protocolVersion: 2 }); return eb.normalizeFields(dec(RID)); });
    expect(n.schemaVersion).toBe(7);
    expect(n).not.toHaveProperty('issuedAt');
  });
});
