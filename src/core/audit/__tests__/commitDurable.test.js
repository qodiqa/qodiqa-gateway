'use strict';

/**
 * a COMMIT survives a crash, and a request that executed never stays without one.
 *
 *   CD-01  a COMMIT the audit store refuses is queued DURABLY (recovery queue / journal); the in-process map is not used
 * CD-02 nothing durable takes it: the in-process lifecycle reconciler keeps it (as)
 *   CD-03  the replay handler: recorded / duplicate / skipped are done, a refusal is retried, a malformed payload is not retried
 *   CD-04  kill between DECISION and COMMIT: the chain on disk has the DECISION, a fresh boot (new module load) finds it, the boot reconciler writes ONE COMMIT
 *          OUTCOME_UNKNOWN / RESPONSE_FAILED / 0 bytes / empty output hash; the chain verifies, no ORPHAN_DECISION, and a second boot writes nothing
 *   CD-05  a request whose true COMMIT waits in the durable queue is left to that replay; a request that already has its COMMIT is not touched
 *   CD-06  audit schema v8 off: nothing is written; a failing boot write is kept for the runtime retry
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn(), flush: jest.fn() }));

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

let dir; let file;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-f513-'));
  file = path.join(dir, 'audit.log');
  process.env.QODIQA_AUDIT_LOG = file;
  process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
  jest.dontMock('../../persistenceRecovery');
  jest.resetModules();
});
afterEach(() => {
  delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_SCHEMA_V8;
  jest.resetModules();
  fs.rmSync(dir, { recursive: true, force: true });
});

const H = (c) => c.repeat(64);
const ctx = (rid) => ({ requestId: rid, signature: H('s'), tenantId: 't' });
const done = { delivered: true, outputHash: H('d'), bytesDelivered: 12, completionStatus: 'COMPLETE' };

/** the previous process: request A got DECISION + COMMIT, request B got only its DECISION (the process died in between) */
async function previousProcess() {
  const a = require('../audit-log');
  const eb = require('../entryBuilder');
  const ids = { A: crypto.randomUUID(), B: crypto.randomUUID(), C: crypto.randomUUID() };
  const decision = (rid) => ({ artifactId: rid, entryType: 'DECISION', decision: 'ALLOW', inputHash: H('a'), signature: H('s'), requestHash: H('b'), policyHash: H('c'),
    verificationResult: true, tenantId: 't', requestId: rid, executingProvider: 'openai', outputHash: eb.outputHashOf('hello'), stage: 'PROVIDER_EXECUTION', issuedAt: 1790000000000, protocolVersion: 1 });
  const { writeLifecycleEntry } = require('../lifecycleEntry');
  const deps = { append: (f, o) => a.appendMandatory(f, o), register: async () => ({ persisted: true }) };
  const intent = (rid) => ({ requestId: rid, inputHash: H('a'), signature: H('s'), requestHash: H('b'), policyHash: H('c'), tenantId: 't', publicKeyId: 'default:key_v1', provider: 'openai', model: 'gpt-4', executingProvider: 'openai', issuedAt: 1790000000000, protocolVersion: 1 });
  await writeLifecycleEntry('INTENT', intent(ids.A), deps);
  await a.appendMandatory(decision(ids.A), { stage: 'ALLOW' });
  await require('../commitEntry').recordCommit(ctx(ids.A), done);
  await writeLifecycleEntry('INTENT', intent(ids.B), deps);
  await a.appendMandatory(decision(ids.B), { stage: 'ALLOW' });                         // ... and the process dies here
  await a.appendMandatory({ ...decision(ids.C), decision: 'BLOCK', executingProvider: undefined, reason: 'POLICY', stage: 'POLICY_CHECK' }, { stage: 'BLOCK' });   // a BLOCK needs no COMMIT
  await a.drainPendingWrites();
  return ids;
}

describe('durable COMMIT, boot reconciliation', () => {
  test('CD-01 a refused COMMIT is queued durably and the in-process map is not used', async () => {
    jest.doMock('../../persistenceRecovery', () => ({ setCommitWriter: jest.fn(), enqueueWithOutcome: jest.fn(async () => ({ phantom: null, durable: 'queue' })), OPERATION_TYPES: { AUDIT_COMMIT_WRITE: 'AUDIT_COMMIT_WRITE' } }));
    const audit = require('../audit-log');
    jest.spyOn(audit, 'appendMandatory').mockRejectedValue(new Error('disk full'));
    const { recordCommit } = require('../commitEntry');
    const rec = require('../lifecycleReconciler');
    const r = await recordCommit(ctx('r-1'), done);
    expect(r).toMatchObject({ recorded: false, failed: true, queued: true });
    const pr = require('../../persistenceRecovery');
    expect(pr.enqueueWithOutcome).toHaveBeenCalledWith('AUDIT_COMMIT_WRITE', { c: expect.objectContaining({ requestId: 'r-1' }), outcome: done }, expect.any(Error));
    expect(rec.pendingCount()).toBe(0);
  });

  test('CD-02 when nothing durable takes it, the in-process reconciler keeps it', async () => {
    jest.doMock('../../persistenceRecovery', () => ({ setCommitWriter: jest.fn(), enqueueWithOutcome: jest.fn(async () => ({ phantom: null, durable: false })), OPERATION_TYPES: { AUDIT_COMMIT_WRITE: 'AUDIT_COMMIT_WRITE' } }));
    const audit = require('../audit-log');
    jest.spyOn(audit, 'appendMandatory').mockRejectedValue(new Error('disk full'));
    const r = await require('../commitEntry').recordCommit(ctx('r-2'), done);
    expect(r).toMatchObject({ recorded: false, failed: true });
    expect(r.queued).toBeUndefined();
    expect(require('../lifecycleReconciler').pendingCount()).toBe(1);
  });

  test('CD-03 the replay handler: done on recorded / duplicate / skipped, retry on refusal, no retry on a malformed payload', async () => {
    jest.resetModules();
    const { _builtinHandlers, OPERATION_TYPES } = require('../../persistenceRecovery/recoveryManager');
    const handler = _builtinHandlers[OPERATION_TYPES.AUDIT_COMMIT_WRITE];
    require('../commitEntry'); // registers the COMMIT writer with the recovery queue, as server startup does (dependency inversion)
    expect(typeof handler).toBe('function');
    expect(await handler({ payload: {} })).toMatchObject({ success: false, error: expect.stringMatching(/^non-retryable/) });
    const audit = require('../audit-log');
    const spy = jest.spyOn(audit, 'appendMandatory');
    spy.mockResolvedValueOnce({ hash: H('e') });
    expect(await handler({ payload: { c: ctx('r-3'), outcome: done } })).toEqual({ success: true });
    spy.mockRejectedValueOnce(new Error('already_executed: r-3'));
    expect(await handler({ payload: { c: ctx('r-3'), outcome: done } })).toEqual({ success: true });
    spy.mockRejectedValue(new Error('disk full'));
    expect(await handler({ payload: { c: ctx('r-4'), outcome: done } })).toMatchObject({ success: false });
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'false'; jest.resetModules();
    const h2 = require('../../persistenceRecovery/recoveryManager')._builtinHandlers[OPERATION_TYPES.AUDIT_COMMIT_WRITE];
    require('../commitEntry');
    expect(await h2({ payload: { c: ctx('r-5'), outcome: done } })).toEqual({ success: true });         // flag off: nothing to write
  });

  test('CD-04 kill between DECISION and COMMIT, restart: one OUTCOME_UNKNOWN COMMIT, chain valid, no ORPHAN_DECISION, second boot writes nothing', async () => {
    const ids = await previousProcess();
    jest.resetModules();                                                                    // the next boot
    require('../commitEntry');                                                              // loaded before the boot reconciliation, as in server/startup.js
    const a = require('../audit-log');
    const rec = require('../lifecycleReconciler');
    expect(a.getUncommittedDecisionsInWindow().map((e) => e.requestId)).toEqual([ids.B]);  // A has its COMMIT, C is a BLOCK
    const r = await rec.reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false });
    expect(r).toEqual({ open: 1, written: 1, queued: 0, failed: 0 });
    const chain = await a.getAuditChain();
    const commits = chain.filter((e) => e.requestId === ids.B && e.entryType === 'COMMIT');
    expect(commits).toHaveLength(1);
    expect(commits[0]).toMatchObject({ decision: 'ALLOW', reason: 'RESPONSE_FAILED', completionStatus: 'OUTCOME_UNKNOWN', bytesDelivered: 0, outputHash: require('../entryBuilder').EMPTY_OUTPUT_HASH, artifactId: `${ids.B}:commit` });
    expect(chain.filter((e) => e.requestId === ids.A && e.entryType === 'COMMIT')).toHaveLength(1);       // untouched
    expect(a.getUncommittedDecisionsInWindow()).toEqual([]);
    // the chain verifies, and the independent lifecycle walk reports no ORPHAN_DECISION (grace passed: the clock is far in the future)
    const vd = a.verifyAuditChainDetailed(chain);
    expect(vd).toMatchObject({ valid: true, reason: null });
    const { createLifecycleTracker } = require('../v7Lifecycle');
    const t = createLifecycleTracker({ lifecycleComplete: true, nowMs: Date.now() + 3600_000 });
    for (const e of chain) t.step(e);
    expect(t.finish().filter((w) => w.code === 'ORPHAN_DECISION')).toEqual([]);
    // without the reconciler the same chain WOULD report it
    const t2 = createLifecycleTracker({ lifecycleComplete: true, nowMs: Date.now() + 3600_000 });
    for (const e of chain.filter((x) => !(x.requestId === ids.B && x.entryType === 'COMMIT'))) t2.step(e);
    expect(t2.finish().map((w) => w.code)).toContain('ORPHAN_DECISION');
    // a second boot
    const before = chain.length;
    jest.resetModules();
    const a2 = require('../audit-log');
    expect(await require('../lifecycleReconciler').reconcileCommitsAtBoot({ auditLog: a2, hasPending: async () => false })).toMatchObject({ open: 0, written: 0 });
    expect((await a2.getAuditChain()).length).toBe(before);
  });

  test('CD-05 a COMMIT waiting in the durable queue is left to its replay', async () => {
    const ids = await previousProcess();
    jest.resetModules();
    const a = require('../audit-log');
    require('../commitEntry'); // loaded before the boot reconciliation, as in server/startup.js
    const r = await require('../lifecycleReconciler').reconcileCommitsAtBoot({ auditLog: a, hasPending: async (id) => id === ids.B });
    expect(r).toEqual({ open: 1, written: 0, queued: 1, failed: 0 });
    expect((await a.getAuditChain()).filter((e) => e.requestId === ids.B && e.entryType === 'COMMIT')).toHaveLength(0);
  });

  test('CD-06 schema v8 off writes nothing; a refused boot write is kept for the runtime retry', async () => {
    const ids = await previousProcess();
    jest.resetModules();
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'false';
    let a = require('../audit-log');
    expect(await require('../lifecycleReconciler').reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false })).toMatchObject({ skipped: 'SCHEMA_V8_OFF', written: 0 });
    jest.resetModules();
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'true';
    a = require('../audit-log');
    jest.doMock('../../persistenceRecovery', () => ({ setCommitWriter: jest.fn(), enqueueWithOutcome: jest.fn(async () => ({ durable: false })), OPERATION_TYPES: { AUDIT_COMMIT_WRITE: 'AUDIT_COMMIT_WRITE' }, hasPendingCommit: async () => false }));
    const spy = jest.spyOn(a, 'appendMandatory').mockRejectedValueOnce(new Error('disk full'));
    require('../commitEntry'); // loaded before the boot reconciliation, as in server/startup.js
    const rec = require('../lifecycleReconciler');
    const r = await rec.reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false });
    expect(r).toMatchObject({ open: 1, written: 0, failed: 1 });
    expect(rec.pendingCount()).toBe(1);
    spy.mockRestore();
    expect(await rec.retryOpenLifecycles()).toEqual({ closed: 1, pending: 0 });
    expect((await a.getAuditChain()).filter((e) => e.requestId === ids.B && e.entryType === 'COMMIT')).toHaveLength(1);
  });
});

describe('D-11 — peers in-flight DECISIONs are not closed', () => {
  test('CD-08 with a minimum age, a DECISION younger than it is left alone (distributed ordering), an older one is closed', async () => {
    const ids = await previousProcess();
    jest.resetModules();
    const a = require('../audit-log');
    require('../commitEntry'); // loaded before the boot reconciliation, as in server/startup.js
    const rec = require('../lifecycleReconciler');
    const young = await rec.reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false, minAgeMs: 600_000 });
    expect(young).toMatchObject({ open: 1, written: 0, young: 1 });
    expect((await a.getAuditChain()).some((e) => e.requestId === ids.B && e.entryType === 'COMMIT')).toBe(false);
    const old = await rec.reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false, minAgeMs: 600_000, nowMs: Date.now() + 3600_000 });
    expect(old).toMatchObject({ open: 1, written: 1 });
  });
});

describe('a real killed process', () => {
  test('CD-07 SIGKILL between DECISION and COMMIT; the next boot writes the OUTCOME_UNKNOWN COMMIT and the chain verifies', async () => {
    const { spawnSync } = require('child_process');
    const rid = crypto.randomUUID();
    const r = spawnSync(process.execPath, [path.join(__dirname, 'helpers', 'crash.js'), rid], { env: { ...process.env, NODE_ENV: 'test', QODIQA_AUDIT_LOG: file, QODIQA_AUDIT_SCHEMA_V8: 'true', QODIQA_PG_ENABLED: 'false' }, encoding: 'utf8', timeout: 60_000 });
    expect(r.status === 0).toBe(false);                                                    // it did not exit normally: it was killed
    expect(fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).map((e) => e.entryType)).toEqual(['INTENT', 'DECISION']);
    jest.resetModules();                                                                    // the next boot
    require('../commitEntry');                                                              // loaded before the boot reconciliation, as in server/startup.js
    const a = require('../audit-log');
    const rec = require('../lifecycleReconciler');
    expect(await rec.reconcileAtBoot({ auditLog: a, writeBlock: async () => ({ recorded: false }) })).toMatchObject({ open: 0 });   // the INTENT was closed by the DECISION
    expect(await rec.reconcileCommitsAtBoot({ auditLog: a, hasPending: async () => false })).toEqual({ open: 1, written: 1, queued: 0, failed: 0 });
    const chain = await a.getAuditChain();
    expect(chain.map((e) => e.entryType)).toEqual(['INTENT', 'DECISION', 'COMMIT']);
    expect(chain[2]).toMatchObject({ completionStatus: 'OUTCOME_UNKNOWN', reason: 'RESPONSE_FAILED', bytesDelivered: 0, requestId: rid });
    expect(a.verifyAuditChainDetailed(chain)).toMatchObject({ valid: true });
    const contract = require('../../../../scripts/audit-repro/verify/auditContract');
    expect(contract.walkChain(chain, { startPrevHash: 'GENESIS' }).valid).toBe(true);
    const { createLifecycleTracker } = require('../v7Lifecycle');
    const t = createLifecycleTracker({ lifecycleComplete: true, nowMs: Date.now() + 3600_000 });
    for (const e of chain) t.step(e);
    expect(t.finish().map((w) => w.code)).not.toContain('ORPHAN_DECISION');
  });

  test('CD-09 the one-way schema guard survives a restart: a v7 append after a v8 head is refused by a fresh process', async () => {
    const { spawnSync } = require('child_process');
    const rid = crypto.randomUUID();
    spawnSync(process.execPath, [path.join(__dirname, 'helpers', 'crash.js'), rid], { env: { ...process.env, NODE_ENV: 'test', QODIQA_AUDIT_LOG: file, QODIQA_AUDIT_SCHEMA_V8: 'true', QODIQA_PG_ENABLED: 'false' }, encoding: 'utf8', timeout: 60_000 });
    jest.resetModules();
    process.env.QODIQA_AUDIT_SCHEMA_V8 = 'false';                                         // the next boot runs with the flag off
    const a = require('../audit-log');
    await expect(a.appendMandatory({ artifactId: crypto.randomUUID(), decision: 'ALLOW', outputHash: require('../entryBuilder').outputHashOf('x'), inputHash: H('a'), signature: H('s'), requestHash: H('b'), policyHash: H('c'), verificationResult: true, tenantId: 't' }, { stage: 'ALLOW' }))
      .rejects.toThrow(/invalid_schema_downgrade/);
  });
});
