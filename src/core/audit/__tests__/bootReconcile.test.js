'use strict';

/**
 * — boot reconciliation of lifecycles the previous process left open. Acceptance
 * L-3, L-4:
 * Real audit-log (file mode). A "previous process" writes: request A INTENT + DECISION (closed), request B INTENT only
 * (non-streaming, died before closing), request C INTENT + STREAM_OPENED (streamed, died mid-stream). A fresh module
 * load (= the next boot) then reconciles.
 *
 *   BR-1  getOpenLifecyclesInWindow() reports exactly B (intent) and C (intent + streamOpened)
 *   BR-2  reconcileAtBoot closes B with ONE BLOCK PROVIDER_OUTCOME_UNRECORDED built from B's INTENT; since audit 2026-10-20 (3.13)
 *         C (streamed, delivery unknown) is ALSO closed — with BLOCK STREAM_OUTCOME_UNKNOWN (never a claim that nothing was
 *         delivered); the chain stays VALID with no ORPHAN_INTENT warning
 *   BR-3  a store that refuses the closing write at boot → deferred to the runtime retry, closed once it recovers;
 *         a second boot finds B closed and appends nothing
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

let dir; let file;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut09-'));
  file = path.join(dir, 'audit.log');
  process.env.QODIQA_AUDIT_LOG = file;
  jest.resetModules();
});
afterEach(() => {
  delete process.env.QODIQA_AUDIT_LOG;
  jest.resetModules();
  fs.rmSync(dir, { recursive: true, force: true });
});

const base = (rid) => ({ requestId: rid, inputHash: 'a'.repeat(64), signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64),
  tenantId: 't', publicKeyId: 'default:key_v1', provider: 'openai', model: 'gpt-4', executingProvider: 'openai' });

async function previousProcess() {
  const a = require('../audit-log');
  const { writeLifecycleEntry } = require('../lifecycleEntry');
  const deps = { append: (f, o) => a.appendMandatory(f, o), register: async () => ({ persisted: true }) };
  const ids = { A: crypto.randomUUID(), B: crypto.randomUUID(), C: crypto.randomUUID() };
  await writeLifecycleEntry('INTENT', base(ids.A), deps);
  await a.appendMandatory({ artifactId: ids.A, entryType: 'DECISION', decision: 'ALLOW', inputHash: 'a'.repeat(64), signature: 's'.repeat(64),
    requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 't', requestId: ids.A, executingProvider: 'openai',
    outputHash: require('../entryBuilder').EMPTY_OUTPUT_HASH, stage: 'PROVIDER_EXECUTION' }, { stage: 'ALLOW' });
  await writeLifecycleEntry('INTENT', base(ids.B), deps);
  await writeLifecycleEntry('INTENT', base(ids.C), deps);
  await writeLifecycleEntry('STREAM_OPENED', base(ids.C), deps);
  return ids;
}
// what aiChat's _writeAuditBlock appends (decision fields only; its transparency leaf is outside this test)
function blockWriter(a, { failFirst = 0 } = {}) {
  let calls = 0;
  return async (args) => {
    calls++;
    if (calls <= failFirst) return { recorded: false };
    try {
      const e = await a.appendMandatory({ artifactId: args.artifactId, entryType: 'DECISION', decision: 'BLOCK', inputHash: args.inputHash, signature: args.signature,
        requestHash: args.requestHash, policyHash: args.policyHash, verificationResult: false, tenantId: args.tenantId, requestId: args.requestId,
        publicKeyId: args.publicKeyId, provider: args.provider, model: args.model, stage: args.stage, reason: args.reason,
        executingProvider: args.executingProvider, executionContext: { stage: args.stage, reason: args.reason } }, { stage: 'BLOCK' });
      return { recorded: true, auditEntryHash: e.hash };
    } catch (err) {
      return String(err.message).startsWith('already_executed') ? { duplicate: true } : { recorded: false };
    }
  };
}

test('BR-1/BR-2 boot closes the open non-streaming INTENT and (3.13) the streamed one with STREAM_OUTCOME_UNKNOWN, chain VALID', async () => {
  const ids = await previousProcess();
  jest.resetModules();                                  // the next boot
  const a = require('../audit-log');
  const rec = require('../lifecycleReconciler');
  const open = a.getOpenLifecyclesInWindow();
  expect(open.map((o) => o.requestId).sort()).toEqual([ids.B, ids.C].sort());
  expect(open.find((o) => o.requestId === ids.C).streamOpened).not.toBeNull();
  const r = await rec.reconcileAtBoot({ auditLog: a, writeBlock: blockWriter(a) });
  expect(r).toEqual({ open: 2, closed: 2, deferred: 0, unreconcilable: 0 });
  const chain = await a.getAuditChain();
  const closing = chain.filter((e) => e.requestId === ids.B && e.entryType === 'DECISION');
  expect(closing).toHaveLength(1);
  expect(closing[0]).toMatchObject({ decision: 'BLOCK', reason: 'PROVIDER_OUTCOME_UNRECORDED', executingProvider: 'openai', artifactId: ids.B });
  const closingC = chain.filter((e) => e.requestId === ids.C && e.entryType === 'DECISION');
  expect(closingC).toHaveLength(1);
  expect(closingC[0]).toMatchObject({ decision: 'BLOCK', reason: 'STREAM_OUTCOME_UNKNOWN', artifactId: ids.C });
  const v = a.verifyAuditChainDetailed(chain);
  expect(v.valid).toBe(true);
  expect(v.warnings || []).toEqual([]);
  expect(a.getOpenLifecyclesInWindow()).toEqual([]);
});

test('BR-3 a refused write at boot is retried at runtime; a later boot appends nothing more', async () => {
  const ids = await previousProcess();
  jest.resetModules();
  const a = require('../audit-log');
  const rec = require('../lifecycleReconciler');
  const writer = blockWriter(a, { failFirst: 1 });
  expect(await rec.reconcileAtBoot({ auditLog: a, writeBlock: writer })).toMatchObject({ closed: 1, deferred: 1 }); // C (stream) closes; B's first write is refused -> deferred
  expect(rec.pendingCount()).toBe(1);
  expect(await rec.retryOpenLifecycles()).toEqual({ closed: 1, pending: 0 });
  const before = (await a.getAuditChain()).length;
  jest.resetModules();
  const a2 = require('../audit-log');
  const rec2 = require('../lifecycleReconciler');
  expect(await rec2.reconcileAtBoot({ auditLog: a2, writeBlock: blockWriter(a2) })).toMatchObject({ open: 0, closed: 0, unreconcilable: 0 });
  expect((await a2.getAuditChain()).length).toBe(before);
  expect((await a2.getAuditChain()).filter((e) => e.requestId === ids.B && e.entryType === 'DECISION')).toHaveLength(1);
});
