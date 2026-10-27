'use strict';

/**
 * the single-node mirror WRITER loop (src/core/audit/audit-log.js _runMirrorWriter) when the
 * backend breaks its own "never throws" contract or hangs, through the REAL append path (file mode, per-file isolated
 * log via test/support/jest.setup.js) with a scripted pg-audit-backend.
 *
 * Gap closed: mirrorWriterBatch.test.js (MBA-02) only drives a backend that always succeeds; the writer's
 * defence-in-depth `catch {}` and its depth/back-pressure accounting on a FAILED batch were never exercised.
 *
 *   MWF-01  persistEntries REJECTS for one batch: the writer does not stop — later entries are still handed over in
 *           chain order, depth returns to 0, back-pressure releases, drainMirrorWriter() resolves; the authoritative
 *           file chain is complete and verifies (the mirror fault never touched it)
 *   MWF-02  persistEntry THROWS synchronously for a single-entry batch: same — the writer survives
 *   MWF-03  a HUNG backend call: appends still succeed (the file chain is never gated on the mirror), depth grows,
 *           back-pressure ENGAGES at the bound (no unbounded queue), and everything drains in order once the call
 *           settles
 *
 * Observation (not a defect under the current contract, recorded in FAILURE-RECOVERY.md as PH16-O1): on a rejected
 * batch the entries are simply dropped from the mirror with no event and no recovery-queue record; only the
 * count reconciler would notice.
 */

process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH = '100'; // the latch's minimum (mirrorBackpressure.MIN_MAX_DEPTH)
process.env.QODIQA_AUDIT_MIRROR_BATCH = '4';

jest.mock('../../services/logger', () => ({ ...jest.requireActual('../../services/logger'), emit: jest.fn() }));
const mockState = { calls: [], script: null };
jest.mock('../../src/infra/postgres/pg-audit-backend', () => {
  const actual = jest.requireActual('../../src/infra/postgres/pg-audit-backend');
  const run = (kind, entries) => { mockState.calls.push({ kind, hashes: entries.map((e) => e.hash) }); return mockState.script(kind, entries); };
  return { ...actual, persistEntry: (e) => run('one', [e]), persistEntries: (es) => run('batch', es) };
});

const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder');
const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH,
  signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
const tick = () => new Promise((r) => setImmediate(r));
afterAll(() => { delete process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH; delete process.env.QODIQA_AUDIT_MIRROR_BATCH; });

let auditLog;
beforeAll(() => { auditLog = require('../../src/core/audit/audit-log'); });
beforeEach(() => { mockState.calls = []; });

async function appendN(k) { const out = []; for (let i = 0; i < k; i++) out.push((await auditLog.append(fields())).hash); return out; }

test('MWF-01 a rejected batch never stops the writer: later batches still delivered in order, depth 0, back-pressure released', async () => {
  const gates = []; let rejected = 0;
  mockState.script = (kind) => {
    if (gates.length === 0 && mockState.calls.length === 1) return new Promise((r) => gates.push(r));  // hold the first call
    if (kind === 'batch' && rejected === 0) { rejected++; return Promise.reject(new Error('injected persistEntries defect')); }
    return Promise.resolve();
  };
  const hashes = await appendN(1);
  await tick();
  hashes.push(...await appendN(9));                                 // accumulate behind the held call -> batches of 4
  gates.shift()();
  await auditLog.drainMirrorWriter();
  expect(rejected).toBe(1);                                         // a multi-entry batch really was rejected
  expect(mockState.calls.some((c) => c.kind === 'batch' && c.hashes.length === 4)).toBe(true);
  expect(mockState.calls.flatMap((c) => c.hashes)).toEqual(hashes); // every entry handed over once, in chain order
  const more = await appendN(3);
  await auditLog.drainMirrorWriter();
  expect(mockState.calls.flatMap((c) => c.hashes).slice(-3)).toEqual(more); // the writer is still alive afterwards
  expect(auditLog.mirrorWriterDepth()).toBe(0);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
  expect(auditLog.verifyAuditChain()).toBe(true);                  // the authoritative file chain is untouched
});

test('MWF-02 a synchronous throw from persistEntry (single-entry batch) never stops the writer', async () => {
  let threw = 0;
  mockState.script = (kind) => { if (kind === 'one' && threw++ === 0) throw new Error('injected sync throw'); return Promise.resolve(); };
  const [h1] = await appendN(1);
  await auditLog.drainMirrorWriter();
  const [h2] = await appendN(1);
  await auditLog.drainMirrorWriter();
  expect(threw).toBeGreaterThanOrEqual(1);
  expect(mockState.calls.flatMap((c) => c.hashes)).toEqual([h1, h2]);
  expect(auditLog.mirrorWriterDepth()).toBe(0);
});

test('MWF-03 a HUNG backend: appends still commit, back-pressure engages at the bound, then everything drains in order', async () => {
  const gates = [];
  mockState.script = () => new Promise((resolve) => gates.push(resolve));
  const first = await appendN(1);                                   // in flight, hung
  await tick();
  const rest = await appendN(104);                                  // the file chain keeps committing
  expect(auditLog.mirrorWriterDepth()).toBe(105);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(true);          // bounded: admission / /ready see it
  let drained = false; auditLog.drainMirrorWriter().then(() => { drained = true; });
  mockState.script = () => Promise.resolve();
  gates.shift()();                                                  // the hung call finally settles
  for (let i = 0; i < 50 && !drained; i++) await tick();
  expect(drained).toBe(true);
  expect(mockState.calls.flatMap((c) => c.hashes)).toEqual([...first, ...rest]);
  expect(auditLog.mirrorWriterDepth()).toBe(0);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
});
