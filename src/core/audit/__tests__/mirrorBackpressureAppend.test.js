'use strict';

/**
 * 2026-10-06 — the audit mirror backlog bound, end to end through the REAL audit-log append path (file mode,
 * per-file isolated scratch log from jest.setup) with a PostgreSQL mirror that is slow but up (persistEntry gated).
 *
 *   MBA-01  appends never wait on the mirror; at QODIQA_AUDIT_MIRROR_MAX_DEPTH pending writes back-pressure ENGAGES and
 *           AUDIT_MIRROR_BACKPRESSURE_ENGAGED is logged once; it stays engaged while the backlog is above half; it
 *           RELEASES (logged once) when the backlog drains to half, and every entry is still mirrored in chain order
 *
 * The soak that exposed the missing log line (a ReferenceError swallowed by a try/catch, so the transition events never
 * reached the log) is; this test pins the events.
 */

process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH = '100';
process.env.QODIQA_AUDIT_MIRROR_BATCH = '1'; // phase 9: pins the per-entry writer here; batching is MBA-02 (mirrorWriterBatch.test.js)

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ ...jest.requireActual('../../../../services/logger'), emit: (...a) => mockEmit(...a) }));
const mockGate = { open: false, waiters: [], persisted: [] };
jest.mock('../../../infra/postgres/pg-audit-backend', () => {
  const actual = jest.requireActual('../../../infra/postgres/pg-audit-backend');
  return {
    ...actual,
    persistEntry: (entry) => new Promise((resolve) => {
      const done = () => { mockGate.persisted.push(entry.hash); resolve(true); };
      if (mockGate.open) done(); else mockGate.waiters.push(done);
    }),
  };
});

const { EMPTY_OUTPUT_HASH } = require('../entryBuilder');
const crypto = require('crypto');

const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH,
  signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
const events = (t) => mockEmit.mock.calls.filter((c) => c[1] === t);

afterAll(() => { delete process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH; delete process.env.QODIQA_AUDIT_MIRROR_BATCH; });

test('MBA-01 engage at the bound, stay engaged above half, release at half; every entry still mirrored', async () => {
  const auditLog = require('../audit-log');
  expect(auditLog.mirrorBackpressureConfig()).toEqual({ maxDepth: 100, resumeDepth: 50 });
  const hashes = [];
  for (let i = 0; i < 99; i++) hashes.push((await auditLog.append(fields())).hash);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
  hashes.push((await auditLog.append(fields())).hash); // the 100th pending write
  expect(auditLog.mirrorWriterDepth()).toBeGreaterThanOrEqual(100);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(true);
  expect(events('AUDIT_MIRROR_BACKPRESSURE_ENGAGED')).toHaveLength(1);
  expect(events('AUDIT_MIRROR_BACKPRESSURE_ENGAGED')[0][2]).toMatchObject({ maxDepth: 100, resumeDepth: 50 });
  for (let i = 0; i < 5; i++) hashes.push((await auditLog.append(fields())).hash); // the chain itself is never blocked
  expect(events('AUDIT_MIRROR_BACKPRESSURE_ENGAGED')).toHaveLength(1);

  // drain one write at a time: still engaged above 50, released at 50
  const step = async () => { const w = mockGate.waiters.shift(); w(); await new Promise((r) => setImmediate(r)); };
  while (auditLog.mirrorWriterDepth() > 51) await step();
  expect(auditLog.mirrorBackpressureEngaged()).toBe(true);
  await step();
  expect(auditLog.mirrorWriterDepth()).toBe(50);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
  expect(events('AUDIT_MIRROR_BACKPRESSURE_RELEASED')).toHaveLength(1);

  mockGate.open = true; while (mockGate.waiters.length) mockGate.waiters.shift()();
  await auditLog.drainMirrorWriter();
  expect(auditLog.mirrorWriterDepth()).toBe(0);
  expect(mockGate.persisted).toEqual(hashes); // FIFO, chain order, nothing dropped
});
