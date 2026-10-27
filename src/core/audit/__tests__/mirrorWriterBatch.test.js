'use strict';

/**
 * phase 9 — batched single-node mirror writer (audit-log.js → pg-audit-backend.persistEntries),
 * through the REAL append path (file mode, per-file isolated log) with a gated mirror.
 *
 *   MBA-02  entries that accumulate while a batch is in flight are handed over together, at most
 *           QODIQA_AUDIT_MIRROR_BATCH per batch, FIFO / chain order; depth falls by a whole batch; back-pressure still
 *           engages at the bound and releases at half; drainMirrorWriter() resolves only when everything is handed over
 */

process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH = '100';
process.env.QODIQA_AUDIT_MIRROR_BATCH = '16';

jest.mock('../../../../services/logger', () => ({ ...jest.requireActual('../../../../services/logger'), emit: jest.fn() }));
const mockState = { batches: [], waiters: [] };
jest.mock('../../../infra/postgres/pg-audit-backend', () => {
  const actual = jest.requireActual('../../../infra/postgres/pg-audit-backend');
  const take = (entries) => new Promise((resolve) => mockState.waiters.push(() => { mockState.batches.push(entries.map((e) => e.hash)); resolve(); }));
  return { ...actual, persistEntry: (e) => take([e]), persistEntries: (es) => take(es) };
});

const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../entryBuilder');
const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH,
  signature: 's'.repeat(64), requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
const tick = () => new Promise((r) => setImmediate(r));
afterAll(() => { delete process.env.QODIQA_AUDIT_MIRROR_MAX_DEPTH; delete process.env.QODIQA_AUDIT_MIRROR_BATCH; });

test('MBA-02 batches of at most QODIQA_AUDIT_MIRROR_BATCH, FIFO, depth/back-pressure per batch', async () => {
  const auditLog = require('../audit-log');
  const hashes = [];
  hashes.push((await auditLog.append(fields())).hash);           // first write: a batch of one, in flight
  await tick();
  expect(mockState.waiters).toHaveLength(1);
  for (let i = 0; i < 104; i++) hashes.push((await auditLog.append(fields())).hash); // accumulate behind it
  expect(auditLog.mirrorWriterDepth()).toBe(105);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(true);
  let drained = false; auditLog.drainMirrorWriter().then(() => { drained = true; });
  const release = async () => { mockState.waiters.shift()(); await tick(); await tick(); };
  await release();                                                 // batch of 1 done → next batch of 16 in flight
  expect(auditLog.mirrorWriterDepth()).toBe(104);
  while (mockState.waiters.length) {
    await release();
    if (auditLog.mirrorWriterDepth() > 50) expect(auditLog.mirrorBackpressureEngaged()).toBe(true);
  }
  await tick();
  expect(drained).toBe(true);
  expect(auditLog.mirrorWriterDepth()).toBe(0);
  expect(auditLog.mirrorBackpressureEngaged()).toBe(false);
  expect(mockState.batches[0]).toHaveLength(1);
  expect(Math.max(...mockState.batches.map((b) => b.length))).toBe(16);
  expect(mockState.batches.flat()).toEqual(hashes);              // nothing lost, chain order
});

test('MBA-03 PH16-O1: a batch the backend throws on is reported (AUDIT_MIRROR_WRITER_BATCH_FAILED), the writer keeps going', async () => {
  const auditLog = require('../audit-log');
  const { emit } = require('../../../../services/logger');
  const backend = require('../../../infra/postgres/pg-audit-backend');
  const real = backend.persistEntries;
  backend.persistEntries = () => Promise.reject(new Error('defect: persistEntries threw'));
  const realOne = backend.persistEntry;
  backend.persistEntry = () => Promise.reject(new Error('defect: persistEntry threw'));
  try {
    for (let i = 0; i < 5; i++) await auditLog.append(fields());
    await auditLog.drainMirrorWriter();
    expect(auditLog.mirrorWriterDepth()).toBe(0);
    expect(emit.mock.calls.some((c) => c[1] === 'AUDIT_MIRROR_WRITER_BATCH_FAILED' && c[2].entries >= 1)).toBe(true);
  } finally { backend.persistEntries = real; backend.persistEntry = realOne; }
});
