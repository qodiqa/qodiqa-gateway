'use strict';

/**
 * — an accepted checkpoint/anchor bootstrap boot must actually start anchoring.
 *
 * Found on the isolated deployment of qodiqa:rc-077f3fc7: the anchors volume was unwritable, so 11 checkpoints
 * were signed and none exported; the next boot failed closed (correct). After repairing the volume, the documented
 * one-boot bootstrap was accepted, but nothing was anchored during that boot — createSignedCheckpoint() returns early
 * when the latest checkpoint already covers the chain — so the following plain restart failed again.
 *
 *   AE-1  checkpoint exists, export empty → the scheduler's first tick publishes that checkpoint, once, and reports it
 *   AE-2  export already holds anchors → never touched (the boot check keeps detecting deleted/truncated exports)
 *   AE-3  no signed checkpoint → nothing published
 *   AE-4  a failing publish is attempted once per process, reported, and never throws out of the tick
 * AE-5 no witness cosigns (e.g. seccomp blocked link()) → nothing is written, the export stays EMPTY (still
 *         recoverable by the chain-bound bootstrap) instead of holding an unwitnessed anchor no bootstrap can clear
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../../entryBuilder');

const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
  requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('anchor export re-establishment', () => {
  let dir; let auditLog; let w; let events; let stops;
  const runner = { runTask: async (_n, fn) => fn() };
  const opts = (extra = {}) => ({ registrar: null, emit: (l, t, d) => events.push({ l, t, d }), ...extra });

  function fakeAnchoring({ initial = [], fail = false, noCosign = false } = {}) {
    const records = [...initial];
    const calls = [];
    return {
      records, calls,
      api: {
        enabled: () => true,
        exportPath: () => path.join(dir, 'anchors', 'anchors.jsonl'),
        read: () => records,
        publish: async (cp, opts = {}) => {
          calls.push(cp);
          if (fail) throw new Error('EACCES: permission denied');
          if (noCosign) {
            const errors = [{ witnessId: 'w', code: 'EPERM', message: 'EPERM: operation not permitted, link' }];
            if (opts.requireCosignature) return { record: null, errors };
            const record = { anchorVersion: 1, checkpoint: cp, cosignatures: [] }; records.push(record); return { record, errors };
          }
          const record = { anchorVersion: 1, checkpoint: cp, cosignatures: [{ witnessId: 'w' }] };
          records.push(record);
          return { record, errors: [] };
        },
      },
    };
  }
  const offAnchoring = { enabled: () => false, exportPath: () => null, read: () => [], publish: async () => ({ record: null, errors: [] }) };

  async function signOneCheckpoint() {
    for (let i = 0; i < 5; i++) await auditLog.append(fields());
    return w.createSignedCheckpoint(opts({ anchoring: offAnchoring })); // signed while anchoring was not working
  }
  const start = (anchoring) => { const stop = w.startCheckpointScheduler(opts({ taskRunner: runner, tickMs: 5, anchoring })); stops.push(stop); return stop; };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-aut06-'));
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    jest.resetModules();
    events = []; stops = [];
    auditLog = require('../../audit-log'); w = require('../checkpointWriter');
  });
  afterEach(() => {
    for (const s of stops) s();
    w._resetSchedulerStateForTests();
    delete process.env.QODIQA_AUDIT_LOG;
    jest.resetModules();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  test('AE-1 checkpoint exists, export empty → published once on the first tick and reported', async () => {
    const cp = await signOneCheckpoint();
    expect(cp).not.toBeNull();
    w._resetSchedulerStateForTests(); // a new process: the scheduler starts after the (bootstrap) boot
    const a = fakeAnchoring();
    start(a.api);
    await sleep(60);
    expect(a.calls).toHaveLength(1);
    expect(a.calls[0].payload.checkpointId).toBe(cp.payload.checkpointId);
    expect(a.records).toHaveLength(1);
    const ev = events.find((e) => e.t === 'AUDIT_ANCHOR_EXPORT_REESTABLISHED');
    expect(ev).toMatchObject({ l: 'WARN', d: { checkpointId: cp.payload.checkpointId, chainLength: cp.payload.chainLength, exported: true, cosignatures: 1 } });
  });

  test('AE-2 an export that already holds anchors is never touched', async () => {
    const cp = await signOneCheckpoint();
    w._resetSchedulerStateForTests();
    const a = fakeAnchoring({ initial: [{ anchorVersion: 1, checkpoint: cp, cosignatures: [{}] }] });
    start(a.api);
    await sleep(60);
    expect(a.calls).toHaveLength(0);
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_EXPORT_REESTABLISHED')).toBe(false);
  });

  test('AE-3 no signed checkpoint → nothing published', async () => {
    const a = fakeAnchoring();
    start(a.api);
    await sleep(60);
    expect(a.calls).toHaveLength(0);
  });

  test('AE-4 a failing publish is attempted once per process, reported, and the scheduler keeps running', async () => {
    await signOneCheckpoint();
    w._resetSchedulerStateForTests();
    const a = fakeAnchoring({ fail: true });
    start(a.api);
    await sleep(80);
    expect(a.calls).toHaveLength(1);
    expect(events.find((e) => e.t === 'AUDIT_ANCHOR_EXPORT_FAILED')).toMatchObject({ l: 'ERROR', d: { phase: 'reestablish' } });
    expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_TICK_FAILED')).toBe(false);
  });

  test('AE-5 no witness cosigns → the re-establishment asks for a cosignature, writes nothing, reports ERROR', async () => {
    await signOneCheckpoint();
    w._resetSchedulerStateForTests();
    const a = fakeAnchoring({ noCosign: true });
    start(a.api);
    await sleep(60);
    expect(a.calls).toHaveLength(1);
    expect(a.records).toHaveLength(0);
    expect(events.find((e) => e.t === 'AUDIT_ANCHOR_WITNESS_FAILED')).toMatchObject({ l: 'ERROR', d: { code: 'EPERM' } });
    expect(events.find((e) => e.t === 'AUDIT_ANCHOR_EXPORT_FAILED')).toMatchObject({ l: 'ERROR', d: { phase: 'reestablish' } });
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_EXPORT_REESTABLISHED')).toBe(false);
  });
});
