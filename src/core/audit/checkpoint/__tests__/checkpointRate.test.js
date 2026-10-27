'use strict';

/**
 * GA-CKPT-RATE — the checkpoint scheduler must keep the premise of the UNCHANGED boot check
 * (> 2 x QODIQA_AUDIT_CHECKPOINT_EVERY uncovered entries → AUDIT_CHECKPOINT_BOOT_FAILED) at any sustained append rate,
 * and a graceful shutdown signs a final checkpoint. Real audit-log in file mode, each case on its own audit.log.
 * QODIQA_AUDIT_CHECKPOINT_EVERY is scaled down to 5 so that the cases are about a hundred fsynced appends in total and finish in about a second even on a two-CPU machine; the arithmetic is the same
 * (every workload below is a fixed fraction or multiple of `every`).
 *
 *   CR-A  sustained append rate far above ~8 req/s with the scheduler running: every boot check along the way and after
 *         a stop passes; the pre-fix cadence (one sign per long tick) reproduces the refusal on the same workload
 *   CR-B  clean shutdown: signFinalCheckpoint covers the tail (the boot then passes); without it the boot refuses
 *   CR-C  crash/restart: the process stops with no final checkpoint; a fresh module load of the same audit.log boots
 *   CR-D  PostgreSQL fault: checkpoint reads/writes fail and the mirror drain never settles — the scheduler keeps signing
 *         to the sidecar (bounded mirror wait) and the boot check passes, during and after the outage
 *   CR-E  boundaries: the scheduler signs at exactly `every` uncovered entries and not one before; the boot check passes
 *         at exactly 2 x every uncovered and refuses at 2 x every + 1 (unchanged strength)
 *   CR-F  a checkpoint just before shutdown: the final checkpoint does not sign the same position twice (which the boot
 *         check refuses as "two different checkpoints vouch for entry N"); one more entry → it signs
 *   CR-G  pgSeq under load: the head's seq is located from the mirrored tail and VERIFIED by hash, else null
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { EMPTY_OUTPUT_HASH } = require('../../entryBuilder');

const EVERY = 5;
const part = (x) => Math.round(x * EVERY);                      // a fixed fraction or multiple of `every`
const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
  requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describe('GA-CKPT-RATE checkpoint cadence', () => {
  let dir; let auditLog; let w; let events; let stops;
  const load = () => { auditLog = require('../../audit-log'); w = require('../checkpointWriter'); };
  const opts = (extra = {}) => ({ registrar: null, emit: (l, t, d) => events.push({ l, t, d }), ...extra });
  const runner = { runTask: async (_n, fn) => fn() };
  const append = async (n) => { for (let i = 0; i < n; i++) await auditLog.append(fields()); };
  const boot = (o = opts()) => w.verifyLatestCheckpointAtBoot(o);
  const side = () => w.readSidecar(auditLog.LOG_PATH);
  const start = (extra = {}) => { const stop = w.startCheckpointScheduler(opts({ taskRunner: runner, tickMs: 5, ...extra })); stops.push(stop); return stop; };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-ckpt-rate-'));
    process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit.log');
    process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = String(EVERY);
    jest.resetModules();
    events = []; stops = [];
    load();
  });
  afterEach(() => {
    for (const s of stops) s();
    w._resetSchedulerStateForTests();
    delete process.env.QODIQA_AUDIT_LOG; delete process.env.QODIQA_AUDIT_CHECKPOINT_EVERY;
    jest.resetModules();
  });

  test('CR-A sustained rate: the uncovered tail never exceeds 2 x every; the pre-fix cadence reproduces the refusal', async () => {
    start();
    for (let burst = 0; burst < 12; burst++) {          // 12 bursts of 0.8 x every appends, a few ms apart: far above one entry per tick
      await append(part(0.8));
      await sleep(8);
      const uncovered = auditLog.memorySnapshot().modernCount - (side().slice(-1)[0] || { payload: { chainLength: 0 } }).payload.chainLength;
      expect(uncovered).toBeLessThanOrEqual(2 * EVERY);
    }
    await sleep(30);                                     // a stop right after load, no final checkpoint
    for (const s of stops) s();
    await expect(boot()).resolves.toMatchObject({ checked: true });
    expect(side().length).toBeGreaterThanOrEqual(Math.floor(12 * part(0.8) / EVERY) - 1);

    // control on a fresh log: one sign per long tick (the pre-fix 60 s cadence, scaled) and the same workload → refused
    jest.resetModules(); process.env.QODIQA_AUDIT_LOG = path.join(dir, 'audit-control.log'); load();
    await append(part(0.2)); await w.createSignedCheckpoint(opts());       // one tick fired early in the run
    start({ tickMs: 60_000 });                                    // the next tick is far away
    await append(part(9.6));
    await expect(boot()).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/not covered by any checkpoint/) });
  });

  test('CR-B clean shutdown: the final checkpoint covers the tail; without it the boot refuses', async () => {
    await append(part(0.2)); await w.createSignedCheckpoint(opts());
    await append(2 * EVERY + part(0.6));
    await expect(boot()).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED' });
    start();
    const r = await w.signFinalCheckpoint(opts());
    expect(r).toMatchObject({ signed: true, chainLength: auditLog.memorySnapshot().modernCount });
    expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_SHUTDOWN' && e.d.signed === true)).toBe(true);
    await expect(boot()).resolves.toMatchObject({ checked: true, chainLength: auditLog.memorySnapshot().modernCount });
    // the scheduler is stopped by the final checkpoint: no checkpoint after it
    const n = side().length; await append(EVERY + 1); await sleep(30);
    expect(side().length).toBe(n);
  });

  test('CR-C crash/restart: no final checkpoint, a fresh load of the same audit.log boots', async () => {
    start();
    for (let i = 0; i < 6; i++) { await append(part(0.9)); await sleep(8); }
    await sleep(30);
    const n = auditLog.memorySnapshot().modernCount;
    for (const s of stops) s(); stops = [];             // the process dies here: no shutdown path runs
    w._resetSchedulerStateForTests();
    jest.resetModules(); load();                       // restart: a new process loads the same files
    expect(auditLog.memorySnapshot().modernCount).toBe(n);
    await expect(boot()).resolves.toMatchObject({ checked: true });
  });

  test('CR-D PostgreSQL fault: reads/writes fail and the mirror never drains — checkpoints continue, the boot passes', async () => {
    let down = false;
    const pgPool = { isEnabled: () => true, query: async () => { if (down) throw new Error('ECONNREFUSED'); return { rows: [] }; } };
    const pgRows = [];
    const backend = {
      getChainTail: async () => { if (down) throw new Error('ECONNREFUSED'); return null; },
      getLatestSignedCheckpoint: async () => { if (down) throw new Error('ECONNREFUSED'); return pgRows.slice(-1)[0] || null; },
      listSignedCheckpoints: async () => { if (down) throw new Error('ECONNREFUSED'); return pgRows.slice(); },
      insertSignedCheckpoint: async (s) => { if (down) throw new Error('ECONNREFUSED'); pgRows.push(s); return true; },
    };
    const stuck = Object.create(auditLog);
    stuck.drainMirrorWriterThrough = () => (down ? new Promise(() => {}) : Promise.resolve()); // never settles while PG is down
    const o = { pgPool, backend, auditLog: stuck, mirrorWaitMs: 10 };
    start(o);
    await append(EVERY + 1); await sleep(30);
    expect(pgRows.length).toBeGreaterThanOrEqual(1);
    down = true;
    for (let i = 0; i < 5; i++) { await append(part(0.8)); await sleep(30); }
    const sidecarDuringOutage = side().length;
    expect(sidecarDuringOutage).toBeGreaterThan(pgRows.length);    // signed to the sidecar while PG was down
    down = false;
    await append(EVERY); await sleep(40);
    for (const s of stops) s(); stops = [];
    await expect(boot(opts(o))).resolves.toMatchObject({ checked: true });
    expect(events.filter((e) => e.t === 'AUDIT_CHECKPOINT_TICK_FAILED').length).toBeGreaterThanOrEqual(1); // the PG insert failures were reported
  });

  test('CR-E boundaries: signs at exactly `every`, not one before; boot passes at 2 x every uncovered, refuses at 2 x every + 1', async () => {
    await append(1); await w.createSignedCheckpoint(opts());
    start();
    await append(EVERY - 1); await sleep(30);
    expect(side()).toHaveLength(1);                                   // every - 1 uncovered: no sign
    await append(1); await sleep(30);
    expect(side()).toHaveLength(2);                                   // exactly every: signed
    expect(side()[1].payload.chainLength).toBe(1 + EVERY);
    for (const s of stops) s(); stops = [];
    await append(2 * EVERY);
    await expect(boot()).resolves.toMatchObject({ checked: true });   // exactly 2 x every uncovered: allowed
    await append(1);
    await expect(boot()).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(new RegExp(`more than 2 x ${EVERY}`)) });
  });

  test('CR-F a checkpoint just before shutdown is not signed twice; one more entry is', async () => {
    await append(EVERY + 3);
    await w.createSignedCheckpoint(opts());
    const before = side().length;
    expect(await w.signFinalCheckpoint(opts())).toMatchObject({ signed: false, reason: 'ALREADY_COVERED' });
    expect(side()).toHaveLength(before);
    await expect(boot()).resolves.toMatchObject({ checked: true });
    await append(1);
    expect(await w.signFinalCheckpoint(opts())).toMatchObject({ signed: true });
    expect(side()).toHaveLength(before + 1);
    await expect(boot()).resolves.toMatchObject({ checked: true });
  });

  test('CR-G pgSeq is located from the mirrored tail and verified by hash, else null', async () => {
    await append(8);
    const n = auditLog.memorySnapshot().modernCount;
    const head = await auditLog.getModernEntryAt(n - 1);
    const counters = { enqueued: 100, settled: 100 };
    const log = Object.create(auditLog);
    log.mirrorWriterCounters = () => counters;
    log.drainMirrorWriterThrough = async () => { counters.settled = 103; }; // 3 more rows mirrored after the head
    const seqHash = new Map([[500, head.hash]]);                                // head at seq 500, a gap after it
    const backend = { getChainTail: async () => ({ hash: 'f'.repeat(64), seq: 504 }), fetchRowBySeq: async (s) => seqHash.get(s) || 'e'.repeat(64),
      insertSignedCheckpoint: async () => true };
    const pgPool = { isEnabled: () => true, query: async () => ({ rows: [] }) };
    const s = await w.createSignedCheckpoint(opts({ auditLog: log, backend, pgPool, logStore: null, anchoring: { enabled: () => false } }));
    expect(s.payload.pgSeq).toBe(500);
    await append(1);
    const s2 = await w.createSignedCheckpoint(opts({ auditLog: log, pgPool, logStore: null, anchoring: { enabled: () => false },
      backend: { ...backend, fetchRowBySeq: async () => 'e'.repeat(64) } }));             // no row matches the head hash
    expect(s2.payload.pgSeq).toBe(null);
  });
});
