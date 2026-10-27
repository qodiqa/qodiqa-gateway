'use strict';

/**
 * step 6 (M1/M2) — checkpoint writer + fail-closed boot verification, on the real audit-log (file mode; the
 * PostgreSQL / transparency parts are proven by test/integration/signedCheckpoints.integration.test.js).
 *
 *   CW-01  a checkpoint signs the current position (lifetime count + head hash), is appended to the sidecar, verifies
 *   CW-02  no growth → the latest checkpoint is returned, nothing new is signed; growth → a new one chained to it
 *   CW-03  boot: no checkpoint yet → nothing to check; a genuine latest checkpoint → verified
 *   CW-04  boot FAILS CLOSED: forged signature; payload re-hashed consistently but not re-signed; a checkpoint whose
 *          headHash is not the chain's entry at chainLength; a checkpoint beyond the chain
 *   CW-05  a torn last sidecar line (crash mid-append) is ignored; a corrupt earlier line is refused
 * CW-08 a failed transparency registration of a checkpoint increments outcome transparency_anchor_failed
 * CW-07 concurrent calls behind a stalled mirror drain sign ONE checkpoint for the position, not one each;
 *          the scheduler skips a tick while a run is in flight
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
const fs = require('fs');
const crypto = require('crypto');

describe('checkpoint writer', () => {
  let auditLog; let w; let cp; let events;
  const opts = () => ({ registrar: null, emit: (l, t, d) => events.push({ l, t, d }) });
  const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
    requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
  const append = async (n) => { for (let i = 0; i < n; i++) await auditLog.append(fields()); };
  const side = () => w.readSidecar(auditLog.LOG_PATH);

  beforeEach(() => {
    jest.resetModules();
    events = [];
    auditLog = require('../../audit-log');
    w = require('../checkpointWriter');
    cp = require('../checkpoint');
    try { fs.unlinkSync(w.sidecarPath(auditLog.LOG_PATH)); } catch { /* none yet */ }   // per-file isolated scratch log (jest.setup)
  });

  // ER 2026-10-06: anchor publication is awaited and every outcome is counted in
  // qodiqa_audit_anchor_events_total{outcome}, which the shipped QodiqaAnchorWitness* / QodiqaAnchorExportFailed alerts use.
  test('CW-06 anchor outcomes: an async refusal is reported as AUDIT_ANCHOR_WITNESS_REFUSED and counted; a publish failure counts export_failed', async () => {
    const metrics = require('../../../../observability/metrics');
    const inc = jest.spyOn(metrics.auditAnchorEventsTotal, 'inc');
    await append(3);
    const refusing = { enabled: () => true, publish: async () => ({ record: { cosignatures: [] }, errors: [{ witnessId: 'w1', code: 'WITNESS_ROLLBACK_REFUSED', message: 'refused' }] }) };
    await w.createSignedCheckpoint({ ...opts(), anchoring: refusing });
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_WITNESS_REFUSED' && e.d.code === 'WITNESS_ROLLBACK_REFUSED')).toBe(true);
    expect(inc.mock.calls.map((c) => c[0].outcome)).toEqual(['anchored', 'witness_refused']);
    inc.mockClear(); await append(2);
    const broken = { enabled: () => true, publish: async () => { throw new Error('disk full'); } };
    await w.createSignedCheckpoint({ ...opts(), anchoring: broken });
    expect(events.some((e) => e.t === 'AUDIT_ANCHOR_EXPORT_FAILED')).toBe(true);
    expect(inc.mock.calls.map((c) => c[0].outcome)).toEqual(['export_failed']);
    inc.mockRestore();
  });

  test('CW-01 signs the current position into the sidecar', async () => {
    await append(5);
    const snap = auditLog.memorySnapshot();
    const s = await w.createSignedCheckpoint({ ...opts(), trigger: 'test' });
    expect(s.payload).toMatchObject({ chainLength: snap.modernCount, headHash: (await auditLog.getModernEntryAt(snap.modernCount - 1)).hash, pgSeq: null });
    expect(cp.verifyCheckpoint(s)).toEqual({ ok: true });
    expect(side().map((x) => x.payloadHash)).toContain(s.payloadHash);
    expect(events.find((e) => e.t === 'AUDIT_CHECKPOINT_SIGNED').d).toMatchObject({ chainLength: snap.modernCount, trigger: 'test', persistedToPg: false });
  });

  test('CW-02 no growth → same checkpoint; growth → a new one chained to the previous', async () => {
    await append(3);
    const a = await w.createSignedCheckpoint(opts());
    const again = await w.createSignedCheckpoint(opts());
    expect(again.payloadHash).toBe(a.payloadHash);
    await append(2);
    const b = await w.createSignedCheckpoint(opts());
    expect(b.payload.chainLength).toBe(a.payload.chainLength + 2);
    expect(b.payload.previousCheckpointHash).toBe(a.payloadHash);
    expect(side().slice(-2).map((x) => x.payloadHash)).toEqual([a.payloadHash, b.payloadHash]);
  });

  test('CW-03 boot: nothing to check, then a genuine checkpoint verifies', async () => {
    await append(2);
    expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: false, reason: 'NO_SIGNED_CHECKPOINT_YET' });
    const s = await w.createSignedCheckpoint(opts());
    expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: true, checkpointId: s.payload.checkpointId, chainLength: s.payload.chainLength });
  });

  test('CW-04 boot fails closed on a forged or mismatched checkpoint', async () => {
    await append(4);
    const s = await w.createSignedCheckpoint(opts());
    const p = w.sidecarPath(auditLog.LOG_PATH);
    const write = (obj) => fs.appendFileSync(p, JSON.stringify(obj) + '\n');
    const expectFail = async (re) => { await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(re) }); };

    // (a) forged signature on a later position
    await append(1);
    const later = { ...s, payload: { ...s.payload, chainLength: s.payload.chainLength + 1, headHash: (await auditLog.getModernEntryAt(s.payload.chainLength)).hash } };
    write({ ...later, payloadHash: cp.checkpointDigest(later.payload).toString('hex'), signature: s.signature });
    await expectFail(/CHECKPOINT_SIGNATURE_INVALID/);
    // (b) genuinely signed, but its headHash is not the chain's entry at that position
    fs.writeFileSync(p, '');
    const wrong = cp.signCheckpoint({ chainLength: 2, headHash: 'e'.repeat(64) });
    write(wrong);
    await expectFail(/entry 2 is .* the signed checkpoint says e{64}/);
    // (c) genuinely signed, beyond the chain
    fs.writeFileSync(p, '');
    write(cp.signCheckpoint({ chainLength: 10_000, headHash: 'f'.repeat(64) }));
    await expectFail(/vouches for 10000/);
  });

  test('CW-05 torn last line ignored; corrupt earlier line refused', async () => {
    await append(2);
    const s = await w.createSignedCheckpoint(opts());
    const p = w.sidecarPath(auditLog.LOG_PATH);
    fs.appendFileSync(p, '{"payload":{"v":1,"chainLe');        // crash mid-append
    expect(w.readSidecar(auditLog.LOG_PATH).map((x) => x.payloadHash)).toEqual([s.payloadHash]);
    fs.writeFileSync(p, 'not json\n' + JSON.stringify(s) + '\n');
    expect(() => w.readSidecar(auditLog.LOG_PATH)).toThrow(/AUDIT_CHECKPOINT_SIDECAR_CORRUPT: line 1/);
  });

  // deleted checkpoints / a failing PG lookup no longer pass the boot gate.
  describe('boot gate fails closed', () => {
    const saved = { every: process.env.QODIQA_AUDIT_CHECKPOINT_EVERY, boot: process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP };
    afterEach(() => {
      for (const [k, v] of [['QODIQA_AUDIT_CHECKPOINT_EVERY', saved.every], ['QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP', saved.boot]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    });

    test('a chain beyond 2 x the interval with its checkpoints deleted → AUDIT_CHECKPOINT_BOOT_FAILED', async () => {
      process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
      await append(3); await w.createSignedCheckpoint(opts()); await append(3);
      fs.unlinkSync(w.sidecarPath(auditLog.LOG_PATH)); // the attacker deletes the checkpoints
      await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/no signed checkpoint exists/) });
    });

    test('the one-boot bootstrap acknowledgement lets a pre-checkpoint chain start, and is reported', async () => {
      process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
      await append(6);
      process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
      expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: false, reason: 'NO_SIGNED_CHECKPOINT_YET' });
      expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_BOOTSTRAP' && e.l === 'WARN')).toBe(true);
    });

    // deleting only the NEWEST checkpoints left an older valid one, and the uncovered tail could be
    // rewritten unseen.
    test('newest checkpoints deleted, an old one kept, > 2 x interval uncovered → AUDIT_CHECKPOINT_BOOT_FAILED', async () => {
      process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
      await append(2); const first = await w.createSignedCheckpoint(opts());
      await append(2); await w.createSignedCheckpoint(opts());
      await append(2); await w.createSignedCheckpoint(opts());
      await append(1);
      fs.writeFileSync(w.sidecarPath(auditLog.LOG_PATH), JSON.stringify(first) + '\n'); // keep only the oldest
      await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/not covered by any checkpoint/) });
      process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
      expect(await w.verifyLatestCheckpointAtBoot(opts())).toMatchObject({ checked: true, chainLength: first.payload.chainLength });
      expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_BOOTSTRAP' && e.d.checkpointedLength === first.payload.chainLength)).toBe(true);
    });

    // Correction pass 2026-10-05 (C13): in production the bootstrap switch alone no longer bypasses the boot gate.
    describe('C13 production bootstrap is bound to the live chain head', () => {
      const savedEnv = { node: process.env.NODE_ENV, ack: process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK };
      afterEach(() => {
        for (const [k, v] of [['NODE_ENV', savedEnv.node], ['QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK', savedEnv.ack]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      });
      const liveAck = async () => {
        const n = auditLog.memorySnapshot().modernCount;
        return `${n}:${String((await auditLog.getModernEntryAt(n - 1)).hash).slice(0, 16)}`;
      };
      const deleteAllCheckpoints = async () => {
        process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
        await append(3); await w.createSignedCheckpoint(opts()); await append(3);
        fs.unlinkSync(w.sidecarPath(auditLog.LOG_PATH)); // the attacker deletes the checkpoints
      };

      test('C13-01 the previous bypass is gone: bare QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP=true in production is refused', async () => {
        await deleteAllCheckpoints();
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.NODE_ENV = 'production';
        await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED' });
        expect(events.some((e) => /AUDIT_CHECKPOINT_BOOTSTRAP/.test(e.t) && e.l !== 'ERROR')).toBe(false);
      });

      test('C13-02 a wrong acknowledgement is refused', async () => {
        await deleteAllCheckpoints();
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK = '6:0123456789abcdef';
        process.env.NODE_ENV = 'production';
        await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED' });
      });

      test('C13-03 the acknowledgement bound to the inspected chain head is accepted once, reported at ERROR', async () => {
        await deleteAllCheckpoints();
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK = await liveAck();
        process.env.NODE_ENV = 'production';
        expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: false, reason: 'NO_SIGNED_CHECKPOINT_YET' });
        expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_BOOTSTRAP_ACCEPTED' && e.l === 'ERROR')).toBe(true);
      });

      test('C13-04 a left-over acknowledgement stops matching once the chain grows (cannot stay on)', async () => {
        await deleteAllCheckpoints();
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK = await liveAck();
        await append(1); // one more request after the acknowledged state
        process.env.NODE_ENV = 'production';
        await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED' });
      });

      test('C13-05 newest checkpoints deleted (old one kept): bare bootstrap refused in production, bound one accepted', async () => {
        process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
        await append(2); const first = await w.createSignedCheckpoint(opts());
        await append(2); await w.createSignedCheckpoint(opts());
        await append(2); await w.createSignedCheckpoint(opts());
        await append(1);
        fs.writeFileSync(w.sidecarPath(auditLog.LOG_PATH), JSON.stringify(first) + '\n');
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.NODE_ENV = 'production';
        await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOTSTRAP_REFUSED' });
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP_ACK = await liveAck();
        expect(await w.verifyLatestCheckpointAtBoot(opts())).toMatchObject({ checked: true, chainLength: first.payload.chainLength });
      });

      test('C13-06 an intact chain never consults the bootstrap: a bare `true` left set does not fail a healthy production boot', async () => {
        process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
        await append(2); const s = await w.createSignedCheckpoint(opts()); await append(1);
        process.env.QODIQA_AUDIT_CHECKPOINT_BOOTSTRAP = 'true';
        process.env.NODE_ENV = 'production';
        expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: true, checkpointId: s.payload.checkpointId, chainLength: s.payload.chainLength });
      });
    });

    test('a tail within 2 x the interval of the latest checkpoint still boots', async () => {
      process.env.QODIQA_AUDIT_CHECKPOINT_EVERY = '2';
      await append(2); const s = await w.createSignedCheckpoint(opts()); await append(4); // exactly 2 x every uncovered
      expect(await w.verifyLatestCheckpointAtBoot(opts())).toEqual({ checked: true, checkpointId: s.payload.checkpointId, chainLength: s.payload.chainLength });
    });

    // the whole checkpoint chain is verified, not just its latest member.
    test('a MIDDLE checkpoint removed (newest kept) → the checkpoint chain is broken → AUDIT_CHECKPOINT_BOOT_FAILED', async () => {
      await append(2); const c1 = await w.createSignedCheckpoint(opts());
      await append(2); await w.createSignedCheckpoint(opts());
      await append(2); const c3 = await w.createSignedCheckpoint(opts());
      fs.writeFileSync(w.sidecarPath(auditLog.LOG_PATH), JSON.stringify(c1) + '\n' + JSON.stringify(c3) + '\n');
      await expect(w.verifyLatestCheckpointAtBoot(opts())).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/checkpoint chain is broken/) });
    });

    test('the newest checkpoint deleted from the sidecar while PostgreSQL still holds it → refused', async () => {
      await append(2); const c1 = await w.createSignedCheckpoint(opts());
      await append(2); const c2 = await w.createSignedCheckpoint(opts());
      fs.writeFileSync(w.sidecarPath(auditLog.LOG_PATH), JSON.stringify(c1) + '\n'); // newest gone from the sidecar
      const o = { ...opts(), pgPool: { isEnabled: () => true },
        backend: { getLatestSignedCheckpoint: async () => c2, listSignedCheckpoints: async () => [c1, c2] } };
      await expect(w.verifyLatestCheckpointAtBoot(o)).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/missing from the checkpoint sidecar/) });
      // legitimate: both stores agree → boots
      fs.writeFileSync(w.sidecarPath(auditLog.LOG_PATH), JSON.stringify(c1) + '\n' + JSON.stringify(c2) + '\n');
      await expect(w.verifyLatestCheckpointAtBoot(o)).resolves.toMatchObject({ checked: true, chainLength: c2.payload.chainLength });
    });

    test('a checkpoint REPLACED in one store (same id, different payload) → refused', async () => {
      await append(2); const c1 = await w.createSignedCheckpoint(opts());
      const forged = cp.signCheckpoint({ checkpointId: c1.payload.checkpointId, chainLength: c1.payload.chainLength, headHash: 'e'.repeat(64) });
      const o = { ...opts(), pgPool: { isEnabled: () => true },
        backend: { getLatestSignedCheckpoint: async () => c1, listSignedCheckpoints: async () => [forged] } };
      await expect(w.verifyLatestCheckpointAtBoot(o)).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/two different payloads/) });
    });

    // Freshness is measured on the uncovered ENTRIES' own timestamps: a span longer than 2 x max-age without a
    // checkpoint is refused; plain downtime (an old checkpoint, a few fresh entries) is NOT.
    test('uncovered entries spanning > 2 x max-age → refused; downtime alone, or a short span, boots', async () => {
      const savedAge = process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS;
      const dir = fs.mkdtempSync(require('path').join(require('os').tmpdir(), 'cw-fresh-'));
      const logPath = require('path').join(dir, 'audit.log');
      const H = (i) => String(i).padStart(64, '0');
      const chain = (stamps) => ({ memorySnapshot: () => ({ modernCount: stamps.length }), getChainStart: () => null,
        getModernEntryAt: async (i) => (i < stamps.length ? { hash: H(i), timestamp: new Date(stamps[i]).toISOString() } : null) });
      const now = Date.now(); const HOUR = 3_600_000;
      try {
        process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS = '60000'; // 2 x = 2 min
        const ck = cp.signCheckpoint({ chainLength: 2, headHash: H(1), createdAt: new Date(now - 72 * HOUR).toISOString() });
        fs.writeFileSync(w.sidecarPath(logPath), JSON.stringify(ck) + '\n');
        const o = (stamps) => ({ ...opts(), logPath, auditLog: chain(stamps), pgPool: { isEnabled: () => false } });
        // uncovered entries 3..5 span 1 hour without a checkpoint → refused
        await expect(w.verifyLatestCheckpointAtBoot(o([now - 73 * HOUR, now - 72 * HOUR, now - HOUR, now - HOUR / 2, now])))
          .rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED', message: expect.stringMatching(/without a checkpoint/) });
        // a 72 h old checkpoint, then (after downtime) three entries within one minute → boots
        await expect(w.verifyLatestCheckpointAtBoot(o([now - 73 * HOUR, now - 72 * HOUR, now - 60_000, now - 30_000, now])))
          .resolves.toMatchObject({ checked: true, chainLength: 2 });
      } finally {
        if (savedAge === undefined) delete process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS; else process.env.QODIQA_AUDIT_CHECKPOINT_MAX_AGE_MS = savedAge;
      }
    });

    test('a PostgreSQL checkpoint lookup error at boot is a failure, not "none yet"', async () => {
      await append(2);
      const o = { ...opts(), pgPool: { isEnabled: () => true }, backend: { getLatestSignedCheckpoint: async () => { throw new Error('connection refused'); } } };
      await expect(w.verifyLatestCheckpointAtBoot(o)).rejects.toMatchObject({ code: 'AUDIT_CHECKPOINT_BOOT_FAILED' });
      expect(await w.latestSignedCheckpoint(o)).toBe(null); // the scheduler's non-strict lookup keeps its behaviour
    });
  });

  test('CW-07 single-flight: overlapping runs behind a stalled mirror drain sign one checkpoint, ticks are skipped', async () => {
    await append(4);
    let release; const stalled = new Promise((r) => { release = r; });
    const slowLog = Object.create(auditLog);
    slowLog.drainMirrorWriter = () => stalled;          // the PostgreSQL mirror is slow but up
    slowLog.drainMirrorWriterThrough = () => stalled;   // GA-CKPT-RATE: the writer now awaits the bounded drain
    const o = { ...opts(), auditLog: slowLog, mirrorWaitMs: 60_000, busyWarnMs: 10 };
    const before = side().length;
    const runs = [1, 2, 3, 4, 5].map(() => w.createSignedCheckpoint({ ...o, trigger: 'test' }));
    await new Promise((r) => setImmediate(r));
    expect(w.checkpointInFlight()).toBe(5);

    // the scheduler does not stack a tick behind the stalled run
    const runner = { runTask: jest.fn(async (_n, fn) => fn()) };
    const stop = w.startCheckpointScheduler({ ...o, taskRunner: runner, tickMs: 5 });
    await new Promise((r) => setTimeout(r, 40));
    stop();
    expect(runner.runTask).not.toHaveBeenCalled();
    // GA-CKPT-RATE: with a 1 s tick a run in flight is normal — reported once per stuck run (after busyWarnMs), not per tick
    expect(events.filter((e) => e.t === 'AUDIT_CHECKPOINT_TICK_SKIPPED')).toHaveLength(1);

    release();
    const out = await Promise.all(runs);
    const added = side().slice(before);
    expect(added).toHaveLength(1);                       // before 5 checkpoints for the same entry
    expect(new Set(out.map((x) => x.payloadHash))).toEqual(new Set([added[0].payloadHash]));
    expect(w.checkpointInFlight()).toBe(0);
  });

  test('CW-08 a failed transparency registration of a checkpoint is counted (transparency_anchor_failed)', async () => {
    const metrics = require('../../../../observability/metrics');
    const inc = jest.spyOn(metrics.auditAnchorEventsTotal, 'inc');
    await append(2);
    const pgPool = { isEnabled: () => true, query: async () => ({ rows: [] }) };
    const backend = { getChainTail: async () => null, insertSignedCheckpoint: async () => true };
    const registrar = { register: async () => { throw new Error('transparency log unavailable'); } };
    const s = await w.createSignedCheckpoint({ ...opts(), pgPool, backend, registrar, logStore: null, anchoring: { enabled: () => false } });
    expect(s).toBeTruthy();                                   // the checkpoint itself is still signed and kept
    expect(inc.mock.calls.map((c) => c[0].outcome)).toEqual(['transparency_anchor_failed']);
    expect(events.some((e) => e.t === 'AUDIT_CHECKPOINT_ANCHOR_FAILED')).toBe(true);
    inc.mockRestore();
  });
});
