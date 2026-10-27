'use strict';

/**
 * phase 8 — checksum-anchor ORDERING with two writer processes on one PostgreSQL.
 *
 * anchorRace (N03-PG-01..05) proves the forward-only anchor inside ONE process (its own coalescing queue + the
 * migration-062 trigger). Two processes — the split-brain / second-instance shape — have two independent queues, so
 * the ONLY ordering authority between them is the trigger. Each writer here is a forked OS process
 * (test/distributed/workers/checksumAnchorWorker.js) running the real checksumAnchor.saveChecksumPg() as qodiqa_app
 * (no BYPASSRLS, so the trigger applies, exactly as the server runs).
 *
 * CAO-01  deterministic interleaving: a lower count from the OTHER process is refused by the trigger and classified a
 *         FAILURE (not "stale own write" — it is not an anchor this process wrote); a strictly higher count from it is
 *         accepted; an equal count with a different tail hash (a fork) is refused and a failure; the anchor row is
 *         always the highest count written, with that writer's tail hash.
 * CAO-02  concurrent coalesced bursts (odd counts from A, even from B, 1..2000, fire-and-forget behind a shared start
 *         barrier), the anchor row sampled throughout: it never decreases and ends at the global maximum; every
 *         refusal is a forward-only refusal (no other error).
 * CAO-03  the same with each write awaited before the next, so the two writers overtake each other write by write:
 *         additionally, the cross-process regression attempts are refused and surfaced (> 0), never applied.
 *
 * Run: bash npx jest test/distributed/checksumAnchorTwoProcess.integration.test.js --runInBand
 * Runs the migration chain (in a child) — belongs in test:component:serial (see phase8/DISTRIBUTED-LOCAL.md).
 */

const path = require('path');
const crypto = require('crypto');
const { startIpcWorker } = require('../helpers/ipcWorker');
const { pgTarget } = require('../helpers/disposableTargets');
const { createMigratedDatabase } = require('../helpers/distributedPg');

const PG = pgTarget();
const describeIf = PG.available ? describe : describe.skip;
if (!PG.available) console.warn(`[checksumAnchorTwoProcess] skipped: ${PG.reason}`); // eslint-disable-line no-console

const WORKER = path.resolve(__dirname, 'workers', 'checksumAnchorWorker.js');
const hash = (by, n) => crypto.createHash('sha256').update(`${by}:entry-${n}`).digest('hex');
const FORWARD_ONLY = /audit_checksum_anchor is forward-only/;

describeIf('phase 8 — checksum anchor ordering across two writer processes (forward-only trigger)', () => {
  let db; const workers = [];

  async function writer() {
    const w = startIpcWorker(WORKER, { env: db.childEnv() });
    workers.push(w);
    await w.waitFor('boot', 30_000);
    return w;
  }
  const row = async () => {
    const r = (await db.admin.query('SELECT count, tail_hash FROM audit_checksum_anchor WHERE id = TRUE')).rows[0];
    return r ? { count: Number(r.count), tailHash: r.tail_hash } : null;
  };
  const failed = (res) => res.events.filter((e) => e.type === 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED');

  beforeAll(async () => {
    db = await createMigratedDatabase('cao');
    const who = (await db.admin.query("SELECT rolbypassrls FROM pg_roles WHERE rolname = $1", [PG.appUser])).rows[0];
    if (!who || who.rolbypassrls) throw new Error(`${PG.appUser} missing or BYPASSRLS — the forward-only trigger would not apply`);
  }, 120_000);

  afterAll(async () => {
    await Promise.all(workers.map((w) => w.exit().catch(() => {})));
    if (db) {
      const r = await db.drop();
      if (!r.dropped) console.warn(`[checksumAnchorTwoProcess] ${db.name} not dropped: ${r.error}`); // eslint-disable-line no-console
    }
  }, 60_000);

  test('CAO-01 deterministic interleaving: the other process\'s regression and fork are refused and surfaced; higher counts win', async () => {
    const A = await writer();
    const B = await writer();

    let r = await A.call('write', { count: 100, by: 'A' });
    expect(r.status.lastPgWriteOk).toBe(true);
    expect(await row()).toEqual({ count: 100, tailHash: hash('A', 100) });

    r = await B.call('write', { count: 50, by: 'B' });            // B is behind: refused, and NOT excused as stale-own
    expect(r.status.lastPgWriteOk).toBe(false);
    expect(r.status.pgStaleWritesRefused).toBe(0);
    expect(failed(r).map((e) => e.error)).toEqual([expect.stringMatching(FORWARD_ONLY)]);
    expect(await row()).toEqual({ count: 100, tailHash: hash('A', 100) });

    r = await B.call('write', { count: 101, by: 'B' });           // strictly higher: accepted
    expect(r.status.lastPgWriteOk).toBe(true);
    expect(await row()).toEqual({ count: 101, tailHash: hash('B', 101) });

    r = await A.call('write', { count: 101, by: 'A' });           // same count, different tail hash: a fork
    expect(r.status.lastPgWriteOk).toBe(false);
    expect(failed(r)).toHaveLength(1);
    expect(await row()).toEqual({ count: 101, tailHash: hash('B', 101) });

    r = await A.call('write', { count: 100, by: 'A' });           // A's own old count, but the current anchor is B's
    expect(r.status.lastPgWriteOk).toBe(false);
    expect(r.status.pgStaleWritesRefused).toBe(0);
    expect(failed(r)).toHaveLength(1);

    r = await A.call('write', { count: 102, by: 'A' });
    expect(r.status.lastPgWriteOk).toBe(true);
    expect(await row()).toEqual({ count: 102, tailHash: hash('A', 102) });
  }, 60_000);

  // Odd counts from A, even from B, behind a shared start barrier, while the parent samples the anchor row every few
  // ms: the sampled count must never decrease.
  async function race(base, sequential) {
    const A = await writer();
    const B = await writer();
    const odd = Array.from({ length: 1000 }, (_, i) => base + 2 * i + 1);   // A: base+1 … base+1999
    const even = Array.from({ length: 1000 }, (_, i) => base + 2 * i + 2);  // B: base+2 … base+2000
    const startAt = Date.now() + 300;
    let sampling = true; const samples = [];
    const sampler = (async () => { while (sampling) { const r = await row(); if (r) samples.push(r.count); await new Promise((s) => setTimeout(s, 3)); } })();
    const [ra, rb] = await Promise.all([
      A.call('burst', { counts: odd, by: 'A', startAt, sequential, jitterMs: sequential ? 3 : 0 }, 120_000),
      B.call('burst', { counts: even, by: 'B', startAt, sequential, jitterMs: sequential ? 3 : 0 }, 120_000),
    ]);
    sampling = false; await sampler;
    expect(ra.ok && rb.ok).toBe(true);
    expect(await row()).toEqual({ count: base + 2000, tailHash: hash('B', base + 2000) }); // the global maximum
    for (const e of [...failed(ra), ...failed(rb)]) expect(e.error).toMatch(FORWARD_ONLY); // no other kind of error
    const regressions = samples.filter((c, i) => i > 0 && c < samples[i - 1]);
    expect(regressions).toEqual([]);
    expect(ra.status.pgWritesQueued).toBe(0);
    expect(rb.status.pgWritesQueued).toBe(0);
    const line = (n, r) => `${n} highest ${r.status.pgHighestWrittenCount}, coalesced ${r.status.pgWritesCoalesced}, stale-own ${r.status.pgStaleWritesRefused}, failure events ${failed(r).length}${r.accepted !== undefined ? `, writes accepted ${r.accepted}/1000` : ''}`;
    console.log(`[CAO ${sequential ? 'sequential' : 'burst'}] ${line('A', ra)}; ${line('B', rb)}; ${samples.length} samples, 0 regressions`); // eslint-disable-line no-console
    return { ra, rb };
  }

  test('CAO-02 coalesced fire-and-forget bursts from two processes: anchor ends at the global maximum, never regresses', async () => {
    await race(10_000, false);
  }, 180_000);

  test('CAO-03 write-by-write overtaking from two processes: cross-process regressions are refused and surfaced, never applied', async () => {
    const { ra, rb } = await race(20_000, true);
    // Two writers walking interleaved counts (with jitter) overtake each other; each overtaken write is a regression
    // attempt the trigger must refuse and the writer must surface (it is not an anchor that writer wrote — so it is a
    // failure event, never excused as stale-own). Failure events are rate-limited by failureEmit (first N per window),
    // so the exact refused count is 1000 − accepted per writer.
    const refusedA = 1000 - ra.accepted; const refusedB = 1000 - rb.accepted;
    expect(refusedA + refusedB).toBeGreaterThan(0);
    if (refusedA) expect(failed(ra).length).toBeGreaterThan(0);
    if (refusedB) expect(failed(rb).length).toBeGreaterThan(0);
    expect(ra.status.pgStaleWritesRefused + rb.status.pgStaleWritesRefused).toBe(0);
  }, 180_000);
});
