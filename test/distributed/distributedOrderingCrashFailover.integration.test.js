'use strict';

/**
 * phase 8 — distributed ordering path (QODIQA_AUDIT_ORDERING_MODE=distributed, NOT enabled in production —
 * bootValidator refuses it there) under REAL multi-process concurrency, a writer crash while it HOLDS the chain-head
 * row lock, and writer restart / takeover. Disposable PostgreSQL only (pl-env.sh); every writer is a separate OS
 * process (test/helpers/distributedAppendWorker.js) running the real distributedOrdering.appendEntry().
 *
 * Gap this fills (agent-distributed.md §4): ADC-02/03 kill a writer at a RANDOM point of a burst; nothing pinned the
 * worst instant — after the INSERT, before the head UPDATE/COMMIT, with the head row locked and other writers queued
 * behind it — nor the cross-process duplicate artifact / nonce race on the PG uniqueness backstops.
 *
 * DOF-01  3 processes × 25 concurrent appends + 2-process races on the same artifactId (20×) and the same nonce (20×):
 *         exactly one winner per race (`already_executed` / `replay_detected` for the loser), one fork-free chain,
 *         chain order == seq order, head == row count.
 * DOF-02  writer A crashes (SIGKILL) holding the head lock with an uncommitted row; writer B, blocked on the lock
 *         (observed as a Lock wait in pg_stat_activity), proceeds once PostgreSQL ends A's session; A's row never
 *         appears; B chains onto the pre-crash tail.
 * DOF-03  restart / takeover: a replacement for A and a third writer append concurrently after the crash; the WHOLE
 *         chain hydrated from PostgreSQL re-verifies with verifyAuditChainDetailed (the boot verifier).
 *
 * Run: bash npx jest test/distributed/distributedOrderingCrashFailover.integration.test.js --runInBand
 * Runs the migration chain (in a child) — belongs in test:component:serial (see phase8/DISTRIBUTED-LOCAL.md).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startIpcWorker } = require('../helpers/ipcWorker');
const { pgTarget } = require('../helpers/disposableTargets');
const { createMigratedDatabase } = require('../helpers/distributedPg');

const PG = pgTarget();
const describeIf = PG.available ? describe : describe.skip;
if (!PG.available) console.warn(`[distributedOrderingCrashFailover] skipped: ${PG.reason}`); // eslint-disable-line no-console

const WORKER = path.resolve(__dirname, '..', 'helpers', 'distributedAppendWorker.js');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const uid = (p) => `${p}-${crypto.randomBytes(4).toString('hex')}`;

describeIf('phase 8 — distributed ordering: multi-process, crash holding the head lock, takeover', () => {
  let db; let dir; const workers = [];

  async function writer() {
    const w = startIpcWorker(WORKER, { env: db.childEnv({ QODIQA_AUDIT_ORDERING_MODE: 'distributed', QODIQA_AUDIT_LOG: path.join(dir, `audit-${workers.length}.log`) }) });
    workers.push(w);
    await w.waitFor('boot', 30_000);
    return w;
  }
  async function head() {
    const r = await db.admin.query('SELECT tail_hash, tail_seq FROM audit_chain_head');
    return { hash: r.rows[0].tail_hash, seq: Number(r.rows[0].tail_seq) };
  }
  async function chainInvariants() {
    const n = Number((await db.admin.query('SELECT count(*) AS n FROM audit_chain')).rows[0].n);
    const forks = (await db.admin.query('SELECT prev_hash, count(*) FROM audit_chain GROUP BY prev_hash HAVING count(*) > 1')).rows;
    // walk the hash links from the oldest row to the head, collecting seq in CHAIN order
    const rows = (await db.admin.query('SELECT hash, prev_hash, seq FROM audit_chain')).rows;
    const byPrev = new Map(rows.map((r) => [r.prev_hash, r]));
    const hashes = new Set(rows.map((r) => r.hash));
    const roots = rows.filter((r) => !hashes.has(r.prev_hash));
    const seqs = [];
    let walked = 0; let cur = roots.length === 1 ? roots[0].prev_hash : null;
    while (cur !== null && byPrev.has(cur)) { const r = byPrev.get(cur); seqs.push(Number(r.seq)); cur = r.hash; walked++; }
    // seq comes from a sequence: an aborted INSERT (a losing duplicate, a crashed writer) burns a value, so gaps are
    // expected; what must hold is that chain order == seq order (the head lock serialises the inserts).
    const seqOrdered = seqs.every((v, i) => i === 0 || v > seqs[i - 1]);
    return { n, forks, seqOrdered, roots: roots.length, walked, tail: cur, head: await head() };
  }

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-p8-dof-'));
    db = await createMigratedDatabase('dof');
  }, 120_000);

  afterAll(async () => {
    await Promise.all(workers.map((w) => w.exit().catch(() => {})));
    if (db) {
      const r = await db.drop();
      if (!r.dropped) console.warn(`[distributedOrderingCrashFailover] ${db.name} not dropped: ${r.error}`); // eslint-disable-line no-console
    }
  }, 60_000);

  test('DOF-01 three writer processes + cross-process duplicate artifact / nonce races: one winner each, one fork-free chain', async () => {
    const [A, B, C] = await Promise.all([writer(), writer(), writer()]);
    const bursts = await Promise.all([A, B, C].map((w, i) => w.call('appendMany', { prefix: uid(`burst${i}`), count: 25 }, 120_000)));
    for (const b of bursts) expect(b.results.every((r) => r.ok)).toBe(true);

    const artifactRaces = [];
    const nonceRaces = [];
    for (let i = 0; i < 20; i++) {
      const art = uid('same-artifact');
      artifactRaces.push(await Promise.all([A.call('append', { artifactId: art }), B.call('append', { artifactId: art })]));
      const nonce = uid('same-nonce');
      nonceRaces.push(await Promise.all([A.call('append', { artifactId: uid('na'), nonce }), B.call('append', { artifactId: uid('nb'), nonce })]));
    }
    for (const pair of artifactRaces) {
      expect(pair.filter((r) => r.ok)).toHaveLength(1);
      expect(pair.find((r) => !r.ok).error).toMatch(/^already_executed/);
    }
    for (const pair of nonceRaces) {
      expect(pair.filter((r) => r.ok)).toHaveLength(1);
      expect(pair.find((r) => !r.ok).error).toMatch(/^replay_detected/);
    }

    const inv = await chainInvariants();
    expect(inv.n).toBe(75 + 20 + 20);
    expect(inv.forks).toEqual([]);
    expect(inv.roots).toBe(1);
    expect(inv.walked).toBe(inv.n);
    expect(inv.tail).toBe(inv.head.hash);
    expect(inv.head.seq).toBe(inv.n);
    expect(inv.seqOrdered).toBe(true);
  }, 180_000);

  test('DOF-02 a writer SIGKILLed while HOLDING the head lock with an uncommitted row: the queued writer proceeds, the row never lands', async () => {
    const A = await writer();
    const B = await writer();
    const before = await head();
    const crashArtifact = uid('crash');

    const holdId = A.send('appendHolding', { artifactId: crashArtifact });
    await A.waitFor(`${holdId}:holding`, 30_000);

    // B queues behind A's row lock.
    const bArtifact = uid('after-crash');
    const bP = B.call('append', { artifactId: bArtifact }, 60_000);
    let waiting = [];
    for (let i = 0; i < 50 && waiting.length === 0; i++) {
      await sleep(100);
      waiting = (await db.admin.query(
        "SELECT pid FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock' AND query LIKE '%audit_chain_head%FOR UPDATE%'", [db.name])).rows;
    }
    expect(waiting.length).toBe(1);                               // B is blocked on the head lock A holds
    expect((await db.admin.query('SELECT 1 FROM audit_chain WHERE artifact_id = $1', [crashArtifact])).rows).toHaveLength(0); // uncommitted: invisible

    const killedAt = Date.now();
    await A.kill('SIGKILL');
    const b = await bP;
    const takeoverMs = Date.now() - killedAt;

    expect(b.ok).toBe(true);
    expect(b.prevHash).toBe(before.hash);                          // chained onto the pre-crash tail
    expect((await db.admin.query('SELECT 1 FROM audit_chain WHERE artifact_id = $1', [crashArtifact])).rows).toHaveLength(0);
    const after = await head();
    expect(after).toEqual({ hash: b.hash, seq: before.seq + 1 });
    expect(takeoverMs).toBeLessThan(30_000);
    console.log(`[DOF-02] queued writer took over ${takeoverMs} ms after SIGKILL of the lock holder`); // eslint-disable-line no-console
  }, 120_000);

  test('DOF-03 restart / takeover: a replacement writer and a third writer append concurrently; the whole chain re-verifies from PostgreSQL', async () => {
    const [A2, C] = await Promise.all([writer(), writer()]);
    const res = await Promise.all([A2.call('appendMany', { prefix: uid('restarted'), count: 15 }, 120_000), C.call('appendMany', { prefix: uid('third'), count: 15 }, 120_000)]);
    for (const r of res) expect(r.results.every((x) => x.ok)).toBe(true);

    const inv = await chainInvariants();
    expect(inv.forks).toEqual([]);
    expect(inv.roots).toBe(1);
    expect(inv.walked).toBe(inv.n);
    expect(inv.head.seq).toBe(inv.n);
    expect(inv.seqOrdered).toBe(true);

    const v = await A2.call('verify', {}, 60_000);
    expect(v).toMatchObject({ ok: true, valid: true, reason: null, tamperingDetected: false, length: inv.n });
  }, 180_000);
});
