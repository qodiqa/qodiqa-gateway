'use strict';

/**
 * phase 8 — duplicate persistence-recovery workers in SEPARATE OS processes.
 *
 * The existing DUR-14 / DUR-16 (test/persistence-recovery-durability.test.js) run two claim loops inside ONE Node
 * process on two pools. This suite runs the REAL src/core/persistenceRecovery/queue.js in two forked processes
 * (test/helpers/recoveryQueueWorker.js), each with its own pg pool, as the app role, against one disposable migrated
 * database — the deployment shape where two server instances both run the recovery worker.
 *
 * RQ2-01  300 operations, two processes claim/complete concurrently: every operation processed EXACTLY once across
 *         both (disjoint sets, union = all), both processes did real work, queue empty afterwards.
 * RQ2-02  a worker SIGKILLed after claiming (mid-handler): its claim is a lease, not a loss — the other process
 *         cannot double-claim it while the lease runs, and claims it exactly once after the lease elapses (the lease
 *         expiry is simulated by moving eligible_at back as the superuser; waiting the real 30 s adds nothing).
 *
 * Run: bash npx jest test/distributed/recoveryQueueTwoProcess.integration.test.js --runInBand
 * Runs the migration chain (in a child) — belongs in test:component:serial (see phase8/DISTRIBUTED-LOCAL.md).
 */

const path = require('path');
const crypto = require('crypto');
const { startIpcWorker } = require('../helpers/ipcWorker');
const { pgTarget } = require('../helpers/disposableTargets');
const { createMigratedDatabase } = require('../helpers/distributedPg');

const PG = pgTarget();
const describeIf = PG.available ? describe : describe.skip;
if (!PG.available) console.warn(`[recoveryQueueTwoProcess] skipped: ${PG.reason}`); // eslint-disable-line no-console

const WORKER = path.resolve(__dirname, '..', 'helpers', 'recoveryQueueWorker.js');
const uid = (p) => `${p}-${crypto.randomBytes(5).toString('hex')}`;

describeIf('phase 8 — persistence recovery queue: two worker PROCESSES (FOR UPDATE SKIP LOCKED)', () => {
  let db; const workers = [];

  async function worker() {
    const w = startIpcWorker(WORKER, { env: db.childEnv() });
    workers.push(w);
    await w.waitFor('boot', 30_000);
    return w;
  }
  const queueRows = async (ids) => (await db.admin.query(
    'SELECT operation_id, status FROM persistence_recovery_queue WHERE operation_id = ANY($1::text[])', [ids])).rows;

  beforeAll(async () => { db = await createMigratedDatabase('rq2'); }, 120_000);

  afterAll(async () => {
    await Promise.all(workers.map((w) => w.exit().catch(() => {})));
    if (db) {
      const r = await db.drop();
      if (!r.dropped) console.warn(`[recoveryQueueTwoProcess] ${db.name} not dropped: ${r.error}`); // eslint-disable-line no-console
    }
  }, 60_000);

  test('RQ2-01 two processes drain 300 operations: each processed exactly once, both did work, queue empty', async () => {
    const [A, B] = await Promise.all([worker(), worker()]);
    const ids = Array.from({ length: 300 }, (_, i) => uid(`rq2-01-${i}`));
    expect(await A.call('enqueueMany', { ids }, 60_000)).toMatchObject({ ok: true, n: 300 });
    expect(await queueRows(ids)).toHaveLength(300);

    const [ra, rb] = await Promise.all([
      A.call('claimLoop', { handlerMs: 3, idleRounds: 5 }, 120_000),
      B.call('claimLoop', { handlerMs: 3, idleRounds: 5 }, 120_000),
    ]);
    expect(ra.ok && rb.ok).toBe(true);
    expect(ra.pid).not.toBe(rb.pid);
    const setA = new Set(ra.claimed); const setB = new Set(rb.claimed);
    expect(setA.size).toBe(ra.claimed.length);                 // no process claimed an item twice
    expect(setB.size).toBe(rb.claimed.length);
    expect(ra.claimed.filter((id) => setB.has(id))).toEqual([]); // no item claimed by both processes
    expect(new Set([...ra.claimed, ...rb.claimed])).toEqual(new Set(ids));
    expect(ra.claimed.length).toBeGreaterThan(0);              // genuinely concurrent: both processes did work
    expect(rb.claimed.length).toBeGreaterThan(0);
    expect(await queueRows(ids)).toEqual([]);
    console.log(`[RQ2-01] process A ${ra.claimed.length} / process B ${rb.claimed.length} of 300, overlap 0`); // eslint-disable-line no-console
  }, 180_000);

  test('RQ2-02 a worker killed after claiming: no double claim while its lease runs, exactly one re-claim after it elapses', async () => {
    const A = await worker();
    const B = await worker();
    const id = uid('rq2-02');
    await A.call('enqueueMany', { ids: [id] });

    const claimed = await A.call('claimOne');
    expect(claimed.operationId).toBe(id);
    await A.kill('SIGKILL');                                    // crash mid-handler: never completed, never released

    expect((await B.call('claimOne')).operationId).toBeNull();  // lease still running: B must not double-process
    expect(await queueRows([id])).toEqual([{ operation_id: id, status: 'PENDING' }]); // the crash lost nothing

    await db.admin.query("UPDATE persistence_recovery_queue SET eligible_at = now() - interval '1 second' WHERE operation_id = $1", [id]);
    const [c1, c2] = await Promise.all([B.call('claimOne'), B.call('claimOne')]);
    expect([c1.operationId, c2.operationId].filter((x) => x === id)).toHaveLength(1);
  }, 120_000);
});
