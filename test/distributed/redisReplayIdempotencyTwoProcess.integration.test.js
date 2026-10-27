'use strict';

/**
 * phase 8 — replay protection and idempotency across TWO server processes sharing one Redis.
 *
 * The existing proofs are in-process (phase49 50 parallel requests in ONE process) or restart-barrier
 * oriented (replayDurability). Here two forked OS processes (test/distributed/workers/redisStoreWorker.js) each own
 * a real nonceStore + idempotencyStore client and race on the same keys in one disposable Redis.
 *
 * RRI-01  5 rounds x 200 request ids, each round registered by BOTH processes behind a shared start barrier (pipelined
 *         bursts on even rounds; on odd rounds one awaited round trip per id, the second process walking the ids in
 *         reverse so the two meet head-on): exactly one process wins every id; the union is the whole round.
 * RRI-02  the winner process exits; a NEW process (restart / another replica) still sees every id as a replay —
 *         replay state lives in Redis, not in the process that accepted the request.
 * RRI-03  tenant scoping holds across processes: the same request id under another tenant is a fresh registration.
 * RRI-04  100 idempotency keys reserved concurrently by both processes: exactly one reservation per key; the loser
 *         sees the winner's pending record (same fingerprint); after the winner completes, the other process reads
 *         the completed outcome.
 *
 * Run: bash npx jest test/distributed/redisReplayIdempotencyTwoProcess.integration.test.js --runInBand
 * Skips (never falls back to 127.0.0.1:6379) when no disposable Redis is configured.
 */

const path = require('path');
const crypto = require('crypto');
const { startIpcWorker } = require('../helpers/ipcWorker');
const { redisTarget } = require('../helpers/disposableTargets');

const REDIS = redisTarget();
const describeIf = REDIS.available ? describe : describe.skip;
if (!REDIS.available) console.warn(`[redisReplayIdempotencyTwoProcess] skipped: ${REDIS.reason}`); // eslint-disable-line no-console

const WORKER = path.resolve(__dirname, 'workers', 'redisStoreWorker.js');

describeIf('phase 8 — replay + idempotency across two processes sharing one Redis', () => {
  // Every key this suite writes is prefixed by this tenant (nonce and idempotency keys are `${tenant}:qodiqa:…`).
  const TENANT = `p8-rri-${crypto.randomBytes(5).toString('hex')}`;
  const TENANT2 = `${TENANT}-other`;
  let workers = []; let control;

  async function spawn(n) {
    const ws = Array.from({ length: n }, () => startIpcWorker(WORKER, { env: { REDIS_URL: REDIS.url } }));
    workers.push(...ws);
    await Promise.all(ws.map((w) => w.waitFor('boot', 30_000)));
    // regression: initialised CONCURRENTLY. Before the fix every process probed Redis with one fixed shared
    // key (`qodiqa:req:v2:_startup_probe`) and concurrent nonceStore.initialize() failed ~8-15% of boots
    // the probe key is now
    // per-process, so every concurrent init must succeed.
    const inits = await Promise.all(ws.map((w) => w.call('init', {}, 30_000)));
    for (const i of inits) expect([i.ok, i.error || null]).toEqual([true, null]);
    return ws;
  }

  beforeAll(async () => {
    const { createClient } = require('redis');
    control = createClient({ url: REDIS.url });
    await control.connect();
  });

  afterAll(async () => {
    await Promise.all(workers.map((w) => w.exit().catch(() => {})));
    // Only this suite's own tenant-prefixed keys.
    for (const t of [TENANT, TENANT2]) {
      for await (const batch of control.scanIterator({ MATCH: `${t}:*`, COUNT: 500 })) {
        const keys = Array.isArray(batch) ? batch : [batch];
        if (keys.length) await control.del(keys);
      }
    }
    await control.disconnect();
  });

  const ROUNDS = 5; const PER_ROUND = 200;
  const ids = [];
  let winners;

  test('RRI-01 5 rounds × 200 request ids, each registered concurrently by two processes: exactly one winner per id', async () => {
    const [A, B] = await spawn(2);
    let aWon = 0; let bWon = 0; const split = [];
    for (let r = 0; r < ROUNDS; r++) {
      const round = Array.from({ length: PER_ROUND }, () => crypto.randomUUID());
      ids.push(...round);
      const startAt = Date.now() + 250; // shared start barrier: both bursts hit Redis at the same moment
      // even rounds: each process fires its 200 registrations at once (pipelined burst); odd rounds: one awaited
      // round trip per id, so the two processes contend key by key.
      const sequential = r % 2 === 1;
      const [ra, rb] = await Promise.all([
        A.call('registerMany', { ids: round, tenantId: TENANT, startAt, sequential }, 60_000),
        // on sequential rounds B walks the ids in REVERSE, so the two processes meet head-on mid-round
        B.call('registerMany', { ids: sequential ? [...round].reverse() : round, tenantId: TENANT, startAt, sequential }, 60_000),
      ]);
      expect(ra.ok && rb.ok).toBe(true);
      const sb = new Set(rb.won);
      expect(ra.won.filter((x) => sb.has(x))).toEqual([]);           // never accepted by both
      expect(new Set([...ra.won, ...rb.won])).toEqual(new Set(round)); // never refused by both
      aWon += ra.won.length; bWon += rb.won.length; split.push(`${ra.won.length}/${rb.won.length}`);
    }
    winners = { aWon, bWon };
    console.log(`[RRI-01] per-round wins A/B: ${split.join(' ')}; accepted by both: 0; refused by both: 0`); // eslint-disable-line no-console
  }, 120_000);

  test('RRI-02 after both processes exit, a NEW process still sees every id as a replay', async () => {
    await Promise.all(workers.map((w) => w.exit()));
    workers = [];
    const [C] = await spawn(1);
    const r = await C.call('registerMany', { ids, tenantId: TENANT }, 60_000);
    expect(r.won).toEqual([]);
    expect((await C.call('isRegistered', { requestId: ids[0], tenantId: TENANT })).registered).toBe(true);
    expect(winners.aWon + winners.bWon).toBe(ids.length);
  }, 90_000);

  test('RRI-03 tenant scoping across processes: the same request id under another tenant is a fresh registration', async () => {
    const [D, E] = await spawn(2);
    const some = ids.slice(0, 20);
    const [rd, re] = await Promise.all([
      D.call('registerMany', { ids: some, tenantId: TENANT2 }),
      E.call('registerMany', { ids: some, tenantId: TENANT2 }),
    ]);
    expect(rd.won.length + re.won.length).toBe(20);
    expect(new Set([...rd.won, ...re.won])).toEqual(new Set(some));
  }, 60_000);

  test('RRI-04 idempotency keys reserved concurrently by two processes: one reservation per key; the other process reads the completed outcome', async () => {
    const [A, B] = workers.length >= 2 ? workers.slice(-2) : await spawn(2);
    const keys = Array.from({ length: 100 }, (_, i) => `p8-idem-${i}-${crypto.randomBytes(3).toString('hex')}`);
    const startAt = Date.now() + 250;
    const [ra, rb] = await Promise.all([
      A.call('reserveMany', { keys, tenantId: TENANT, fingerprint: 'fp-A', startAt, sequential: true }, 60_000),
      B.call('reserveMany', { keys: [...keys].reverse(), tenantId: TENANT, fingerprint: 'fp-B', startAt, sequential: true }, 60_000),
    ]);
    rb.results.reverse(); // back into `keys` order
    const aRes = ra.results.filter((x) => x.reserved).length;
    console.log(`[RRI-04] reservations A/B: ${aRes}/${keys.length - aRes}`); // eslint-disable-line no-console
    for (let i = 0; i < keys.length; i++) {
      const a = ra.results[i]; const b = rb.results[i];
      expect([a.reserved, b.reserved].filter(Boolean)).toHaveLength(1);
      const loser = a.reserved ? b : a;
      expect(loser.existing).toMatchObject({ status: 'pending', fingerprint: a.reserved ? 'fp-A' : 'fp-B', tenantId: TENANT });
    }
    // The winner completes; the OTHER process then reads the completed record (what a retried request is answered with).
    const k = keys[0];
    const [winner, other] = ra.results[0].reserved ? [A, B] : [B, A];
    expect(await winner.call('complete', { key: k, tenantId: TENANT, record: { httpStatus: 200, body: { v: 1 } } })).toMatchObject({ completed: true });
    expect((await other.call('get', { key: k, tenantId: TENANT })).record).toMatchObject({ status: 'completed', httpStatus: 200, body: { v: 1 } });
  }, 90_000);
});
