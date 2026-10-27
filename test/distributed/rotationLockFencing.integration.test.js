'use strict';

/**
 * phase 8 — T-23: the key-rotation lock outlived by its holder, with REAL processes and a
 * REAL Redis.
 *
 * Defect (agent-distributed.md): rotationLock.js is a lease (SET NX PX 30 s + compare-and-delete). A
 * rotation that outlives the TTL — a paused process, a slow filesystem or KMS — lets a second rotator in, and the
 * first one still commits when it resumes: two rotations built from the same starting state, i.e. two "N+1"
 * generations or a lost one.
 *
 * Fix (lock side, src/infra/keys/rotationLock.js): acquire() returns a fencing token issued atomically while the lock
 * is owned (strictly increasing in ownership order), assertHeld() re-checks ownership before a commit, renew() is a
 * compare-and-extend heartbeat. The resource half (keystore refuses a non-increasing fence) is modelled by
 * test/helpers/fencedKeystoreCommit.js; the exact keyStore.js change is in
 *
 *
 * Process model: two or three forked OS processes (test/helpers/rotationFenceWorker.js), each with its own Redis
 * client, sharing one Redis and one scratch keystore file. A "pause" is a synchronous Atomics.wait in the child
 * (portable stand-in for SIGSTOP / GC pause: no renewal, no observation while frozen).
 *
 * RLF-01  holder frozen past its TTL: the second rotator gets in (a lease cannot prevent that), commits; the thawed
 *         holder's ownership re-check fails AND its fenced commit is refused → exactly ONE generation.
 * RLF-02  holder frozen AFTER its re-check passed (the gap a re-check cannot cover): only the fence refuses it.
 * RLF-03  slow-but-alive holder with a heartbeat: the lease never lapses, nobody else gets in, rotations serialise.
 * RLF-04  three processes contending over many rounds: every committed fence is strictly greater than the previous
 *         one and every commit is accepted (no false refusal of a live holder).
 *
 * Run: bash npx jest test/distributed/rotationLockFencing.integration.test.js --runInBand
 * Skips (never falls back to 127.0.0.1:6379) when no disposable Redis is configured.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { startIpcWorker } = require('../helpers/ipcWorker');
const { redisTarget } = require('../helpers/disposableTargets');
const { initStore, readStore } = require('../helpers/fencedKeystoreCommit');

const REDIS = redisTarget();
const describeIf = REDIS.available ? describe : describe.skip;
if (!REDIS.available) {
  // eslint-disable-next-line no-console
  console.warn(`[rotationLockFencing] skipped: ${REDIS.reason}`);
}

const WORKER = path.resolve(__dirname, '..', 'helpers', 'rotationFenceWorker.js');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

describeIf('T-23 rotation lock fencing — real processes, real Redis', () => {
  let dir; let workers = []; let control; const clientIds = [];

  function newClientId() { const id = `p8-fence-${crypto.randomBytes(5).toString('hex')}`; clientIds.push(id); return id; }
  async function spawn(n) {
    const ws = Array.from({ length: n }, () => startIpcWorker(WORKER, { env: { REDIS_URL: REDIS.url } }));
    workers.push(...ws);
    await Promise.all(ws.map((w) => w.waitFor('boot')));
    return ws;
  }

  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-p8-fence-'));
    const { createClient } = require('redis');
    control = createClient({ url: REDIS.url });
    await control.connect();
  });

  afterEach(async () => {
    await Promise.all(workers.map((w) => w.exit()));
    workers = [];
  });

  afterAll(async () => {
    // Only this suite's own uniquely named keys.
    const { buildLockKey, buildFenceKey } = require('../../src/infra/keys/rotationLock');
    for (const id of clientIds) await control.del([buildLockKey(id), buildFenceKey(id)]);
    await control.disconnect();
  });

  test('RLF-01 a holder frozen past its TTL cannot commit after a second rotator was let in — exactly one generation', async () => {
    const file = path.join(dir, 'rlf01.json'); initStore(file);
    const clientId = newClientId();
    const [A, B] = await spawn(2);
    const TTL = 800;

    const a = await A.call('acquire', { clientId, ttlMs: TTL });
    expect(a.acquired).toBe(true);
    const freezeId = A.send('freeze', { ms: TTL + 1500 });
    await A.waitFor(freezeId);

    // While A holds a live lease, B is refused.
    expect((await B.call('acquire', { clientId, ttlMs: 30_000 })).acquired).toBe(false);
    await sleep(TTL + 300);

    // The lease lapsed while A was frozen: B gets in (a lease cannot stop this) with a NEWER fence, and commits.
    const b = await B.call('acquire', { clientId, ttlMs: 30_000 });
    expect(b.acquired).toBe(true);
    expect(b.fence).toBeGreaterThan(a.fence);
    expect((await B.call('assertHeld', { clientId, token: b.token })).ok).toBe(true);
    const bCommit = await B.call('commit', { file, clientId, fence: b.fence, by: 'B' });
    expect(bCommit).toMatchObject({ ok: true, version: 1 });

    // A thaws and continues its rotation exactly as the scheduler would.
    await A.waitFor(`${freezeId}:thawed`, 10_000);
    const aHeld = await A.call('assertHeld', { clientId, token: a.token });
    expect(aHeld).toMatchObject({ ok: false, code: 'KEY_ROTATION_LOCK_LOST' });
    const aCommit = await A.call('commit', { file, clientId, fence: a.fence, by: 'A' });
    expect(aCommit).toMatchObject({ ok: false, code: 'KEYSTORE_STALE_FENCE' });
    // A's compare-and-delete must not free B's lock.
    expect((await A.call('release', { clientId, token: a.token })).released).toBe(false);

    const store = readStore(file);
    expect(store.version).toBe(1);
    expect(store.history).toEqual([{ by: 'B', clientId, fence: b.fence, version: 1 }]);
    expect((await B.call('release', { clientId, token: b.token })).released).toBe(true);
  }, 60_000);

  test('RLF-02 a holder frozen AFTER its ownership re-check passed is stopped by the fence alone', async () => {
    const file = path.join(dir, 'rlf02.json'); initStore(file);
    const clientId = newClientId();
    const [A, B] = await spawn(2);
    const TTL = 800;

    const a = await A.call('acquire', { clientId, ttlMs: TTL });
    expect((await A.call('assertHeld', { clientId, token: a.token })).ok).toBe(true); // re-check PASSES
    const freezeId = A.send('freeze', { ms: TTL + 1500 });                              // …then the pause hits
    await A.waitFor(freezeId);
    await sleep(TTL + 300);

    const b = await B.call('acquire', { clientId, ttlMs: 30_000 });
    expect(b.acquired).toBe(true);
    expect(await B.call('commit', { file, clientId, fence: b.fence, by: 'B' })).toMatchObject({ ok: true, version: 1 });

    await A.waitFor(`${freezeId}:thawed`, 10_000);
    // A goes straight to its commit (its re-check already passed): only the resource's fence check refuses it.
    expect(await A.call('commit', { file, clientId, fence: a.fence, by: 'A' }))
      .toMatchObject({ ok: false, code: 'KEYSTORE_STALE_FENCE' });
    expect(readStore(file).history.map((h) => h.by)).toEqual(['B']);
    await B.call('release', { clientId, token: b.token });
  }, 60_000);

  test('RLF-03 a slow-but-alive rotation with a heartbeat keeps the lease: nobody else gets in, rotations serialise', async () => {
    const file = path.join(dir, 'rlf03.json'); initStore(file);
    const clientId = newClientId();
    const [A, B] = await spawn(2);
    const TTL = 600;

    const a = await A.call('acquire', { clientId, ttlMs: TTL });
    expect(a.acquired).toBe(true);
    const slow = A.call('slowRotationWithHeartbeat', { clientId, token: a.token, ttlMs: TTL, everyMs: 150, durationMs: 2_400 }, 30_000);

    // 4× the TTL elapses during A's rotation; B must be refused on every attempt.
    const attempts = [];
    for (let i = 0; i < 10; i++) { await sleep(200); attempts.push((await B.call('acquire', { clientId, ttlMs: 30_000 })).acquired); }
    const hb = await slow;
    expect(attempts.every((x) => x === false)).toBe(true);
    expect(hb.failedRenewals).toBe(0);
    expect(hb.renewals).toBeGreaterThanOrEqual(10);

    expect((await A.call('assertHeld', { clientId, token: a.token, minRemainingMs: 1 })).ok).toBe(true);
    expect(await A.call('commit', { file, clientId, fence: a.fence, by: 'A' })).toMatchObject({ ok: true, version: 1 });
    expect((await A.call('release', { clientId, token: a.token })).released).toBe(true);

    const b = await B.call('acquire', { clientId, ttlMs: 30_000 });
    expect(b.acquired).toBe(true);
    expect(b.fence).toBeGreaterThan(a.fence);
    expect(await B.call('commit', { file, clientId, fence: b.fence, by: 'B' })).toMatchObject({ ok: true, version: 2 });
    await B.call('release', { clientId, token: b.token });
    expect(readStore(file).history.map((h) => h.by)).toEqual(['A', 'B']);
  }, 60_000);

  test('RLF-04 three contending processes over 15 rounds: one winner per round, fences strictly increase, no live holder refused', async () => {
    const file = path.join(dir, 'rlf04.json'); initStore(file);
    const clientId = newClientId();
    const ws = await spawn(3);
    const ROUNDS = 15;
    for (let r = 0; r < ROUNDS; r++) {
      const results = await Promise.all(ws.map((w) => w.call('acquire', { clientId, ttlMs: 10_000 })));
      const winners = results.map((res, i) => ({ res, w: ws[i] })).filter((x) => x.res.acquired);
      expect(winners).toHaveLength(1);
      const { res, w } = winners[0];
      expect((await w.call('assertHeld', { clientId, token: res.token })).ok).toBe(true);
      expect(await w.call('commit', { file, clientId, fence: res.fence, by: `w${ws.indexOf(w)}` })).toMatchObject({ ok: true, version: r + 1 });
      expect((await w.call('release', { clientId, token: res.token })).released).toBe(true);
    }
    const fences = readStore(file).history.map((h) => h.fence);
    expect(fences).toHaveLength(ROUNDS);
    for (let i = 1; i < fences.length; i++) expect(fences[i]).toBeGreaterThan(fences[i - 1]);
  }, 60_000);
});
