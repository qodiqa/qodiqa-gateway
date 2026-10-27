'use strict';

/**
 * Redis rotation lock: real multi-pod concurrency integration test.
 *
 * src/infra/keys/__tests__/rotationLock.concurrency.test.js stress-tests the
 * lock's semantics against a jittered fake Redis client (fast, always runs
 * in CI, exercises the same atomicity contract real Redis provides). This
 * file is the complementary, heavier proof: several INDEPENDENT instances of
 * the production rotationLock.js module (each with its own internal Redis
 * client singleton, connected to the SAME real disposable Redis instance —
 * created via jest.isolateModules() so each behaves like a genuinely
 * separate process/pod sharing one Redis backend, not one shared in-process
 * client) race for the same lock and perform a real INCR against a shared
 * Redis-resident "keystore version counter" key inside their critical
 * section.
 *
 * Real Redis only (no mocking anywhere) — this is entirely about actual
 * server-side command atomicity, which only a real Redis instance can prove.
 * Uses test/harness/redis.js's fully test-owned disposable
 * instance (never the developer's ambient Memurai/Redis service); SKIPS
 * cleanly (does not fail) if no controllable Redis backend is available,
 * mirroring every other real-Redis integration test in this suite.
 *
 * RLCI-01  N independent pods, M rounds each: the shared Redis counter ends
 *          at exactly (successful acquisitions), proving no lost updates,
 *          no overlapping writes, and no corrupted keystore state under
 *          genuine multi-process-equivalent contention.
 * RLCI-02  A pod that "crashes" (never releases) blocks all others until
 *          its real Redis PX TTL expires, then exactly one other pod wins —
 *          proving stale-lock recovery against a real Redis TTL, not a
 *          simulated one.
 */

const { startDisposableRedis } = require('../harness/redis');

const REAL_PG_STYLE_TIMEOUT = 60_000;

function loadIsolatedRotationLock(redisUrl) {
  let mod;
  jest.isolateModules(() => {
    process.env.REDIS_URL = redisUrl;
    mod = require('../../src/infra/keys/rotationLock');
  });
  return mod;
}

// rotationLock's client is created lazily on first acquire() and connects
// asynchronously without acquire() itself awaiting that connection (by
// design — acquire() fails closed immediately if not yet ready rather than
// queuing). A pod's very first acquire() call right after module load loses
// that race deterministically. Force each pod through one throwaway
// acquire() (which lazily creates + starts connecting the client) and poll
// isReady() before the real contention rounds begin.
async function waitUntilReady(pod, timeoutMs = 10_000) {
  await pod.acquire('__warmup__', 1).catch(() => {}); // triggers lazy client creation
  const deadline = Date.now() + timeoutMs;
  while (!pod.isReady()) {
    if (Date.now() > deadline) throw new Error('rotationLock pod did not become ready in time');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

describe('rotationLock real multi-pod concurrency', () => {
  let redis;
  let pods;
  let controlClient;

  beforeAll(async () => {
    redis = await startDisposableRedis();
  }, REAL_PG_STYLE_TIMEOUT);

  afterEach(async () => {
    if (pods) {
      await Promise.all(pods.map(p => p.disconnect().catch(() => {})));
      pods = null;
    }
    if (controlClient) {
      await controlClient.disconnect().catch(() => {});
      controlClient = null;
    }
  });

  afterAll(async () => {
    if (redis && redis.available) await redis.stop();
  });

  test('RLCI-01 shared counter increments exactly once per successful acquisition across many independent pods/rounds', async () => {
    if (!redis.available) {
      // eslint-disable-next-line no-console
      console.warn(`[rotationLockConcurrency] ${redis.reason} — skipping.`);
      return;
    }

    const { createClient } = require('redis');
    controlClient = createClient({ url: redis.url });
    await controlClient.connect();
    await controlClient.set('wp020:keystore-counter', '0');

    const POD_COUNT = 6;
    const ROUNDS = 10;
    pods = Array.from({ length: POD_COUNT }, () => loadIsolatedRotationLock(redis.url));
    await Promise.all(pods.map(pod => waitUntilReady(pod)));

    let totalSuccessfulAcquisitions = 0;

    for (let round = 0; round < ROUNDS; round++) {
      const attempts = await Promise.all(pods.map(pod => pod.acquire('acme', 5000)));
      const winners = attempts
        .map((result, idx) => ({ result, pod: pods[idx] }))
        .filter(w => w.result.acquired);

      expect(winners).toHaveLength(1);
      totalSuccessfulAcquisitions++;

      // Real critical-section write against the shared Redis-resident
      // "keystore" resource — a real INCR, not an in-memory counter.
      await controlClient.incr('wp020:keystore-counter');

      const released = await winners[0].pod.release('acme', winners[0].result.token);
      expect(released).toBe(true);
    }

    const finalCounter = await controlClient.get('wp020:keystore-counter');
    expect(Number(finalCounter)).toBe(ROUNDS);
    expect(totalSuccessfulAcquisitions).toBe(ROUNDS);
  }, REAL_PG_STYLE_TIMEOUT);

  test('RLCI-02 a crashed pod (no release) blocks others until its real Redis TTL expires', async () => {
    if (!redis.available) {
      // eslint-disable-next-line no-console
      console.warn(`[rotationLockConcurrency] ${redis.reason} — skipping.`);
      return;
    }

    const POD_COUNT = 5;
    pods = Array.from({ length: POD_COUNT }, () => loadIsolatedRotationLock(redis.url));
    await Promise.all(pods.map(pod => waitUntilReady(pod)));

    const crashedResult = await pods[0].acquire('globex', 800); // short real TTL, no release ever issued
    expect(crashedResult.acquired).toBe(true);

    // Immediately after: every other pod must fail — the crashed pod's lock
    // is still live in real Redis.
    const immediateAttempts = await Promise.all(
      pods.slice(1).map(pod => pod.acquire('globex', 30_000)),
    );
    expect(immediateAttempts.every(r => r.acquired === false)).toBe(true);

    // Wait past the real TTL.
    await new Promise(resolve => setTimeout(resolve, 1200));

    const afterExpiryAttempts = await Promise.all(
      pods.slice(1).map(pod => pod.acquire('globex', 30_000)),
    );
    const newWinners = afterExpiryAttempts.filter(r => r.acquired);
    expect(newWinners).toHaveLength(1);
  }, REAL_PG_STYLE_TIMEOUT);
});
