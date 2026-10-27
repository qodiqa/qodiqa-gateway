'use strict';

/**
 * Real Redis outage-recovery integration test.
 *
 * This is the test that did not exist before every prior session that
 * touched this defect (S4's live discovery, this session's own live
 * witness) demonstrated the failure mode by hand against a real Memurai
 * process, but nothing in the automated suite proved recovery. This file
 * closes that gap the same way redisSentinelFailover.integration.test.js
 * proves a REAL, disposable Redis-compatible instance (Memurai on
 * Windows, redis-server on Linux/CI, or Docker), no protocol mocking.
 *
 * Sequence, against one representative store (nonceStore — the module S4's
 * own live witness and's finding both centered on; the shared strategy
 * itself is unit-tested exhaustively in
 * src/infra/redis/__tests__/reconnectStrategy.test.js, and the other three
 * stores' wiring is covered by their own existing suites plus the
 * sanity-load check every store file passed before this fix was committed):
 *
 *   1. Start a disposable Redis, point nonceStore at it, connect, confirm ready.
 *   2. Kill the Redis process outright (the exact failure mode S4 witnessed).
 * 3. Wait past the OLD MAX_RECONNECTS budget (~3.1s) — the store
 *      would have permanently given up here (reconnectStrategy returns
 *      false, node-redis closes the client for good). Assert it has NOT:
 *      still not ready, but a fresh operation attempt still throws a
 *      *fail-closed* error (not "client is closed" / socket destroyed).
 *   4. Assert the WARN signal fired at least once with pastOldThreshold:true
 *      — the "loud past the old cap" requirement, exercised for real.
 *   5. Restart Redis on the SAME port (nothing about the Node process
 *      restarts — same require() cache, same client instance throughout).
 *   6. Assert the store becomes ready again and a real register() call
 *      succeeds — genuine functional recovery, not just a socket flag.
 */

const crypto = require('crypto');
const { startDisposableRedis } = require('../harness/redis');
const { waitForCondition } = require('../harness/process');

jest.setTimeout(60_000);

const mockEmit = jest.fn();
jest.mock('../../services/logger', () => ({
  ...jest.requireActual('../../services/logger'),
  emit: (...args) => {
    mockEmit(...args);
    return jest.requireActual('../../services/logger').emit(...args);
  },
}));

describe('Redis outage recovery (real disposable Redis, no process restart)', () => {
  let disposable;
  let nonceStore;

  afterEach(async () => {
    if (nonceStore) {
      try { await nonceStore.disconnect(); } catch { /* already down */ }
    }
    if (disposable?.stop) {
      try { await disposable.stop(); } catch { /* already stopped */ }
    }
    delete process.env.REDIS_URL;
    jest.resetModules();
    mockEmit.mockClear();
  });

  test('nonceStore recovers from a Redis outage without a server restart, past the old reconnect budget', async () => {
    disposable = await startDisposableRedis();
    if (!disposable.available) {
      console.warn(`SKIPPED: no controllable Redis backend available (${disposable.reason})`);
      return;
    }

    process.env.REDIS_URL = disposable.url;
    nonceStore = require('../../src/validation/nonceStore');

    // ── 1. Connect, confirm ready ────────────────────────────────────────
    await nonceStore.initialize();
    expect(nonceStore.isReady()).toBe(true);

    const firstId = crypto.randomUUID();
    const firstResult = await nonceStore.register(firstId, Date.now() + 60_000, null);
    expect(firstResult).toEqual({ registered: true });

    // ── 2. Kill Redis outright ───────────────────────────────────────────
    const port = disposable.port;
    await disposable.stop();
    disposable = null; // already stopped — afterEach shouldn't stop it again

    // isReady() flips to false once the client detects the drop (not
    // necessarily instantaneous) — poll briefly rather than asserting the
    // exact tick.
    await waitForCondition(() => !nonceStore.isReady(), { timeoutMs: 5_000, intervalMs: 100 });
    expect(nonceStore.isReady()).toBe(false);

    // ── 3. Wait past the OLD MAX_RECONNECTS budget (~3.1s) ──────────────
    // Pre-F5, every one of the four stores would have permanently given up
    // by now (reconnectStrategy returns false at retries>=5, node-redis
    // emits 'end' and stops trying forever). Assert the store is still
    // alive and fail-closed, not permanently dead: a fresh registration
    // attempt still throws the store's own fail-closed error, never a raw
    // "client is closed"/socket-destroyed error that would indicate the
    // client gave up.
    await new Promise((resolve) => setTimeout(resolve, 4_500));
    expect(nonceStore.isReady()).toBe(false);
    await expect(
      nonceStore.register(crypto.randomUUID(), Date.now() + 60_000, null),
    ).rejects.toThrow(/NONCE_STORE|fail.?closed/i);

    // ── 4. The "loud past the old cap" signal fired for real ────────────
    const pastThresholdWarnings = mockEmit.mock.calls.filter(
      ([level, event, payload]) => level === 'WARN' && event === 'REDIS_RECONNECTING' && payload?.pastOldThreshold === true,
    );
    expect(pastThresholdWarnings.length).toBeGreaterThan(0);

    // ── 5. Restart Redis on the SAME port — no Node process restart ─────
    const restarted = await startDisposableRedis({ port });
    expect(restarted.available).toBe(true);
    disposable = restarted;

    // ── 6. Recovery: ready again, and a real operation succeeds ─────────
    const becameReady = await waitForCondition(() => nonceStore.isReady(), { timeoutMs: 20_000, intervalMs: 200 });
    expect(becameReady).toBe(true);

    const recoveredId = crypto.randomUUID();
    const recoveredResult = await nonceStore.register(recoveredId, Date.now() + 60_000, null);
    expect(recoveredResult).toEqual({ registered: true });
  });
});
