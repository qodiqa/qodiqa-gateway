'use strict';

/**
 * Real Redis outage-recovery integration test for the consent-
 * revocation and org-status subscribers.
 *
 * Mirrors test/integration/redisReconnectRecovery.integration.test.js ('s own
 * outage-recovery precedent for the other four Redis-backed stores) against
 * a REAL, disposable Redis-compatible instance — no protocol mocking.
 *
 * What this proves that a "reconnectStrategy never returns false" unit test
 * cannot:, RevocationSubscriber.js/OrgStatusSubscriber.js each
 * implemented their own bounded reconnectStrategy (MAX_RECONNECTS, default
 * 10, exponential backoff capped at 5000ms — cumulative default budget
 * ~31.2s). Once exhausted, node-redis's own socket layer stops retrying for
 * good — traced directly against @redis/client's socket.js, this path
 * emits 'error' and then goes silent; it never emits 'end', so
 * managedClient.js's Finding-49 self-healing supervisor (which listens for
 * 'end') never engaged either. The only way this was previously observed to
 * recover was a full process restart (
 *). A test asserting only "the strategy function never returns false"
 * would not catch this — it has to actually outlive the configured old
 * budget against a real dying/reviving Redis and prove BOTH subscribers
 * come back WITHOUT restarting the process.
 *
 * REVOCATION_SUBSCRIBER_MAX_RECONNECTS / ORG_STATUS_SUBSCRIBER_MAX_RECONNECTS
 * are lowered to 2 for this test (via the exact same env vars an operator
 * could configure in production) — this exercises the identical code path
 * and the identical "give up after N attempts" semantics the real ~31.2s
 * default budget has, just on a fast clock (~0.6s to reach retries=2
 * instead of ~31.2s), so the test proves the real defect and its real fix
 * without a multi-minute run.
 *
 * Sequence, against both subscribers sharing ONE disposable Redis instance
 * (a single real outage affects both simultaneously, exactly as witnessed
 * live Session 1):
 *   1. Start a disposable Redis, start both subscribers against it, confirm ready.
 *   2. Kill the Redis process outright.
 * 3. Wait past the (lowered) old MAX_RECONNECTS budget — both
 *      subscribers would have permanently given up by now. Assert the
 *      "loud past the old cap" telemetry fired for both, and that both are
 *      still (correctly) not ready — fail-closed during the outage is
 *      unchanged by this fix.
 *   4. Restart Redis on the SAME port (no process restart anywhere).
 *   5. Assert BOTH subscribers become ready again.
 *   6. Genuine functional recovery, not just a socket flag: publish a real
 *      revocation event and a real org-status change through each
 *      subscriber's own real publisher, and assert each is actually
 *      received and processed — proving re-subscription genuinely
 *      happened, not merely that isReady() flipped back to true.
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

// Defensive teardown guard — a client mid-backoff should still disconnect
// promptly, but this test must never hang the whole suite if one doesn't.
// The fallback timer is always cleared once the race settles either way —
// an uncleared timer would itself leak a handle and keep Jest alive for
// the full `ms`, even on the fast/successful path.
function withTimeout(promise, ms, label) {
  let timer;
  const fallback = new Promise((resolve) => {
    timer = setTimeout(() => {
      console.warn(`test: ${label} did not settle within ${ms}ms — continuing teardown`);
      resolve();
    }, ms);
  });
  return Promise.race([promise, fallback]).finally(() => clearTimeout(timer));
}

describe('RevocationSubscriber + OrgStatusSubscriber outage recovery (real disposable Redis, no process restart)', () => {
  let disposable;
  let revocationSubscriber;
  let orgStatusSubscriber;
  let revocationPublisher;
  let orgStatusPublisher;
  let mockRegistry;

  afterEach(async () => {
    if (revocationSubscriber) await withTimeout(revocationSubscriber.stop().catch(() => {}), 5_000, 'revocationSubscriber.stop()');
    if (orgStatusSubscriber)  await withTimeout(orgStatusSubscriber.stop().catch(() => {}), 5_000, 'orgStatusSubscriber.stop()');
    if (revocationPublisher)  await withTimeout(revocationPublisher.disconnect().catch(() => {}), 5_000, 'revocationPublisher.disconnect()');
    if (orgStatusPublisher)   await withTimeout(orgStatusPublisher.disconnect().catch(() => {}), 5_000, 'orgStatusPublisher.disconnect()');
    // RevocationSubscriber._handleMessage lazily requires ConsentCache
    // (its own separate 'consentCache' Redis client); OrgStatusSubscriber
    // similarly owns a separate 'orgStatusStore' client via OrgStatusStore.
    // Both must be disconnected too, or their own reconnect timers keep
    // Jest's process alive/emitting after this test has torn down.
    try {
      const consentCache = require('../../src/core/consent/ConsentCache');
      await withTimeout(consentCache.disconnect().catch(() => {}), 5_000, 'ConsentCache.disconnect()');
    } catch { /* module never loaded this run */ }
    try {
      const orgStatusStore = require('../../src/core/organizations/status/OrgStatusStore');
      await withTimeout(orgStatusStore.disconnect().catch(() => {}), 5_000, 'OrgStatusStore.disconnect()');
    } catch { /* module never loaded this run */ }
    if (disposable?.stop) { try { await disposable.stop(); } catch { /* already stopped */ } }
    delete process.env.REDIS_URL;
    delete process.env.REVOCATION_SUBSCRIBER_MAX_RECONNECTS;
    delete process.env.ORG_STATUS_SUBSCRIBER_MAX_RECONNECTS;
    jest.resetModules();
    mockEmit.mockClear();
  });

  test('both subscribers recover from a shared Redis outage without a server restart, past the old reconnect budget', async () => {
    disposable = await startDisposableRedis();
    if (!disposable.available) {
      console.warn(`SKIPPED: no controllable Redis backend available (${disposable.reason})`);
      return;
    }

    process.env.REDIS_URL = disposable.url;
    // Lowered old-threshold budget — see file header. The strategy itself
    // (never returns false) is unaffected; only where "pastOldThreshold"
    // telemetry flips is affected, so the outage-wait below can be seconds
    // instead of the real ~31.2s default.
    process.env.REVOCATION_SUBSCRIBER_MAX_RECONNECTS = '2';
    process.env.ORG_STATUS_SUBSCRIBER_MAX_RECONNECTS = '2';

    revocationSubscriber = require('../../src/core/consent/revocation/RevocationSubscriber');
    orgStatusSubscriber  = require('../../src/core/organizations/status/OrgStatusSubscriber');
    revocationPublisher  = require('../../src/core/consent/revocation/RevocationPublisher');
    orgStatusPublisher   = require('../../src/core/organizations/status/OrgStatusPublisher');

    mockRegistry = {
      listOrganizations:     jest.fn().mockReturnValue([]),
      _applyRemoteStatus:    jest.fn().mockReturnValue(true),
      _touchStatusFreshness: jest.fn(),
    };
    orgStatusSubscriber.setOrganizationRegistry(mockRegistry);

    // ── 1. Connect both, confirm ready ───────────────────────────────────
    await revocationSubscriber.start();
    await orgStatusSubscriber.start();
    expect(revocationSubscriber.isReady()).toBe(true);
    expect(orgStatusSubscriber.isReady()).toBe(true);

    // ── 2. Kill Redis outright — one outage, both subscribers affected ──
    const port = disposable.port;
    await disposable.stop();
    disposable = null; // already stopped — afterEach shouldn't stop it again

    await waitForCondition(() => !revocationSubscriber.isReady(), { timeoutMs: 5_000, intervalMs: 100 });
    await waitForCondition(() => !orgStatusSubscriber.isReady(), { timeoutMs: 5_000, intervalMs: 100 });
    expect(revocationSubscriber.isReady()).toBe(false);
    expect(orgStatusSubscriber.isReady()).toBe(false);

    // ── 3. Wait past the (lowered) old MAX_RECONNECTS=2 budget ──────────
    // Pre-F22, both subscribers' own bounded reconnectStrategy would have
    // returned an Error once retries reached this threshold, node-redis
    // would have stopped retrying for good (confirmed by tracing
    // socket.js: this path never emits 'end', so the managedClient.js
    // self-healing supervisor never engages either), and nothing short of
    // a full process restart would recover them. Assert they are still
    // alive and correctly not-ready (fail-closed unaffected by this fix),
    // and that the loud past-old-cap telemetry fired for both.
    // NOTE: waitForCondition() treats ANY truthy predicate result as
    // success, and a JS array is truthy even when empty — so the predicate
    // must explicitly check .length, not just return the filtered array.
    await waitForCondition(
      () => mockEmit.mock.calls.some(
        ([level, event, payload]) => level === 'WARN' && event === 'REVOCATION_SUBSCRIBER_RECONNECT_ATTEMPT' && payload?.pastOldThreshold === true,
      ),
      { timeoutMs: 15_000, intervalMs: 200 },
    );
    await waitForCondition(
      () => mockEmit.mock.calls.some(
        ([level, event, payload]) => level === 'WARN' && event === 'ORG_STATUS_SUBSCRIBER_RECONNECT_ATTEMPT' && payload?.pastOldThreshold === true,
      ),
      { timeoutMs: 15_000, intervalMs: 200 },
    );
    const revocationPastThreshold = mockEmit.mock.calls.filter(
      ([level, event, payload]) => level === 'WARN' && event === 'REVOCATION_SUBSCRIBER_RECONNECT_ATTEMPT' && payload?.pastOldThreshold === true,
    );
    const orgStatusPastThreshold = mockEmit.mock.calls.filter(
      ([level, event, payload]) => level === 'WARN' && event === 'ORG_STATUS_SUBSCRIBER_RECONNECT_ATTEMPT' && payload?.pastOldThreshold === true,
    );
    expect(revocationPastThreshold.length).toBeGreaterThan(0);
    expect(orgStatusPastThreshold.length).toBeGreaterThan(0);
    expect(revocationSubscriber.isReady()).toBe(false);
    expect(orgStatusSubscriber.isReady()).toBe(false);

    // ── 4. Restart Redis on the SAME port — no Node process restart ─────
    const restarted = await startDisposableRedis({ port });
    expect(restarted.available).toBe(true);
    disposable = restarted;

    // ── 5. Both become ready again ───────────────────────────────────────
    const revocationRecovered = await waitForCondition(() => revocationSubscriber.isReady(), { timeoutMs: 40_000, intervalMs: 200 });
    const orgStatusRecovered  = await waitForCondition(() => orgStatusSubscriber.isReady(),  { timeoutMs: 40_000, intervalMs: 200 });
    expect(revocationRecovered).toBe(true);
    expect(orgStatusRecovered).toBe(true);

    // ── 6. Genuine re-subscription, not just a socket flag ───────────────
    // revocationPublisher/orgStatusPublisher are SEPARATE clients from the
    // subscribers under test — they connect lazily on their own first
    // publish() call, so their very first attempt can race the just-
    // recovered/just-restarted Redis instance's own startup (unrelated to
    // this fix; both publishers already document publish() as non-fatal
    // and tolerant of exactly this). Retry briefly rather than asserting
    // on the very first attempt.
    async function publishWithRetry(fn, isOk, attempts = 8, delayMs = 500) {
      let last;
      for (let i = 0; i < attempts; i++) {
        last = await fn();
        if (isOk(last)) return last;
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
      return last;
    }

    mockEmit.mockClear();

    const subjectId = `f22-test-actor-${crypto.randomUUID()}`;
    const published = await publishWithRetry(
      () => revocationPublisher.publish({ subjectId, action: 'f22-test-action' }),
      (result) => result === true,
    );
    expect(published).toBe(true);

    const revocationProcessed = await waitForCondition(
      () => mockEmit.mock.calls.some(
        ([level, event, payload]) => level === 'INFO' && event === 'REVOCATION_EVENT_PROCESSED' && payload?.subjectId === subjectId,
      ),
      { timeoutMs: 10_000, intervalMs: 100 },
    );
    expect(revocationProcessed).toBeTruthy();

    const organizationId = `f22-test-org-${crypto.randomUUID()}`;
    const statusResult = await publishWithRetry(
      () => orgStatusPublisher.publishStatusChange({ organizationId, status: 'suspended' }),
      (result) => result?.published === true,
    );
    expect(statusResult.published).toBe(true);

    const orgStatusApplied = await waitForCondition(
      () => mockRegistry._applyRemoteStatus.mock.calls.some(
        ([orgId, status]) => orgId === organizationId && status === 'suspended',
      ),
      { timeoutMs: 10_000, intervalMs: 100 },
    );
    expect(orgStatusApplied).toBeTruthy();
  });
});
