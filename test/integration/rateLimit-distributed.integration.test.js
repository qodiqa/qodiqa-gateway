'use strict';

/**
 * Multi-Instance Distributed Rate Limiting Integration Test
 *
 * Every production route now enforces its rate limit via
 * src/core/rateLimit/middleware.js (Redis-backed), not the legacy
 * single-process middleware/publicRateLimit.js. The whole point of that
 * migration is that N replicas share one counter instead of each replica
 * enforcing its own independent one (which would silently multiply the
 * effective limit by N). This test proves that property against two real,
 * separately-spawned server.js processes sharing one real Redis instance —
 * not an in-process simulation.
 *
 * Modeled on test/integration/audit-chain-distributed.integration.test.js (real
 * multi-process test for the analogous SCAL-11 audit-chain-ordering
 * property) and reuses the existing acceptance-test helpers:
 *   - test/harness/redis.js's startDisposableRedis() — a fully
 *     owned, isolated Redis instance (never the developer's ambient
 *     Memurai/Redis service), so re-running this test never sees leftover
 *     counts from a previous run.
 *   - test/harness/server.js's startBootstrapped() — spawns a
 *     real, unmocked `node scripts/bootstrap-dev.js` (same entry point
 *     `npm run dev` uses) on its own free port with fully isolated on-disk
 *     state, waiting for the real GATEWAY_START event.
 *   - test/harness/http.js's get() — plain fetch-based HTTP
 *     client against the spawned server's real network port.
 *
 * Redis reachability (or a controllable local backend to spin one up) is a
 * genuine prerequisite — this test probes for it and SKIPS (does not fail)
 * if unavailable, mirroring test/serverStartupSmoke.test.js's existing
 * conditional-skip convention.
 *
 * Surface under test: 'well_known' (GET /.well-known/qodiqa/keys) — public,
 * unauthenticated, migrated off publicRateLimit.js in this change
 * (src/api/routes/well-known.js). Its limit is overridden via the surface's
 * own env-var knobs (RL_WELL_KNOWN_MAX/_WINDOW — src/core/rateLimit/
 * config.js) to a small number so the test runs fast without needing
 * hundreds of requests.
 */

const { startDisposableRedis } = require('../harness/redis');
const { startBootstrapped }    = require('../harness/server');
const { get }                  = require('../harness/http');

const CONFIGURED_LIMIT  = 4;
const REQUESTS_PER_SIDE = 6; // > CONFIGURED_LIMIT on its own, and > CONFIGURED_LIMIT × 2 combined isn't required — just enough over the limit for a clear signal either way
// Generous: this dev machine has been observed taking >30s to reach
// GATEWAY_START for the second of two sequentially-spawned real server
// processes under load (helpers/server.js's own default is 25s). A
// too-tight timeout here manifests as a misleading "process exited with
// code null" — waitForCondition timing out while the process is actually
// still mid-boot, not a real crash.
const STARTUP_TIMEOUT_MS = 60_000;

describe('distributed rate limiting enforces one shared limit across multiple instances', () => {
  test('combined accepted requests across two instances equals the configured single-instance limit, not limit × instance count', async () => {
    const redis = await startDisposableRedis();
    if (!redis.available) {
      // eslint-disable-next-line no-console
      console.warn(`[rateLimit-distributed] ${redis.reason} — skipping.`);
      return;
    }

    const sharedEnv = {
      REDIS_URL:            redis.url,
      RL_ENABLED:           'true',
      RL_WELL_KNOWN_MAX:    String(CONFIGURED_LIMIT),
      RL_WELL_KNOWN_WINDOW: '120',
      // This test is only about Redis-backed rate limiting — it has no
      // business depending on (or being flaked by) whatever state the
      // ambient local PostgreSQL instance is in. Mirrors
      // test/serverStartupSmoke.test.js's identical rationale: opt out of
      // the PG mirror entirely rather than trying to reset a real external
      // database this test doesn't own.
      QODIQA_PG_ENABLED: 'false',
    };

    let instanceA;
    let instanceB;
    try {
      // Spawned sequentially, not via Promise.all: helpers/server.js's own
      // header comment documents a getFreePort()-then-bind race under rapid
      // concurrent spawns (two children can be handed the same "free" port
      // before either has actually bound it). The property under test is
      // that two RUNNING instances share one Redis-backed counter — nothing
      // requires them to have booted at the same instant, so starting them
      // one after another sidesteps the race entirely.
      instanceA = await startBootstrapped({ env: sharedEnv, timeoutMs: STARTUP_TIMEOUT_MS });
      instanceB = await startBootstrapped({ env: sharedEnv, timeoutMs: STARTUP_TIMEOUT_MS });

      // Interleave requests across both instances (round-robin) rather than
      // exhausting one instance's "share" before the other — this is what
      // actually exercises cross-instance shared state; hitting one
      // instance REQUESTS_PER_SIDE times then the other would still pass
      // even with two independent per-process counters, as long as neither
      // side alone exceeded CONFIGURED_LIMIT.
      const requests = [];
      for (let i = 0; i < REQUESTS_PER_SIDE; i += 1) {
        requests.push(get(`${instanceA.baseUrl}/.well-known/qodiqa/keys`));
        requests.push(get(`${instanceB.baseUrl}/.well-known/qodiqa/keys`));
      }
      const results = await Promise.all(requests);

      const accepted = results.filter((r) => r.status === 200).length;
      const limited  = results.filter((r) => r.status === 429).length;

      expect(accepted + limited).toBe(results.length);
      // The defect this guards against: each instance enforcing its own
      // independent in-memory counter would allow CONFIGURED_LIMIT accepted
      // requests PER instance (2 × CONFIGURED_LIMIT combined) instead of
      // CONFIGURED_LIMIT total across both.
      expect(accepted).toBe(CONFIGURED_LIMIT);
      expect(accepted).toBeLessThan(CONFIGURED_LIMIT * 2);
    } finally {
      await Promise.all([
        instanceA?.stop(),
        instanceB?.stop(),
        redis.stop(),
      ]);
    }
  }, 300_000);
});
