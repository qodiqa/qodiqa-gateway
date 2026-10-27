'use strict';

/**
 * Item 24 — dedicated, disposable Redis DB for perf-harness runs.
 *
 * No Redis client anywhere in this codebase ever sets a `database` option —
 * every client (nonceStore.js, anomalyStore.js, services/policy/store.js's
 * rate-limit store) resolves its DB index purely from REDIS_URL's path
 * segment, via buildClientOptions() (src/infra/redis/clientConfig.js), read
 * fresh at first-connect time (lazy singleton), not at module-require time.
 * So forcing REDIS_URL's path to /1 here, before any store's first connect,
 * routes ALL of them onto DB 1. Confirmed live against this repo's redis@5
 * client: a client built from `redis://localhost:6379/1` reports `db: 1`
 * via CLIENT INFO.
 *
 * DB 0 is the shared dev/Memurai database — this module never selects or
 * touches it, and every flush path here asserts the connected DB index
 * before acting rather than assuming it.
 */

const { createClient } = require('redis');

const TEST_DB_INDEX = 1;
const SENTINEL_KEY = 'qodiqa:perf:sentinel';

/**
 * Force REDIS_URL's path (DB index) to TEST_DB_INDEX, preserving whatever
 * host/port/auth/TLS scheme is already configured (or the default
 * redis://localhost:6379 when unset). Must be called before any store's
 * first Redis operation.
 * @returns {string} the resolved URL, also written to process.env.REDIS_URL
 */
function resolveTestRedisUrl() {
  const raw = process.env.REDIS_URL || 'redis://localhost:6379';
  const u = new URL(raw);
  u.pathname = `/${TEST_DB_INDEX}`;
  const resolved = u.toString();
  process.env.REDIS_URL = resolved;
  return resolved;
}

/**
 * Independent admin connection, separate from nonceStore/anomalyStore/
 * services/policy/store.js's own private client singletons (those are not
 * exported), used purely for sentinel/flush/guard duties.
 */
async function createAdminClient() {
  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  const client = createClient({ url });
  await client.connect();
  return client;
}

/**
 * Hard guard: refuses to proceed unless the connection is confirmed to be
 * on TEST_DB_INDEX AND the sentinel key (written by writeSentinel() at
 * harness startup) is present. Re-checked fresh before every flush rather
 * than trusted from setup time.
 */
async function assertTestDb(client) {
  const info = await client.clientInfo();
  if (info.db !== TEST_DB_INDEX) {
    throw new Error(
      `redisTestDb: refusing to proceed — connected DB index is ${info.db}, expected ${TEST_DB_INDEX}. ` +
      `This guard exists specifically to prevent flushing the shared dev Redis DB (index 0).`,
    );
  }
  const sentinel = await client.get(SENTINEL_KEY);
  if (sentinel !== '1') {
    throw new Error(
      `redisTestDb: refusing to proceed — sentinel key "${SENTINEL_KEY}" not found on DB ${TEST_DB_INDEX}. ` +
      `Expected it to have been written by writeSentinel() at harness startup.`,
    );
  }
}

async function writeSentinel(client) {
  await client.set(SENTINEL_KEY, '1');
}

/**
 * Assert-then-flush-then-re-write-sentinel — used between load levels.
 * FLUSHDB removes the sentinel along with everything else, so it's
 * rewritten immediately so the NEXT level's guard still finds it present.
 */
async function guardedFlush(client) {
  await assertTestDb(client);
  await client.flushDb();
  await writeSentinel(client);
}

/**
 * End-of-run cleanup — assert, then flush, leaving DB 1 empty (sentinel
 * gone with everything else; no separate DEL needed).
 */
async function finalCleanup(client) {
  await assertTestDb(client);
  await client.flushDb();
}

module.exports = {
  TEST_DB_INDEX,
  SENTINEL_KEY,
  resolveTestRedisUrl,
  createAdminClient,
  assertTestDb,
  writeSentinel,
  guardedFlush,
  finalCleanup,
};
