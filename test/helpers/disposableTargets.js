'use strict';

/**
 * phase 8 — resolve the DISPOSABLE PostgreSQL / Redis targets for test/distributed/*, refusing the
 * developer machine's LIVE services.
 *
 * On this machine 127.0.0.1:5432 (PostgreSQL) and 127.0.0.1:6379 (Docker qodiqa-redis) host LIVE / dev-live data
 *. These suites run only through
 * bash npx jest test/distributed/...
 * which points them at qodiqa-er-pg (:55510) and qodiqa-er-redis (:56510). There is deliberately NO fallback to a
 * default host/port: an unset target means "skip", never "use localhost defaults". In CI (CI=true) the service
 * containers on the default ports are disposable, so the default-port refusal is lifted there only.
 */

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

function redisTarget() {
  const raw = process.env.REDIS_URL;
  if (!raw) return { available: false, reason: 'REDIS_URL not set (run through pl-env.sh)' };
  let u;
  try { u = new URL(raw); } catch { return { available: false, reason: 'REDIS_URL unparsable' }; }
  const port = parseInt(u.port || '6379', 10);
  if (process.env.CI !== 'true' && LOCAL_HOSTS.has(u.hostname) && port === 6379) {
    return { available: false, reason: 'REDIS_URL is the local 6379 (LIVE qodiqa-redis) — refused' };
  }
  return { available: true, url: raw };
}

function pgTarget() {
  if (process.env.QODIQA_PG_ENABLED !== 'true' || process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS !== 'true') {
    return { available: false, reason: 'PG not opted in (QODIQA_PG_ENABLED / QODIQA_ALLOW_PG_INTEGRATION_TESTS)' };
  }
  const host = process.env.QODIQA_PG_HOST;
  const port = parseInt(process.env.QODIQA_PG_PORT || '', 10);
  if (!host || !Number.isFinite(port)) return { available: false, reason: 'QODIQA_PG_HOST/PORT not set explicitly' };
  if (process.env.CI !== 'true' && LOCAL_HOSTS.has(host) && port === 5432) {
    return { available: false, reason: 'QODIQA_PG_PORT is the local 5432 (LIVE cluster) — refused' };
  }
  return {
    available: true,
    host,
    port,
    adminUser: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_MIG_USER,
    adminPassword: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_MIG_PASSWORD,
    appUser: process.env.QODIQA_PG_USER,
    appPassword: process.env.QODIQA_PG_PASSWORD,
  };
}

module.exports = { redisTarget, pgTarget };
