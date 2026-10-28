'use strict';

// The Redis that real-server / partition suites use: REDIS_URL when set (a disposable rehearsal Redis via pl-env.sh,
// CI's service container) — and NOTHING otherwise. this used to fall back to 127.0.0.1:6379, the
// `qodiqa-redis` container that holds LIVE/dev-live data on the development machine, so an ad-hoc local run /
// / productionBootProfile wrote its keys there. Without an explicit REDIS_URL the target is now
// "not configured" (`url` null): `reachable()` is false and the suite skips or, in a gate run, fails loudly.
// An explicit REDIS_URL that names a LIVE port on this machine (own-host :6379/:5432) is likewise refused outside CI
// (`refused` carries the reason) — `reachable()` never even probes it.
const liveGuard = require('./liveEndpointGuard');

function build(raw) {
  let host = null; let port = null; let url = null; let refused = null;
  if (raw) {
    const u = new URL(raw);
    host = u.hostname === 'localhost' ? '127.0.0.1' : u.hostname;
    port = parseInt(u.port || '6379', 10);
    url = `redis://${host}:${port}`;
    if (!liveGuard.isExempt(process.env) && liveGuard.isLiveEndpoint(u.hostname, port)) {
      refused = `REDIS_URL ${u.hostname}:${port} is a LIVE port on this machine — use a disposable Redis (pl-env.sh)`;
    }
  }
  /** true only when the target is a non-LIVE Redis that answers a TCP connect; never probes a default address. */
  async function reachable() {
    if (!url || refused) return false;
    return require('../../scripts/lib/redisProbe').probeRedisReachable(url);
  }
  return { url, host, port, configured: !!url && !refused, refused, reachable };
}

const fromEnv = (v) => (typeof v === 'string' ? v.trim() : '');
const target = build(fromEnv(process.env.REDIS_URL));
// A run that must keep REDIS_URL unset (the coverage run) names the disposable Redis in QODIQA_TEST_REDIS_URL. Only the two Redis
// resilience suites ask for it: every other suite keeps seeing "no Redis configured", exactly as before.
target.withTestFallback = () => build(fromEnv(process.env.REDIS_URL) || fromEnv(process.env.QODIQA_TEST_REDIS_URL));

module.exports = target;
