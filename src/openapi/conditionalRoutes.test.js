'use strict';

/**
 * — routes that exist only behind a feature flag were neither documented nor
 * explicitly excluded: liveRouteParity.test.js builds the app with the flags OFF, so a flag-gated route could be
 * added, removed or changed with no contract check noticing. This suite builds the REAL app with every route-mounting
 * flag ON and requires the routes it adds — beyond the documented spec and the reviewed KNOWN_UNDOCUMENTED list — to
 * equal this reviewed CONDITIONAL_ROUTES table exactly, each tied to the flag that mounts it.
 *
 *   CR-01 flags ON: mounted − documented − KNOWN_UNDOCUMENTED == CONDITIONAL_ROUTES (no unreviewed flag-gated route)
 *   CR-02 every conditional route is really absent from the default (flags OFF) build — it is conditional, not stale
 */

const live = require('./liveRoutes');
const { KNOWN_UNDOCUMENTED } = require('./routeExclusions');

// Reviewed 2026-10-04. tenant portal: src/app.js `if (ctx.portalEnabled)` (own session auth + RBAC, not part
// of the public protocol contract); bench readout: src/app.js `if (ST.ON)` (loopback-only stage-timing readout, never
// enabled in production — bootValidator).
const CONDITIONAL_ROUTES = Object.freeze({
  QODIQA_PORTAL_ENABLED: [
    'get /tenant-portal/login', 'get /tenant-portal/callback', 'get /tenant-portal/dev-login',
    'get /tenant-portal/api/me', 'get /tenant-portal/api/consent', 'get /tenant-portal/api/keys',
    'get /tenant-portal/api/usage', 'get /tenant-portal/api/usage/export', 'post /tenant-portal/logout',
  ],
  QODIQA_BENCH_STAGE_TIMING: ['get /__bench/stages', 'post /__bench/stages/reset'],
});

jest.setTimeout(120_000);

// Load-time monitors are started by EACH isolated build; they must be stopped on those same module instances (a
// top-level require in afterAll reaches a different registry), or a timer fires after Jest's teardown.
const MONITORS = ['../runtime/eventLoopMonitor', '../observability/latencySlaMonitor', '../../services/artifact/keyExpiryMonitor'];
const stoppers = [];

function build(flags) {
  const keys = ['QODIQA_OPS_AUTH_LOCKOUT_ENABLED', 'IDEMPOTENCY_ENABLED', 'QODIQA_CLIENT_ID', 'LOCAL_BASE_URL', ...Object.keys(flags)];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  const isolate = { QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'false', IDEMPOTENCY_ENABLED: 'false', QODIQA_CLIENT_ID: 'route-parity-client', LOCAL_BASE_URL: 'http://127.0.0.1:1/v1' };
  for (const [k, v] of Object.entries(isolate)) if (saved[k] === undefined) process.env[k] = v;
  for (const [k, v] of Object.entries(flags)) process.env[k] = v;
  let routes;
  jest.isolateModules(() => {
    live.instrument(require('express'));
    const app = require('../../server');
    routes = live.collect(app).routes;
    // ER 2026-10-06: stop EVERY load-time side effect of this isolated build (pools, recovery worker, stores, alerting,
    // monitors) through server/startup's own stopLoadTimeSideEffects() on the same instance — the MONITORS-only list
    // left the recovery worker and the PostgreSQL pool alive when PG is enabled (the CI coverage job never exited).
    const { stopLoadTimeSideEffects } = require('../../server/startup');
    stoppers.push(() => stopLoadTimeSideEffects());
    for (const m of MONITORS) {
      try { const mod = require(m); if (mod && typeof mod.shutdown === 'function') stoppers.push(() => mod.shutdown()); } catch { /* not loaded */ }
    }
  });
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  return routes;
}

describe('flag-gated routes are reviewed and explicitly listed', () => {
  let on; let off; let specOps;

  beforeAll(() => {
    off = build({ QODIQA_PORTAL_ENABLED: 'false', QODIQA_BENCH_STAGE_TIMING: 'false' });
    on = build({ QODIQA_PORTAL_ENABLED: 'true', QODIQA_BENCH_STAGE_TIMING: 'true' });
    const { generateSpec } = require('./generator');
    const spec = generateSpec({ fresh: true });
    specOps = new Set();
    for (const [p, item] of Object.entries(spec.paths)) for (const m of Object.keys(item)) specOps.add(`${m} ${p}`);
  });

  afterAll(async () => {
    for (const stop of stoppers) { try { await stop(); } catch { /* best effort */ } }
  });

  test('CR-01 flags ON: every mounted route beyond the documented spec is a reviewed conditional route', () => {
    const extra = on.filter((r) => !specOps.has(r) && !KNOWN_UNDOCUMENTED.has(r)).sort();
    expect(extra).toEqual(Object.values(CONDITIONAL_ROUTES).flat().sort());
  });

  test('CR-02 every conditional route is absent when its flag is off', () => {
    const offSet = new Set(off);
    expect(Object.values(CONDITIONAL_ROUTES).flat().filter((r) => offSet.has(r))).toEqual([]);
  });
});

module.exports = { CONDITIONAL_ROUTES };
