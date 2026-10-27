'use strict';

/**
 * OpenAPI ↔ LIVE application parity (the implementation is the source of truth).
 *
 * Builds the REAL application through server.js (the production composition root: server/startup.js + src/app.js
 * createApp) with Express instrumented by liveRoutes.js, collects every (method, path) the app actually mounts, and
 * requires it to equal the generated OpenAPI operation set exactly (except the reviewed KNOWN_UNDOCUMENTED list, the
 * same exclusions routeParity.test.js has always applied). Unlike routeParity.test.js it does not depend on the
 * hand-copied mount table: a router mounted, removed or remounted in src/app.js changes this result directly.
 *
 *   LP-01 the live app mounts every documented operation, and documents every mounted operation
 *   LP-02 no mounted route has a non-string (regex) path the spec could not represent
 *   LP-03 the hand-copied mount table (routeMounts.js) agrees with the live app (no stale prefix)
 *   LP-04 every router the app creates is reachable through a mounted layer, or explained by a reviewed resolver
 *         (OPAQUE_MOUNTS: a router invoked from a wrapper closure) — an unexplained one is a dead or hidden route set
 */

const path = require('path');
const live = require('./liveRoutes');

const { KNOWN_UNDOCUMENTED } = require('./routeExclusions'); // shared with conditionalRoutes.test.js

// Routers the app invokes from a wrapper closure (not reachable by walking mounted layers). Each entry is reviewed
// against the code that performs the dispatch and maps the router's own route paths to the public paths.
const OPAQUE_MOUNTS = [
  { mount: '/v1/policy/visual', routerPrefix: '/visual', where: "src/app.js app.use('/v1/policy/visual', …, (req,res,next) => { req.url = '/visual' + req.url; _policyVisualRouter(…) })",
    owns: (routes) => routes.length > 0 && routes.every((r) => r.split(' ')[1].startsWith('/visual/')) },
];

jest.setTimeout(120_000);

describe('OpenAPI ↔ live application route parity', () => {
  let liveRoutes; let nonString; let specOps; let unreached; const resolved = []; const unexplained = [];

  // Building the app runs server/startup.js's module-load side effects, some of which outlive the suite unless isolated
  // (found by the full unit gate: 3 "required after the Jest environment has been torn down" errors). The two
  // Redis clients created at load — the ops auth-lockout RedisStorage and the idempotency store — are switched off for
  // this suite, exactly like test/support/jest.setup.js already switches off /sign's lockout; neither flag changes which routes are
  // mounted (both only gate middleware/handler behaviour: server/startup.js, src/api/routes/aiChat.js). The load-time
  // monitors' timers are stopped in afterAll through the same shutdown() calls the graceful-shutdown sequence uses.
  // QODIQA_CLIENT_ID and a provider are boot-validator requirements that used to come from the developer's
  // .env; a clean checkout has none. Applied only when unset, like the two isolation flags.
  const ISOLATE = { QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'false', IDEMPOTENCY_ENABLED: 'false', QODIQA_CLIENT_ID: 'route-parity-client', LOCAL_BASE_URL: 'http://127.0.0.1:1/v1' };
  const saved = Object.fromEntries(Object.keys(ISOLATE).map((k) => [k, process.env[k]]));
  afterAll(async () => {
    // ER 2026-10-06: every load-time side effect (pools, recovery worker, stores, alerting, monitors), not just three
    // monitors — with PostgreSQL enabled the rest kept a --runInBand process alive forever (CI coverage-gate job).
    try { await require('../../server/startup').stopLoadTimeSideEffects(); } catch { /* server not loaded: nothing to stop */ }
    for (const m of ['../runtime/eventLoopMonitor', '../observability/latencySlaMonitor', '../../services/artifact/keyExpiryMonitor']) {
      try { const mod = require(m); if (mod && typeof mod.shutdown === 'function') await mod.shutdown(); } catch { /* module absent or not loaded: nothing to stop */ }
    }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  beforeAll(() => {
    for (const [k, v] of Object.entries(ISOLATE)) if (saved[k] === undefined) process.env[k] = v;
    jest.resetModules();
    live.instrument(require('express'));
    const app = require('../../server');
    ({ routes: liveRoutes, nonString, unreached } = live.collect(app));
    for (const u of unreached) {
      const o = OPAQUE_MOUNTS.find((x) => x.owns(u.routes));
      if (!o) { unexplained.push(u.routes); continue; }
      const mapped = u.routes.map((r) => { const [m, p] = r.split(' '); return `${m} ${o.mount}${p.slice(o.routerPrefix.length)}`; });
      resolved.push({ mount: o.mount, routes: mapped });
      liveRoutes = [...new Set([...liveRoutes, ...mapped])].sort();
    }
    const { generateSpec } = require('./generator');
    const spec = generateSpec({ fresh: true });
    specOps = [];
    for (const [p, item] of Object.entries(spec.paths)) for (const m of Object.keys(item)) if (['get', 'post', 'put', 'patch', 'delete', 'options', 'head'].includes(m)) specOps.push(`${m} ${p}`);
    specOps.sort();
  });

  test('LP-01 live mounted operations == generated OpenAPI operations', () => {
    expect(liveRoutes.length).toBeGreaterThan(100);
    const liveSet = new Set(liveRoutes.filter((r) => !KNOWN_UNDOCUMENTED.has(r)));
    const specSet = new Set(specOps);
    const mountedNotDocumented = [...liveSet].filter((r) => !specSet.has(r));
    const documentedNotMounted = [...specSet].filter((r) => !liveSet.has(r));
    expect({ mountedNotDocumented, documentedNotMounted }).toEqual({ mountedNotDocumented: [], documentedNotMounted: [] });
  });

  test('LP-02 every mounted path is a plain string path', () => {
    expect(nonString).toEqual([]);
  });

  test('LP-03 routeMounts.js prefixes all exist in the live app', () => {
    const { MOUNTS } = require('./routeMounts');
    const missing = MOUNTS.map((m) => m.prefix).filter((p) => !liveRoutes.some((r) => r.split(' ')[1] === p || r.split(' ')[1].startsWith(`${p}/`)));
    expect(missing).toEqual([]);
  });

  test('LP-04 every created router is reachable or explained by a reviewed opaque mount (each used exactly once)', () => {
    expect(unexplained).toEqual([]);
    expect(resolved.map((r) => r.mount).sort()).toEqual(OPAQUE_MOUNTS.map((o) => o.mount).sort());
  });

  test('KNOWN_UNDOCUMENTED entries are still mounted (the exclusion list cannot go stale)', () => {
    expect([...KNOWN_UNDOCUMENTED].filter((r) => !liveRoutes.includes(r))).toEqual([]);
  });
});

module.exports = { KNOWN_UNDOCUMENTED, OPAQUE_MOUNTS, _path: path };
