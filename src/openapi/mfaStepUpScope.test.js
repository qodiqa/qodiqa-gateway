'use strict';

/**
 * / API-04 — the OpenAPI's MFA step-up declarations equal the LIVE app's step-up enforcement.
 *
 * Builds the real application through server.js (as liveRouteParity.test.js does), walks every route's middleware
 * chain, and for each `mfaStepUp` middleware in it INVOKES the middleware with a request for that route (no operator,
 * MFA required): a gated operation answers 403 (step-up needs an operator), an ungated one calls next() — so the
 * createMfaStepUp({ when }) predicates are exercised, not restated. The resulting set must equal the operations the
 * generated spec marks `x-qodiqa-mfa-step-up` (src/openapi/mfaStepUpScope.js), and each of those must declare the
 * X-QODIQA-OTP header and the step-up responses.
 *
 *   MS-01 live step-up set == spec step-up set (and is non-trivial)
 *   MS-02 every spec step-up operation declares a required X-QODIQA-OTP header and the 401/403/429 step-up responses
 *   MS-03 reads are never gated in the live app
 * MS-04 every admin-plane mutation (a non-read route behind ctx.adminStack(), i.e. with rbacResolve in its
 *         chain) is step-up gated OR listed in the approved exemption registry (mfaStepUp.js STEP_UP_EXEMPTIONS)
 * MS-05 the exemption registry is exact - no entry is gated anyway, every entry names a mounted route
 * MS-06 each mutation the due-diligence audit found ungated now answers 403 MFA_ENROLLMENT_REQUIRED (no MFA
 *         enrolled) and 401 MFA_REQUIRED (enrolled, no code) when MFA is required, and passes when it is not
 */

const live = require('./liveRoutes');

jest.setTimeout(120_000);

const _join = (a, b) => (`${a}/${b}`).replace(/\/+/g, '/').replace(/(.)\/$/, '$1');
const _toOpenApi = (p) => p.replace(/:([A-Za-z0-9_]+)(\([^)]*\))?\??/g, '{$1}');
const _concrete = (p) => p.replace(/\{[^}]+\}/g, 'x');

/** [{ op: 'method /openapi/path', full, chain: [{ handle, mount }] }] for every route of the app. */
function routesWithChains(app) {
  const out = [];
  (function walk(stack, pre, inherited) {
    const before = [...inherited];
    for (const l of stack) {
      const mounts = Array.isArray(l.__qodiqaMountPath) ? l.__qodiqaMountPath : [l.__qodiqaMountPath || '/'];
      if (l.route) {
        const routeChain = l.route.stack.map((s) => ({ handle: s.handle, mount: null }));
        const paths = Array.isArray(l.route.path) ? l.route.path : [l.route.path];
        for (const p of paths) {
          if (typeof p !== 'string') continue;
          const full = _toOpenApi(_join(pre, p));
          for (const m of Object.keys(l.route.methods)) {
            if (!l.route.methods[m] || m === '_all') continue;
            const chain = [...before.filter((b) => full === b.mount || full.startsWith(`${b.mount}/`) || b.mount === '/'), ...routeChain.map((r) => ({ ...r, mount: full }))];
            out.push({ op: `${m} ${full}`, method: m, full, chain });
          }
        }
      } else if (l.handle && Array.isArray(l.handle.stack)) {
        for (const m of mounts) if (typeof m === 'string') walk(l.handle.stack, _join(pre, m), before);
      } else if (typeof l.handle === 'function') {
        for (const m of mounts) if (typeof m === 'string') before.push({ handle: l.handle, mount: _join(pre, m) });
      }
    }
  }(app._router.stack, '/', []));
  return out;
}

/** Invoke one step-up middleware for a route: true = it gates the request, false = it passes it on. */
function gates(handle, method, mount, full, rbacUser) {
  return invoke(handle, method, mount, full, rbacUser).then((r) => r.gated);
}
/** As gates(), with the refusal's status and error code. req.baseUrl + req.path = the concrete full path, as in Express. */
function invoke(handle, method, mount, full, rbacUser) {
  return new Promise((resolve, reject) => {
    const concrete = _concrete(full);
    const routeLevel = mount === full;
    const rel = routeLevel ? '/' : (concrete.slice(_concrete(mount).length) || '/');
    const req = { method: method.toUpperCase(), path: rel, baseUrl: routeLevel ? concrete : _concrete(mount), originalUrl: concrete, requestId: null, rbacUser, get: () => undefined };
    const res = { locals: {}, statusCode: 200, set() { return this; }, status(c) { this.statusCode = c; return this; },
      json(b) { resolve({ gated: true, status: this.statusCode, code: b && b.error ? b.error.code : null }); return this; } };
    Promise.resolve(handle(req, res, (err) => (err ? reject(err) : resolve({ gated: false })))).catch(reject);
  });
}

describe('MFA step-up: OpenAPI declarations == live enforcement', () => {
  let liveStepUp; let liveReadsGated; let spec; let routes; let adminMutations; let stepUpHandles; let app;
  // QODIQA_CLIENT_ID and a provider are boot-validator requirements that used to come from the developer's
  // .env; a clean checkout has none. Applied only when unset, like the two isolation flags.
  const ISOLATE = { QODIQA_OPS_AUTH_LOCKOUT_ENABLED: 'false', IDEMPOTENCY_ENABLED: 'false', QODIQA_CLIENT_ID: 'route-parity-client', LOCAL_BASE_URL: 'http://127.0.0.1:1/v1' };
  const saved = Object.fromEntries([...Object.keys(ISOLATE), 'QODIQA_OPS_MFA_REQUIRED'].map((k) => [k, process.env[k]]));

  afterAll(async () => {
    // ER 2026-10-06: every load-time side effect (see liveRouteParity.test.js / server/startup stopLoadTimeSideEffects).
    try { await require('../../server/startup').stopLoadTimeSideEffects(); } catch { /* server not loaded: nothing to stop */ }
    for (const m of ['../runtime/eventLoopMonitor', '../observability/latencySlaMonitor', '../../services/artifact/keyExpiryMonitor']) {
      try { const mod = require(m); if (mod && typeof mod.shutdown === 'function') await mod.shutdown(); } catch { /* not loaded */ }
    }
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  });

  beforeAll(async () => {
    for (const [k, v] of Object.entries(ISOLATE)) if (saved[k] === undefined) process.env[k] = v;
    jest.resetModules();
    live.instrument(require('express'));
    app = require('../../server');
    routes = routesWithChains(app);
    process.env.QODIQA_OPS_MFA_REQUIRED = 'true'; // mfa.isRequired() is read per request
    liveStepUp = new Set(); liveReadsGated = []; stepUpHandles = new Map();
    for (const r of routes) {
      for (const { handle, mount } of r.chain) {
        if (handle.name !== 'mfaStepUp') continue;
        if (await gates(handle, r.method, mount, r.full)) {
          if (['get', 'head', 'options'].includes(r.method)) liveReadsGated.push(r.op); else { liveStepUp.add(r.op); stepUpHandles.set(r.op, { handle, mount, r }); }
          break;
        }
      }
    }
    // the admin plane = routes whose chain carries the admin stack's rbacResolve (opsOnlyStack has none;
    // optionalAuth wraps its stack in one closure, so the public verification routes do not count).
    adminMutations = routes.filter((r) => !['get', 'head', 'options'].includes(r.method) && r.chain.some((c) => c.handle.name === 'rbacResolve'));
    const { generateSpec } = require('./generator');
    spec = generateSpec({ fresh: true });
  });

  const specStepUp = () => {
    const s = new Set();
    for (const [p, item] of Object.entries(spec.paths)) for (const [m, op] of Object.entries(item)) if (op && op['x-qodiqa-mfa-step-up']) s.add(`${m} ${p}`);
    return s;
  };

  test('MS-01 live step-up operations == spec step-up operations', () => {
    const l = [...liveStepUp].sort(); const s = [...specStepUp()].sort();
    expect(l.length).toBeGreaterThan(40);
    expect({ liveNotInSpec: l.filter((x) => !s.includes(x)), specNotLive: s.filter((x) => !l.includes(x)) }).toEqual({ liveNotInSpec: [], specNotLive: [] });
  });

  test('MS-02 every step-up operation declares X-QODIQA-OTP and the step-up responses', () => {
    const bad = [];
    for (const op of specStepUp()) {
      const [m, p] = op.split(' '); const o = spec.paths[p][m];
      const hdr = (o.parameters || []).find((x) => x.in === 'header' && x.name === 'X-QODIQA-OTP');
      const ok = hdr && hdr.required === true
        && o.responses['401'] && o.responses['401'].$ref === '#/components/responses/UnauthorizedOrMfaRequired'
        && o.responses['403'] && o.responses['403'].$ref === '#/components/responses/ForbiddenOrMfaEnrollmentRequired'
        && o.responses['429'] && o.responses['429'].$ref === '#/components/responses/TooManyRequestsOrMfaLocked';
      if (!ok) bad.push(op);
    }
    expect(bad).toEqual([]);
    for (const k of ['UnauthorizedOrMfaRequired', 'ForbiddenOrMfaEnrollmentRequired', 'TooManyRequestsOrMfaLocked']) expect(spec.components.responses[k]).toBeDefined();
  });

  test('MS-03 reads are never gated by the step-up', () => {
    expect(liveReadsGated).toEqual([]);
  });

  const { STEP_UP_EXEMPTIONS, isStepUpExempt } = require('../middleware/mfaStepUp');
  // Deliberately outside OPERATOR step-up: tenant-user portal sessions (reasons: src/app.js `_stepUpAdmin` comment).
  const NOT_OPERATOR_PLANE = /^\/tenant-portal(\/|$)/;

  test('MS-04 every admin-plane mutation is step-up gated or a approved exemption', () => {
    expect(adminMutations.length).toBeGreaterThan(80);
    const uncovered = adminMutations
      .filter((r) => !NOT_OPERATOR_PLANE.test(r.full))
      .filter((r) => !liveStepUp.has(r.op) && !isStepUpExempt(r.method, _concrete(r.full)))
      .map((r) => r.op);
    expect(uncovered).toEqual([]);
  });

  test('MS-05 the exemption registry is exact (no gated entry, no stale entry, every entry has a reason)', () => {
    // /v1/policy/visual/* is reached through src/app.js's url-rewriting wrapper, which the chain walk cannot follow;
    // those routes come from the live route collector's `unreached` list instead (router-relative '/visual/...').
    const visual = live.collect(app).unreached.flatMap((u) => u.routes)
      .filter((op) => / \/visual\//.test(op)).map((op) => op.replace(' /visual/', ' /v1/policy/visual/'));
    const mounted = new Set([...routes.map((r) => r.op), ...visual]);
    for (const e of STEP_UP_EXEMPTIONS) expect(typeof e.reason === 'string' && e.reason.length > 10).toBe(true);
    expect(STEP_UP_EXEMPTIONS.map((e) => e.op).filter((op) => liveStepUp.has(op))).toEqual([]);
    expect(STEP_UP_EXEMPTIONS.map((e) => e.op).filter((op) => !mounted.has(op))).toEqual([]);
  });

  // The state-changing mutations that must sit behind MFA step-up,
  // their /v1 aliases, alerts suppress (moved from route-level to mount-level), certification evaluate, and the
  // audit-viewer investigation create (both grouped with read-like endpoints, but they persist records).
  const MFA_SCOPE_OPS = [
    'post /audit-store/retention/policies', 'post /audit-store/retention/apply', 'post /audit-store/retention/holds',
    'delete /audit-store/retention/holds/{holdName}',
    'post /consent', 'post /consent/{id}/revoke', 'post /consent/{id}/suspend', 'post /consent/{id}/resume',
    'post /consent/actor/{actorId}/revoke', 'delete /consent/actor/{actorId}',
    'post /transparency/register', 'post /transparency/admin/roots/generate',
    'post /v1/transparency/register', 'post /v1/transparency/admin/roots/generate',
    'post /compliance/report/generate',
    'post /v1/certifications/batch', 'post /v1/certifications/batch/{batchId}/cancel',
    'post /alerts/test/{channel}', 'post /alerts', 'post /alerts/{id}/acknowledge', 'post /alerts/{id}/resolve',
    'post /alerts/{id}/false-positive', 'post /alerts/{id}/suppress',
    'post /v1/policy/governance/draft', 'post /v1/policy/governance/{id}/submit', 'post /v1/policy/governance/{id}/review',
    'post /v1/policy/governance/{id}/reject', 'post /v1/policy/governance/{id}/withdraw',
    'post /v1/policy/governance/rollback', 'post /v1/policy/governance/emergency/sweep-expired',
    'post /v1/certification/evaluate', 'post /audit-viewer/investigation',
  ];

  test('MS-06 each newly covered mutation refuses without MFA (403) and without a code (401)', async () => {
    expect(MFA_SCOPE_OPS.filter((op) => !liveStepUp.has(op))).toEqual([]);
    const store = require('../core/rbac/store'); const mfa = require('../core/rbac/mfa');
    const u0 = store.createUser({ username: `mfa-scope-noenrol-${Date.now()}`, role: 'admin' });
    const u1 = store.createUser({ username: `mfa-scope-enrolled-${Date.now()}`, role: 'admin' });
    const op1 = { id: u1.id, username: u1.username };
    const { secret } = mfa.beginEnrollment(op1);
    await mfa.confirmEnrollment(op1, mfa.totp(mfa.base32Decode(secret), Date.now() - 60_000), undefined, Date.now() - 60_000);
    const bad = [];
    for (const op of MFA_SCOPE_OPS) {
      const { handle, mount, r } = stepUpHandles.get(op);
      const a = await invoke(handle, r.method, mount, r.full, { id: u0.id, username: u0.username });
      const b = await invoke(handle, r.method, mount, r.full, op1);
      if (!(a.status === 403 && a.code === 'MFA_ENROLLMENT_REQUIRED' && b.status === 401 && b.code === 'MFA_REQUIRED')) bad.push({ op, a, b });
    }
    expect(bad).toEqual([]);
  });

  test('MS-06b with QODIQA_OPS_MFA_REQUIRED=false (the unit-gate default, test/support/jest.setup.js) they pass', async () => {
    const savedReq = process.env.QODIQA_OPS_MFA_REQUIRED;
    process.env.QODIQA_OPS_MFA_REQUIRED = 'false';
    try {
      for (const op of MFA_SCOPE_OPS) {
        const { handle, mount, r } = stepUpHandles.get(op);
        expect(await gates(handle, r.method, mount, r.full)).toBe(false);
      }
    } finally { process.env.QODIQA_OPS_MFA_REQUIRED = savedReq; }
  });
});
