#!/usr/bin/env node
'use strict';
/**
 * Route → guard table, generated from code (not by hand).
 *
 *   node scripts/security/routeGuardTable.js [--md <file>] [--json <file>]
 *
 * How it works (nothing per-route is written by hand):
 *  1. Every store the app could touch at module load is pointed at one reused
 *     temp directory (never data/, never the repository policies.json).
 *  2. The REAL app is built: src/app.js createApp(ctx), where ctx is assembled
 *     with the SAME factory calls server/startup.js makes (createAdminProtection,
 *     createOpsAuthMiddleware, createRequirePermission, createRateLimitMiddleware
 *     ...). A drift check fails the run if startup.js's ctx keys or factory calls
 *     differ from the ones built here. The tenant portal is mounted too
 *     (QODIQA_PORTAL_ENABLED=true) and its rows are marked conditional.
 *  3. The live Express router tree is walked. For every route, the effective
 *     middleware chain is computed with Express's own rule: every earlier
 *     non-route layer whose mount path is a prefix of the request path, at every
 *     level, then the route's own stack. Earlier routers with a next-less
 *     catch-all on a covering prefix make later routes UNREACHABLE.
 *  4. Each middleware/handler is resolved through the V8 inspector to its source
 *     file:line, and its closure is read ([[Scopes]]): the rate-limit bucket is
 *     the limiter's `surface`, the RBAC permission is rbacPermissionCheck's
 *     `permission`. Guard kinds come from the implementing file (GUARD_FILES).
 *  5. Writes are STATIC ANALYSIS (acorn): from each handler, calls are followed
 *     through same-file functions and require()d modules (depth ≤ 7) to sinks:
 *     audit-log append, transparency register/generateRoot, SQL INSERT/UPDATE/
 *     DELETE text, fs write calls. It is a best-effort lower bound: calls through
 *     dynamic dispatch the resolver cannot see are not followed.
 *  6. Gaps are flagged by rule (see GAP RULES in the output).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const inspector = require('inspector');

const REPO = path.join(__dirname, '..', '..');
const ARGS = Object.fromEntries(process.argv.slice(2).reduce((a, v, i, arr) => (v.startsWith('--') ? [...a, [v.slice(2), arr[i + 1]]] : a), []));
const MD_OUT = ARGS.md || path.join(REPO, 'evidence', 'w4', 'ROUTE-GUARD-TABLE.md');
const JSON_OUT = ARGS.json || path.join(REPO, 'evidence', 'w4', 'route-guard-table.json');
const rel = (p) => (p ? path.relative(REPO, p).split(path.sep).join('/') : p);

// ── 1. isolation ─────────────────────────────────────────────────────────────
const ISO = path.join(os.tmpdir(), 'qodiqa-route-guard-table');
fs.mkdirSync(ISO, { recursive: true });
const { STORE_ENV } = require(path.join(REPO, 'scripts/lib/devEnvironment'));
const isoPaths = {
  keysPath: 'keys.json', transparencyKeysPath: 'transparency-keys.json', auditLogPath: 'audit.log', signingStorePath: 'signing-identities.json',
  orgStorePath: 'organizations.json', tenantStorePath: 'tenants.json', policyStorePath: 'policy-store.json', rbacStorePath: 'rbac-users.json',
  rbacCustomRoleStorePath: 'rbac-custom-roles.json', portalUserStorePath: 'tenant-portal-users.json',
};
for (const k of Object.keys(isoPaths)) isoPaths[k] = path.join(ISO, isoPaths[k]);
Object.assign(process.env, {
  NODE_ENV: 'development', QODIQA_PG_ENABLED: 'false', QODIQA_PORTAL_ENABLED: 'true',
  QODIQA_KEY_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'), QODIQA_EXECUTION_INVARIANT_SECRET: crypto.randomBytes(32).toString('hex'),
  QODIQA_KEYS_PATH: isoPaths.keysPath, QODIQA_AUDIT_LOG: isoPaths.auditLogPath, QODIQA_TRANSPARENCY_KEYS_PATH: isoPaths.transparencyKeysPath,
  QODIQA_SIGNING_STORE_PATH: isoPaths.signingStorePath, QODIQA_PRQ_JOURNAL_DIR: path.join(ISO, 'prq-journal'),
});
for (const [env, key] of Object.entries(STORE_ENV)) process.env[env] = isoPaths[key];
const policyCopy = path.join(ISO, 'policies.json');
fs.copyFileSync(path.join(REPO, 'policies.json'), policyCopy);
process.env.POLICY_FILE = policyCopy;
for (const k of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'MISTRAL_API_KEY', 'LLAMA_BASE_URL', 'LOCAL_BASE_URL', 'REDIS_URL', 'RL_ENABLED']) delete process.env[k];
// quiet the structured logger for this tool
const logger = require(path.join(REPO, 'services/logger'));
const _emit = logger.emit; logger.emit = () => {}; // eslint-disable-line no-unused-vars

// ── 2. ctx with the same factories as server/startup.js ─────────────────────
const r = (p) => require(path.join(REPO, p));
const { loadOpsConfig } = r('src/infra/config/opsConfig');
const { createOpsAuthMiddleware } = r('src/middleware/opsAuth');
const { createOpsIpAllowlistMiddleware } = r('src/middleware/opsIpAllowlist');
const { createOpsDiagnosticsGate, createOpsAdminGate } = r('src/middleware/opsEnabled');
const { createProfilingDiagnosticsGate } = r('src/middleware/profilingEnabled');
const { createHealthAuthMiddleware } = r('src/middleware/healthAuth');
const { createHealthLoopbackMiddleware } = r('src/middleware/healthLoopback');
const { createRbacResolveMiddleware, createRequirePermission } = r('src/middleware/rbac');
const { isPermitted, isValidPermission } = r('src/core/rbac/authorize');
const { createAdminProtection } = r('src/middleware/adminProtection');
const rbacStore = r('src/core/rbac/store');
const { createPortalSessionMiddleware } = r('src/middleware/portalAuth');
const portalUserStore = r('src/core/portal/tenantPortalUserStore');
const { verifySessionToken } = r('services/portal/portalSessionToken');
const { createRateLimitMiddleware } = r('src/core/rateLimit');
const { createAuthLockout } = r('src/core/authLockout');
const policyStore = r('services/policy/store');
const { loadPolicies } = r('services/policy/loader');

const startupSrc = fs.readFileSync(path.join(REPO, 'server/startup.js'), 'utf8');
const EXPECTED_CTX_KEYS = ['maxBodyBytes', 'getPolicies', 'reloadPolicies', 'policyStore', 'tracing', 'opsIpAllow', 'healthLoopback', 'healthAuth', 'opsOnlyStack',
  'adminStack', 'requirePermission', 'profilingGate', 'portalEnabled', 'portalSessionAuth', 'portalRateLimit', 'rbacResolve'];
const EXPECTED_CALLS = ["createRateLimitMiddleware('ops_admin'", "createRateLimitMiddleware('tenant_portal'", 'createAdminProtection({', 'createOpsAuthMiddleware(_opsConfig, rbacStore, _authLockout)',
  'createOpsIpAllowlistMiddleware(_opsConfig, { envelope: \'management\' })', 'createHealthAuthMiddleware(_opsConfig, rbacStore, _authLockout)', 'createRbacResolveMiddleware({ store: rbacStore })'];
const ctxBlock = (startupSrc.match(/const ctx = \{([\s\S]*?)\n\};/) || [])[1] || '';
const startupCtxKeys = [...ctxBlock.matchAll(/^\s*([A-Za-z_$][\w$]*)\s*:/gm)].map((m) => m[1]);
const drift = { ctxKeysOnlyInStartup: startupCtxKeys.filter((k) => !EXPECTED_CTX_KEYS.includes(k)), ctxKeysMissingInStartup: EXPECTED_CTX_KEYS.filter((k) => !startupCtxKeys.includes(k)),
  factoryCallsMissing: EXPECTED_CALLS.filter((c) => !startupSrc.includes(c)) };
if (drift.ctxKeysOnlyInStartup.length || drift.ctxKeysMissingInStartup.length || drift.factoryCallsMissing.length) {
  console.error('routeGuardTable: server/startup.js ctx drifted from this generator:', JSON.stringify(drift)); process.exit(2);
}
const MAX_BODY_BYTES = (() => { const v = parseInt(process.env.MAX_BODY_BYTES, 10); return Number.isFinite(v) && v > 0 ? v : 65_536; })();
const opsConfig = loadOpsConfig();
const lockout = createAuthLockout(opsConfig);
const requirePermission = createRequirePermission({ isPermitted, isValidPermission });
const { adminStack, opsOnlyStack } = createAdminProtection({
  rateLimit: createRateLimitMiddleware('ops_admin', { envelope: 'legacyFailure' }),
  opsIpAllow: createOpsIpAllowlistMiddleware(opsConfig, { envelope: 'management' }),
  opsAuth: createOpsAuthMiddleware(opsConfig, rbacStore, lockout),
  rbacResolve: createRbacResolveMiddleware({ store: rbacStore }),
  requirePermission, opsGate: createOpsDiagnosticsGate(opsConfig), adminGate: createOpsAdminGate(opsConfig),
});
let policies = []; try { policies = loadPolicies(policyCopy); } catch { policies = []; }
const ctx = {
  maxBodyBytes: MAX_BODY_BYTES, getPolicies: () => policies, reloadPolicies: () => {}, policyStore,
  tracing: { requestMiddleware: function tracingNoop(req, res, next) { next(); } },
  opsIpAllow: createOpsIpAllowlistMiddleware(opsConfig), healthLoopback: createHealthLoopbackMiddleware(opsConfig),
  healthAuth: createHealthAuthMiddleware(opsConfig, rbacStore, lockout), opsOnlyStack, adminStack, requirePermission,
  profilingGate: createProfilingDiagnosticsGate(opsConfig), portalEnabled: true,
  portalSessionAuth: createPortalSessionMiddleware({ verifySessionToken, getPortalUserById: portalUserStore.getById }),
  portalRateLimit: createRateLimitMiddleware('tenant_portal', { envelope: 'management' }), rbacResolve: createRbacResolveMiddleware({ store: rbacStore }),
};
const { createApp } = r('src/app');
const app = createApp(ctx);

// ── 3/4. inspector helpers ───────────────────────────────────────────────────
const session = new inspector.Session(); session.connect();
const post = (m, p) => { let out; let err; session.post(m, p, (e, res) => { err = e; out = res; }); if (err) throw err; return out; };
const scripts = new Map();
session.on('Debugger.scriptParsed', (m) => scripts.set(m.params.scriptId, m.params.url));
post('Debugger.enable');
const fnInfoCache = new Map();
function fnInfo(fn) {
  if (fnInfoCache.has(fn)) return fnInfoCache.get(fn);
  globalThis.__rgtFn = fn;
  const { result } = post('Runtime.evaluate', { expression: 'globalThis.__rgtFn' });
  const props = post('Runtime.getProperties', { objectId: result.objectId, ownProperties: true });
  const loc = (props.internalProperties || []).find((p) => p.name === '[[FunctionLocation]]');
  const scopesRef = (props.internalProperties || []).find((p) => p.name === '[[Scopes]]');
  let file = null; let line = null;
  if (loc) { const url = scripts.get(loc.value.value.scriptId) || ''; file = url.startsWith('file://') ? require('url').fileURLToPath(url) : url; line = loc.value.value.lineNumber + 1; }
  const closure = {}; const closureFns = {};
  if (scopesRef) {
    const scopes = post('Runtime.getProperties', { objectId: scopesRef.value.objectId, ownProperties: true }).result;
    for (const s of scopes) {
      if (!s.value || !/^Closure/.test(s.value.description || '')) continue;
      const vars = post('Runtime.getProperties', { objectId: s.value.objectId, ownProperties: true }).result;
      for (const v of vars) {
        if (!(v.name in closure) && v.value && ['string', 'number', 'boolean'].includes(v.value.type)) closure[v.name] = v.value.value;
        if (!(v.name in closureFns) && v.value && (v.value.type === 'function' || (v.value.type === 'object' && v.value.subtype !== 'null'))) {
          post('Runtime.callFunctionOn', { objectId: v.value.objectId, functionDeclaration: 'function(){ globalThis.__rgtOut = this; }' });
          closureFns[v.name] = globalThis.__rgtOut; // functions AND injected objects (e.g. a store passed to a router factory)
        }
      }
    }
  }
  const info = { name: fn.name || '(anonymous)', file, line, closure, closureFns };
  fnInfoCache.set(fn, info);
  return info;
}

// Guard implementations, by implementing file (labels, not per-route entries).
const GUARD_FILES = [
  ['src/core/rateLimit/middleware.js', 'rateLimit'], ['src/middleware/opsAuth.js', 'auth:ops-api-key'], ['src/middleware/signAuth.js', 'auth:signing-identity'],
  ['src/middleware/portalAuth.js', 'auth:portal-session'], ['src/middleware/healthAuth.js', 'auth:health-token(optional)'], ['src/middleware/opsIpAllowlist.js', 'ipAllowlist'],
  ['src/middleware/rbac.js', 'rbac'], ['src/middleware/opsEnabled.js', 'planeGate'], ['src/middleware/profilingEnabled.js', 'planeGate'],
  ['src/middleware/healthLoopback.js', 'loopbackGate'],
  // Optional admin auth (anonymous → ephemeral; credential → full admin stack) and MFA step-up.
  ['src/middleware/optionalAuth.js', 'auth:ops-api-key(optional)'], ['src/middleware/mfaStepUp.js', 'mfaStepUp'],
];
function classify(fn) {
  const i = fnInfo(fn); const f = rel(i.file) || '';
  const hit = GUARD_FILES.find(([p]) => f === p);
  const g = { fn: `${i.name}@${f}:${i.line}`, kind: hit ? hit[1] : 'other' };
  if (g.kind === 'rateLimit') g.bucket = i.closure.surface;
  if (g.kind === 'rbac') { if (i.name === 'rbacPermissionCheck') { g.kind = 'rbac:permission'; g.permission = i.closure.permission; } else g.kind = 'rbac:resolve'; }
  if (g.kind === 'planeGate') g.gate = i.name;
  if (g.kind === 'auth:ops-api-key(optional)') {
    const layers = Array.isArray(i.closureFns.layers) ? i.closureFns.layers : [];
    const perm = layers.map((l) => fnInfo(l)).find((li) => li.name === 'rbacPermissionCheck');
    g.permission = perm ? perm.closure.permission : null;
  }
  if (g.kind === 'mfaStepUp') {
    const w = i.closureFns.when; const src = typeof w === 'function' ? w.toString() : '';
    g.scope = /GOVERNANCE_STEP_UP/.test(src) ? 'governance approve/publish/schedule/activate' : /RBAC_SELF_ENROLL/.test(src) ? 'all mutations except self MFA enrol/confirm' : 'all mutations';
  }
  if (/jsonParser|urlencodedParser|rawParser|textParser/.test(i.name)) { g.kind = 'bodyParser'; g.limit = i.closure.limit ?? null; }
  return g;
}

// ── 3. walk the router tree ──────────────────────────────────────────────────
function mountPathOf(layer) {
  if (layer.path && typeof layer.path === 'string') return layer.path;
  // A route layer's own path is authoritative; its regexp encodes a param as (?:/([^/]+?)), which the
  // mount-path reconstruction below did not recognise, so /:id routes lost their router-level guards in the table.
  if (layer.route && typeof layer.route.path === 'string') return layer.route.path === '/' ? '' : layer.route.path;
  const src = layer.regexp && layer.regexp.source;
  if (!src || layer.regexp.fast_slash) return '';
  let s = src.replace(/^\^/, '').replace(/\\\/\?\(\?=\\\/\|\$\)$/, '').replace(/\(\?:\(\[\^\\\/\]\+\?\)\)/g, (m, off) => `:${(layer.keys.shift() || { name: 'p' }).name}`).replace(/\\\//g, '/').replace(/\\\./g, '.').replace(/\\-/g, '-');
  s = s.replace(/\/\?\$$/, '').replace(/\$$/, '');
  return s === '/' ? '' : s;
}
const isRouterFn = (f) => typeof f === 'function' && Array.isArray(f.stack);
const routes = []; const unreachable = [];
function delegateRouter(fn) {
  // A shim like (req,res,next)=>{ req.url='/visual'+req.url; innerRouter(req,res,next) } — find the router it calls.
  const src = fn.toString(); const m = src.match(/req\.url\s*=\s*['"]([^'"]+)['"]\s*\+\s*req\.url/);
  globalThis.__rgtFn = fn;
  const { result } = post('Runtime.evaluate', { expression: 'globalThis.__rgtFn' });
  const scopesRef = (post('Runtime.getProperties', { objectId: result.objectId, ownProperties: true }).internalProperties || []).find((p) => p.name === '[[Scopes]]');
  if (!scopesRef) return null;
  for (const s of post('Runtime.getProperties', { objectId: scopesRef.value.objectId, ownProperties: true }).result) {
    if (!s.value || !/^Closure/.test(s.value.description || '')) continue;
    for (const v of post('Runtime.getProperties', { objectId: s.value.objectId, ownProperties: true }).result) {
      if (v.value && v.value.type === 'function' && src.includes(`${v.name}(req, res, next)`)) {
        const got = post('Runtime.callFunctionOn', { objectId: v.value.objectId, functionDeclaration: 'function(){ globalThis.__rgtOut = this; }' });
        void got; const inner = globalThis.__rgtOut; if (isRouterFn(inner)) return { router: inner, stripPrefix: m ? m[1] : '' };
      }
    }
  }
  return null;
}
const terminalCatchAll = (layer) => !layer.route && !isRouterFn(layer.handle) && layer.handle.length < 3 && (mountPathOf(layer) === '');
function walk(stack, prefix, inherited, ctxInfo) {
  const levelLayers = [];
  for (let i = 0; i < stack.length; i++) {
    const layer = stack[i]; const mp = mountPathOf(layer);
    const full = (prefix + mp) || '/';
    if (layer.route) {
      const chain = [...inherited, ...levelLayers.filter((L) => pathCovers(L.full, full)).map((L) => L.handle), ...layer.route.stack.map((s) => s.handle)];
      const methods = Object.keys(layer.route.methods).filter((m) => m !== '_all').map((m) => m.toUpperCase());
      if (layer.route.methods._all) methods.push('ALL');
      routes.push({ path: (prefix + layer.route.path).replace(/\/+$/, '') || '/', methods, chain, handler: layer.route.stack[layer.route.stack.length - 1].handle, portal: ctxInfo.portal, routerId: ctxInfo.routerId, shadowedBy: ctxInfo.shadowedBy });
      continue;
    }
    const handle = layer.handle;
    if (isRouterFn(handle)) {
      const covering = levelLayers.filter((L) => pathCovers(L.full, full) && L.router && L.terminal);
      walk(handle.stack, prefix + mp, [...inherited, ...levelLayers.filter((L) => !L.router && pathCovers(L.full, full)).map((L) => L.handle)],
        { portal: ctxInfo.portal || (prefix + mp).startsWith('/tenant-portal'), routerId: routerIds.get(handle) ?? routerIds.set(handle, routerIds.size + 1).get(handle), shadowedBy: covering.length ? covering[0].full : ctxInfo.shadowedBy });
      levelLayers.push({ full, handle, router: true, terminal: handle.stack.some(terminalCatchAll) });
      continue;
    }
    const d = delegateRouter(handle);
    if (d) {
      const covering = levelLayers.filter((L) => pathCovers(L.full, full) && L.router && L.terminal);
      const inner = d.router;
      const sub = inner.stack.map((L) => L);
      // walk the delegate with its declared paths; strip the rewrite prefix so rows show the real request path
      const before = routes.length;
      walk(sub, prefix + mp, [...inherited, ...levelLayers.filter((L) => !L.router && pathCovers(L.full, full)).map((L) => L.handle), handle],
        { portal: ctxInfo.portal, routerId: routerIds.get(inner) ?? routerIds.set(inner, routerIds.size + 1).get(inner), shadowedBy: covering.length ? covering[0].full : ctxInfo.shadowedBy });
      for (let k = before; k < routes.length; k++) routes[k].path = routes[k].path.replace(prefix + mp + d.stripPrefix, prefix + mp) || '/';
      levelLayers.push({ full, handle, router: true, terminal: inner.stack.some(terminalCatchAll) });
      continue;
    }
    levelLayers.push({ full, handle, router: false });
  }
}
const routerIds = new Map();
function pathCovers(mount, p) { if (mount === '/' || mount === '') return true; return p === mount || p.startsWith(mount + '/') || (mount.includes(':') && new RegExp('^' + mount.replace(/:[^/]+/g, '[^/]+') + '(/|$)').test(p)); }
walk(app._router.stack, '', [], { portal: false, routerId: 0, shadowedBy: null });

// static files (express.static) → one synthetic row
const staticLayer = app._router.stack.find((L) => L.handle && L.handle.name === 'serveStatic');

// ── 5. static write analysis ─────────────────────────────────────────────────
const acorn = require('acorn'); const walkAst = require('acorn-walk');
const fileCache = new Map();
function parseFile(file) {
  if (fileCache.has(file)) return fileCache.get(file);
  let src = ''; try { src = fs.readFileSync(file, 'utf8'); } catch { fileCache.set(file, null); return null; }
  let ast; try { ast = acorn.parse(src.replace(/^#!.*/, ''), { ecmaVersion: 'latest', sourceType: 'script', allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true }); } catch { fileCache.set(file, null); return null; }
  const funcs = new Map(); const requires = new Map(); const destructured = new Map(); const aliases = new Map(); const wrappers = [];
  const factoryInstances = []; // `const store = createX(...)` with createX imported → store's members live in createX's module
  const addFn = (name, node) => { if (!name) return; if (!funcs.has(name)) funcs.set(name, []); funcs.get(name).push(node); };
  const reqPath = (node) => (node && node.type === 'CallExpression' && node.callee.name === 'require' && node.arguments[0] && node.arguments[0].type === 'Literal' ? node.arguments[0].value : null);
  walkAst.full(ast, (n) => {
    if (n.type === 'FunctionDeclaration' && n.id) addFn(n.id.name, n);
    if (n.type === 'VariableDeclarator') {
      if (n.id.type === 'Identifier' && n.init && /Function/.test(n.init.type)) addFn(n.id.name, n.init);
      const rq = reqPath(n.init) || (n.init && n.init.type === 'MemberExpression' ? reqPath(n.init.object) : null);
      if (rq) {
        const resolved = resolveReq(file, rq);
        if (n.id.type === 'Identifier') { if (n.init.type === 'MemberExpression') destructured.set(n.id.name, { file: resolved, name: n.init.property.name }); else requires.set(n.id.name, resolved); }
        if (n.id.type === 'ObjectPattern') for (const p of n.id.properties) if (p.type === 'Property') destructured.set(p.value.name || (p.value.left && p.value.left.name), { file: resolved, name: p.key.name });
      }
    }
    if ((n.type === 'Property' || n.type === 'MethodDefinition') && n.key && /Function/.test((n.value || {}).type || '')) addFn(n.key.name || n.key.value, n.value);
    // re-export aliases: { grant: registry.grant } / { grant } / { grant: _grant }
    if (n.type === 'Property' && n.key && n.value && !/Function/.test(n.value.type)) {
      const k = n.key.name || n.key.value;
      if (n.value.type === 'MemberExpression' && n.value.object.type === 'Identifier' && n.value.property.type === 'Identifier') aliases.set(k, { obj: n.value.object.name, prop: n.value.property.name });
      if (n.value.type === 'Identifier' && n.value.name !== k) aliases.set(k, { ident: n.value.name });
    }
    if (n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression' && /Function/.test(n.right.type)) addFn(n.left.property.name, n.right);
    // The bench stage timer's wrappers are transparent — `const f = ST.timeAsync('S33', g)` (or
    // timeSync / wrapMiddleware) calls g, so f must resolve to g or the write sinks behind g vanish
    // from this analysis. Resolved after the walk (g may be declared later in the file).
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init && n.init.type === 'CallExpression'
        && n.init.callee.type === 'MemberExpression' && n.init.callee.property.type === 'Identifier'
        && /^(timeSync|timeAsync|wrapMiddleware)$/.test(n.init.callee.property.name) && n.init.arguments.length === 2) {
      wrappers.push([n.id.name, n.init.arguments[1]]);
    }
    // Factory instances. transparencyKeyStore.js became `const store = createEd25519KeyStore({...})` and
    // re-exports `getActiveKey: store.getActiveKey`; the lazy first-key write now sits in the factory's inner
    // functions (ed25519KeyStore.js). Without this, `store` resolves to nothing and that file write — still real —
    // vanished from the analysis. Only `create*` callees imported from another module are treated this way.
    if (n.type === 'VariableDeclarator' && n.id.type === 'Identifier' && n.init && n.init.type === 'CallExpression'
        && n.init.callee.type === 'Identifier' && /^create[A-Z]/.test(n.init.callee.name)) {
      factoryInstances.push([n.id.name, n.init.callee.name]);
    }
  });
  for (const [name, callee] of factoryInstances) { // see above — resolved after the walk (imports may come later)
    const d = destructured.get(callee);
    if (d && d.file && !requires.has(name)) requires.set(name, d.file);
  }
  for (const [name, target] of wrappers) { // transparent stage-timer wrappers (see above)
    if (target.type === 'Identifier') {
      if (destructured.has(target.name)) destructured.set(name, destructured.get(target.name));
      else if (funcs.has(target.name)) for (const f of funcs.get(target.name)) addFn(name, f);
      else if (requires.has(target.name)) requires.set(name, requires.get(target.name));
    } else if (target.type === 'MemberExpression' && target.property.type === 'Identifier') {
      const rq = reqPath(target.object);
      if (rq) destructured.set(name, { file: resolveReq(file, rq), name: target.property.name });
      else if (target.object.type === 'Identifier' && requires.has(target.object.name)) destructured.set(name, { file: requires.get(target.object.name), name: target.property.name });
    }
  }
  const out = { file, src, ast, funcs, requires, destructured, aliases };
  fileCache.set(file, out); return out;
}
function resolveReq(from, spec) { if (!spec.startsWith('.')) return null; try { return require.resolve(path.resolve(path.dirname(from), spec)); } catch { return null; } }
const SINKS = [
  { kind: 'audit', test: (f, name) => rel(f) === 'src/core/audit/audit-log.js' && /^append/.test(name) },
  { kind: 'transparency', test: (f, name) => rel(f) === 'src/core/transparency/registrar.js' && /^(register|generateRoot)$/.test(name) },
];
const SQL_WRITE = /\b(INSERT\s+INTO|UPDATE\s+[a-z_"]+\s+SET|DELETE\s+FROM)\b/i;
// control-plane stores write through their Collection (_col.put/_col.remove) to PostgreSQL.
const CP_WRITE = /\b_col\.(put|remove)\s*\(/;
const FS_WRITE = /\bfs(?:p|Promises|\.promises)?\.(writeFileSync|writeFile|appendFileSync|appendFile|renameSync|copyFileSync|createWriteStream)\s*\(/;
function analyseWrites(fn, runtimeScope = null) {
  const info = fnInfo(fn); if (!info.file || !info.file.startsWith(REPO)) return { writes: [], via: [] };
  // Runtime bindings for dependency-injected objects: `store.createUser()` where `store` is a closure object of
  // the handler (e.g. passed to the router factory) resolves to the real method's source location.
  const scopeObjs = runtimeScope || info.closureFns;
  const found = new Set(); const via = [];
  const seen = new Set();
  const visit = (file, node, depth, label) => {
    const key = `${file}:${node.start}`; if (seen.has(key) || depth > 7) return; seen.add(key);
    const P = parseFile(file); if (!P) return;
    const text = P.src.slice(node.start, node.end);
    for (const s of SINKS) if (s.test(file, label)) { found.add(s.kind); via.push(`${s.kind}←${rel(file)}#${label}`); }
    if (SQL_WRITE.test(text)) { found.add('db'); via.push(`db←${rel(file)}#${label}`); }
    if (FS_WRITE.test(text)) { found.add('files'); via.push(`files←${rel(file)}#${label}`); }
    if (CP_WRITE.test(text)) { found.add('control-plane'); via.push(`control-plane←${rel(file)}#${label}`); }
    walkAst.simple(node, { CallExpression(c) {
      const cal = c.callee;
      if (cal.type === 'Identifier') {
        if (P.funcs.has(cal.name)) for (const f of P.funcs.get(cal.name)) if (f !== node) visit(file, f, depth + 1, cal.name);
        const d = P.destructured.get(cal.name); if (d && d.file) visitExport(d.file, d.name, depth + 1);
      } else if (cal.type === 'MemberExpression' && cal.object.type === 'Identifier' && cal.property.type === 'Identifier') {
        const m = P.requires.get(cal.object.name); if (m) visitExport(m, cal.property.name, depth + 1);
        else if (scopeObjs && scopeObjs[cal.object.name] && typeof scopeObjs[cal.object.name] === 'object' && typeof scopeObjs[cal.object.name][cal.property.name] === 'function') {
          const target = fnInfo(scopeObjs[cal.object.name][cal.property.name]);
          if (target.file && target.file.startsWith(REPO)) {
            const TP = parseFile(target.file);
            if (TP) {
              const lines = TP.src.split('\n'); let off = 0; for (let i = 0; i < target.line - 1; i++) off += lines[i].length + 1;
              let node = null; walkAst.full(TP.ast, (x) => { if (/Function/.test(x.type) && x.start >= off - 1 && x.start <= off + lines[target.line - 1].length && (!node || x.start < node.start)) node = x; });
              if (node) visit(target.file, node, depth + 1, cal.property.name);
            }
          }
        } else if (P.funcs.has(cal.property.name) && ['this', 'self'].includes(cal.object.name) === false) { /* instance method of a local object: follow same-file definitions */ for (const f of P.funcs.get(cal.property.name)) if (f !== node) visit(file, f, depth + 1, cal.property.name); }
      }
    } });
  };
  const visitExport = (file, name, depth) => {
    const P = parseFile(file); if (!P) return;
    for (const s of SINKS) if (s.test(file, name)) { found.add(s.kind); via.push(`${s.kind}←${rel(file)}#${name}`); }
    for (const f of P.funcs.get(name) || []) visit(file, f, depth, name);
    const d = P.destructured.get(name); if (d && d.file) visitExport(d.file, d.name, depth + 1);
    const a = P.aliases.get(name);
    if (a && depth < 8) {
      if (a.obj && P.requires.get(a.obj)) visitExport(P.requires.get(a.obj), a.prop, depth + 1);
      if (a.ident) visitExport(file, a.ident, depth + 1);
    }
  };
  // locate the handler node by its source position
  const P = parseFile(info.file); if (!P) return { writes: [], via: [] };
  const lines = P.src.split('\n'); let offset = 0; for (let i = 0; i < info.line - 1; i++) offset += lines[i].length + 1;
  let best = null;
  walkAst.full(P.ast, (n) => { if (/Function/.test(n.type) && n.start <= offset + lines[info.line - 1].length && n.end > offset && (!best || n.start >= best.start) && n.start >= offset - 1) best = n; });
  if (!best) walkAst.full(P.ast, (n) => { if (/Function/.test(n.type) && n.start <= offset && n.end >= offset && (!best || n.start > best.start)) best = n; });
  if (best) visit(info.file, best, 0, info.name);
  return { writes: [...found].sort(), via: [...new Set(via)].slice(0, 6) };
}

// ── table assembly ──────────────────────────────────────────────────────────
// A generic handler wrapper (e.g. `_wrap(handler)` → `async (req,res) => { … await handler(req,res,actor) }`)
// closes over the real handler: follow any closure function the wrapper calls by name, repeatedly.
function unwrap(fn) {
  for (let i = 0; i < 4; i++) {
    const info = fnInfo(fn); const src = fn.toString();
    // A wrapper HANDS OVER the request: the call `name(req, res…)` is in statement position (after ; { } =>,
    // a line start, or `return`/`await` in such a position). A helper whose result is used is not followed.
    const handsOver = (n) => [...src.matchAll(new RegExp(`\\b${n}\\s*\\(\\s*req\\s*,\\s*res\\b`, 'g'))].some((m) => {
      let before = src.slice(0, m.index).replace(/\s+$/, '');
      if (/\bawait$/.test(before)) before = before.slice(0, -5).replace(/\s+$/, '');
      if (/\breturn$/.test(before)) before = before.slice(0, -6).replace(/\s+$/, '');
      return before === '' || /[;{}]$|=>$|\n$/.test(before) || /^[^\n]*$/.test(before) === false && /\n\s*$/.test(src.slice(0, m.index));
    });
    const inner = Object.entries(info.closureFns).find(([n, f]) => typeof f === 'function' && f !== fn && handsOver(n) && fnInfo(f).file && fnInfo(f).file.startsWith(REPO));
    if (!inner) return fn; fn = inner[1];
  }
  return fn;
}
const rows = [];
for (const rt of routes) {
  rt.handler = unwrap(rt.handler);
  const guards = rt.chain.map(classify);
  const kinds = guards.map((g) => g.kind);
  // healthAuth is OFF unless QODIQA_HEALTH_PROBE_AUTH_REQUIRED=true: it does not make a route authenticated.
  const auth = guards.filter((g) => g.kind.startsWith('auth:') && !/optional/.test(g.kind)).map((g) => g.kind.slice(5));
  const optionalAuth = guards.filter((g) => /optional/.test(g.kind)).map((g) => g.kind.slice(5) + (g.permission ? `[${g.permission}]` : ''));
  const mfa = guards.find((g) => g.kind === 'mfaStepUp');
  const handlerSrc = rt.handler.toString();
  const artifactAuth = /x-qodiqa-artifact|validateBoundRequest|_enforce/.test(handlerSrc) && rel(fnInfo(rt.handler).file || '').match(/aiChat\.js|verify\.js/);
  const perms = guards.filter((g) => g.kind === 'rbac:permission').map((g) => g.permission);
  const buckets = [...new Set(guards.filter((g) => g.kind === 'rateLimit').map((g) => g.bucket))];
  const parsers = guards.filter((g) => g.kind === 'bodyParser').map((g) => g.limit);
  const w = analyseWrites(rt.handler);
  const hInfo = fnInfo(rt.handler);
  const publicRoute = auth.length === 0 && !artifactAuth;
  const gaps = [];
  if (rt.shadowedBy) gaps.push(`UNREACHABLE (shadowed by a next-less catch-all under ${rt.shadowedBy})`);
  if (publicRoute && w.writes.length) gaps.push(`PUBLIC WRITE (${w.writes.join('+')})`);
  if (artifactAuth && w.writes.length) gaps.push(`WRITES REACHABLE BEFORE CALLER AUTH (auth is in-handler; ${w.writes.join('+')})`);
  if (auth.includes('ops-api-key') && perms.length === 0) gaps.push('AUTHENTICATED, NO RBAC PERMISSION');
  if (buckets.length === 0 && !/^\/(health|ready)(\/|$)/.test(rt.path)) gaps.push('NO RATE LIMIT');
  if (buckets.length === 0 && /^\/(health|ready)(\/|$)/.test(rt.path)) gaps.push('no rate limit (probe endpoints)');
  rows.push({
    methods: rt.methods, path: rt.path, routerId: rt.routerId, conditional: rt.portal ? 'QODIQA_PORTAL_ENABLED=true' : null,
    access: publicRoute ? 'public' : 'authenticated', auth: artifactAuth ? [...auth, 'signed-artifact(in handler)'] : auth,
    optionalAuth, permissions: perms, rateLimitBuckets: buckets, planeGates: guards.filter((g) => g.kind === 'planeGate').map((g) => g.gate),
    mfaStepUp: mfa ? mfa.scope : null,
    ipAllowlist: kinds.includes('ipAllowlist'), bodyLimit: parsers.length ? parsers.join('/') : `global express.json ${MAX_BODY_BYTES} B`,
    writes: w.writes, writesVia: w.via, handler: `${hInfo.name}@${rel(hInfo.file)}:${hInfo.line}`, chain: guards.filter((g) => g.kind !== 'other').map((g) => g.kind + (g.bucket ? `(${g.bucket})` : g.permission ? `(${g.permission})` : '')), gaps,
  });
}
// aliases: the same router instance mounted under several prefixes
const byRouter = new Map();
for (const row of rows) { const k = `${row.routerId}|${row.methods.join(',')}|${row.path.replace(/^\/v1(?=\/)/, '')}`; if (!byRouter.has(k)) byRouter.set(k, []); byRouter.get(k).push(row.path); }
for (const row of rows) { const k = `${row.routerId}|${row.methods.join(',')}|${row.path.replace(/^\/v1(?=\/)/, '')}`; row.aliases = byRouter.get(k).filter((p) => p !== row.path); }

const http = require('http');
const out = {
  generatedAt: new Date().toISOString(),
  sha: (() => { try { return require('child_process').execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).trim(); } catch { return null; } })(),
  global: {
    bodyLimitBytes: MAX_BODY_BYTES, maxHeaderSizeBytes: http.maxHeaderSize, maxHeadersCount: 100,
    routing: 'Express 4 defaults: case-insensitive, non-strict (trailing slash matches)',
    rateLimiterEnabledNow: require(path.join(REPO, 'src/core/rateLimit'))._isRlEnabled(),
    globalMiddleware: app._router.stack.filter((L) => !L.route && !isRouterFn(L.handle) && mountPathOf(L) === '').map((L) => { const i = fnInfo(L.handle); return `${i.name}@${rel(i.file)}:${i.line}`; }),
    staticFiles: staticLayer ? 'express.static(public/) — public, GET/HEAD, no limiter' : null,
  },
  rows,
};
fs.mkdirSync(path.dirname(JSON_OUT), { recursive: true });
fs.writeFileSync(JSON_OUT, JSON.stringify(out, null, 1));

const esc = (s) => String(s).replace(/\|/g, '\\|');
const gapRows = rows.filter((x) => x.gaps.some((g) => !/F-28/.test(g)));
const md = [];
md.push('# Route → guard table (generated)', '');
md.push(`Generated ${out.generatedAt} at \`${out.sha}\` by \`scripts/security/routeGuardTable.js\` — do not edit by hand.`, '');
md.push('## Global', '');
md.push(`- Body limit: \`express.json\` ${MAX_BODY_BYTES} bytes for every route (no route has its own parser). Headers: Node \`maxHeaderSize\` ${http.maxHeaderSize} bytes, \`maxHeadersCount\` 100 (\`src/infra/network/tlsDefaults.js\`).`);
md.push(`- Routing: ${out.global.routing}. Every row therefore also answers its trailing-slash and case variants.`);
md.push(`- Rate limiters: every bucket below is a **no-op unless \`REDIS_URL\` or \`RL_ENABLED=true\`** (\`src/core/rateLimit/middleware.js\` \`_isRlEnabled\`). In this generator's environment: enabled = ${out.global.rateLimiterEnabledNow}.`);
md.push(`- Global middleware (every request): ${out.global.globalMiddleware.map((g) => `\`${g}\``).join(', ')}.`);
md.push(`- Static files: ${out.global.staticFiles}.`, '');
md.push('## Gap rules', '', '- **PUBLIC WRITE**: no authentication middleware and no in-handler signed artifact, and the handler reaches a write sink.',
  '- **WRITES REACHABLE BEFORE CALLER AUTH**: authentication happens inside the handler (signed artifact), and the handler reaches a write sink (rejected requests may write).',
  '- **AUTHENTICATED, NO RBAC PERMISSION**: ops-API-key authentication but no `requirePermission` on the mount or the route.',
  '- **NO RATE LIMIT**: no limiter in the chain. **UNREACHABLE**: an earlier router on a covering prefix ends in a next-less catch-all.', '',
  'Writes are static analysis (lower bound): calls followed from the handler through same-file functions and required modules to audit-log append, transparency register/generateRoot, SQL INSERT/UPDATE/DELETE, fs writes. Logger `emit()` is not counted as a write.', '');
md.push(`## Gaps (${gapRows.length} routes)`, '');
md.push('| Method | Path | Gaps |', '|---|---|---|');
for (const x of gapRows) md.push(`| ${x.methods.join(',')} | \`${esc(x.path)}\` | ${x.gaps.filter((g) => !/F-28/.test(g)).map(esc).join('; ')} |`);
md.push('', `## All routes (${rows.length})`, '');
md.push('| Method | Path | Aliases | Access | Auth | RBAC permission | Rate-limit bucket | Gates | Writes | Handler | Gaps |', '|---|---|---|---|---|---|---|---|---|---|---|');
for (const x of rows.slice().sort((a, b) => a.path.localeCompare(b.path) || a.methods.join().localeCompare(b.methods.join()))) {
  md.push(`| ${x.methods.join(',')} | \`${esc(x.path)}\`${x.conditional ? ' (portal)' : ''} | ${x.aliases.map((a) => `\`${esc(a)}\``).join(' ') || ''} | ${x.access} | ${esc(x.auth.join(', ') || '—')} | ${esc(x.permissions.join(', ') || '—')} | ${esc(x.rateLimitBuckets.join(', ') || '—')} | ${esc([x.ipAllowlist ? 'ipAllow' : null, x.mfaStepUp ? `MFA step-up (${x.mfaStepUp})` : null, ...x.planeGates, ...x.optionalAuth.map((a) => `${a} (opt-in)`)].filter(Boolean).join(', ') || '—')} | ${esc(x.writes.join(', ') || '—')} | \`${esc(x.handler)}\` | ${esc(x.gaps.join('; ') || '')} |`);
}
fs.writeFileSync(MD_OUT, md.join('\n') + '\n');
console.log(JSON.stringify({ routes: rows.length, gapRoutes: gapRows.length, md: rel(MD_OUT), json: rel(JSON_OUT), isolation: ISO }));
session.disconnect();
process.exit(0);
