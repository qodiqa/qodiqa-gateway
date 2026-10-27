'use strict';

/**
 * the LIVE route surface of the real Express app (OpenAPI ground truth).
 *
 * routeParity.test.js extracts routes from router source text through a hand-copied mount table (routeMounts.js).
 * This module reads what the assembled application actually mounts. instrument() wraps Express's app.use and
 * Router.use so every mounted layer records the path it was mounted at, and wraps express.Router so every router the
 * application creates is known. collect(app) then walks the real router stack and returns:
 *   routes      every (method, full path) the app dispatches through mounted routers (sorted, unique, OpenAPI {param})
 *   unreached   routers that were created and carry routes but are NOT reachable through a mounted layer — i.e. invoked
 *               from a wrapper closure (e.g. src/app.js /v1/policy/visual, which rewrites req.url) or never mounted
 *               at all. Each must be explained by the caller (a reviewed resolver) or it is drift / dead code.
 *   nonString   regex/non-string route or mount paths (the spec cannot represent them)
 * Nothing about the routes is restated here.
 *
 * Usage (must run BEFORE the app is built):
 *   const live = require('./liveRoutes'); live.instrument(require('express'));
 *   const app = require('../../server');   // the real composition root
 *   live.collect(app)
 */

const MARK = Symbol.for('qodiqa.w12.liveRoutes.instrumented');
const _created = [];

function _tag(stack, from, p) { for (let i = from; i < stack.length; i++) stack[i].__qodiqaMountPath = p; }
const _mountArg = (args) => (typeof args[0] === 'string' || Array.isArray(args[0]) ? args[0] : '/');

function instrument(express) {
  if (express[MARK]) return;
  const appUse = express.application.use;
  express.application.use = function use(...args) {
    if (typeof this.lazyrouter === 'function') this.lazyrouter();
    const before = this._router ? this._router.stack.length : 0;
    const r = appUse.apply(this, args);
    _tag(this._router.stack, before, _mountArg(args));
    return r;
  };
  const OrigRouter = express.Router;
  const proto = Object.getPrototypeOf(OrigRouter());
  const routerUse = proto.use;
  proto.use = function use(...args) {
    const before = this.stack.length;
    const r = routerUse.apply(this, args);
    _tag(this.stack, before, _mountArg(args));
    return r;
  };
  express.Router = function Router(...a) { const r = OrigRouter.apply(this, a); _created.push(r); return r; };
  express[MARK] = true;
}

// join a prefix and a route path; a trailing '/' declared by the route itself is kept ('/docs/' ≠ '/docs')
function _join(prefix, p, keepTrailing) {
  const j = (`${prefix}/${p}`).replace(/\/+/g, '/');
  return keepTrailing && p.length > 1 && p.endsWith('/') ? j : j.replace(/(.)\/$/, '$1');
}
// Express ':name' (optionally with a (regex) constraint and/or '?') → OpenAPI '{name}'
const _toOpenApi = (p) => p.replace(/:([A-Za-z0-9_]+)(\([^)]*\))?\??/g, '{$1}');

/** Routes of one router, relative to it (no mount prefix), in OpenAPI form. */
function routesOf(router, prefix = '') {
  const out = new Set(); const nonString = [];
  (function walk(stack, pre, seen) {
    for (const l of stack) {
      if (l.route) {
        const paths = Array.isArray(l.route.path) ? l.route.path : [l.route.path];
        for (const p of paths) {
          if (typeof p !== 'string') { nonString.push(`${pre} ${String(p)}`); continue; }
          for (const m of Object.keys(l.route.methods)) if (l.route.methods[m] && m !== '_all') out.add(`${m} ${_toOpenApi(_join(pre, p, true))}`);
        }
      } else if (l.handle && Array.isArray(l.handle.stack)) {
        seen.add(l.handle);
        const mounts = Array.isArray(l.__qodiqaMountPath) ? l.__qodiqaMountPath : [l.__qodiqaMountPath || '/'];
        for (const m of mounts) {
          if (typeof m !== 'string') { nonString.push(`${pre} ${String(m)}`); continue; }
          walk(l.handle.stack, _join(pre, m, false), seen);
        }
      }
    }
  }(router.stack, prefix, routesOf._seen || new Set()));
  return { routes: [...out].sort(), nonString };
}

function collect(app) {
  if (!app || !app._router) throw new Error('liveRoutes.collect: not an Express 4 app (no _router)');
  const seen = new Set([app._router]);
  routesOf._seen = seen;
  const { routes, nonString } = routesOf(app._router, '');
  routesOf._seen = null;
  const unreached = _created.filter((r) => !seen.has(r)).map((r) => ({ router: r, routes: routesOf(r, '').routes })).filter((u) => u.routes.length > 0);
  return { routes, nonString, unreached };
}

module.exports = { instrument, collect, routesOf, _toOpenApi };
