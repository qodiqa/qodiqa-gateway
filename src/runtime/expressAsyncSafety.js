'use strict';

/**
 * Express 4 does not catch rejections from async route handlers: a rejected promise becomes an unhandledRejection, which
 * src/runtime/processHardening.js treats as a coding error on the primary path and answers with process.exit(1) — one failing
 * request (e.g. AUDIT_HISTORY_UNAVAILABLE, a PostgreSQL error, a TypeError in an admin route) then takes down the whole gateway.
 * (Z01a R1/R2: GET /audit-viewer/replay/:artifactId reproduced exactly this on the real application.)
 *
 * This patches Layer#handle_request once, process-wide, so that a promise returned by ANY route/middleware handler that
 * rejects is forwarded to next(err) — i.e. to the app's final error middleware (500 JSON) — exactly as Express 5 does. The
 * behaviour for synchronous throws and for non-promise returns is unchanged. The process-level unhandledRejection backstop
 * stays in place for rejections that do not originate in a route handler.
 */

const Layer = require('express/lib/router/layer');

const PATCH_MARK = Symbol.for('qodiqa.expressAsyncSafety');

function install() {
  if (Layer.prototype.handle_request[PATCH_MARK]) return false;
  Layer.prototype.handle_request = function handleRequest(req, res, next) {
    const fn = this.handle;
    if (fn.length > 3) return next(); // error-handling middleware: not a standard request handler
    try {
      const out = fn(req, res, next);
      if (out && typeof out.then === 'function') out.then(undefined, next);
    } catch (err) {
      next(err);
    }
  };
  Layer.prototype.handle_request[PATCH_MARK] = true;
  return true;
}

module.exports = { install };
