'use strict';

/**
 * Per-request audit context.
 *
 * Audit v8 records, in every entry a request produces, WHEN the artifact it consumed was issued and WHICH protocol
 * version it used (`issuedAt`, `protocolVersion`). Those two facts are known once, right after the artifact is verified,
 * but the entries are written from many places (decisions, lifecycle entries, the stream path). Instead of threading
 * the values through every call site, the route installs a mutable holder in an AsyncLocalStorage for the lifetime of
 * the request, the enforcement pipeline binds the verified values into it, and `entryBuilder.normalizeFields` reads them
 * for an entry of the SAME request (matched by requestId, so an entry of another request, or a system entry, can never
 * pick them up). Outside a request (boot reconciliation, background writers) there is no holder and the fields stay null.
 */

const { AsyncLocalStorage } = require('async_hooks');

const _als = new AsyncLocalStorage();

/**
 * Express middleware: runs the rest of the request inside a fresh, empty holder.
 *
 * It also lets a BLOCK response carry the signed receipt of its own decision: the audit/transparency write of a BLOCK
 * happens deep inside the pipeline, far from the many places that answer the client, so the writer parks the receipt in the
 * holder and `res.json` adds it to a response body that states a decision and has no receipt of its own. An EXECUTE response
 * states its receipt explicitly (and caches it for idempotent replays), so this never touches it.
 */
function requestAuditContextMiddleware(_req, res, next) {
  const holder = { requestId: null, issuedAt: null, protocolVersion: null, receipt: null, clientGone: false };
  // the client closed the connection before the application ended the response (a response ended on a dead socket still "finishes")
  if (res && typeof res.once === 'function') res.once('close', () => { if (!res.writableEnded) holder.clientGone = true; });
  if (res && typeof res.json === 'function') {
    const original = res.json;
    res.json = function receiptAwareJson(body) {
      if (holder.receipt && body && typeof body === 'object' && !Array.isArray(body) && body.decision !== undefined && body.receipt === undefined) {
        return original.call(this, { ...body, receipt: holder.receipt });
      }
      return original.call(this, body);
    };
  }
  _als.run(holder, next);
}

/** Park the receipt of this request's own decision (a no-op outside a request, or for another request's id). */
function setRequestReceipt(requestId, receipt) {
  const store = _als.getStore();
  if (!store || !store.requestId || store.requestId !== requestId || !receipt) return false;
  store.receipt = receipt;
  return true;
}

/** Bind the verified artifact facts for this request; a no-op outside a request context. */
function bindArtifactFacts({ requestId, issuedAt, protocolVersion }) {
  const store = _als.getStore();
  if (!store) return;
  store.requestId = typeof requestId === 'string' && requestId ? requestId : null;
  store.issuedAt = Number.isSafeInteger(issuedAt) && issuedAt >= 0 ? issuedAt : null;
  store.protocolVersion = Number.isSafeInteger(protocolVersion) && protocolVersion >= 1 ? protocolVersion : null;
}

/** The holder of the current request, or null. */
function currentArtifactFacts() {
  return _als.getStore() || null;
}

module.exports = { requestAuditContextMiddleware, bindArtifactFacts, currentArtifactFacts, setRequestReceipt };
