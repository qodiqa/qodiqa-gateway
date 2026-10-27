'use strict';

// await fire-and-forget work a suite itself started, before the
// suite closes the PostgreSQL pool.
//
// Some production paths deliberately do not await a post-commit side effect
// (audit-log.js → pgAuditBackend.recordEvidenceForEntry() in distributed mode;
// ConsentVerifier → store.logVerification()). A suite that closes the pool in
// afterAll while such a call is still in flight gets a pool-acquire failure
// after Jest has torn the environment down — "You are trying to `require` a
// file after the Jest environment has been torn down" — and Jest exits 1 even
// though every test passed. A sleep would only make that less likely; this
// waits for exactly the promises that are outstanding.
//
// trackInFlight(moduleObject, 'method') wraps the method on that exact module
// instance (callers must look it up as a property at call time, which both
// call sites above do) and returns { settle, restore }:
//   settle()  — resolves once every promise the method has returned so far,
//               and any started while waiting, has settled;
//   restore() — puts the original method back.

function trackInFlight(obj, method) {
  const original = obj[method];
  if (typeof original !== 'function') throw new Error(`trackInFlight: ${method} is not a function`);
  const pending = new Set();
  obj[method] = function tracked(...args) {
    // Called synchronously, exactly as the caller would call the original —
    // no added microtask, same return value.
    const ret = original.apply(this, args);
    const p = Promise.resolve(ret);
    pending.add(p);
    p.then(() => pending.delete(p), () => pending.delete(p));
    return ret;
  };
  return {
    async settle() {
      while (pending.size) await Promise.allSettled([...pending]);
    },
    restore() { obj[method] = original; },
    get size() { return pending.size; },
  };
}

module.exports = { trackInFlight };
