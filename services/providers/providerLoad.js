'use strict';

/**
 * In-flight call counter per provider: the "load" signal of policy routing (strategy `least-loaded`). Counts calls this process has dispatched to a provider and not yet
 * finished; it is per process by design (a routing hint, never a security or accounting control).
 */

const inflight = new Map();

function begin(name) {
  inflight.set(name, (inflight.get(name) || 0) + 1);
  let done = false;
  return () => { if (done) return; done = true; const n = (inflight.get(name) || 1) - 1; if (n <= 0) inflight.delete(name); else inflight.set(name, n); };
}

/** Run an async call while counting it. */
async function track(name, fn) {
  const end = begin(name);
  try { return await fn(); } finally { end(); }
}

const get = (name) => inflight.get(name) || 0;
const resetAll = () => inflight.clear();

module.exports = { begin, track, get, resetAll };
