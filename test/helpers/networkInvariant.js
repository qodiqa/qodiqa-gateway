'use strict';

/**
 * SEM-F — reusable network-call interceptor for asserting the D3 invariant
 * ("no calls outside the local machine on the decision path" — localhost
 * Ollama/ONNX permitted, cloud not) as a dedicated, named, tested property
 * rather than an implicit consequence of today's implementation choices.
 *
 * Generalized from the pattern first proven in SEM-C sessions 2-4
 * ('s
 * verifyNoNetwork()) — one implementation, two consumers now:
 *   - that script's real-model D3 check, CI-gated via
 *     .github/workflows/test.yml's embedding-similarity-gate job (hard
 *     check — non-zero exit on violation).
 
 *     (this repo's Jest-hosted regression suite, test:unit, mocked
 *     embedding backend — proves the wiring/glue code around the
 *     classifiers never makes an outbound call, independent of whether the
 *     real ONNX model itself does).
 * See that test file's header for why both layers exist and neither
 * subsumes the other.
 *
 * Scope, deliberately: patches http.request/http.get, https.request/
 * https.get, and global.fetch — the public call surfaces every HTTP-ish
 * outbound request in this codebase goes through. Does NOT patch
 * undici/net.connect internals directly: nothing on the semantic decision
 * path calls them directly (confirmed by inspection — @xenova/transformers
 * itself only uses fetch/https, never undici or net), and patching a
 * transitive dependency's internals instead of the public API boundary
 * would be fragile for no real coverage gain. Raw TCP infra connections
 * (Postgres, Redis) are a different, already-covered concern, not what D3
 * is about — this interceptor would not and should not catch those.
 */

const http = require('http');
const https = require('https');

const LOCALHOST_ALLOWLIST = new Set(['127.0.0.1', '::1', 'localhost']);

class NetworkInvariantViolation extends Error {
  constructor(mod, host) {
    super(`NETWORK INVARIANT VIOLATION (D3): ${mod} call to non-localhost host "${host}" attempted on the semantic decision path`);
    this.name = 'NetworkInvariantViolation';
    this.mod = mod;
    this.host = host;
  }
}

function _hostFromArgs(args) {
  const first = args[0];
  if (typeof first === 'string') {
    try { return new URL(first).hostname; } catch { return first; }
  }
  if (first instanceof URL) return first.hostname;
  if (first && typeof first === 'object') return first.hostname || first.host || '(unknown)';
  return '(unknown)';
}

/**
 * Installs the interceptor. Returns:
 *   - state: { callCount, calls: [{mod, host}] } — mutated live as calls happen
 *   - restore(): MUST be called (e.g. afterEach) to remove the patch —
 *     leaving it installed would leak into unrelated tests in the same
 *     process/module registry.
 *
 * A call to an allowlisted host is recorded in `state` but does not throw —
 * this matches D3's own governing text ("localhost ... permitted, cloud
 * not"), not a stricter "zero calls ever" property (that stronger claim,
 * where it happens to hold — e.g. classify() with cached ONNX weights —
 * is what runRealModelVerification.js's own D3 check separately asserts).
 */
function installNetworkInvariant() {
  const state = { callCount: 0, calls: [] };

  const original = {
    httpRequest: http.request,
    httpGet: http.get,
    httpsRequest: https.request,
    httpsGet: https.get,
    fetch: global.fetch,
  };

  function guard(mod, args) {
    const host = _hostFromArgs(args);
    state.callCount += 1;
    state.calls.push({ mod, host });
    if (!LOCALHOST_ALLOWLIST.has(host)) {
      throw new NetworkInvariantViolation(mod, host);
    }
  }

  http.request = function (...args) { guard('http.request', args); return original.httpRequest.apply(http, args); };
  http.get = function (...args) { guard('http.get', args); return original.httpGet.apply(http, args); };
  https.request = function (...args) { guard('https.request', args); return original.httpsRequest.apply(https, args); };
  https.get = function (...args) { guard('https.get', args); return original.httpsGet.apply(https, args); };
  global.fetch = function (...args) {
    guard('fetch', args);
    if (!original.fetch) throw new Error('installNetworkInvariant: no underlying global.fetch to delegate an allowlisted call to');
    return original.fetch.apply(global, args);
  };

  function restore() {
    http.request = original.httpRequest;
    http.get = original.httpGet;
    https.request = original.httpsRequest;
    https.get = original.httpsGet;
    global.fetch = original.fetch;
  }

  return { state, restore };
}

module.exports = { installNetworkInvariant, NetworkInvariantViolation, LOCALHOST_ALLOWLIST };
