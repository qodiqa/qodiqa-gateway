'use strict';

/**
 * JWKS cache for OpenID Connect providers.
 *
 *   const jwks = createJwksCache({ uri, fetchJson, now, ttlMs, minRefetchMs, staleIfErrorMs })
 *   await jwks.refreshIfNeeded(kid)        // makes sure a lookup for `kid` can be answered from the cache, fetching at most as often as the limits allow
 *   jwks.keyFor({ alg, kid })              // synchronous: the public KeyObject, or null
 *
 * `fetchJson(uri)` is injected: the caller owns the network (the core wires an SSRF-guarded, redirect-refusing, size- and time-bounded fetch), so this module has no I/O of its own.
 *
 * Behaviour:
 *   - Keys are cached for ttlMs (default 10 min). A token whose `kid` is not in the cache triggers ONE refetch, but never more often than minRefetchMs (default 30 s) - an attacker
 *     sending random kids cannot make the gateway hammer the IdP (and cannot flush a good cache: a failed or empty refetch never discards keys that were good).
 *   - If the IdP is unreachable the last good key set keeps serving for staleIfErrorMs (default 1 h) after it expired; beyond that every lookup fails closed.
 *   - Only keys that are safe to verify with are kept: `use` absent or "sig", `key_ops` absent or including "verify", kty RSA (modulus >= 2048 bits), EC (P-256/384/521) and OKP
 *     Ed25519; anything else (symmetric "oct", private members, short RSA keys, unknown curves) is dropped. A key without `kid` is usable only when it is the ONLY key of the set.
 *   - At most 100 keys per set.
 */

const crypto = require('crypto');

const MAX_KEYS = 100;
const CURVES = Object.freeze({ 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' });

function importJwk(jwk) {
  if (!jwk || typeof jwk !== 'object') return null;
  if (jwk.use !== undefined && jwk.use !== 'sig') return null;
  if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) return null;
  for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) if (jwk[priv] !== undefined) return null;          // a private or symmetric member: never trust such an entry
  try {
    if (jwk.kty === 'RSA') {
      if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return null;
      if (Buffer.from(jwk.n, 'base64url').length * 8 < 2048) return null;
    } else if (jwk.kty === 'EC') {
      if (!Object.prototype.hasOwnProperty.call(CURVES, jwk.crv) || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return null;
    } else if (jwk.kty === 'OKP') {
      if (jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') return null;
    } else return null;
    return crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
  } catch { return null; }
}

function parseSet(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.keys)) return null;
  const keys = []; let anonymous = 0;
  for (const jwk of doc.keys.slice(0, MAX_KEYS)) {
    const k = importJwk(jwk);
    if (!k) continue;
    const kid = typeof jwk.kid === 'string' && jwk.kid && jwk.kid.length <= 256 ? jwk.kid : null;
    if (kid === null) anonymous++;
    keys.push({ kid, key: k, alg: typeof jwk.alg === 'string' ? jwk.alg : null });
  }
  return { keys, onlyAnonymous: keys.length === 1 && anonymous === 1 };
}

function createJwksCache({ uri, fetchJson, now = () => Date.now(), ttlMs = 600_000, minRefetchMs = 30_000, staleIfErrorMs = 3_600_000 }) {
  if (typeof fetchJson !== 'function') throw new TypeError('createJwksCache: fetchJson is required');
  let set = null; let fetchedAt = 0; let lastAttemptAt = 0; let inflight = null; let lastError = null;

  async function load() {
    lastAttemptAt = now();
    try {
      const parsed = parseSet(await fetchJson(uri));
      if (!parsed || parsed.keys.length === 0) throw new Error('the JWKS has no usable key');
      set = parsed; fetchedAt = now(); lastError = null;
    } catch (e) { lastError = e; }
  }

  function fresh() { return set !== null && now() - fetchedAt < ttlMs; }
  function usable() { return set !== null && now() - fetchedAt < ttlMs + staleIfErrorMs; }
  const has = (kid) => set !== null && set.keys.some((k) => (kid === null ? set.onlyAnonymous : k.kid === kid));

  async function refreshIfNeeded(kid = null) {
    const wantRefresh = !fresh() || (!has(kid) && now() - lastAttemptAt >= minRefetchMs);
    if (!wantRefresh) return;
    if (!fresh() && now() - lastAttemptAt < Math.min(minRefetchMs, 5_000) && lastError) return;        // do not retry a failing IdP on every request
    if (!inflight) inflight = load().finally(() => { inflight = null; });
    await inflight;
  }

  function keyFor({ alg, kid }) {
    if (!usable()) return null;
    for (const k of set.keys) {
      if (kid === null ? !(set.onlyAnonymous && k.kid === null) : k.kid !== kid) continue;
      if (k.alg && k.alg !== alg) return null;                       // a key pinned to one algorithm is not usable with another
      return k.key;
    }
    return null;
  }

  return { refreshIfNeeded, keyFor, _state: () => ({ keys: set ? set.keys.length : 0, fetchedAt, lastAttemptAt, lastError: lastError ? String(lastError.message) : null }) };
}

module.exports = { createJwksCache, importJwk, parseSet, MAX_KEYS };
