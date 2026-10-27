'use strict';

/**
 * Trust-boundary-aware client IP resolution — single source of truth.
 *
 * QODIQA-PROTOCOL-SPEC.md does not define a client-IP resolution algorithm
 * (verified: no mention of clientIp / X-Forwarded-For / trust proxy anywhere
 * in the spec). This module follows industry best practice instead, and
 * documents every assumption made in its absence:
 *
 *   ASSUMPTION 1 — X-Forwarded-For / X-Real-IP are attacker-controlled on any
 *   request that reaches this process directly. They may ONLY be honoured
 *   when the immediate TCP peer (req.socket.remoteAddress) is itself a
 *   configured trusted proxy. A request from an untrusted or unknown peer
 *   MUST resolve to that peer's own address — forwarded headers are ignored
 *   entirely, never partially trusted.
 *
 *   ASSUMPTION 2 — When the immediate peer IS trusted, the forwarding chain
 *   is walked from the nearest hop (rightmost X-Forwarded-For entry) outward,
 *   stopping at the first hop that is NOT itself a trusted proxy — that hop
 *   is the real client. This is the same algorithm Express's own `req.ip`
 *   uses via the `proxy-addr` package, and is the de facto industry standard
 *   (RFC 7239 "Forwarded" has the same intent). If every hop in the chain is
 *   a trusted proxy, the farthest (leftmost) entry is returned.
 *
 *   ASSUMPTION 3 — A malformed forwarding chain (any entry that is not a
 *   syntactically valid IP address) is treated as untrustworthy in its
 *   entirety: the header is ignored and resolution falls back to the
 *   immediate peer. Chain DEPTH is bounded separately, earlier in the
 *   pipeline, by src/infra/network/proxyValidation.js
 *   (createProxyValidationMiddleware, PROXY_CHAIN_TOO_DEEP) — this resolver
 *   assumes that check has already run and does not duplicate it.
 *
 *   ASSUMPTION 4 — Trust configuration reuses the exact same format and
 *   default as Express's own `trust proxy` setting (see server.js
 *   TRUSTED_PROXY) — the named presets `loopback`, `linklocal`, and
 *   `uniquelocal` expand to the same IANA-reserved ranges Express/proxy-addr
 *   use, so operators configure trust ONCE and every consumer (audit
 *   logging, rate limiting, anomaly detection, ops IP allowlisting) agrees.
 *
 * This is the ONLY place clientIp resolution logic lives. Do not
 * re-implement header parsing elsewhere — import resolveClientIp().
 */

const net = require('net');
const { _buildMatcher, _normalizeIp } = require('./ipMatch');

// Named presets — must match Express/proxy-addr's own definitions exactly so
// TRUSTED_PROXY=loopback,linklocal,uniquelocal means the same thing whether
// consulted via Express's `trust proxy` setting or via this resolver.
const _PRESETS = Object.freeze({
  loopback:    ['127.0.0.0/8', '::1/128'],
  linklocal:   ['169.254.0.0/16', 'fe80::/10'],
  uniquelocal: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'],
});

function _expandPresets(entries) {
  const out = [];
  for (const entry of entries) {
    const preset = _PRESETS[String(entry).toLowerCase()];
    if (preset) out.push(...preset);
    else out.push(entry);
  }
  return out;
}

/**
 * Build a trust predicate from a trust configuration value.
 *
 * @param {true|false|null|undefined|string[]} trustConfig
 *   true            — trust every immediate peer unconditionally (opt-in;
 *                      equivalent to Express `trust proxy: true` — use only
 *                      when the process is NEVER reachable except through a
 *                      proxy, e.g. a sidecar deployment).
 *   false/null/[]   — trust no one; forwarded headers are always ignored.
 *   string[]        — IP / CIDR entries and/or preset names
 *                      ('loopback' | 'linklocal' | 'uniquelocal').
 * @returns {(ip: string) => boolean}
 */
function _makeTrustPredicate(trustConfig) {
  if (trustConfig === true) return () => true;
  if (!trustConfig || (Array.isArray(trustConfig) && trustConfig.length === 0)) {
    return () => false;
  }

  const raw     = Array.isArray(trustConfig) ? trustConfig : [trustConfig];
  const entries = _expandPresets(raw);
  // Entries that fail to compile are dropped rather than treated as a fatal
  // error — a single bad entry in a long trust list should not silently
  // disable trust for every other correctly-configured entry. Operators are
  // warned about TRUSTED_PROXY problems at startup by validateProxyConfig().
  const matchers = entries.map(_buildMatcher).filter(Boolean);

  return (ip) => {
    const norm = _normalizeIp(ip) ?? ip;
    return matchers.some(m => m(norm));
  };
}

/**
 * Resolve the real client IP for a request, honouring forwarded headers
 * ONLY when the immediate TCP peer is a trusted proxy.
 *
 * @param {import('http').IncomingMessage} req
 * @param {true|false|null|undefined|string[]} trustConfig — see _makeTrustPredicate
 * @returns {string|null} — null only when no peer address is available at all
 */
function resolveClientIp(req, trustConfig) {
  const rawPeer = req.socket?.remoteAddress ?? null;
  const peer    = rawPeer ? (_normalizeIp(rawPeer) ?? rawPeer) : null;

  if (!peer || net.isIP(peer) === 0) return null;

  const isTrusted = _makeTrustPredicate(trustConfig);

  if (!isTrusted(peer)) {
    // Direct peer is not a trusted proxy — forwarded headers are attacker
    // controlled from here; never consult them.
    return peer;
  }

  const xffRaw = req.headers['x-forwarded-for'];
  const xriRaw = req.headers['x-real-ip'];

  const chain = (typeof xffRaw === 'string' && xffRaw.trim())
    ? xffRaw.split(',').map(s => s.trim())
    : [];

  if (chain.length === 0) {
    // No X-Forwarded-For — X-Real-IP is a single-value (non-chained) claim
    // from the trusted proxy about the original client.: honoured only when the
    // operator declares the proxy sets it (TRUSTED_PROXY_REAL_IP=true) — a proxy that forwards a client-supplied
    // X-Real-IP unchanged would otherwise let the client choose its IP.
    if (process.env.TRUSTED_PROXY_REAL_IP === 'true' && typeof xriRaw === 'string' && xriRaw.trim()) {
      const xri = xriRaw.trim();
      if (net.isIP(xri) !== 0) return _normalizeIp(xri) ?? xri;
    }
    return peer;
  }

  // A malformed chain (any non-IP entry) is untrustworthy in its entirety —
  // fall back to the peer rather than propagating a partially-parsed value.
  if (chain.some(entry => net.isIP(entry) === 0)) {
    return peer;
  }

  // Walk from nearest hop (rightmost) to farthest (leftmost), stopping at
  // the first hop that is not itself a trusted proxy — that is the client.
  let resolved = peer;
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = _normalizeIp(chain[i]) ?? chain[i];
    resolved = hop;
    if (!isTrusted(hop)) break;
  }

  return resolved;
}

/**
 * Parse the TRUSTED_PROXY env var into the trust configuration format
 * consumed by resolveClientIp() / Express's `trust proxy` setting.
 *
 * Single source of truth for this parsing — server.js (Express `trust
 * proxy`) and middleware/clientIp.js (resolveClientIp) MUST both derive
 * their trust config from this function so they can never disagree about
 * which proxies are trusted.
 *
 * default-off (Findings Register). Previously defaulted to
 * ['loopback', 'linklocal', 'uniquelocal'] when TRUSTED_PROXY was unset —
 * trusting the entire RFC1918 + link-local space by default, not just
 * loopback, so any peer on that range could spoof X-Forwarded-For /
 * X-Real-IP and defeat every IP-keyed control at once (sign_auth,
 * BLOCK_IP, route-level rate limiters, ops IP allowlisting, audit-log IP
 * evidentiary integrity). Unset now means an EMPTY trust list — no
 * forwarded header is ever honoured unless a proxy allowlist is
 * explicitly configured. Deployments behind a real reverse proxy (or
 * relying on private-network adjacency) must now set TRUSTED_PROXY
 * explicitly — see #25 quickstart.
 *
 * @param {string|undefined} [raw] — defaults to process.env.TRUSTED_PROXY
 * @returns {string[]} — defaults to [] (no proxy trusted; TRUSTED_PROXY must
 *   be set explicitly to honour any forwarded header)
 */
// the default when TRUSTED_PROXY is UNSET is 'loopback' — only
// a same-host reverse proxy may supply X-Forwarded-For. An explicitly EMPTY
// value still means "trust no proxy". Every consumer (Express trust proxy,
// req.clientIp, the admin IP allowlist) reads this one list.
const DEFAULT_TRUSTED_PROXY = 'loopback';
function parseTrustedProxyConfig(raw) {
  const value = raw !== undefined ? raw : process.env.TRUSTED_PROXY;
  const v = value === undefined ? DEFAULT_TRUSTED_PROXY : value;
  return v
    ? v.split(',').map(s => s.trim()).filter(Boolean)
    : [];
}

module.exports = { resolveClientIp, parseTrustedProxyConfig, _makeTrustPredicate, DEFAULT_TRUSTED_PROXY, _PRESETS };
