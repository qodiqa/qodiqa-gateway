'use strict';

/**
 * SSRF protection — outbound URL validators.
 *
 * validateProviderUrl(url)
 *   Validates that a provider destination URL is:
 *     1. A valid URL that can be parsed
 *     2. Using HTTPS — no plain-HTTP, file://, ftp://, etc.
 *     3. Targeting an explicitly allowlisted hostname
 *     4. Not an IP literal (any form — IPv4, IPv6, decimal-encoded, etc.)
 *     5. Not a private/loopback/link-local/APIPA network address
 *
 * validateLocalProviderUrl(url)
 *   Relaxed validator for operator-configured self-hosted endpoints.
 *   Allows:
 *     - HTTP or HTTPS
 *     - Private network destinations (localhost, 192.168.x, 10.x, etc.)
 *   Still enforces:
 *     - Valid parseable URL
 *     - http: or https: protocol only (no file://, ftp://, etc.)
 *     - Non-empty hostname
 *   Used for: local, and llama with private-network base URLs.
 *
 * Return value: { valid: boolean, reason: string | null }
 *
 * Reason codes on failure:
 *   INVALID_URL                  — not a parseable URL
 *   NON_HTTPS_PROTOCOL           — protocol other than https: (standard validator)
 *   NON_HTTP_PROTOCOL            — protocol other than http:/https: (local validator)
 *   IP_LITERAL_DESTINATION       — hostname is an IP address (any form)
 *   PRIVATE_NETWORK_DESTINATION  — hostname is localhost or a private-range IP
 *   HOSTNAME_NOT_ALLOWED         — hostname is not in ALLOWED_HOSTNAMES
 */

// Canonically allowed provider hostnames for public commercial providers.
// Extend this set when new public providers are added.
const ALLOWED_HOSTNAMES = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.mistral.ai',
  'login.microsoftonline.com',                // Microsoft Entra token endpoint (Azure OpenAI)
]);

// providers whose hostnames are tenant- or region-specific and so cannot be listed one by one: still exact, anchored patterns of the vendor's own domain
// (never a free suffix match, never an IP literal - those are rejected before this is consulted).
const ALLOWED_HOSTNAME_PATTERNS = [
  /^[a-z0-9][a-z0-9-]{0,62}\.(openai|cognitiveservices)\.azure\.com$/,          // Azure OpenAI resource endpoints
  /^bedrock-runtime\.[a-z]{2}(-[a-z]+)+-[0-9]\.amazonaws\.com$/,                // AWS Bedrock runtime, per region
];

// Detects any raw IPv4 literal: four dotted decimal octets.
const IPV4_LITERAL_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function _isIpLiteral(hostname) {
  // IPv4 literal: four dotted octets
  if (IPV4_LITERAL_RE.test(hostname)) return true;
  // IPv6 literal: the URL parser strips the surrounding brackets,
  // leaving something like '::1' or '2001:db8::1'
  if (hostname.includes(':')) return true;
  return false;
}

// Private / loopback / link-local hostname patterns.
const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^.*\.localhost$/i,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,           // APIPA / link-local
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // RFC 6598 shared space
  /^198\.(1[89])\./,       // RFC 5737 test-net-2/3
  /^203\.0\.113\./,        // RFC 5737 test-net-3
  /^192\.0\.2\./,          // RFC 5737 test-net-1
  /^240\./,                // Reserved (future)
  /^255\./,                // Broadcast
];

function _isPrivateHost(hostname) {
  const lower = hostname.toLowerCase();
  for (const pattern of PRIVATE_HOST_PATTERNS) {
    if (pattern.test(lower)) return true;
  }
  return false;
}

/**
 * Validate a public provider base URL against the full SSRF policy.
 * Requires HTTPS, non-IP hostname, and allowlisted hostname.
 *
 * @param {string} rawUrl
 * @returns {{ valid: boolean, reason: string | null }}
 */
function validateProviderUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) {
    return { valid: false, reason: 'INVALID_URL' };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'INVALID_URL' };
  }

  // Must be HTTPS — no http, file, ftp, data, etc.
  if (parsed.protocol !== 'https:') {
    return { valid: false, reason: 'NON_HTTPS_PROTOCOL' };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Reject all IP literals before allowlist check
  if (_isIpLiteral(hostname)) {
    return { valid: false, reason: 'IP_LITERAL_DESTINATION' };
  }

  // Reject localhost and known private-network hostnames
  if (_isPrivateHost(hostname)) {
    return { valid: false, reason: 'PRIVATE_NETWORK_DESTINATION' };
  }

  // Reject any hostname not in the explicit allowlist
  if (!ALLOWED_HOSTNAMES.has(hostname) && !ALLOWED_HOSTNAME_PATTERNS.some((re) => re.test(hostname))) {
    return { valid: false, reason: 'HOSTNAME_NOT_ALLOWED' };
  }

  return { valid: true, reason: null };
}

/**
 * Validate an operator-configured self-hosted endpoint URL.
 *
 * This relaxed validator is for LLAMA_BASE_URL and LOCAL_BASE_URL where
 * the operator deliberately points QODIQA at a private or localhost endpoint.
 * It still enforces minimum URL hygiene but allows private network destinations.
 *
 * Permits: http:// and https://, private networks, localhost.
 * Rejects: file://, ftp://, data://, empty hostname, malformed URLs.
 *
 * @param {string} rawUrl
 * @returns {{ valid: boolean, reason: string | null }}
 */
function validateLocalProviderUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) {
    return { valid: false, reason: 'INVALID_URL' };
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'INVALID_URL' };
  }

  // Only allow http: or https: — no file://, ftp://, data://, etc.
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, reason: 'NON_HTTP_PROTOCOL' };
  }

  // Must have a non-empty hostname
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { valid: false, reason: 'INVALID_URL' };
  }

  // Private networks and localhost are explicitly allowed for local deployments (operator-configured, operator-accountable) —
  // EXCEPT addresses that are never a model server: metadata/link-local, unspecified, multicast, reserved (item 3.8). The
  // URL parser already normalises decimal/hex/octal IPv4 forms to dotted quads, so one check covers http://2852039166 too.
  const bare = hostname.replace(/^\[|\]$/g, '');
  const literalReason = blockedAddressReason(bare, { blockPrivate: process.env.LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS === 'true' });
  if (literalReason) return { valid: false, reason: 'BLOCKED_DESTINATION_ADDRESS' };
  return { valid: true, reason: null };
}

// ── Resolved-address guard for operator-configured (local / llama) endpoints ─────────────────────────────────
// validateLocalProviderUrl() deliberately allows localhost and private networks (Ollama
// on 127.0.0.1, the `ollama` container on a Docker/K8s network are the supported deployments), but it used to stop at the
// URL text: a hostname that resolved — or later re-resolved (DNS rebinding) — to the cloud metadata service or another
// non-service address was connected to, and IP-literal URLs (http://169.254.169.254/) were accepted. Now the ADDRESS is
// checked at connect time (agent `lookup`) and for IP literals in the URL:
//   always refused  : 0.0.0.0/8, 169.254.0.0/16 (link-local incl. 169.254.169.254), 224.0.0.0/4 multicast, 240.0.0.0/4
//                     reserved + broadcast, ::, fe80::/10, ff00::/8, fd00:ec2::254 (AWS IMDS over IPv6), IPv4-mapped forms
//   allowed         : loopback (127/8, ::1) — a local runtime on the same host is the primary use case
//   opt-in refusal  : RFC 1918 / CGNAT / ULA ranges when LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS=true (for deployments whose
//                     model host is NOT on a private network); default stays open because the shipped compose/K8s overlays
//                     reach the model server on a private address.
const net   = require('net');
const dns   = require('dns');
const http  = require('http');
const https = require('https');

function _v4int(a) { const p = a.split('.').map(Number); return (((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0); }
function _inV4(ip, base, bits) { const m = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0; return ((_v4int(ip) & m) >>> 0) === ((_v4int(base) & m) >>> 0); }

/** Expands an IPv6 literal to eight 16-bit groups (handles '::' and a trailing dotted quad); null if unparseable. */
function _expandV6(a) {
  let t = a.replace(/%.*$/, '');
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(t);
  if (dotted) { const n = dotted.slice(1).map(Number); t = t.slice(0, dotted.index) + ((n[0] << 8) | n[1]).toString(16) + ':' + ((n[2] << 8) | n[3]).toString(16); }
  const parts = t.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 1 ? head.length !== 8 : missing < 0) return null;
  const all = parts.length === 1 ? head : [...head, ...Array(missing).fill('0'), ...tail];
  const nums = all.map((x) => parseInt(x, 16));
  return nums.some((x) => !Number.isInteger(x) || x < 0 || x > 0xffff) ? null : nums;
}

/** @returns {string|null} reason the address is refused, or null if allowed */
function blockedAddressReason(address, { blockPrivate = false, blockLoopback = false } = {}) {
  let a = String(address || '').toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(a);
  if (mapped) a = mapped[1];
  // the WHATWG URL parser (and dns) render IPv4-mapped IPv6 in hex: ::ffff:a9fe:a9fe == 169.254.169.254
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(a);
  if (mappedHex) { const hi = parseInt(mappedHex[1], 16); const lo = parseInt(mappedHex[2], 16); a = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`; }
  if (net.isIPv6(a)) {
    // (verification): addresses that embed an IPv4 destination (NAT64 64:ff9b::/96, 6to4 2002::/16, IPv4-compatible::/96)
    // are judged by the IPv4 address they carry, otherwise 64:ff9b::a9fe:a9fe would reach 169.254.169.254 through a NAT64 gateway.
    const h = _expandV6(a);
    if (h) {
      const v4 = (x, y) => `${x >> 8}.${x & 255}.${y >> 8}.${y & 255}`;
      let embedded = null;
      if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) embedded = v4(h[6], h[7]);
      else if (h[0] === 0x2002) embedded = v4(h[1], h[2]);
      else if (h.slice(0, 6).every((x) => x === 0) && (h[6] || h[7]) && !(h[6] === 0 && h[7] === 1)) embedded = v4(h[6], h[7]);
      else if (h.slice(0, 4).every((x) => x === 0) && h[4] === 0xffff && h[5] === 0) embedded = v4(h[6], h[7]); // SIIT ::ffff:0:a.b.c.d
      if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return blockLoopback ? 'LOOPBACK_ADDRESS' : null; // non-canonical spellings of ::1
      if (embedded) { const r = blockedAddressReason(embedded, { blockPrivate, blockLoopback }); if (r) return r; }
    }
  }
  if (net.isIPv4(a)) {
    if (a === '100.100.100.200' || a === '168.63.129.16' || a === '192.0.0.192') return 'LINK_LOCAL_OR_METADATA_ADDRESS'; // Alibaba / Azure wireserver / Oracle metadata
    if (_inV4(a, '0.0.0.0', 8))        return 'UNSPECIFIED_ADDRESS';
    if (blockLoopback && _inV4(a, '127.0.0.0', 8)) return 'LOOPBACK_ADDRESS';
    if (_inV4(a, '169.254.0.0', 16))   return 'LINK_LOCAL_OR_METADATA_ADDRESS';
    if (_inV4(a, '224.0.0.0', 4))      return 'MULTICAST_ADDRESS';
    if (_inV4(a, '240.0.0.0', 4))      return 'RESERVED_OR_BROADCAST_ADDRESS';
    if (blockPrivate && (_inV4(a, '10.0.0.0', 8) || _inV4(a, '172.16.0.0', 12) || _inV4(a, '192.168.0.0', 16)
        || _inV4(a, '100.64.0.0', 10) || _inV4(a, '198.18.0.0', 15)
        || _inV4(a, '192.0.0.0', 24) || _inV4(a, '192.0.2.0', 24) || _inV4(a, '198.51.100.0', 24) || _inV4(a, '203.0.113.0', 24))) return 'PRIVATE_NETWORK_ADDRESS';       // + IETF protocol and documentation ranges
    return null;
  }
  if (net.isIPv6(a)) {
    if (a === '::' || a === '0:0:0:0:0:0:0:0') return 'UNSPECIFIED_ADDRESS';
    if (a === '::1') return blockLoopback ? 'LOOPBACK_ADDRESS' : null;
    const first = parseInt(a.split(':')[0] || '0', 16);
    if ((first & 0xffc0) === 0xfe80) return 'LINK_LOCAL_OR_METADATA_ADDRESS';
    if ((first & 0xff00) === 0xff00) return 'MULTICAST_ADDRESS';
    if (a.startsWith('fd00:ec2:')) return 'LINK_LOCAL_OR_METADATA_ADDRESS';
    if (blockPrivate && (first & 0xfe00) === 0xfc00) return 'PRIVATE_NETWORK_ADDRESS';
    if (blockPrivate && ((first & 0xffc0) === 0xfec0 || a.startsWith('2001:db8:') || a.startsWith('2001:0db8:'))) return 'PRIVATE_NETWORK_ADDRESS';        // site-local (deprecated) and documentation
    return null;
  }
  return null; // not an IP: the caller resolves it
}

function _blockPrivate(env) { return env.LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS === 'true'; }
// STRICT PUBLIC mode (hosted / registry providers): the host must resolve to a PUBLIC address - loopback, private, link-local, documentation and reserved ranges are refused even for
// the operator-named host itself (a public name that re-resolves to 127.0.0.1 is DNS rebinding). Only set by adapters whose endpoint is not a self-hosted one.
function _strictPublic(env) { return env.PROVIDER_GUARD_STRICT_PUBLIC === 'true'; }

/** dns.lookup replacement that refuses to hand Node a forbidden address (honours the Node >= 20 `all: true` contract). */
function createGuardedLookup(env = process.env, { trustedHost = null } = {}) {
  // private/loopback targets are allowed (unless the strict opt-in is set) ONLY for the operator-configured host itself;
  // any other host reached through this agent (a redirect hop, a rebinding to a different name) is held to the strict policy.
  const untrusted = (host) => _strictPublic(env) || (trustedHost !== null && String(host).toLowerCase() !== trustedHost);
  const strictFor = (host) => _blockPrivate(env) || untrusted(host);
  return function guardedLookup(hostname, options, callback) {
    const cb = typeof options === 'function' ? options : callback;
    const opts = (options && typeof options === 'object') ? options : {};
    dns.lookup(hostname, { all: true, family: opts.family, hints: opts.hints }, (err, addrs) => {
      if (err) return cb(err);
      for (const { address } of addrs) {
        const reason = blockedAddressReason(address, { blockPrivate: strictFor(hostname), blockLoopback: untrusted(hostname) });
        if (reason) {
          /** @type {any} */ const e = new Error(`SSRF guard: ${hostname} resolved to a refused address (${reason})`);
          e.code = 'SSRF_BLOCKED_RESOLVED_ADDRESS';
          return cb(e);
        }
      }
      if (opts.all) return cb(null, addrs.map((x) => ({ address: x.address, family: x.family })));
      return cb(null, addrs[0].address, addrs[0].family);
    });
  };
}

/** http(s).Agent whose connections go through the guarded lookup — pass to baseAdapter.guardedFetch().
 * (verification): `lookup` is never consulted for IP-literal hosts, so an allowed endpoint answering
 *  `302 Location: http://169.254.169.254/` was followed. createConnection now checks literal hosts too (redirect hops included). */
function createGuardedAgent(rawUrl, env = process.env) {
  let protocol = 'http:';
  let trustedHost = null;
  try { const u = new URL(rawUrl); protocol = u.protocol; trustedHost = u.hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch (_) { /* validated elsewhere */ }
  const lookup = createGuardedLookup(env, { trustedHost });
  const Base = protocol === 'https:' ? https.Agent : http.Agent;
  class GuardedAgent extends Base {
    createConnection(options, cb) {
      const host = String((options && (options.host || options.hostname)) || '').replace(/^\[|\]$/g, '');
      const reason = net.isIP(host) ? blockedAddressReason(host, { blockPrivate: _blockPrivate(env) || _strictPublic(env) || (trustedHost !== null && host.toLowerCase() !== trustedHost), blockLoopback: _strictPublic(env) || (trustedHost !== null && host.toLowerCase() !== trustedHost) }) : null;
      if (reason) {
        /** @type {any} */ const e = new Error(`SSRF guard: connection to ${host} refused (${reason})`);
        e.code = 'SSRF_BLOCKED_RESOLVED_ADDRESS';
        const sock = new net.Socket();
        process.nextTick(() => sock.destroy(e));
        return sock;
      }
      return super.createConnection(options, cb);
    }
  }
  return new GuardedAgent({ lookup, keepAlive: true });
}

module.exports = { validateProviderUrl, validateLocalProviderUrl, ALLOWED_HOSTNAMES, blockedAddressReason, createGuardedLookup, createGuardedAgent };
