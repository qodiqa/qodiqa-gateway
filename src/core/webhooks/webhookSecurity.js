'use strict';

/**
 * Webhook Security — Component 44.6
 *
 * Enforces all outbound security controls before and during every HTTPS
 * webhook request:
 *
 *   1. Protocol allowlist (HTTPS only)
 *   2. Blocked scheme rejection (file://, ftp://, gopher://, etc.)
 *   3. Comprehensive SSRF protection (loopback, RFC-1918, link-local,
 *      carrier-grade NAT, multicast, reserved, documentation, benchmark,
 *      unique-local IPv6, cloud metadata endpoints)
 *   4. DNS pre-resolution with IP validation
 *   5. DNS re-validation at TCP connection time (rebinding protection)
 *   6. Allowlist / denylist matching (hosts, wildcard domains, CIDRs)
 *   7. Redirect security (per-hop revalidation, HTTPS downgrade rejection)
 *   8. TLS options enforcement (min version, cert verification)
 *   9. Structured audit logging of every decision
 *
 * Security model: fail-closed. Any error, ambiguity, or validation failure
 * produces a rejection. Connections are never silently permitted.
 *
 * Public API:
 *   validateDestination(rawUrl, config)        → Promise<ValidationResult>
 *   createSecureLookup(hostname, first, config) → lookupFn (for https.request)
 *   validateRedirect(fromUrl, toUrl, hopCount, config) → Promise<ValidationResult>
 *   buildTlsOptions(config)                    → object
 */

const dns    = require('dns').promises;
const net    = require('net');
const { emit } = require('../../../services/logger');

// ── Blocked protocols ─────────────────────────────────────────────────────────

const ALLOWED_PROTOCOLS = new Set(['https:']);

const BLOCKED_PROTOCOLS = new Set([
  'http:', 'ftp:', 'ftps:', 'file:', 'gopher:', 'dict:',
  'ldap:', 'ldaps:', 'jar:', 'data:', 'javascript:', 'vbscript:',
  'ws:', 'wss:',
]);

// ── Blocked hostnames (exact) ─────────────────────────────────────────────────

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
  'metadata.google.internal',
  // Kubernetes internal DNS
  'kubernetes.default',
  'kubernetes.default.svc',
  'kubernetes.default.svc.cluster.local',
  // Common Docker bridge names
  'host.docker.internal',
  'gateway.docker.internal',
]);

// Hostname suffix patterns for metadata / internal services
const BLOCKED_HOSTNAME_SUFFIXES = [
  '.svc.cluster.local',
  '.cluster.local',
  '.internal',
];

// ── IPv4 blocked CIDR ranges ──────────────────────────────────────────────────

const BLOCKED_IPV4_CIDRS = [
  ['0.0.0.0',       8],   // "This" network (RFC 1122)
  ['10.0.0.0',      8],   // RFC-1918 private
  ['100.64.0.0',   10],   // Carrier-grade NAT (RFC 6598)
  ['127.0.0.0',     8],   // Loopback (RFC 1122)
  ['169.254.0.0',  16],   // Link-local / APIPA (RFC 3927)
  ['172.16.0.0',   12],   // RFC-1918 private
  ['192.0.0.0',    24],   // IETF Protocol Assignments (RFC 6890)
  ['192.0.2.0',    24],   // Documentation TEST-NET-1 (RFC 5737)
  ['192.88.99.0',  24],   // 6to4 relay anycast (RFC 7526, deprecated)
  ['192.168.0.0',  16],   // RFC-1918 private
  ['198.18.0.0',   15],   // Benchmark testing (RFC 2544)
  ['198.51.100.0', 24],   // Documentation TEST-NET-2 (RFC 5737)
  ['203.0.113.0',  24],   // Documentation TEST-NET-3 (RFC 5737)
  ['224.0.0.0',     4],   // Multicast (RFC 3171)
  ['240.0.0.0',     4],   // Reserved for future use (RFC 1112)
  ['255.255.255.255', 32], // Broadcast
];

// ── IPv6 blocked prefix ranges ────────────────────────────────────────────────

// Stored as [expandedPrefix32hex, prefixLenBits]
// We keep the human-readable prefix and expand at validation time.
const BLOCKED_IPV6_PREFIXES = [
  // Exact addresses
  ['::',             128],  // Unspecified (RFC 4291)
  ['::1',            128],  // Loopback (RFC 4291)
  // IPv4-mapped / IPv4-compatible
  ['::',              96],  // IPv4-compatible, deprecated (RFC 4291 §2.5.5.1) — ::a.b.c.d embeds any IPv4
  ['::ffff:0:0',      96],  // IPv4-mapped (RFC 4291)
  ['::ffff:0:0:0',    96],  // IPv4-translated (RFC 6145) — same prefix bits
  ['64:ff9b::',       96],  // IPv4/IPv6 translation (RFC 6052)
  ['64:ff9b:1::',     48],  // IPv4/IPv6 translation (RFC 8215)
  // Special ranges
  ['100::',           64],  // Discard (RFC 6666)
  ['2001::',          32],  // Teredo (RFC 4380)
  ['2001:2::',        48],  // Benchmarking (RFC 5180)
  ['2001:db8::',      32],  // Documentation (RFC 3849)
  ['2001:10::',       28],  // ORCHID (RFC 4843, obsoleted by RFC 7343)
  ['2002::',          16],  // 6to4 (RFC 3056)
  ['fc00::',           7],  // Unique local (RFC 4193)
  ['fe80::',          10],  // Link-local (RFC 4291)
  ['ff00::',           8],  // Multicast (RFC 4291)
];

// ── IPv4 helpers ──────────────────────────────────────────────────────────────

function _ipv4ToUint32(ip) {
  const parts = ip.split('.');
  return (
    ((parseInt(parts[0], 10) & 0xff) * 0x1000000) +
    ((parseInt(parts[1], 10) & 0xff) * 0x10000)   +
    ((parseInt(parts[2], 10) & 0xff) * 0x100)      +
     (parseInt(parts[3], 10) & 0xff)
  );
}

function _isIpv4InCidr(ip, networkStr, prefixLen) {
  if (prefixLen === 0) return true;
  const mask    = prefixLen === 32 ? 0xffffffff : ~(0xffffffff >>> prefixLen) >>> 0;
  const ipInt   = _ipv4ToUint32(ip);
  const netInt  = _ipv4ToUint32(networkStr);
  return (ipInt & mask) === (netInt & mask);
}

// ── IPv6 helpers ──────────────────────────────────────────────────────────────

/**
 * Expand an IPv6 address to a lowercase 32-character hex string (no colons).
 * Handles :: shorthand and IPv4-mapped forms.
 *
 * @param {string} addr
 * @returns {string}  32 lowercase hex chars, or '' on parse error
 */
function _expandIpv6(addr) {
  try {
    // Strip zone ID (e.g. fe80::1%eth0)
    const zoneIdx = addr.indexOf('%');
    if (zoneIdx !== -1) addr = addr.slice(0, zoneIdx);

    // IPv4-mapped/compatible: ends in dotted-decimal (e.g. ::ffff:1.2.3.4)
    const dotIdx = addr.lastIndexOf('.');
    if (dotIdx !== -1) {
      const lastColon = addr.lastIndexOf(':');
      const ipv4      = addr.slice(lastColon + 1).split('.').map(n => parseInt(n, 10));
      if (ipv4.length !== 4 || ipv4.some(n => isNaN(n) || n < 0 || n > 255)) return '';
      const hi = ((ipv4[0] << 8) | ipv4[1]).toString(16).padStart(4, '0');
      const lo = ((ipv4[2] << 8) | ipv4[3]).toString(16).padStart(4, '0');
      addr = addr.slice(0, lastColon + 1) + hi + ':' + lo;
    }

    // Split on ::
    const halves = addr.split('::');
    if (halves.length > 2) return ''; // malformed

    const toGroups = (s) => s ? s.split(':').map(g => g.padStart(4, '0')) : [];

    if (halves.length === 2) {
      const left    = toGroups(halves[0]);
      const right   = toGroups(halves[1]);
      const missing = 8 - left.length - right.length;
      if (missing < 0) return ''; // malformed
      const mid = Array(missing).fill('0000');
      return [...left, ...mid, ...right].join('');
    }

    const groups = toGroups(halves[0]);
    if (groups.length !== 8) return '';
    return groups.join('');
  } catch {
    return '';
  }
}

/**
 * Test whether an IPv6 address falls within a prefix.
 *
 * @param {string} addr       IPv6 address
 * @param {string} prefix     IPv6 prefix (e.g. 'fc00::')
 * @param {number} prefixLen  bit length of prefix
 * @returns {boolean}
 */
function _isIpv6InPrefix(addr, prefix, prefixLen) {
  const addrHex   = _expandIpv6(addr);
  const prefixHex = _expandIpv6(prefix);
  if (!addrHex || !prefixHex) return false;
  if (prefixLen === 0) return true;

  // Compare nibble by nibble
  const fullNibbles  = Math.floor(prefixLen / 4);
  const remainBits   = prefixLen % 4;

  if (addrHex.slice(0, fullNibbles) !== prefixHex.slice(0, fullNibbles)) return false;
  if (remainBits === 0) return true;

  const aNibble = parseInt(addrHex[fullNibbles], 16);
  const pNibble = parseInt(prefixHex[fullNibbles], 16);
  const mask    = 0xf & ~((1 << (4 - remainBits)) - 1);
  return (aNibble & mask) === (pNibble & mask);
}

// ── IP classification ─────────────────────────────────────────────────────────

/**
 * Returns a rejection reason string if the IPv4 address is blocked, else null.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function _blockedIpv4Reason(ip) {
  for (const [network, prefix] of BLOCKED_IPV4_CIDRS) {
    if (_isIpv4InCidr(ip, network, prefix)) {
      return `blocked IPv4 address ${ip} (matches ${network}/${prefix})`;
    }
  }
  return null;
}

/**
 * Returns a rejection reason string if the IPv6 address is blocked, else null.
 *
 * @param {string} ip
 * @returns {string|null}
 */
function _blockedIpv6Reason(ip) {
  // Strip brackets that may be present in URL hostnames
  const addr = ip.replace(/^\[|\]$/g, '');
  for (const [prefix, len] of BLOCKED_IPV6_PREFIXES) {
    if (_isIpv6InPrefix(addr, prefix, len)) {
      return `blocked IPv6 address ${addr} (matches ${prefix}/${len})`;
    }
  }
  return null;
}

/**
 * Returns a rejection reason string if the IP is blocked (any family), else null.
 *
 * @param {string}  address  IP address string
 * @param {4|6}     family   IP family
 * @returns {string|null}
 */
function _blockedIpReason(address, family) {
  return family === 6 ? _blockedIpv6Reason(address) : _blockedIpv4Reason(address);
}

// ── Hostname checks ───────────────────────────────────────────────────────────

/**
 * Returns true if the hostname is on the blocked list.
 *
 * @param {string} hostname  lowercased
 * @returns {boolean}
 */
function _isBlockedHostname(hostname) {
  if (BLOCKED_HOSTNAMES.has(hostname)) return true;
  for (const suffix of BLOCKED_HOSTNAME_SUFFIXES) {
    if (hostname.endsWith(suffix)) return true;
  }
  return false;
}

// ── Allowlist / denylist ──────────────────────────────────────────────────────

/**
 * Test whether a hostname matches a wildcard domain rule.
 * '*.example.com' matches exactly one subdomain level of example.com.
 *
 * @param {string} hostname
 * @param {string} rule      e.g. '*.example.com' or 'example.com'
 * @returns {boolean}
 */
function _matchesDomainRule(hostname, rule) {
  const r = rule.toLowerCase();
  if (!r.startsWith('*.')) {
    return hostname === r;
  }
  const base    = r.slice(2); // remove '*.'
  const suffix  = '.' + base;
  if (!hostname.endsWith(suffix)) return false;
  // Ensure exactly one label before the base (no deeper nesting)
  const sub = hostname.slice(0, hostname.length - suffix.length);
  return sub.length > 0 && !sub.includes('.');
}

/**
 * Test whether an IP address falls within a CIDR string (IPv4 or IPv6).
 *
 * @param {string}  address
 * @param {4|6}     family
 * @param {string}  cidr     e.g. '10.0.0.0/8' or 'fc00::/7'
 * @returns {boolean}
 */
function _ipMatchesCidr(address, family, cidr) {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) return false;
  const network   = cidr.slice(0, slash);
  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  if (!Number.isFinite(prefixLen)) return false;
  if (family === 4 && net.isIPv4(network)) {
    return _isIpv4InCidr(address, network, prefixLen);
  }
  if (family === 6 && net.isIPv6(network)) {
    return _isIpv6InPrefix(address, network, prefixLen);
  }
  return false;
}

/**
 * Check whether a destination matches denylist rules.
 * Deny is checked against hostname and all resolved IPs.
 *
 * @returns {{ denied: boolean, reason: string|null }}
 */
function _checkDenylist(hostname, resolvedAddresses, config) {
  const h = hostname.toLowerCase();

  for (const rule of config.deniedHosts) {
    if (h === rule.toLowerCase()) {
      return { denied: true, reason: `hostname ${hostname} matches denied host ${rule}` };
    }
  }

  for (const rule of config.deniedDomains) {
    if (_matchesDomainRule(h, rule)) {
      return { denied: true, reason: `hostname ${hostname} matches denied domain ${rule}` };
    }
  }

  for (const { address, family } of resolvedAddresses) {
    for (const cidr of config.deniedCidrs) {
      if (_ipMatchesCidr(address, family, cidr)) {
        return { denied: true, reason: `IP ${address} matches denied CIDR ${cidr}` };
      }
    }
  }

  return { denied: false, reason: null };
}

/**
 * Check whether a destination satisfies allowlist rules.
 * If no allowlist rules are configured, returns { allowed: true }.
 *
 * @returns {{ allowed: boolean, reason: string|null }}
 */
function _checkAllowlist(hostname, resolvedAddresses, config) {
  const hasAllowRules =
    config.allowedHosts.length > 0 ||
    config.allowedDomains.length > 0 ||
    config.allowedCidrs.length > 0;

  if (!hasAllowRules) return { allowed: true, reason: null };

  const h = hostname.toLowerCase();

  for (const rule of config.allowedHosts) {
    if (h === rule.toLowerCase()) return { allowed: true, reason: null };
  }

  for (const rule of config.allowedDomains) {
    if (_matchesDomainRule(h, rule)) return { allowed: true, reason: null };
  }

  for (const { address, family } of resolvedAddresses) {
    for (const cidr of config.allowedCidrs) {
      if (_ipMatchesCidr(address, family, cidr)) return { allowed: true, reason: null };
    }
  }

  return {
    allowed: false,
    reason: `hostname ${hostname} is not in the webhook allowlist`,
  };
}

// ── DNS resolution ────────────────────────────────────────────────────────────

/**
 * Resolve a hostname to all addresses using the OS resolver.
 * Times out after config.dnsTimeoutMs.
 *
 * @param {string} hostname
 * @param {object} config
 * @returns {Promise<Array<{ address: string, family: 4|6 }>>}
 */
async function _resolveHostname(hostname, config) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`DNS timeout for ${hostname} after ${config.dnsTimeoutMs}ms`));
    }, config.dnsTimeoutMs);

    dns.lookup(hostname, { all: true })
      .then(records => {
        clearTimeout(timer);
        resolve(records);
      })
      .catch(err => {
        clearTimeout(timer);
        reject(new Error(`DNS resolution failed for ${hostname}: ${err.message}`));
      });
  });
}

/**
 * Validate every address in a set of DNS records.
 * Returns the first blocked reason found, or null if all are clean.
 *
 * @param {Array<{ address: string, family: 4|6 }>} records
 * @returns {string|null}
 */
function _validateAddresses(records) {
  for (const { address, family } of records) {
    const reason = _blockedIpReason(address, family);
    if (reason) return reason;
  }
  return null;
}

/**
 * Build a string key from a set of address records for change-detection.
 *
 * @param {Array<{ address: string, family: 4|6 }>} records
 * @returns {string}
 */
function _addressSetKey(records) {
  return [...records]
    .map(r => `${r.family}:${r.address.toLowerCase()}`)
    .sort()
    .join('|');
}

// ── Core validation ───────────────────────────────────────────────────────────

/**
 * @typedef {{ ok: true, parsedUrl: URL, hostname: string,
 *             resolvedAddresses: Array<{ address: string, family: 4|6 }>,
 *             addressSetKey: string }}  SuccessResult
 *
 * @typedef {{ ok: false, error: string }}  FailureResult
 *
 * @typedef {SuccessResult | FailureResult}  ValidationResult
 */

/**
 * Full pre-connection security validation for a webhook destination URL.
 *
 * Sequence:
 *   1. URL parse
 *   2. Protocol check (HTTPS only, blocked schemes rejected)
 *   3. Hostname check (blocked names, bare-IP SSRFs)
 *   4. DNS resolution (with timeout)
 *   5. IP validation (all SSRF ranges, cloud metadata)
 *   6. Denylist check
 *   7. Allowlist check
 *
 * @param {string} rawUrl
 * @param {object} config  from webhookSecurityConfig
 * @returns {Promise<ValidationResult>}
 */
async function validateDestination(rawUrl, config) {
  // ── 1. URL parse ────────────────────────────────────────────────────────────

  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return _reject('SSRF_INVALID_URL', { url: rawUrl }, `Invalid URL: ${rawUrl}`);
  }

  // ── 2. Protocol ─────────────────────────────────────────────────────────────

  if (BLOCKED_PROTOCOLS.has(parsedUrl.protocol)) {
    return _reject('SSRF_BLOCKED_PROTOCOL', { url: rawUrl, protocol: parsedUrl.protocol },
      `Protocol not permitted: ${parsedUrl.protocol} — only HTTPS is allowed`);
  }

  if (!ALLOWED_PROTOCOLS.has(parsedUrl.protocol)) {
    return _reject('SSRF_UNSUPPORTED_PROTOCOL', { url: rawUrl, protocol: parsedUrl.protocol },
      `Unsupported protocol: ${parsedUrl.protocol} — only HTTPS is permitted`);
  }

  // ── 3. Hostname pre-check ───────────────────────────────────────────────────

  const rawHostname = parsedUrl.hostname.toLowerCase();

  if (!rawHostname) {
    return _reject('SSRF_MISSING_HOSTNAME', { url: rawUrl }, 'URL has no hostname');
  }

  if (_isBlockedHostname(rawHostname)) {
    return _reject('SSRF_BLOCKED_HOSTNAME', { url: rawUrl, hostname: rawHostname },
      `Blocked hostname: ${rawHostname}`);
  }

  // If the hostname is already a bare IP, skip DNS and validate directly
  const isIpv4 = net.isIPv4(rawHostname);
  const isIpv6 = net.isIPv6(rawHostname.replace(/^\[|\]$/g, ''));

  if (isIpv4 || isIpv6) {
    const ipAddr   = rawHostname.replace(/^\[|\]$/g, '');
    const family   = isIpv6 ? 6 : 4;
    const ipReason = _blockedIpReason(ipAddr, family);
    if (ipReason) {
      return _reject('SSRF_BLOCKED_IP', { url: rawUrl, ip: ipAddr }, ipReason);
    }

    const syntheticRecords = [{ address: ipAddr, family }];

    const deny = _checkDenylist(rawHostname, syntheticRecords, config);
    if (deny.denied) {
      return _reject('WEBHOOK_DENYLIST_BLOCKED', { url: rawUrl, hostname: rawHostname }, deny.reason);
    }

    const allow = _checkAllowlist(rawHostname, syntheticRecords, config);
    if (!allow.allowed) {
      return _reject('WEBHOOK_ALLOWLIST_BLOCKED', { url: rawUrl, hostname: rawHostname }, allow.reason);
    }

    return {
      ok:                true,
      parsedUrl,
      hostname:          rawHostname,
      resolvedAddresses: syntheticRecords,
      addressSetKey:     _addressSetKey(syntheticRecords),
    };
  }

  // ── 4. DNS resolution ───────────────────────────────────────────────────────

  let resolvedAddresses;
  try {
    resolvedAddresses = await _resolveHostname(rawHostname, config);
  } catch (err) {
    return _reject('SSRF_DNS_FAILED', { url: rawUrl, hostname: rawHostname }, err.message);
  }

  if (!resolvedAddresses || resolvedAddresses.length === 0) {
    return _reject('SSRF_DNS_NO_RECORDS', { url: rawUrl, hostname: rawHostname },
      `DNS returned no addresses for ${rawHostname}`);
  }

  // ── 5. IP validation ────────────────────────────────────────────────────────

  const blockedReason = _validateAddresses(resolvedAddresses);
  if (blockedReason) {
    return _reject('SSRF_BLOCKED_IP', { url: rawUrl, hostname: rawHostname, resolvedAddresses }, blockedReason);
  }

  // ── 6. Denylist ─────────────────────────────────────────────────────────────

  const deny = _checkDenylist(rawHostname, resolvedAddresses, config);
  if (deny.denied) {
    return _reject('WEBHOOK_DENYLIST_BLOCKED', { url: rawUrl, hostname: rawHostname }, deny.reason);
  }

  // ── 7. Allowlist ────────────────────────────────────────────────────────────

  const allow = _checkAllowlist(rawHostname, resolvedAddresses, config);
  if (!allow.allowed) {
    return _reject('WEBHOOK_ALLOWLIST_BLOCKED', { url: rawUrl, hostname: rawHostname }, allow.reason);
  }

  emit('INFO', 'WEBHOOK_DESTINATION_VALIDATED', {
    hostname:          rawHostname,
    resolvedAddresses: resolvedAddresses.map(r => `${r.family}:${r.address}`),
  });

  return {
    ok:                true,
    parsedUrl,
    hostname:          rawHostname,
    resolvedAddresses,
    addressSetKey:     _addressSetKey(resolvedAddresses),
  };
}

// ── DNS re-validation (rebinding protection) ──────────────────────────────────

/**
 * Build a custom Node.js `lookup` function for use in https.request options.
 *
 * The returned function is called by Node.js immediately before the TCP
 * socket is opened.  It re-resolves the hostname, validates every returned
 * IP, and compares the address set against the first resolution.  If
 * anything differs (DNS rebinding, TTL expiry to a new IP, etc.) the
 * connection is aborted with an error before a single byte is sent.
 *
 * @param {string}  hostname        Original hostname
 * @param {string}  firstSetKey     addressSetKey from validateDestination
 * @param {object}  config
 * @returns {Function}  Node.js dns.lookup-compatible callback function
 */
function createSecureLookup(hostname, firstSetKey, config) {
  return function secureLookup(_host, _options, _callback) {
    // since Node 20 (autoSelectFamily) https.request calls lookup with { all: true } and expects
    // an ARRAY of { address, family }; answering with the single-address form made every webhook to a normal hostname fail
    // with ERR_INVALID_IP_ADDRESS on the project's runtime (Node 24). Also support the (host, callback) call form.
    const callback = typeof _options === 'function' ? _options : _callback;
    const wantAll = !!(_options && typeof _options === 'object' && _options.all);
    dns.lookup(hostname, { all: true })
      .then(secondRecords => {
        if (!secondRecords || secondRecords.length === 0) {
          const err = new Error(`DNS rebinding check: no addresses on re-resolution of ${hostname}`);
          err.code = 'WEBHOOK_DNS_REVALIDATION_EMPTY';
          return callback(err);
        }

        // IP validation on second resolution
        const blockedReason = _validateAddresses(secondRecords);
        if (blockedReason) {
          const err = new Error(`DNS rebinding check: resolved IP is now blocked (${blockedReason})`);
          err.code = 'WEBHOOK_DNS_REVALIDATION_BLOCKED';
          emit('CRITICAL', 'WEBHOOK_DNS_REBINDING_DETECTED', {
            hostname,
            reason: blockedReason,
          });
          return callback(err);
        }

        // Compare address sets
        const secondKey = _addressSetKey(secondRecords);
        if (secondKey !== firstSetKey) {
          const err = new Error(
            `DNS rebinding detected: address set changed for ${hostname} ` +
            `(pre-connect resolution differs from connection-time resolution)`,
          );
          err.code = 'WEBHOOK_DNS_REBINDING_DETECTED';
          emit('CRITICAL', 'WEBHOOK_DNS_REBINDING_DETECTED', {
            hostname,
            firstSetKey,
            secondSetKey: secondKey,
          });
          return callback(err);
        }

        // All checks passed — provide the first validated address to Node.js
        if (wantAll) {
          // every returned address has just been validated and matched the first resolution
          return callback(null, secondRecords.map((r) => ({ address: r.address, family: r.family })));
        }
        const { address, family } = secondRecords[0];
        callback(null, address, family);
      })
      .catch(err => {
        const wrapped = new Error(
          `DNS re-validation failed for ${hostname}: ${err.message}`,
        );
        wrapped.code = 'WEBHOOK_DNS_REVALIDATION_FAILED';
        callback(wrapped);
      });
  };
}

// ── Redirect security ─────────────────────────────────────────────────────────

/**
 * Validate a single redirect hop.
 *
 * Rejects redirects that:
 *   • exceed maxRedirects
 *   • change protocol from HTTPS to anything else
 *   • land on a private/blocked destination
 *   • land on a denied host/domain/CIDR
 *   • are not in the allowlist (if configured)
 *
 * @param {string}  fromUrl
 * @param {string}  toUrl
 * @param {number}  hopCount   0-based hop index (0 = first redirect)
 * @param {object}  config
 * @returns {Promise<ValidationResult>}
 */
async function validateRedirect(fromUrl, toUrl, hopCount, config) {
  if (hopCount >= config.maxRedirects) {
    return _reject('WEBHOOK_REDIRECT_LIMIT', { fromUrl, toUrl, hopCount },
      `Redirect limit exceeded (max ${config.maxRedirects})`);
  }

  let fromParsed, toParsed;
  try { fromParsed = new URL(fromUrl); } catch {
    return _reject('WEBHOOK_REDIRECT_INVALID_FROM', { fromUrl }, `Invalid redirect origin URL: ${fromUrl}`);
  }
  try { toParsed = new URL(toUrl); } catch {
    return _reject('WEBHOOK_REDIRECT_INVALID_TO', { toUrl }, `Invalid redirect destination URL: ${toUrl}`);
  }

  // HTTPS downgrade is never permitted
  if (fromParsed.protocol === 'https:' && toParsed.protocol !== 'https:') {
    return _reject('WEBHOOK_REDIRECT_DOWNGRADE', { fromUrl, toUrl },
      `HTTPS downgrade detected: redirect to ${toParsed.protocol} is not permitted`);
  }

  // Full destination validation on the redirect target
  const result = await validateDestination(toUrl, config);
  if (!result.ok) {
    return _reject('WEBHOOK_REDIRECT_BLOCKED', { fromUrl, toUrl, reason: result.error }, result.error);
  }

  emit('INFO', 'WEBHOOK_REDIRECT_VALIDATED', { from: fromUrl, to: toUrl, hopCount });
  return result;
}

// ── TLS options ───────────────────────────────────────────────────────────────

/**
 * Build TLS options for https.request that enforce the security policy.
 *
 * @param {object} config
 * @returns {object}
 */
function buildTlsOptions(config) {
  return {
    minVersion:          config.tlsMinVersion,
    rejectUnauthorized:  true,
    // Strong cipher suites: TLS 1.3 preferred, TLS 1.2 strong fallback
    ciphers: [
      'TLS_AES_256_GCM_SHA384',
      'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_AES_128_GCM_SHA256',
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':'),
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function _reject(event, extra, error) {
  emit('WARN', event, { ...extra, error });
  return { ok: false, error };
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  validateDestination,
  createSecureLookup,
  validateRedirect,
  buildTlsOptions,
  // Exported for testing
  _blockedIpv4Reason,
  _blockedIpv6Reason,
  _expandIpv6,
  _isIpv4InCidr,
  _isIpv6InPrefix,
  _isBlockedHostname,
  _matchesDomainRule,
  _ipMatchesCidr,
  _checkAllowlist,
  _checkDenylist,
  _addressSetKey,
};
