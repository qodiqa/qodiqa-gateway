'use strict';

/**
 * IP / CIDR matching primitives — single source of truth.
 *
 * Extracted from src/middleware/opsIpAllowlist.js (Phase: clientIp trust
 * remediation) so the same tested matcher logic can be shared by the
 * trust-aware client IP resolver (src/infra/network/clientIpResolver.js)
 * without duplicating IPv4/IPv6 CIDR arithmetic in two places.
 *
 * All matcher builders fail closed: malformed input returns null rather
 * than throwing or silently matching everything.
 */

const net = require('net');

// ── IPv4 utilities ────────────────────────────────────────────────────────────

function _ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return NaN;
  let n = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return NaN;
    n = (n * 256 + octet) >>> 0;
  }
  return n;
}

// ── IPv6 utilities ────────────────────────────────────────────────────────────

// Expand a compressed IPv6 address to full 8-group form.
// Returns null for invalid input or IPv4-mapped addresses (those are
// handled separately by _normalizeIp before matching).
function _expandIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower.includes('.')) return null; // IPv4-mapped forms not handled here

  const halves = lower.split('::');
  if (halves.length > 2) return null;

  let groups;
  if (halves.length === 1) {
    groups = halves[0].split(':');
  } else {
    const left  = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const fill  = 8 - left.length - right.length;
    if (fill < 0) return null;
    groups = [...left, ...new Array(fill).fill('0'), ...right];
  }

  if (groups.length !== 8) return null;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
  }

  return groups.map(g => g.padStart(4, '0')).join(':');
}

// Convert a valid IPv6 address string to a 128-bit BigInt.
// Returns null on failure (fail-closed).
function _ipv6ToBigInt(ip) {
  const expanded = _expandIPv6(ip);
  if (!expanded) return null;
  let result = 0n;
  for (const g of expanded.split(':')) {
    result = (result << 16n) | BigInt(parseInt(g, 16));
  }
  return result;
}

// Build an IPv6 matcher from a CIDR string or bare IPv6 address.
// Uses 128-bit BigInt arithmetic for prefix masking.
// Returns null on parse failure (fail-closed).
function _buildIPv6Matcher(entry) {
  const slash = entry.indexOf('/');
  let ipPart, prefixLen;

  if (slash === -1) {
    ipPart    = entry;
    prefixLen = 128;
  } else {
    ipPart    = entry.slice(0, slash);
    prefixLen = parseInt(entry.slice(slash + 1), 10);
    if (!Number.isInteger(prefixLen) || prefixLen < 0 || prefixLen > 128) return null;
  }

  const ipInt = _ipv6ToBigInt(ipPart);
  if (ipInt === null) return null;

  const mask    = prefixLen === 0
    ? 0n
    : ((1n << BigInt(prefixLen)) - 1n) << BigInt(128 - prefixLen);
  const network = ipInt & mask;

  return (candidate) => {
    const c = _ipv6ToBigInt(candidate);
    return c !== null && (c & mask) === network;
  };
}

// Build a matcher function from a CIDR string or bare IP (IPv4 or IPv6).
// Returns null on parse failure (fail-closed).
function _buildMatcher(entry) {
  const slash  = entry.indexOf('/');
  const ipPart = slash === -1 ? entry : entry.slice(0, slash);

  // Dispatch to IPv6 path when the address portion is a native IPv6 address.
  // Exclude IPv4-mapped forms (they contain dots and are handled via _normalizeIp).
  if (ipPart.includes(':') && !ipPart.includes('.') && net.isIPv6(ipPart)) {
    return _buildIPv6Matcher(entry);
  }

  // IPv4 path
  let prefixLen;
  if (slash === -1) {
    prefixLen = 32;
  } else {
    prefixLen = parseInt(entry.slice(slash + 1), 10);
    if (!Number.isInteger(prefixLen) || prefixLen < 0 || prefixLen > 32) return null;
  }

  const ipInt = _ipToInt(ipPart);
  if (isNaN(ipInt)) return null;

  const mask    = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  const network = (ipInt & mask) >>> 0;

  return (candidate) => {
    const c = _ipToInt(candidate);
    return !isNaN(c) && ((c & mask) >>> 0) === network;
  };
}

// Strip IPv4-mapped IPv6 prefix so the plain IPv4 matcher can handle it.
function _normalizeIp(ip) {
  if (typeof ip !== 'string') return null;
  if (ip.startsWith('::ffff:')) {
    const v4 = ip.slice(7);
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v4)) return v4;
  }
  return ip;
}

module.exports = {
  _ipToInt,
  _expandIPv6,
  _ipv6ToBigInt,
  _buildIPv6Matcher,
  _buildMatcher,
  _normalizeIp,
};
