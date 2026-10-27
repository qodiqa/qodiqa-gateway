'use strict';

const net = require('net');

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`Invalid IP address: ${ip}`);
  return parts.reduce((acc, octet) => {
    const n = parseInt(octet, 10);
    if (isNaN(n) || n < 0 || n > 255) throw new Error(`Invalid IP octet: ${octet} in ${ip}`);
    return ((acc << 8) | n) >>> 0;
  }, 0);
}

function parseCidr(cidr) {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) throw new Error(`Invalid CIDR (missing prefix): ${cidr}`);

  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) {
    throw new Error(`Invalid CIDR prefix length: ${cidr}`);
  }

  const base = ipToInt(cidr.slice(0, slash));
  const mask = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
  return {
    start: (base & mask) >>> 0,
    end:   ((base & mask) | (~mask >>> 0)) >>> 0,
  };
}

// S-01: IPv6 CIDR support. A CIDR whose base contains ':' is an IPv6 range
// (e.g. '::/0', '2001:db8::/32') and is matched with Node's net.BlockList. Before this change such a CIDR was
// REJECTED by validate() (ipToInt threw), so no previously valid configuration changes behaviour: IPv4 CIDRs
// keep exactly the integer-range path below, and an IPv6 client still never matches an IPv4 range.
function _isV6Cidr(cidr) {
  return typeof cidr === 'string' && cidr.slice(0, cidr.lastIndexOf('/')).includes(':');
}

function parseCidrV6(cidr) {
  const slash = cidr.lastIndexOf('/');
  if (slash === -1) throw new Error(`Invalid CIDR (missing prefix): ${cidr}`);
  const base = cidr.slice(0, slash);
  const prefixRaw = cidr.slice(slash + 1);
  if (!/^[0-9]{1,3}$/.test(prefixRaw)) throw new Error(`Invalid CIDR prefix length: ${cidr}`);
  const prefixLen = parseInt(prefixRaw, 10);
  if (prefixLen < 0 || prefixLen > 128) throw new Error(`Invalid CIDR prefix length: ${cidr}`);
  if (net.isIPv6(base) !== true) throw new Error(`Invalid IPv6 address: ${base}`);
  return { base, prefixLen };
}

function validate(config) {
  if (!Array.isArray(config.blocklist)) throw new Error('config.blocklist must be an array');
  if (!Array.isArray(config.cidrs))     throw new Error('config.cidrs must be an array');
  for (const ip   of config.blocklist) ipToInt(ip);
  for (const cidr of config.cidrs) {
    if (_isV6Cidr(cidr)) parseCidrV6(cidr);
    else parseCidr(cidr);
  }
}

function preprocess(config) {
  const v4 = config.cidrs.filter(c => !_isV6Cidr(c));
  const v6 = config.cidrs.filter(_isV6Cidr);
  let v6List = null;
  if (v6.length > 0) {
    v6List = new net.BlockList();
    for (const c of v6) {
      const { base, prefixLen } = parseCidrV6(c);
      v6List.addSubnet(base, prefixLen, 'ipv6');
    }
  }
  return {
    ...config,
    _blocklistSet: new Set(config.blocklist),
    _cidrRanges:   v4.map(parseCidr),
    _cidrV6List:   v6List,
  };
}

function evaluate(context, config) {
  const { ip } = context;
  if (!ip || typeof ip !== 'string') {
    return { pass: false, reason: 'IP_MISSING' };
  }

  if (config._blocklistSet.has(ip)) {
    return { pass: false, reason: 'IP_BLOCKED' };
  }

  // CIDR ranges in this evaluator are IPv4-only. A non-IPv4 address (e.g. ::1)
  // cannot match any IPv4 range — skip range checks rather than blocking it.
  // The exact blocklist above already handles IPv6 entries when present.
  let ipInt;
  try {
    ipInt = ipToInt(ip);
  } catch {
    // Not IPv4. Only an explicitly configured IPv6 CIDR (S-01) can match it.
    if (config._cidrV6List && net.isIPv6(ip) && config._cidrV6List.check(ip, 'ipv6')) {
      return { pass: false, reason: 'IP_BLOCKED' };
    }
    return { pass: true };
  }

  for (const range of config._cidrRanges) {
    if (ipInt >= range.start && ipInt <= range.end) {
      return { pass: false, reason: 'IP_BLOCKED' };
    }
  }

  return { pass: true };
}

module.exports = { validate, preprocess, evaluate };
