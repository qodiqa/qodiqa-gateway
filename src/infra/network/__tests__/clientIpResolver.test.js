'use strict';

/**
 * clientIpResolver — trust-boundary-aware client IP resolution
 *
 * Regression suite for the defect fixed in "clientIp Trust Handling
 * Remediation": middleware/clientIp.js used to honour X-Forwarded-For /
 * X-Real-IP unconditionally, with no check on whether the request's actual
 * TCP peer was a trusted proxy. Any external attacker connecting directly
 * could set X-Forwarded-For to an arbitrary value and have it accepted as
 * req.clientIp — spoofing their identity for audit logs, rate limiting,
 * anomaly detection, and (via a separately-configured allowlist) potentially
 * bypassing IP-based access control.
 *
 * QODIQA-PROTOCOL-SPEC.md does not define a clientIp resolution algorithm
 * (verified: no mention anywhere in the spec) — this suite validates the
 * industry-best-practice algorithm documented in clientIpResolver.js.
 */

const { resolveClientIp, parseTrustedProxyConfig } = require('../clientIpResolver');

function makeReq(headers = {}, remoteAddress = '203.0.113.1') {
  return { headers, socket: { remoteAddress } };
}

describe('resolveClientIp — direct connections (no proxy)', () => {
  test('no forwarding headers → socket address, regardless of trust config', () => {
    const req = makeReq({}, '198.51.100.5');
    expect(resolveClientIp(req, false)).toBe('198.51.100.5');
    expect(resolveClientIp(req, true)).toBe('198.51.100.5');
    expect(resolveClientIp(req, ['198.51.100.5'])).toBe('198.51.100.5');
  });

  test('no socket at all → null', () => {
    expect(resolveClientIp({ headers: {}, socket: {} }, true)).toBeNull();
  });
});

describe('resolveClientIp — untrusted peer (the core vulnerability)', () => {
  test('spoofed X-Forwarded-For from a direct, untrusted attacker is IGNORED', () => {
    // Attacker connects directly (peer = their own IP, not a proxy) and sets
    // X-Forwarded-For to an arbitrary value, e.g. to impersonate a trusted
    // internal IP or someone else entirely.
    const req = makeReq({ 'x-forwarded-for': '127.0.0.1' }, '198.51.100.66');
    expect(resolveClientIp(req, ['10.0.0.1'])).toBe('198.51.100.66'); // NOT '127.0.0.1'
  });

  test('spoofed X-Real-IP from an untrusted peer is IGNORED', () => {
    const req = makeReq({ 'x-real-ip': '10.0.0.1' }, '198.51.100.66');
    expect(resolveClientIp(req, ['10.0.0.1'])).toBe('198.51.100.66');
  });

  test('untrusted peer with no trust config at all (default false) is always ignored', () => {
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4' }, '198.51.100.66');
    expect(resolveClientIp(req, undefined)).toBe('198.51.100.66');
    expect(resolveClientIp(req, null)).toBe('198.51.100.66');
    expect(resolveClientIp(req, [])).toBe('198.51.100.66');
  });

  test('peer just outside a configured CIDR is untrusted', () => {
    const req = makeReq({ 'x-forwarded-for': '9.9.9.9' }, '10.0.1.1');
    expect(resolveClientIp(req, ['10.0.0.0/24'])).toBe('10.0.1.1');
  });
});

describe('resolveClientIp — trusted single proxy', () => {
  test('peer is the trusted proxy → XFF single entry is honoured', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('203.0.113.42');
  });

  test('trusted proxy via CIDR range', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.200');
    expect(resolveClientIp(req, ['10.0.0.0/24'])).toBe('203.0.113.42');
  });

  test('trusted proxy via named preset "uniquelocal"', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '192.168.1.1');
    expect(resolveClientIp(req, ['uniquelocal'])).toBe('203.0.113.42');
  });

  test('trusted proxy via named preset "loopback"', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    expect(resolveClientIp(req, ['loopback'])).toBe('203.0.113.42');
  });

  // X-Real-IP is honoured only with TRUSTED_PROXY_REAL_IP=true.
  test('X-Real-IP honoured when X-Forwarded-For is absent, the peer is trusted AND TRUSTED_PROXY_REAL_IP=true', () => {
    process.env.TRUSTED_PROXY_REAL_IP = 'true';
    try {
      const req = makeReq({ 'x-real-ip': '203.0.113.9' }, '10.0.0.5');
      expect(resolveClientIp(req, ['10.0.0.5'])).toBe('203.0.113.9');
    } finally { delete process.env.TRUSTED_PROXY_REAL_IP; }
  });

  test('X-Real-IP from a trusted peer is IGNORED by default (the peer is used)', () => {
    delete process.env.TRUSTED_PROXY_REAL_IP;
    const req = makeReq({ 'x-real-ip': '203.0.113.9' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('X-Forwarded-For takes precedence over X-Real-IP', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.1', 'x-real-ip': '203.0.113.9' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('203.0.113.1');
  });
});

describe('resolveClientIp — multiple trusted proxies (chain walking)', () => {
  test('two trusted proxies in sequence → resolves to the original client, not either proxy', () => {
    // client(203.0.113.42) -> proxyA(10.0.0.1) -> proxyB(10.0.0.2) -> server
    // proxyB is our direct peer; XFF = "203.0.113.42, 10.0.0.1" (proxyA's IP appended by proxyB)
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42, 10.0.0.1' }, '10.0.0.2');
    expect(resolveClientIp(req, ['10.0.0.1', '10.0.0.2'])).toBe('203.0.113.42');
  });

  test('three trusted proxies in sequence', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42, 10.0.0.1, 10.0.0.2' }, '10.0.0.3');
    expect(resolveClientIp(req, ['10.0.0.0/24'])).toBe('203.0.113.42');
  });

  test('chain where the outermost hop is also trusted → returns the leftmost (farthest) entry', () => {
    const req = makeReq({ 'x-forwarded-for': '10.0.0.1, 10.0.0.2' }, '10.0.0.3');
    expect(resolveClientIp(req, ['10.0.0.0/24'])).toBe('10.0.0.1');
  });
});

describe('resolveClientIp — mixed trusted/untrusted chain', () => {
  test('untrusted hop partway through the chain stops the walk at that hop', () => {
    // peer=trustedProxy, but XFF contains an entry that is NOT a trusted proxy
    // partway through — that entry is the real client; anything further left
    // (potentially attacker-appended, since a non-proxy shouldn't be forwarding)
    // is not consulted.
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4, 203.0.113.42' }, '10.0.0.1');
    // Walking from the right: 203.0.113.42 is NOT trusted -> stop here, that's the client.
    expect(resolveClientIp(req, ['10.0.0.1'])).toBe('203.0.113.42');
  });
});

describe('resolveClientIp — malformed forwarding chains', () => {
  test('non-IP entry anywhere in the chain → whole header ignored, falls back to peer', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.99, evil.host' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('IP with port suffix is rejected as malformed', () => {
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4:8080' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('empty string header → treated as absent, socket used', () => {
    const req = makeReq({ 'x-forwarded-for': '' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('whitespace-only header → treated as absent', () => {
    const req = makeReq({ 'x-forwarded-for': '   ' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('SQL-injection-style value is rejected as malformed', () => {
    const req = makeReq({ 'x-forwarded-for': "'; DROP TABLE sessions;--" }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('CRLF-injected header value is rejected as malformed', () => {
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4\r\nX-Admin: true' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('duplicate entries in the chain are walked normally (not treated as an error)', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42, 203.0.113.42, 10.0.0.1' }, '10.0.0.2');
    expect(resolveClientIp(req, ['10.0.0.1', '10.0.0.2'])).toBe('203.0.113.42');
  });

  test('invalid separators (semicolons instead of commas) → treated as one malformed entry, falls back to peer', () => {
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4; 5.6.7.8' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('10.0.0.5');
  });

  test('very long forwarding chain of otherwise-valid IPs still resolves correctly', () => {
    const hops = Array.from({ length: 50 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`);
    const chain = ['203.0.113.42', ...hops].join(', ');
    const req = makeReq({ 'x-forwarded-for': chain }, '10.0.0.1');
    expect(resolveClientIp(req, ['10.0.0.0/8'])).toBe('203.0.113.42');
  });
});

describe('resolveClientIp — whitespace normalization', () => {
  test('leading/trailing spaces around chain entries are trimmed', () => {
    const req = makeReq({ 'x-forwarded-for': '  203.0.113.42  ,  10.0.0.1  ' }, '10.0.0.1');
    expect(resolveClientIp(req, ['10.0.0.1'])).toBe('203.0.113.42');
  });
});

describe('resolveClientIp — IPv4 / IPv6 mixed', () => {
  test('IPv6 client behind a trusted IPv4 proxy', () => {
    const req = makeReq({ 'x-forwarded-for': '2001:db8::1' }, '10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('2001:db8::1');
  });

  test('IPv4-mapped IPv6 peer matches an IPv4 trust entry', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '::ffff:10.0.0.5');
    expect(resolveClientIp(req, ['10.0.0.5'])).toBe('203.0.113.42');
  });

  test('IPv6 trusted proxy via CIDR', () => {
    const req = makeReq({ 'x-forwarded-for': '2001:db8::42' }, 'fd00::1');
    expect(resolveClientIp(req, ['fc00::/7'])).toBe('2001:db8::42');
  });

  test('loopback preset covers ::1', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '::1');
    expect(resolveClientIp(req, ['loopback'])).toBe('203.0.113.42');
  });

  test('IPv4-mapped IPv6 in X-Real-IP is normalized to plain IPv4', () => {
    process.env.TRUSTED_PROXY_REAL_IP = 'true'; // opt-in
    try {
      const req = makeReq({ 'x-real-ip': '::ffff:203.0.113.42' }, '10.0.0.5');
      expect(resolveClientIp(req, ['10.0.0.5'])).toBe('203.0.113.42');
    } finally { delete process.env.TRUSTED_PROXY_REAL_IP; }
  });
});

describe('resolveClientIp — loopback / private / public address handling', () => {
  test('loopback peer untrusted by explicit empty config → returns loopback address itself', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    expect(resolveClientIp(req, [])).toBe('127.0.0.1');
  });

  test('private-range peer (192.168.x.x) untrusted by default → returned as-is', () => {
    const req = makeReq({}, '192.168.1.50');
    expect(resolveClientIp(req, false)).toBe('192.168.1.50');
  });

  test('public peer address resolves to itself with no headers', () => {
    const req = makeReq({}, '203.0.113.200');
    expect(resolveClientIp(req, ['uniquelocal'])).toBe('203.0.113.200');
  });
});

describe('resolveClientIp — trust config: true (trust every peer unconditionally)', () => {
  test('trustConfig=true honours XFF from any peer (opt-in permissive mode)', () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '8.8.8.8');
    expect(resolveClientIp(req, true)).toBe('203.0.113.42');
  });
});

describe('parseTrustedProxyConfig', () => {
  // (Findings Register): unset TRUSTED_PROXY used to default to
  // ['loopback', 'linklocal', 'uniquelocal'] — trusting the entire RFC1918 +
  // link-local space, not just loopback, so any peer on that range could
  // spoof X-Forwarded-For / X-Real-IP by default. Now default-off: an empty
  // trust list, no forwarded header ever honoured unless explicitly configured.
  // unset now defaults to ['loopback'] — a
  // same-host reverse proxy only.'s defect (the whole RFC1918 + link-local
  // space trusted by default) stays closed: see the private-range tests below.
  test('unset env var defaults to loopback only', () => {
    expect(parseTrustedProxyConfig(undefined)).toEqual(['loopback']);
  });

  test('comma-separated env var is parsed and trimmed', () => {
    expect(parseTrustedProxyConfig(' 10.0.0.1 , 10.0.0.2 ')).toEqual(['10.0.0.1', '10.0.0.2']);
  });

  test('empty string env var falls back to the default (empty trust list)', () => {
    expect(parseTrustedProxyConfig('')).toEqual([]);
  });

  test('the old preset default remains available, opt-in, via explicit configuration', () => {
    expect(parseTrustedProxyConfig('loopback,linklocal,uniquelocal')).toEqual(['loopback', 'linklocal', 'uniquelocal']);
  });
});

describe('resolveClientIp — regression: default-off, opt-in restores the old behaviour', () => {
  test('a request direct from the public internet with the default trust config never honours XFF', () => {
    const defaultTrust = parseTrustedProxyConfig(undefined);
    const req = makeReq({ 'x-forwarded-for': '127.0.0.1' }, '203.0.113.200');
    expect(resolveClientIp(req, defaultTrust)).toBe('203.0.113.200');
  });

  // (D6 → B): a same-host reverse proxy (loopback peer) is trusted by
  // default, so the real client behind it is resolved (otherwise every proxied
  // client would appear as 127.0.0.1 — e.g. to the admin allowlist). An
  // explicitly EMPTY TRUSTED_PROXY still trusts nothing.
  test('a request via a loopback peer, under the default, resolves the forwarded client; empty TRUSTED_PROXY trusts nothing', () => {
    const defaultTrust = parseTrustedProxyConfig(undefined);
    expect(defaultTrust).toEqual(['loopback']);
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    expect(resolveClientIp(req, defaultTrust)).toBe('203.0.113.42');
    expect(resolveClientIp(req, parseTrustedProxyConfig(''))).toBe('127.0.0.1');
  });

  test('a request via a loopback-adjacent peer, with TRUSTED_PROXY explicitly configured, honours XFF as before', () => {
    const explicitTrust = parseTrustedProxyConfig('loopback,linklocal,uniquelocal');
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    expect(resolveClientIp(req, explicitTrust)).toBe('203.0.113.42');
  });

  test('a request via a private-network (RFC1918) peer, under the NEW default, does NOT honour XFF either', () => {
    const defaultTrust = parseTrustedProxyConfig(undefined);
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.5');
    expect(resolveClientIp(req, defaultTrust)).toBe('10.0.0.5');
  });
});
