'use strict';

/**
 * Webhook Security Tests — Component 44.6
 *
 * WSC-01…10   IPv4 SSRF range blocking
 * WSC-11…20   IPv6 SSRF range blocking
 * WSC-21…27   Hostname blocking (exact + suffix)
 * WSC-28…33   Protocol enforcement
 * WSC-34…40   DNS resolution + IP validation (mocked)
 * WSC-41…50   DNS rebinding detection (address-set change)
 * WSC-51…60   Allowlist matching (hosts, wildcard domains, CIDRs)
 * WSC-61…68   Denylist matching (hosts, wildcard domains, CIDRs)
 * WSC-69…74   Allowlist + denylist interaction (deny overrides allow)
 * WSC-75…83   Redirect security
 * WSC-84…92   Circuit breaker (closed → open → half-open → closed)
 * WSC-93…98   validateDestination integration
 * WSC-99…106  Edge cases: malformed URLs, empty hostname, IPv6 expansion
 * WSC-107…113 Concurrent / race-condition safety
 */

// ── Global mocks (must precede all requires) ──────────────────────────────────

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(),
}));

const mockDnsLookup = jest.fn();
jest.mock('dns', () => ({
  promises: { lookup: mockDnsLookup },
}));

// ── Imports ───────────────────────────────────────────────────────────────────

const {
  validateDestination,
  createSecureLookup,
  validateRedirect,
  buildTlsOptions,
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
} = require('../webhookSecurity');

const {
  CircuitBreaker,
  getCircuitBreaker,
  resetAll: resetCircuitBreakers,
  STATE_CLOSED,
  STATE_OPEN,
  STATE_HALF_OPEN,
} = require('../webhookCircuitBreaker');

const { buildConfig } = require('../webhookSecurityConfig');

// ── Shared helpers ────────────────────────────────────────────────────────────

const OPEN_CONFIG = buildConfig(); // default config with no allow/deny lists

function cfgWith(overrides) {
  return Object.freeze({ ...OPEN_CONFIG, ...overrides });
}

function mockDns(records) {
  mockDnsLookup.mockResolvedValue(records);
}

function mockDnsSeq(...sequences) {
  let i = 0;
  mockDnsLookup.mockImplementation(() => {
    if (i >= sequences.length) return Promise.resolve(sequences[sequences.length - 1]);
    return Promise.resolve(sequences[i++]);
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  resetCircuitBreakers();
  // Default: resolve to a safe public IP
  mockDns([{ address: '93.184.216.34', family: 4 }]);
});

// ── WSC-01…10: IPv4 SSRF range blocking ──────────────────────────────────────

describe('WSC — IPv4 SSRF blocking', () => {
  test('WSC-01 permits public IPv4 (93.184.216.34)', () => {
    expect(_blockedIpv4Reason('93.184.216.34')).toBeNull();
  });

  test('WSC-02 blocks loopback 127.0.0.1', () => {
    expect(_blockedIpv4Reason('127.0.0.1')).toMatch(/blocked/i);
  });

  test('WSC-03 blocks loopback edge 127.255.255.255', () => {
    expect(_blockedIpv4Reason('127.255.255.255')).toMatch(/blocked/i);
  });

  test('WSC-04 blocks RFC-1918 10.0.0.1', () => {
    expect(_blockedIpv4Reason('10.0.0.1')).toMatch(/blocked/i);
  });

  test('WSC-05 blocks RFC-1918 172.16.0.1', () => {
    expect(_blockedIpv4Reason('172.16.0.1')).toMatch(/blocked/i);
  });

  test('WSC-06 blocks RFC-1918 172.31.255.255', () => {
    expect(_blockedIpv4Reason('172.31.255.255')).toMatch(/blocked/i);
  });

  test('WSC-07 permits 172.32.0.1 (outside 172.16/12)', () => {
    expect(_blockedIpv4Reason('172.32.0.1')).toBeNull();
  });

  test('WSC-08 blocks RFC-1918 192.168.0.1', () => {
    expect(_blockedIpv4Reason('192.168.0.1')).toMatch(/blocked/i);
  });

  test('WSC-09 blocks link-local 169.254.169.254 (AWS/GCP metadata)', () => {
    expect(_blockedIpv4Reason('169.254.169.254')).toMatch(/blocked/i);
  });

  test('WSC-10 blocks carrier-grade NAT 100.64.0.1', () => {
    expect(_blockedIpv4Reason('100.64.0.1')).toMatch(/blocked/i);
  });
});

// ── WSC-11…20: IPv4 additional ranges ────────────────────────────────────────

describe('WSC — IPv4 additional blocked ranges', () => {
  test('WSC-11 blocks 0.0.0.0/8 this-network', () => {
    expect(_blockedIpv4Reason('0.1.2.3')).toMatch(/blocked/i);
  });

  test('WSC-12 blocks documentation 192.0.2.1 (TEST-NET-1)', () => {
    expect(_blockedIpv4Reason('192.0.2.1')).toMatch(/blocked/i);
  });

  test('WSC-13 blocks documentation 198.51.100.1 (TEST-NET-2)', () => {
    expect(_blockedIpv4Reason('198.51.100.1')).toMatch(/blocked/i);
  });

  test('WSC-14 blocks documentation 203.0.113.1 (TEST-NET-3)', () => {
    expect(_blockedIpv4Reason('203.0.113.1')).toMatch(/blocked/i);
  });

  test('WSC-15 blocks benchmark 198.18.0.1', () => {
    expect(_blockedIpv4Reason('198.18.0.1')).toMatch(/blocked/i);
  });

  test('WSC-16 blocks benchmark 198.19.255.255', () => {
    expect(_blockedIpv4Reason('198.19.255.255')).toMatch(/blocked/i);
  });

  test('WSC-17 blocks multicast 224.0.0.1', () => {
    expect(_blockedIpv4Reason('224.0.0.1')).toMatch(/blocked/i);
  });

  test('WSC-18 blocks reserved 240.0.0.1', () => {
    expect(_blockedIpv4Reason('240.0.0.1')).toMatch(/blocked/i);
  });

  test('WSC-19 blocks broadcast 255.255.255.255', () => {
    expect(_blockedIpv4Reason('255.255.255.255')).toMatch(/blocked/i);
  });

  test('WSC-20 permits 8.8.8.8', () => {
    expect(_blockedIpv4Reason('8.8.8.8')).toBeNull();
  });
});

// ── WSC-21…27: Hostname blocking ─────────────────────────────────────────────

describe('WSC — hostname blocking', () => {
  test('WSC-21 blocks localhost', () => {
    expect(_isBlockedHostname('localhost')).toBe(true);
  });

  test('WSC-22 blocks ip6-localhost', () => {
    expect(_isBlockedHostname('ip6-localhost')).toBe(true);
  });

  test('WSC-23 blocks metadata.google.internal', () => {
    expect(_isBlockedHostname('metadata.google.internal')).toBe(true);
  });

  test('WSC-24 blocks kubernetes.default.svc.cluster.local', () => {
    expect(_isBlockedHostname('kubernetes.default.svc.cluster.local')).toBe(true);
  });

  test('WSC-25 blocks any .svc.cluster.local suffix', () => {
    expect(_isBlockedHostname('my-service.default.svc.cluster.local')).toBe(true);
  });

  test('WSC-26 blocks host.docker.internal', () => {
    expect(_isBlockedHostname('host.docker.internal')).toBe(true);
  });

  test('WSC-27 permits example.com', () => {
    expect(_isBlockedHostname('example.com')).toBe(false);
  });
});

// ── WSC-28…33: Protocol enforcement ──────────────────────────────────────────

describe('WSC — protocol enforcement', () => {
  test('WSC-28 rejects http://', async () => {
    const r = await validateDestination('http://example.com/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/protocol/i);
  });

  test('WSC-29 rejects ftp://', async () => {
    const r = await validateDestination('ftp://example.com/file', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/protocol/i);
  });

  test('WSC-30 rejects file://', async () => {
    const r = await validateDestination('file:///etc/passwd', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-31 rejects gopher://', async () => {
    const r = await validateDestination('gopher://example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-32 rejects ldap://', async () => {
    const r = await validateDestination('ldap://example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-33 accepts https://', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const r = await validateDestination('https://example.com/hook', OPEN_CONFIG);
    expect(r.ok).toBe(true);
  });
});

// ── WSC-34…40: DNS resolution and IP validation ───────────────────────────────

describe('WSC — DNS resolution and IP validation', () => {
  test('WSC-34 rejects when DNS returns private IP (10.x)', async () => {
    mockDns([{ address: '10.0.0.5', family: 4 }]);
    const r = await validateDestination('https://internal.example.com/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/blocked/i);
  });

  test('WSC-35 rejects when DNS returns 127.x loopback', async () => {
    mockDns([{ address: '127.0.0.1', family: 4 }]);
    const r = await validateDestination('https://evil.example.com/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-36 rejects when DNS returns link-local 169.254.169.254', async () => {
    mockDns([{ address: '169.254.169.254', family: 4 }]);
    const r = await validateDestination('https://aws-spoof.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-37 rejects when any resolved IP is private (mixed results)', async () => {
    mockDns([
      { address: '93.184.216.34', family: 4 },
      { address: '192.168.1.1',   family: 4 },
    ]);
    const r = await validateDestination('https://mixed.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-38 rejects when DNS fails (mock rejection)', async () => {
    mockDnsLookup.mockRejectedValue(new Error('ENOTFOUND no-such-host.invalid'));
    const r = await validateDestination('https://no-such-host.invalid/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/DNS/i);
  });

  test('WSC-39 accepts when DNS returns a valid public IP', async () => {
    mockDns([{ address: '8.8.8.8', family: 4 }]);
    const r = await validateDestination('https://dns-ok.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(true);
    expect(r.hostname).toBe('dns-ok.example.com');
    expect(r.resolvedAddresses[0].address).toBe('8.8.8.8');
  });

  test('WSC-40 rejects when DNS returns empty array', async () => {
    mockDns([]);
    const r = await validateDestination('https://empty-dns.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });
});

// ── WSC-41…50: DNS rebinding detection ───────────────────────────────────────

describe('WSC — DNS rebinding detection', () => {
  test('WSC-41 rejects when address set changes between resolutions', (done) => {
    const hostname    = 'rebind.example.com';
    const firstSetKey = _addressSetKey([{ address: '93.184.216.34', family: 4 }]);

    // Second resolution returns a different valid public IP — pure address-set change
    mockDns([{ address: '1.2.3.4', family: 4 }]);

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err) => {
      try {
        expect(err).not.toBeNull();
        expect(err.code).toBe('WEBHOOK_DNS_REBINDING_DETECTED');
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-42 rejects when IP is valid but address set differs (new public IP)', (done) => {
    const hostname    = 'cdn.example.com';
    const firstSetKey = _addressSetKey([{ address: '1.2.3.4', family: 4 }]);

    // Second resolution returns a different (valid) IP — still a change
    mockDns([{ address: '5.6.7.8', family: 4 }]);

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err) => {
      try {
        expect(err).not.toBeNull();
        expect(err.code).toBe('WEBHOOK_DNS_REBINDING_DETECTED');
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-43 permits when address set is identical on second resolution', (done) => {
    const hostname    = 'stable.example.com';
    const records     = [{ address: '93.184.216.34', family: 4 }];
    const firstSetKey = _addressSetKey(records);

    mockDns(records); // same result on re-resolution

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err, addr, fam) => {
      try {
        expect(err).toBeNull();
        expect(addr).toBe('93.184.216.34');
        expect(fam).toBe(4);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-44 rejects when second resolution returns empty', (done) => {
    const hostname    = 'flap.example.com';
    const firstSetKey = _addressSetKey([{ address: '93.184.216.34', family: 4 }]);

    mockDns([]);

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err) => {
      try {
        expect(err).not.toBeNull();
        expect(err.code).toBe('WEBHOOK_DNS_REVALIDATION_EMPTY');
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-45 rejects when second resolution throws', (done) => {
    const hostname    = 'fail.example.com';
    const firstSetKey = _addressSetKey([{ address: '93.184.216.34', family: 4 }]);

    mockDnsLookup.mockRejectedValue(new Error('network error'));

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err) => {
      try {
        expect(err).not.toBeNull();
        expect(err.code).toBe('WEBHOOK_DNS_REVALIDATION_FAILED');
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-46 addressSetKey is order-independent', () => {
    const a = _addressSetKey([{ address: '1.2.3.4', family: 4 }, { address: '5.6.7.8', family: 4 }]);
    const b = _addressSetKey([{ address: '5.6.7.8', family: 4 }, { address: '1.2.3.4', family: 4 }]);
    expect(a).toBe(b);
  });

  test('WSC-47 addressSetKey distinguishes different addresses', () => {
    const a = _addressSetKey([{ address: '1.2.3.4', family: 4 }]);
    const b = _addressSetKey([{ address: '5.6.7.8', family: 4 }]);
    expect(a).not.toBe(b);
  });

  test('WSC-48 rejects when second resolution returns blocked IP (critical log)', (done) => {
    const { emit } = require('../../../../services/logger');
    const hostname    = 'ssrf-rebind.example.com';
    const firstSetKey = _addressSetKey([{ address: '93.184.216.34', family: 4 }]);

    // Second resolution resolves to metadata endpoint
    mockDns([{ address: '169.254.169.254', family: 4 }]);

    const lookup = createSecureLookup(hostname, firstSetKey, OPEN_CONFIG);
    lookup(hostname, {}, (err) => {
      try {
        expect(err).not.toBeNull();
        expect(err.code).toBe('WEBHOOK_DNS_REVALIDATION_BLOCKED');
        // Must emit CRITICAL for security incident
        expect(emit).toHaveBeenCalledWith('CRITICAL', 'WEBHOOK_DNS_REBINDING_DETECTED', expect.any(Object));
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  test('WSC-49 validateDestination returns addressSetKey for use in secureLookup', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const r = await validateDestination('https://example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(true);
    expect(typeof r.addressSetKey).toBe('string');
    expect(r.addressSetKey.length).toBeGreaterThan(0);
  });

  test('WSC-50 addressSetKey is case-insensitive for IPv6', () => {
    const a = _addressSetKey([{ address: '2001:DB8::1', family: 6 }]);
    const b = _addressSetKey([{ address: '2001:db8::1', family: 6 }]);
    expect(a).toBe(b);
  });
});

// ── WSC-51…60: Allowlist ──────────────────────────────────────────────────────

describe('WSC — allowlist', () => {
  test('WSC-51 permits any host when allowlist is empty', () => {
    const result = _checkAllowlist('example.com', [{ address: '93.184.216.34', family: 4 }], OPEN_CONFIG);
    expect(result.allowed).toBe(true);
  });

  test('WSC-52 permits exact host match in allowedHosts', () => {
    const cfg = cfgWith({ allowedHosts: ['hooks.example.com'] });
    const r   = _checkAllowlist('hooks.example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(true);
  });

  test('WSC-53 rejects host not in allowedHosts (allowlist configured)', () => {
    const cfg = cfgWith({ allowedHosts: ['hooks.example.com'] });
    const r   = _checkAllowlist('other.example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(false);
  });

  test('WSC-54 permits wildcard domain match *.example.com', () => {
    const cfg = cfgWith({ allowedDomains: ['*.example.com'] });
    const r   = _checkAllowlist('sub.example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(true);
  });

  test('WSC-55 rejects second-level subdomain with single-star wildcard', () => {
    const cfg = cfgWith({ allowedDomains: ['*.example.com'] });
    const r   = _checkAllowlist('deep.sub.example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(false);
  });

  test('WSC-56 rejects bare domain when allowedDomains has *.example.com', () => {
    const cfg = cfgWith({ allowedDomains: ['*.example.com'] });
    const r   = _checkAllowlist('example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(false);
  });

  test('WSC-57 permits IP in allowedCidrs', () => {
    const cfg = cfgWith({ allowedCidrs: ['203.0.113.0/24'] });
    // 203.0.113.x is documentation range but allowed via allowlist
    const r   = _checkAllowlist('1.2.3.4', [{ address: '203.0.113.5', family: 4 }], cfg);
    expect(r.allowed).toBe(true);
  });

  test('WSC-58 rejects IP outside allowedCidrs', () => {
    const cfg = cfgWith({ allowedCidrs: ['203.0.113.0/24'] });
    const r   = _checkAllowlist('example.com', [{ address: '8.8.8.8', family: 4 }], cfg);
    expect(r.allowed).toBe(false);
  });

  test('WSC-59 host allowlist is case-insensitive', () => {
    const cfg = cfgWith({ allowedHosts: ['HOOKS.Example.COM'] });
    const r   = _checkAllowlist('hooks.example.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.allowed).toBe(true);
  });

  test('WSC-60 allowlist match via any rule (host OR domain OR cidr)', () => {
    const cfg = cfgWith({ allowedHosts: ['x.com'], allowedDomains: ['*.y.com'], allowedCidrs: [] });
    const r1 = _checkAllowlist('x.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    const r2 = _checkAllowlist('a.y.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    const r3 = _checkAllowlist('z.com',  [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);
  });
});

// ── WSC-61…68: Denylist ───────────────────────────────────────────────────────

describe('WSC — denylist', () => {
  test('WSC-61 permits host not in denylist', () => {
    const cfg = cfgWith({ deniedHosts: ['evil.com'] });
    const r   = _checkDenylist('good.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.denied).toBe(false);
  });

  test('WSC-62 blocks exact host in deniedHosts', () => {
    const cfg = cfgWith({ deniedHosts: ['evil.com'] });
    const r   = _checkDenylist('evil.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.denied).toBe(true);
  });

  test('WSC-63 blocks wildcard domain in deniedDomains', () => {
    const cfg = cfgWith({ deniedDomains: ['*.evil.com'] });
    const r   = _checkDenylist('sub.evil.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.denied).toBe(true);
  });

  test('WSC-64 does not block parent when wildcard is *.evil.com', () => {
    const cfg = cfgWith({ deniedDomains: ['*.evil.com'] });
    const r   = _checkDenylist('evil.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.denied).toBe(false);
  });

  test('WSC-65 blocks IP in deniedCidrs', () => {
    const cfg = cfgWith({ deniedCidrs: ['8.8.8.0/24'] });
    const r   = _checkDenylist('dns.google', [{ address: '8.8.8.8', family: 4 }], cfg);
    expect(r.denied).toBe(true);
  });

  test('WSC-66 does not block IP outside deniedCidrs', () => {
    const cfg = cfgWith({ deniedCidrs: ['8.8.8.0/24'] });
    const r   = _checkDenylist('other.com', [{ address: '9.9.9.9', family: 4 }], cfg);
    expect(r.denied).toBe(false);
  });

  test('WSC-67 denylist check is case-insensitive for host', () => {
    const cfg = cfgWith({ deniedHosts: ['EVIL.COM'] });
    const r   = _checkDenylist('evil.com', [{ address: '1.2.3.4', family: 4 }], cfg);
    expect(r.denied).toBe(true);
  });

  test('WSC-68 deny blocks even if multiple IPs and only one matches', () => {
    const cfg     = cfgWith({ deniedCidrs: ['10.0.0.0/8'] });
    const addrs   = [{ address: '8.8.8.8', family: 4 }, { address: '10.0.0.1', family: 4 }];
    const r       = _checkDenylist('mixed.example.com', addrs, cfg);
    expect(r.denied).toBe(true);
  });
});

// ── WSC-69…74: Deny overrides allow ──────────────────────────────────────────

describe('WSC — deny overrides allow', () => {
  test('WSC-69 deny wins when host is in both allowedHosts and deniedHosts', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ allowedHosts: ['example.com'], deniedHosts: ['example.com'] });
    const r   = await validateDestination('https://example.com/', cfg);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/denied/i);
  });

  test('WSC-70 deny wins when IP is in allowedCidrs and deniedCidrs', async () => {
    mockDns([{ address: '8.8.8.8', family: 4 }]);
    const cfg = cfgWith({ allowedCidrs: ['8.0.0.0/8'], deniedCidrs: ['8.8.8.0/24'] });
    const r   = await validateDestination('https://dns.google/', cfg);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/denied/i);
  });

  test('WSC-71 deny wins for domain in both allowedDomains and deniedDomains', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ allowedDomains: ['*.example.com'], deniedDomains: ['*.example.com'] });
    const r   = await validateDestination('https://hooks.example.com/', cfg);
    expect(r.ok).toBe(false);
  });

  test('WSC-72 empty denylist does not interfere with open allowlist', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ allowedHosts: [], deniedHosts: [] });
    const r   = await validateDestination('https://example.com/', cfg);
    expect(r.ok).toBe(true);
  });

  test('WSC-73 allowlist blocks host not matching even if denylist empty', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ allowedHosts: ['allowed.example.com'], deniedHosts: [] });
    const r   = await validateDestination('https://other.example.com/', cfg);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/allowlist/i);
  });

  test('WSC-74 allowlist permits configured host with empty denylist', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ allowedHosts: ['example.com'], deniedHosts: [] });
    const r   = await validateDestination('https://example.com/', cfg);
    expect(r.ok).toBe(true);
  });
});

// ── WSC-75…83: Redirect security ─────────────────────────────────────────────

describe('WSC — redirect security', () => {
  test('WSC-75 permits valid HTTPS redirect', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const r = await validateRedirect('https://a.example.com/', 'https://b.example.com/', 0, OPEN_CONFIG);
    expect(r.ok).toBe(true);
  });

  test('WSC-76 rejects HTTPS→HTTP downgrade', async () => {
    const r = await validateRedirect('https://example.com/', 'http://example.com/', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/downgrade/i);
  });

  test('WSC-77 rejects redirect to private IP destination', async () => {
    mockDns([{ address: '192.168.1.1', family: 4 }]);
    const r = await validateRedirect('https://example.com/', 'https://internal.example.com/', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-78 rejects redirect exceeding maxRedirects', async () => {
    const cfg = cfgWith({ maxRedirects: 3 });
    const r   = await validateRedirect('https://a.com/', 'https://b.com/', 3, cfg);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/limit/i);
  });

  test('WSC-79 allows redirect at exactly maxRedirects - 1', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const cfg = cfgWith({ maxRedirects: 3 });
    const r   = await validateRedirect('https://a.com/', 'https://b.com/', 2, cfg);
    expect(r.ok).toBe(true);
  });

  test('WSC-80 rejects redirect to blocked hostname', async () => {
    const r = await validateRedirect('https://example.com/', 'https://localhost/hook', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-81 rejects redirect with malformed destination URL', async () => {
    const r = await validateRedirect('https://example.com/', 'not-a-url', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-82 rejects redirect with malformed origin URL', async () => {
    const r = await validateRedirect('not-a-url', 'https://example.com/', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-83 rejects HTTPS→ftp downgrade in redirect', async () => {
    const r = await validateRedirect('https://example.com/', 'ftp://example.com/', 0, OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });
});

// ── WSC-84…92: Circuit breaker ───────────────────────────────────────────────

describe('WSC — circuit breaker', () => {
  test('WSC-84 starts in CLOSED state', () => {
    const cb = new CircuitBreaker('cb-test.com', OPEN_CONFIG);
    expect(cb.state).toBe(STATE_CLOSED);
  });

  test('WSC-85 allowRequest returns true when CLOSED', () => {
    const cb = new CircuitBreaker('cb-test.com', OPEN_CONFIG);
    expect(cb.allowRequest()).toBe(true);
  });

  test('WSC-86 transitions to OPEN after cbFailureThreshold consecutive failures', () => {
    const cfg = cfgWith({ cbFailureThreshold: 3 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    cb.onFailure();
    expect(cb.state).toBe(STATE_CLOSED);
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('WSC-87 rejects requests when OPEN (allowRequest returns false)', () => {
    const cfg = cfgWith({ cbFailureThreshold: 1 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
    expect(cb.allowRequest()).toBe(false);
  });

  test('WSC-88 transitions to HALF_OPEN after recovery timeout', () => {
    const cfg = cfgWith({ cbFailureThreshold: 1, cbRecoveryMs: 0 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
    // Recovery timeout is 0ms — already elapsed
    expect(cb.allowRequest()).toBe(true);
    expect(cb.state).toBe(STATE_HALF_OPEN);
  });

  test('WSC-89 transitions HALF_OPEN→CLOSED after cbSuccessThreshold successes', () => {
    const cfg = cfgWith({ cbFailureThreshold: 1, cbRecoveryMs: 0, cbSuccessThreshold: 2 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    cb.allowRequest(); // triggers HALF_OPEN transition
    cb.onSuccess();
    expect(cb.state).toBe(STATE_HALF_OPEN);
    cb.onSuccess();
    expect(cb.state).toBe(STATE_CLOSED);
  });

  test('WSC-90 transitions HALF_OPEN→OPEN on failure', () => {
    const cfg = cfgWith({ cbFailureThreshold: 1, cbRecoveryMs: 0 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    cb.allowRequest(); // HALF_OPEN
    cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('WSC-91 success in CLOSED resets consecutive failure count', () => {
    const cfg = cfgWith({ cbFailureThreshold: 3 });
    const cb  = new CircuitBreaker('host.com', cfg);
    cb.onFailure();
    cb.onFailure();
    cb.onSuccess(); // reset
    cb.onFailure();
    cb.onFailure();
    // Two failures after reset — not yet at threshold of 3
    expect(cb.state).toBe(STATE_CLOSED);
  });

  test('WSC-92 getCircuitBreaker returns same instance for same host', () => {
    const cb1 = getCircuitBreaker('shared.com', OPEN_CONFIG);
    const cb2 = getCircuitBreaker('shared.com', OPEN_CONFIG);
    expect(cb1).toBe(cb2);
  });
});

// ── WSC-93…98: validateDestination integration ───────────────────────────────

describe('WSC — validateDestination integration', () => {
  test('WSC-93 rejects bare IP that is loopback', async () => {
    const r = await validateDestination('https://127.0.0.1/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-94 rejects bare IPv6 loopback [::1]', async () => {
    const r = await validateDestination('https://[::1]/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-95 rejects bare IPv4-private IP (no DNS needed)', async () => {
    const r = await validateDestination('https://192.168.0.1/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    // DNS should NOT have been called for bare IPs
    expect(mockDnsLookup).not.toHaveBeenCalled();
  });

  test('WSC-96 accepts valid bare public IP (no DNS)', async () => {
    const r = await validateDestination('https://93.184.216.34/hook', OPEN_CONFIG);
    expect(r.ok).toBe(true);
    expect(mockDnsLookup).not.toHaveBeenCalled();
  });

  test('WSC-97 rejects malformed URL', async () => {
    const r = await validateDestination(':::not-a-url', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Invalid URL/i);
  });

  test('WSC-98 rejects URL with only a port and no hostname', async () => {
    // A URL that the parser accepts but has no usable hostname
    const r = await validateDestination('https://:443/path', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });
});

// ── WSC-99…106: Edge cases ────────────────────────────────────────────────────

describe('WSC — edge cases', () => {
  test('WSC-99 _expandIpv6 expands :: shorthand', () => {
    expect(_expandIpv6('::')).toBe('00000000000000000000000000000000');
  });

  test('WSC-100 _expandIpv6 expands ::1 (loopback)', () => {
    expect(_expandIpv6('::1')).toBe('00000000000000000000000000000001');
  });

  test('WSC-101 _expandIpv6 expands fc00:: (ULA prefix)', () => {
    expect(_expandIpv6('fc00::1')).toMatch(/^fc00/i);
  });

  test('WSC-102 _expandIpv6 handles IPv4-mapped ::ffff:1.2.3.4', () => {
    const expanded = _expandIpv6('::ffff:1.2.3.4');
    expect(expanded.length).toBe(32);
    expect(expanded).toMatch(/^00000000000000000000ffff/i);
  });

  test('WSC-103 _expandIpv6 returns empty string for malformed input', () => {
    expect(_expandIpv6('not::valid::ipv6::address::here::extra')).toBe('');
  });

  test('WSC-104 _matchesDomainRule exact match', () => {
    expect(_matchesDomainRule('example.com', 'example.com')).toBe(true);
    expect(_matchesDomainRule('other.com',   'example.com')).toBe(false);
  });

  test('WSC-105 _matchesDomainRule wildcard does not match two levels deep', () => {
    expect(_matchesDomainRule('a.b.example.com', '*.example.com')).toBe(false);
  });

  test('WSC-106 _ipMatchesCidr works for /0 (matches everything)', () => {
    expect(_ipMatchesCidr('1.2.3.4', 4, '0.0.0.0/0')).toBe(true);
  });
});

// ── WSC-107…113: Concurrent and regression safety ────────────────────────────

describe('WSC — concurrent and regression safety', () => {
  test('WSC-107 validateDestination is safe under concurrent calls', async () => {
    mockDns([{ address: '93.184.216.34', family: 4 }]);
    const requests = Array.from({ length: 10 }, () =>
      validateDestination('https://example.com/', OPEN_CONFIG),
    );
    const results = await Promise.all(requests);
    expect(results.every(r => r.ok)).toBe(true);
  });

  test('WSC-108 circuit breaker maintains state under concurrent onFailure calls', () => {
    const cfg = cfgWith({ cbFailureThreshold: 5 });
    const cb  = new CircuitBreaker('concurrent.com', cfg);
    for (let i = 0; i < 5; i++) cb.onFailure();
    expect(cb.state).toBe(STATE_OPEN);
  });

  test('WSC-109 validateDestination rejects 10.x bare IP without calling DNS', async () => {
    const r = await validateDestination('https://10.255.255.255/hook', OPEN_CONFIG);
    expect(r.ok).toBe(false);
    expect(mockDnsLookup).not.toHaveBeenCalled();
  });

  test('WSC-110 buildTlsOptions returns rejectUnauthorized=true', () => {
    const tls = buildTlsOptions(OPEN_CONFIG);
    expect(tls.rejectUnauthorized).toBe(true);
  });

  test('WSC-111 buildTlsOptions sets minimum TLS version', () => {
    const tls = buildTlsOptions(OPEN_CONFIG);
    expect(tls.minVersion).toBe('TLSv1.2');
  });

  test('WSC-112 buildTlsOptions includes cipher suite list', () => {
    const tls = buildTlsOptions(OPEN_CONFIG);
    expect(typeof tls.ciphers).toBe('string');
    expect(tls.ciphers.length).toBeGreaterThan(0);
  });

  test('WSC-113 createSecureLookup is deterministic for identical inputs', (done) => {
    const records     = [{ address: '93.184.216.34', family: 4 }];
    const firstSetKey = _addressSetKey(records);
    mockDns(records);

    const lookup = createSecureLookup('example.com', firstSetKey, OPEN_CONFIG);

    lookup('example.com', {}, (err1, addr1, fam1) => {
      mockDns(records);
      lookup('example.com', {}, (err2, addr2, fam2) => {
        expect(err1).toBeNull();
        expect(err2).toBeNull();
        expect(addr1).toBe(addr2);
        expect(fam1).toBe(fam2);
        done();
      });
    });
  });
});

// ── WSC-IPv6 blocking ─────────────────────────────────────────────────────────

describe('WSC — IPv6 SSRF blocking', () => {
  test('WSC-IPv6-01 blocks ::1 loopback', () => {
    expect(_blockedIpv6Reason('::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-02 blocks fc00:: unique local', () => {
    expect(_blockedIpv6Reason('fc00::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-03 blocks fd12:3456:789a::1 unique local', () => {
    expect(_blockedIpv6Reason('fd12:3456:789a::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-04 blocks fe80::1 link-local', () => {
    expect(_blockedIpv6Reason('fe80::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-05 blocks ff02::1 multicast', () => {
    expect(_blockedIpv6Reason('ff02::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-06 blocks 2001:db8::1 documentation', () => {
    expect(_blockedIpv6Reason('2001:db8::1')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-07 blocks ::ffff:169.254.169.254 IPv4-mapped metadata', () => {
    expect(_blockedIpv6Reason('::ffff:169.254.169.254')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-08 permits 2001:4860:4860::8888 (Google public DNS)', () => {
    expect(_blockedIpv6Reason('2001:4860:4860::8888')).toBeNull();
  });

  test('WSC-IPv6-09 blocks bracketed [::1] (URL hostname form)', () => {
    expect(_blockedIpv6Reason('[::1]')).toMatch(/blocked/i);
  });

  test('WSC-IPv6-10 validateDestination rejects IPv6 ULA resolved by DNS', async () => {
    mockDns([{ address: 'fc00::1', family: 6 }]);
    const r = await validateDestination('https://some-host.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  // the deprecated IPv4-compatible block::/96 (RFC 4291 §2.5.5.1) embeds any
  // IPv4 address, loopback and cloud metadata included. The list's own comment claimed it; the prefix was missing.
  test.each([
    ['::7f00:1', 'IPv4-compatible 127.0.0.1 (loopback)'],
    ['::127.0.0.1', 'IPv4-compatible 127.0.0.1, dotted form'],
    ['::a9fe:a9fe', 'IPv4-compatible 169.254.169.254 (metadata)'],
    ['::169.254.169.254', 'IPv4-compatible metadata, dotted form'],
    ['::a00:1', 'IPv4-compatible 10.0.0.1'],
    ['[::7f00:1]', 'bracketed URL-hostname form'],
  ])('WSC-IPv6-11 blocks %s (%s)', (addr) => {
    expect(_blockedIpv6Reason(addr)).toMatch(/blocked/i);
  });

  test('WSC-IPv6-12 validateDestination rejects a hostname that resolves to an IPv4-compatible loopback', async () => {
    mockDns([{ address: '::7f00:1', family: 6 }]);
    const r = await validateDestination('https://compat-loopback.example.com/', OPEN_CONFIG);
    expect(r.ok).toBe(false);
  });

  test('WSC-IPv6-13 control: ::/96 does not over-block — global unicast and the next /96 stay allowed', () => {
    expect(_blockedIpv6Reason('2606:4700:4700::1111')).toBeNull();
    expect(_blockedIpv6Reason('0:0:0:0:1::1')).toBeNull(); // ::1:0:0:1 lies outside ::/96
  });
});
