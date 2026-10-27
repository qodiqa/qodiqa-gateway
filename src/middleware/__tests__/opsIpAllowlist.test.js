'use strict';

const request  = require('supertest');
const express  = require('express');
const {
  createOpsIpAllowlistMiddleware,
  _normalizeIp,
  _buildMatcher,
  _ipToInt,
  _expandIPv6,
  _ipv6ToBigInt,
  _buildIPv6Matcher,
} = require('../opsIpAllowlist');

function buildApp(opsConfig, socketIp = '127.0.0.1') {
  const app = express();
  app.use((req, _res, next) => {
    req.requestId = 'test-req-id';
    // Simulate socket IP
    req.socket = { remoteAddress: socketIp };
    next();
  });
  app.use(createOpsIpAllowlistMiddleware(opsConfig));
  app.get('/probe', (_req, res) => res.status(200).json({ ok: true }));
  return app;
}

// ── Allowlisting disabled ─────────────────────────────────────────────────────

describe('opsIpAllowlist — disabled', () => {
  const config = {
    ipAllowlistEnabled: false,
    allowlistEntries:   [],
    allowlistConfigValid: true,
    trustProxy: false,
  };

  it('allows any IP through when allowlisting is disabled', async () => {
    const app = buildApp(config, '1.2.3.4');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });
});

// ── Fail-closed: empty/invalid allowlist with allowlisting enabled ────────────

describe('opsIpAllowlist — fail-closed on misconfiguration', () => {
  it('denies all when allowlist is empty but enabled', async () => {
    const config = {
      ipAllowlistEnabled: true,
      allowlistEntries:   [],
      allowlistConfigValid: true,
      trustProxy: false,
    };
    const app = buildApp(config, '127.0.0.1');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });

  it('denies all when allowlist config is invalid', async () => {
    const config = {
      ipAllowlistEnabled: true,
      allowlistEntries:   ['not-valid'],
      allowlistConfigValid: false,
      trustProxy: false,
    };
    const app = buildApp(config, '127.0.0.1');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });

  it('response body matches platform BLOCK shape', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     [],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '127.0.0.1');
    const res = await request(app).get('/probe');
    expect(res.body).toMatchObject({ decision: 'BLOCK', reason: 'FORBIDDEN', details: {} });
  });
});

// ── Bare IPv4 allowlisting ────────────────────────────────────────────────────

describe('opsIpAllowlist — bare IPv4 entries', () => {
  const config = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['10.0.0.5'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('allows the exact listed IP', async () => {
    const app = buildApp(config, '10.0.0.5');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });

  it('denies an IP not in the list', async () => {
    const app = buildApp(config, '10.0.0.6');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });

  it('denies 0.0.0.0 when not listed', async () => {
    const app = buildApp(config, '0.0.0.0');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });
});

// ── CIDR range matching ───────────────────────────────────────────────────────

describe('opsIpAllowlist — CIDR ranges', () => {
  const config = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['10.0.0.0/24'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('allows first address in CIDR block', async () => {
    const app = buildApp(config, '10.0.0.1');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });

  it('allows last address in CIDR block', async () => {
    const app = buildApp(config, '10.0.0.254');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });

  it('denies address outside CIDR block', async () => {
    const app = buildApp(config, '10.0.1.1');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });

  it('/32 matches only the exact host', async () => {
    const cfg = { ...config, allowlistEntries: ['192.168.1.5/32'] };
    const app1 = buildApp(cfg, '192.168.1.5');
    const app2 = buildApp(cfg, '192.168.1.6');
    expect((await request(app1).get('/probe')).status).toBe(200);
    expect((await request(app2).get('/probe')).status).toBe(403);
  });

  it('/0 matches all addresses', async () => {
    const cfg = { ...config, allowlistEntries: ['0.0.0.0/0'] };
    const app = buildApp(cfg, '8.8.8.8');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });
});

// ── Multiple allowlist entries ────────────────────────────────────────────────

describe('opsIpAllowlist — multiple entries', () => {
  const config = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['10.0.0.5', '192.168.1.0/24'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('allows IP matching first entry', async () => {
    const app = buildApp(config, '10.0.0.5');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('allows IP matching second (CIDR) entry', async () => {
    const app = buildApp(config, '192.168.1.99');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('denies IP matching neither entry', async () => {
    const app = buildApp(config, '172.16.0.1');
    expect((await request(app).get('/probe')).status).toBe(403);
  });
});

// ── Proxy safety: X-Forwarded-For only trusted when configured ────────────────

describe('opsIpAllowlist — proxy header safety', () => {
  const allowedConfig = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['10.0.0.1'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('ignores X-Forwarded-For when trustProxy=false', async () => {
    // Socket IP is denied; XFF claims it is allowed — should still be denied
    const app = buildApp(allowedConfig, '8.8.8.8');
    const res = await request(app).get('/probe')
      .set('X-Forwarded-For', '10.0.0.1');
    expect(res.status).toBe(403);
  });

  it('ignores X-Real-IP when trustProxy=false', async () => {
    const app = buildApp(allowedConfig, '8.8.8.8');
    const res = await request(app).get('/probe')
      .set('X-Real-IP', '10.0.0.1');
    expect(res.status).toBe(403);
  });

  // the allowlist resolves the client with the ONE trusted-proxy
  // list (TRUSTED_PROXY). XFF is honoured through proxies that are listed there.
  async function withTrustedProxy(value, fn) {
    const prev = process.env.TRUSTED_PROXY;
    if (value === undefined) delete process.env.TRUSTED_PROXY; else process.env.TRUSTED_PROXY = value;
    try { return await fn(); } finally { if (prev === undefined) delete process.env.TRUSTED_PROXY; else process.env.TRUSTED_PROXY = prev; }
  }
  
  it('uses X-Forwarded-For through proxies listed in TRUSTED_PROXY', async () => {
    const app = buildApp(allowedConfig, '172.16.0.1'); // socket is denied
    const res = await withTrustedProxy('172.16.0.1', () => request(app).get('/probe')
      .set('X-Forwarded-For', '10.0.0.1, 172.16.0.1'));
    expect(res.status).toBe(200);
  });

  // the audit's bypass — QODIQA_OPS_TRUST_PROXY=true used to trust
  // EVERY peer, so a spoofed XFF walked past the allowlist. It no longer does.
  it('trustProxy=true no longer trusts an unlisted peer — spoofed XFF is ignored', async () => {
    const config = { ...allowedConfig, trustProxy: true };
    const app = buildApp(config, '203.0.113.1'); // an ordinary client, not a proxy
    const res = await withTrustedProxy(undefined, () => request(app).get('/probe')
      .set('X-Forwarded-For', '10.0.0.1'));
    expect(res.status).toBe(403);
  });

  it('XFF spoofing is blocked when trustProxy=false', async () => {
    // Attacker sends XFF claiming allowed IP; socket is actual denied IP
    const app = buildApp(allowedConfig, '203.0.113.1');
    const res = await request(app).get('/probe')
      .set('X-Forwarded-For', '10.0.0.1');
    expect(res.status).toBe(403);
  });

  // X-Real-IP is honoured only when the operator declares the proxy sets it (TRUSTED_PROXY_REAL_IP=true).
  it('uses X-Real-IP as fallback over socket from a proxy listed in TRUSTED_PROXY when TRUSTED_PROXY_REAL_IP=true', async () => {
    const app = buildApp(allowedConfig, '172.16.0.1'); // socket is denied
    const prev = process.env.TRUSTED_PROXY_REAL_IP;
    process.env.TRUSTED_PROXY_REAL_IP = 'true';
    try {
      const res = await withTrustedProxy('172.16.0.1', () => request(app).get('/probe')
        .set('X-Real-IP', '10.0.0.1'));
      expect(res.status).toBe(200);
    } finally {
      if (prev === undefined) delete process.env.TRUSTED_PROXY_REAL_IP; else process.env.TRUSTED_PROXY_REAL_IP = prev;
    }
  });

  it('ignores X-Real-IP from a listed proxy unless TRUSTED_PROXY_REAL_IP=true', async () => {
    const app = buildApp(allowedConfig, '172.16.0.1'); // socket is denied
    const prev = process.env.TRUSTED_PROXY_REAL_IP;
    delete process.env.TRUSTED_PROXY_REAL_IP;
    try {
      const res = await withTrustedProxy('172.16.0.1', () => request(app).get('/probe')
        .set('X-Real-IP', '10.0.0.1'));
      expect(res.status).toBe(403);
    } finally {
      if (prev !== undefined) process.env.TRUSTED_PROXY_REAL_IP = prev;
    }
  });
});

// ── IPv4-mapped IPv6 normalization ────────────────────────────────────────────

describe('opsIpAllowlist — IPv4-mapped IPv6 normalization', () => {
  it('strips ::ffff: prefix and matches IPv4', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['127.0.0.1'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '::ffff:127.0.0.1');
    const res = await request(app).get('/probe');
    expect(res.status).toBe(200);
  });
});

// ── Unresolvable client IP ────────────────────────────────────────────────────

describe('opsIpAllowlist — unresolvable client IP', () => {
  it('denies when socket.remoteAddress is null', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['10.0.0.1'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, null);
    const res = await request(app).get('/probe');
    expect(res.status).toBe(403);
  });
});

// ── Unit: _normalizeIp ────────────────────────────────────────────────────────

describe('_normalizeIp', () => {
  it('strips ::ffff: prefix', () => {
    expect(_normalizeIp('::ffff:10.0.0.1')).toBe('10.0.0.1');
  });

  it('leaves plain IPv4 unchanged', () => {
    expect(_normalizeIp('192.168.1.1')).toBe('192.168.1.1');
  });

  it('leaves plain IPv6 unchanged', () => {
    expect(_normalizeIp('::1')).toBe('::1');
  });

  it('returns null for null input', () => {
    expect(_normalizeIp(null)).toBeNull();
  });

  it('returns null for non-string input', () => {
    expect(_normalizeIp(12345)).toBeNull();
  });
});

// ── Unit: _buildMatcher ───────────────────────────────────────────────────────

describe('_buildMatcher', () => {
  it('returns null for invalid CIDR prefix > 32', () => {
    expect(_buildMatcher('10.0.0.0/33')).toBeNull();
  });

  it('returns null for invalid IP octets', () => {
    expect(_buildMatcher('999.0.0.0')).toBeNull();
  });

  it('bare IP matches exactly that IP', () => {
    const m = _buildMatcher('10.0.0.5');
    expect(m('10.0.0.5')).toBe(true);
    expect(m('10.0.0.6')).toBe(false);
  });

  it('CIDR /24 matches subnet', () => {
    const m = _buildMatcher('10.0.0.0/24');
    expect(m('10.0.0.1')).toBe(true);
    expect(m('10.0.1.1')).toBe(false);
  });
});

// ── Unit: _expandIPv6 ─────────────────────────────────────────────────────────

describe('_expandIPv6', () => {
  it('expands :: loopback to full form', () => {
    expect(_expandIPv6('::1')).toBe('0000:0000:0000:0000:0000:0000:0000:0001');
  });

  it('expands trailing :: to full form', () => {
    expect(_expandIPv6('2001:db8::')).toBe('2001:0db8:0000:0000:0000:0000:0000:0000');
  });

  it('expands all-zeros ::', () => {
    expect(_expandIPv6('::')).toBe('0000:0000:0000:0000:0000:0000:0000:0000');
  });

  it('handles full form without :: unchanged', () => {
    expect(_expandIPv6('2001:0db8:0000:0000:0000:0000:0000:0001'))
      .toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
  });

  it('is case-insensitive (lowercases input)', () => {
    expect(_expandIPv6('2001:DB8::1')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
  });

  it('returns null for IPv4-mapped address (contains dot)', () => {
    expect(_expandIPv6('::ffff:192.168.1.1')).toBeNull();
  });

  it('returns null for triple-colon (invalid)', () => {
    expect(_expandIPv6('2001:::1')).toBeNull();
  });

  it('returns null for too many groups', () => {
    expect(_expandIPv6('1:2:3:4:5:6:7:8:9')).toBeNull();
  });
});

// ── Unit: _buildIPv6Matcher ───────────────────────────────────────────────────

describe('_buildIPv6Matcher', () => {
  it('bare IPv6 address matches exactly that address', () => {
    const m = _buildIPv6Matcher('2001:db8::1');
    expect(m('2001:db8::1')).toBe(true);
    expect(m('2001:db8::2')).toBe(false);
  });

  it('compressed and expanded forms match each other', () => {
    const m = _buildIPv6Matcher('2001:db8::1');
    expect(m('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(true);
  });

  it('/32 CIDR matches address within network', () => {
    const m = _buildIPv6Matcher('2001:db8::/32');
    expect(m('2001:db8::1234')).toBe(true);
    expect(m('2001:db8::ffff')).toBe(true);
  });

  it('/32 CIDR does not match address outside network', () => {
    const m = _buildIPv6Matcher('2001:db8::/32');
    expect(m('2001:db9::1')).toBe(false);
  });

  it('/128 matches only the exact host', () => {
    const m = _buildIPv6Matcher('2001:db8::1/128');
    expect(m('2001:db8::1')).toBe(true);
    expect(m('2001:db8::2')).toBe(false);
  });

  it('/0 matches all IPv6 addresses', () => {
    const m = _buildIPv6Matcher('::/0');
    expect(m('2001:db8::1')).toBe(true);
    expect(m('::1')).toBe(true);
    expect(m('fd00::1')).toBe(true);
  });

  it('fd00::/8 matches ULA addresses', () => {
    const m = _buildIPv6Matcher('fd00::/8');
    expect(m('fd00::1')).toBe(true);
    expect(m('fd12:3456::1')).toBe(true);
    expect(m('fe80::1')).toBe(false);
  });

  it('returns null for prefix > 128', () => {
    expect(_buildIPv6Matcher('2001:db8::/129')).toBeNull();
  });

  it('returns null for malformed IPv6 address', () => {
    expect(_buildIPv6Matcher('2001:::1')).toBeNull();
  });
});

// ── IPv6 bare address middleware tests ────────────────────────────────────────

describe('opsIpAllowlist — bare IPv6 allowlisting', () => {
  it('allows exact IPv6 address match', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['2001:db8::1'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '2001:db8::1');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('denies non-matching IPv6 address', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['2001:db8::1'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '2001:db8::2');
    expect((await request(app).get('/probe')).status).toBe(403);
  });

  it('allows loopback ::1 when listed', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['::1'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '::1');
    expect((await request(app).get('/probe')).status).toBe(200);
  });
});

// ── IPv6 CIDR middleware tests ─────────────────────────────────────────────────

describe('opsIpAllowlist — IPv6 CIDR ranges', () => {
  const config = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['2001:db8::/32'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('allows address within IPv6 CIDR block', async () => {
    const app = buildApp(config, '2001:db8::1234');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('allows another address within IPv6 CIDR block', async () => {
    const app = buildApp(config, '2001:db8:0:1::1');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('denies address outside IPv6 CIDR block', async () => {
    const app = buildApp(config, '2001:db9::1');
    expect((await request(app).get('/probe')).status).toBe(403);
  });

  it('/128 allows only exact host', async () => {
    const cfg = { ...config, allowlistEntries: ['2001:db8::1/128'] };
    expect((await request(buildApp(cfg, '2001:db8::1')).get('/probe')).status).toBe(200);
    expect((await request(buildApp(cfg, '2001:db8::2')).get('/probe')).status).toBe(403);
  });
});

// ── IPv6 CIDR: compressed vs expanded notation ────────────────────────────────

describe('opsIpAllowlist — IPv6 notation variants', () => {
  it('compressed client address matches compressed allowlist entry', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['2001:db8::/32'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '2001:db8::1');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('expanded client address matches compressed allowlist entry', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['2001:db8::/32'],
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '2001:0db8:0000:0000:0000:0000:0000:0001');
    expect((await request(app).get('/probe')).status).toBe(200);
  });
});

// ── IPv6 + IPv4 mixed allowlist ───────────────────────────────────────────────

describe('opsIpAllowlist — mixed IPv4 and IPv6 allowlist', () => {
  const config = {
    ipAllowlistEnabled:   true,
    allowlistEntries:     ['10.0.0.5', '2001:db8::/32'],
    allowlistConfigValid: true,
    trustProxy:           false,
  };

  it('allows IPv4 address matching IPv4 entry', async () => {
    const app = buildApp(config, '10.0.0.5');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('allows IPv6 address matching IPv6 CIDR entry', async () => {
    const app = buildApp(config, '2001:db8::1');
    expect((await request(app).get('/probe')).status).toBe(200);
  });

  it('denies address matching neither entry', async () => {
    const app = buildApp(config, 'fd00::1');
    expect((await request(app).get('/probe')).status).toBe(403);
  });
});

// ── IPv6 fail-closed: malformed entry in allowlist ────────────────────────────

describe('opsIpAllowlist — fail-closed on malformed IPv6 allowlist entry', () => {
  it('denies all when a malformed IPv6 CIDR is in the allowlist', async () => {
    const config = {
      ipAllowlistEnabled:   true,
      allowlistEntries:     ['2001:::1'],  // malformed — _buildMatcher returns null
      allowlistConfigValid: true,
      trustProxy:           false,
    };
    const app = buildApp(config, '2001:db8::1');
    expect((await request(app).get('/probe')).status).toBe(403);
  });
});
