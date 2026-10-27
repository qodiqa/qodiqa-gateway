'use strict';

/**
 * Unit tests for middleware/clientIp.js
 *
 * This middleware is now a thin wrapper around
 * src/infra/network/clientIpResolver.js (single source of truth for the
 * trust-boundary-aware algorithm — see clientIpResolver.test.js for the full
 * matrix of trust/spoofing/malformed-header cases). This file validates:
 *   1. req.clientIp is attached correctly for direct + trusted-proxy cases
 *   2. TRUSTED_PROXY env var is honoured (same parsing as server.js)
 *   3. An untrusted/direct attacker cannot spoof req.clientIp via headers
 *   4. next() is always called
 */

const attachClientIp = require('../clientIp');

function makeReq(headers = {}, remoteAddress = '192.168.1.1') {
  return {
    headers,
    socket: { remoteAddress },
  };
}

function runMiddleware(req) {
  return new Promise((resolve) => {
    attachClientIp(req, {}, resolve);
  });
}

const ORIGINAL_TRUSTED_PROXY = process.env.TRUSTED_PROXY;

afterEach(() => {
  if (ORIGINAL_TRUSTED_PROXY === undefined) delete process.env.TRUSTED_PROXY;
  else process.env.TRUSTED_PROXY = ORIGINAL_TRUSTED_PROXY;
});

describe('clientIp — default trust config (TRUSTED_PROXY unset)', () => {
  beforeEach(() => { delete process.env.TRUSTED_PROXY; });

  test('no headers → middleware sets req.clientIp to socket address', async () => {
    const req = makeReq({}, '10.0.0.1');
    await runMiddleware(req);
    expect(req.clientIp).toBe('10.0.0.1');
  });

  test('direct connection from a public IP with a spoofed X-Forwarded-For is NOT honoured', async () => {
    // The core vulnerability this remediation fixes: an attacker connecting
    // directly (not through any proxy) sets X-Forwarded-For hoping it will be
    // trusted. Default trust config only covers loopback/linklocal/uniquelocal
    // — a public peer address must never be treated as a trusted proxy.
    const req = makeReq({ 'x-forwarded-for': '10.0.0.1' }, '203.0.113.200');
    await runMiddleware(req);
    expect(req.clientIp).toBe('203.0.113.200'); // NOT '10.0.0.1'
  });

  // (Findings Register): previously the default trust list was
  // ['loopback', 'linklocal', 'uniquelocal'] — a loopback (or any RFC1918)
  // peer was trusted by default, so this test used to assert
  // req.clientIp === '203.0.113.42'. That was the defect: any loopback or
  // private-network peer could spoof X-Forwarded-For with no configuration
  // at all. Default is now an empty trust list — no peer is trusted absent
  // explicit TRUSTED_PROXY configuration.
  // the default is now 'loopback'
  // — a same-host reverse proxy is trusted out of the box, because with an
  // empty default every client behind it appeared as 127.0.0.1 to the admin
  // IP allowlist and the rate limiter. Only loopback is trusted:'s
  // private-range and public-peer guarantees (tests around this one) stand.
  // TRUSTED_PROXY='' restores's trust-nothing behaviour exactly.
  test('request via a loopback peer, under the default, honours X-Forwarded-For', async () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    await runMiddleware(req);
    expect(req.clientIp).toBe('203.0.113.42');
  });

  test('TRUSTED_PROXY="" (explicit empty) trusts nothing — loopback XFF NOT honoured', async () => {
    process.env.TRUSTED_PROXY = '';
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    await runMiddleware(req);
    expect(req.clientIp).toBe('127.0.0.1');
  });

  test('request via a private-network (RFC1918) peer, under the NEW default, does NOT honour X-Forwarded-For', async () => {
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '192.168.0.5');
    await runMiddleware(req);
    expect(req.clientIp).toBe('192.168.0.5'); // NOT '203.0.113.42'
  });

  test('invalid header + untrusted peer → falls back to socket address', async () => {
    const req = makeReq({ 'x-forwarded-for': 'not-an-ip' }, '192.168.0.5');
    await runMiddleware(req);
    // No peer is trusted by default — the header is malformed AND the
    // peer isn't trusted either way, so this falls back to itself regardless.
    expect(req.clientIp).toBe('192.168.0.5');
  });

  test('no headers, no socket → req.clientIp is null', async () => {
    const req = { headers: {}, socket: {} };
    await runMiddleware(req);
    expect(req.clientIp).toBeNull();
  });

  test('middleware calls next()', async () => {
    const req  = makeReq();
    let called = false;
    attachClientIp(req, {}, () => { called = true; });
    expect(called).toBe(true);
  });
});

describe('clientIp — TRUSTED_PROXY env var honoured (matches server.js parsing)', () => {
  test('explicit TRUSTED_PROXY IP is trusted; peers outside it are not', async () => {
    process.env.TRUSTED_PROXY = '10.0.0.5';

    const trusted = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.5');
    await runMiddleware(trusted);
    expect(trusted.clientIp).toBe('203.0.113.42');

    const untrusted = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.9');
    await runMiddleware(untrusted);
    expect(untrusted.clientIp).toBe('10.0.0.9');
  });

  test('TRUSTED_PROXY as CIDR range covers all peers within it', async () => {
    process.env.TRUSTED_PROXY = '10.0.0.0/24';
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '10.0.0.250');
    await runMiddleware(req);
    expect(req.clientIp).toBe('203.0.113.42');
  });

  test('TRUSTED_PROXY with multiple comma-separated entries', async () => {
    process.env.TRUSTED_PROXY = '10.0.0.5,10.0.0.6';

    const req1 = makeReq({ 'x-forwarded-for': '203.0.113.1' }, '10.0.0.5');
    await runMiddleware(req1);
    expect(req1.clientIp).toBe('203.0.113.1');

    const req2 = makeReq({ 'x-forwarded-for': '203.0.113.2' }, '10.0.0.6');
    await runMiddleware(req2);
    expect(req2.clientIp).toBe('203.0.113.2');
  });

  test('setting TRUSTED_PROXY narrows trust beyond the default presets', async () => {
    // With an explicit TRUSTED_PROXY, a loopback peer is no longer
    // automatically trusted unless loopback is included in the list.
    process.env.TRUSTED_PROXY = '10.0.0.5';
    const req = makeReq({ 'x-forwarded-for': '203.0.113.42' }, '127.0.0.1');
    await runMiddleware(req);
    expect(req.clientIp).toBe('127.0.0.1'); // NOT '203.0.113.42' — loopback not in the explicit list
  });
});

describe('clientIp — chained IP lists via a trusted proxy', () => {
  test('multiple trusted proxies → resolves to the original client', async () => {
    process.env.TRUSTED_PROXY = '10.0.0.1,10.0.0.2';
    const req = makeReq({ 'x-forwarded-for': '1.2.3.4, 10.0.0.1' }, '10.0.0.2');
    await runMiddleware(req);
    expect(req.clientIp).toBe('1.2.3.4');
  });
});
