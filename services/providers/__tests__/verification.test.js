'use strict';

/**
 * independent verification findings, items 3.7 and 3.8:
 *   - a *_TIMEOUT_MS above 2^31-1 overflows setTimeout (fires after ~1 ms) and must fall back to the default;
 *   - a late releaseProbe() from an EXPIRED half-open probe must not free the slot of a newer probe;
 *   - addresses that embed an IPv4 destination (NAT64, 6to4, IPv4-compatible) are judged by that IPv4 address, and the
 *     Alibaba / Azure / Oracle metadata addresses are refused;
 *   - the guarded agent refuses IP-literal hosts (the `lookup` hook is never called for literals, so a 302 to
 *     http://169.254.169.254/ used to be followed).
 */

jest.mock('../../../src/infra/time/monotonicClock', () => ({ monoNowMs: () => Date.now(), wallFromMono: (m) => m || null }));
jest.mock('../../logger', () => ({ emit: jest.fn() }));

const http = require('http');
const { getCircuitBreaker, resetAll } = require('../providerCircuitBreaker');
const { resolveTimeoutMs, DEFAULT_TIMEOUT_MS } = require('../timeout');
const { blockedAddressReason, createGuardedAgent } = require('../ssrf');

describe('timeout upper bound', () => {
  test.each(['2147483648', '3000000000', '9999999999'])('F1-TO-01 %s falls back to the default', (v) => {
    expect(resolveTimeoutMs('X_F1_TIMEOUT_MS', DEFAULT_TIMEOUT_MS, { X_F1_TIMEOUT_MS: v })).toBe(DEFAULT_TIMEOUT_MS);
  });
  test('F1-TO-02 the largest safe value is accepted', () => {
    expect(resolveTimeoutMs('X', 1, { X: '2147483647' })).toBe(2147483647);
  });
});

describe('stale probe release', () => {
  const CONFIG = Object.freeze({ cbFailureThreshold: 2, cbWindowMs: 10_000, cbRecoveryMs: 5_000, cbSuccessThreshold: 1 });
  beforeEach(() => { resetAll(); jest.useFakeTimers(); });
  afterEach(() => { jest.useRealTimers(); });

  test('F1-HO-01 a late release from an expired probe does not free the newer probe', () => {
    const cb = getCircuitBreaker('openai', CONFIG);
    cb.onFailure(); cb.onFailure();
    jest.advanceTimersByTime(5_001);
    const first = cb.acquire();
    expect(first.probe).toBe(true);
    jest.advanceTimersByTime(5_001);                 // the first probe is now considered lost
    const second = cb.acquire();
    expect(second.probe).toBe(true);
    expect(second.probeId).not.toBe(first.probeId);
    cb.releaseProbe(first.probeId);                  // late, stale release
    expect(cb.acquire().allowed).toBe(false);        // second probe still owns the slot
    cb.releaseProbe(second.probeId);
    expect(cb.acquire().allowed).toBe(true);
  });
});

describe('embedded IPv4 and extra metadata addresses', () => {
  test.each([
    '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::', '::a9fe:a9fe', '::ffff:0:a9fe:a9fe', '100.100.100.200', '168.63.129.16', '192.0.0.192',
  ])('F1-SSRF-01 %s is refused', (a) => {
    expect(blockedAddressReason(a)).toBe('LINK_LOCAL_OR_METADATA_ADDRESS');
  });
  test.each(['::1', '127.0.0.1', '::ffff:127.0.0.1', '64:ff9b::808:808', '2001:db8::1'])('F1-SSRF-02 %s stays allowed by default', (a) => {
    expect(blockedAddressReason(a)).toBeNull();
  });
});

describe('guarded agent and IP-literal hosts', () => {
  test('F1-SSRF-03 a request to a literal metadata address fails with SSRF_BLOCKED_RESOLVED_ADDRESS before any connect', async () => {
    const agent = createGuardedAgent('http://127.0.0.1:11434');
    const err = await new Promise((resolve) => {
      const req = http.request({ host: '169.254.169.254', port: 80, path: '/', agent }, () => resolve(null));
      req.on('error', resolve);
      req.end();
    });
    expect(err && err.code).toBe('SSRF_BLOCKED_RESOLVED_ADDRESS');
  });

  test('F1-SSRF-04 a redirect from an allowed local endpoint to the metadata address is not followed at connect level', async () => {
    const srv = http.createServer((_q, r) => { r.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' }); r.end(); });
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    const agent = createGuardedAgent(`http://127.0.0.1:${srv.address().port}`);
    try {
      const first = await new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port: srv.address().port, agent }, resolve).on('error', reject);
      });
      expect(first.statusCode).toBe(302);              // the allowed endpoint itself is reachable
      const err = await new Promise((resolve) => {
        const u = new URL(first.headers.location);
        http.get({ host: u.hostname, port: 80, path: u.pathname, agent }, () => resolve(null)).on('error', resolve);
      });
      expect(err && err.code).toBe('SSRF_BLOCKED_RESOLVED_ADDRESS');   // the follow-up hop (what an SDK redirect does) is refused
    } finally { srv.close(); agent.destroy(); }
  });
});

describe('trusted-host scoping of the private-network allowance', () => {
  const { createGuardedLookup } = require('../ssrf');
  const dns = require('dns');
  const lookupWith = (trusted, map) => {
    const spy = jest.spyOn(dns, 'lookup').mockImplementation((host, _o, cb) => cb(null, [{ address: map[host], family: 4 }]));
    const l = createGuardedLookup({}, { trustedHost: trusted });
    return { l, restore: () => spy.mockRestore() };
  };
  const run = (l, host) => new Promise((resolve) => l(host, { all: true }, (err, addrs) => resolve({ err, addrs })));

  test('.2-01 the configured host may resolve to a private address', async () => {
    const { l, restore } = lookupWith('ollama', { ollama: '10.1.2.3' });
    expect((await run(l, 'ollama')).addrs[0].address).toBe('10.1.2.3');
    restore();
  });
  test('.2-02 any OTHER host resolving to a private or loopback address is refused (redirect hop / rebinding)', async () => {
    for (const addr of ['10.1.2.3', '192.168.0.9', '127.0.0.1']) {
      const { l, restore } = lookupWith('ollama', { evil: addr });
      expect((await run(l, 'evil')).err.code).toBe('SSRF_BLOCKED_RESOLVED_ADDRESS');
      restore();
    }
  });
  test('.2-03 without a configured host (legacy callers) behaviour is unchanged: private allowed', async () => {
    const { l, restore } = lookupWith(null, { x: '10.1.2.3' });
    expect((await run(l, 'x')).addrs[0].address).toBe('10.1.2.3');
    restore();
  });
});

describe('verification findings', () => {
  test('F2-SSRF-05 non-canonical spellings of ::1 are loopback for an untrusted host and stay allowed for the configured one', () => {
    for (const a of ['0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001', '::1']) {
      expect({ a, r: blockedAddressReason(a, { blockLoopback: true }) }).toEqual({ a, r: 'LOOPBACK_ADDRESS' });
      expect({ a, r: blockedAddressReason(a) }).toEqual({ a, r: null });
    }
  });
});
