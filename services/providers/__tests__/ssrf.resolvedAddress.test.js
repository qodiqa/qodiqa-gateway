'use strict';

/**
 * operator-configured endpoints (local / llama) may be loopback or private, but the
 * RESOLVED / literal address must never be metadata, link-local, unspecified, multicast or reserved — at validation time
 * and at connect time (DNS rebinding).
 */

const http = require('http');

jest.mock('dns', () => {
  const real = jest.requireActual('dns');
  return { ...real, lookup: jest.fn(real.lookup) };
});

const dns = require('dns');
const { validateLocalProviderUrl, blockedAddressReason, createGuardedLookup, createGuardedAgent } = require('../ssrf');

afterEach(() => { delete process.env.LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS; });

describe('validateLocalProviderUrl — literal destinations', () => {
  test('SR-01 the cloud metadata address is refused in every spelling', () => {
    for (const u of ['http://169.254.169.254/latest/meta-data', 'http://2852039166/', 'http://0xA9FEA9FE/', 'http://[::ffff:169.254.169.254]/', 'http://[fd00:ec2::254]/', 'http://0.0.0.0:11434/v1', 'http://224.0.0.1/', 'http://255.255.255.255/']) {
      expect(validateLocalProviderUrl(u)).toEqual({ valid: false, reason: 'BLOCKED_DESTINATION_ADDRESS' });
    }
  });
  test('SR-02 loopback, container hostnames and private addresses stay valid by default (the supported deployments)', () => {
    for (const u of ['http://127.0.0.1:11434/v1', 'http://localhost:11434/v1', 'http://[::1]:11434/v1', 'http://ollama:11434/v1', 'http://10.0.0.5:8080/v1', 'http://192.168.1.20:11434/v1']) {
      expect(validateLocalProviderUrl(u).valid).toBe(true);
    }
  });
  test('SR-03 LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS=true also refuses RFC1918/CGNAT/ULA literals but keeps loopback', () => {
    process.env.LOCAL_PROVIDER_BLOCK_PRIVATE_NETWORKS = 'true';
    expect(validateLocalProviderUrl('http://10.0.0.5:8080/v1').valid).toBe(false);
    expect(validateLocalProviderUrl('http://172.20.0.3:8080/v1').valid).toBe(false);
    expect(validateLocalProviderUrl('http://100.64.1.1/').valid).toBe(false);
    expect(validateLocalProviderUrl('http://[fc00::1]/').valid).toBe(false);
    expect(validateLocalProviderUrl('http://127.0.0.1:11434/v1').valid).toBe(true);
  });
  test('SR-04 blockedAddressReason classifies without touching DNS', () => {
    expect(blockedAddressReason('169.254.169.254')).toBe('LINK_LOCAL_OR_METADATA_ADDRESS');
    expect(blockedAddressReason('fe80::1')).toBe('LINK_LOCAL_OR_METADATA_ADDRESS');
    expect(blockedAddressReason('10.1.2.3')).toBeNull();
    expect(blockedAddressReason('10.1.2.3', { blockPrivate: true })).toBe('PRIVATE_NETWORK_ADDRESS');
    expect(blockedAddressReason('93.184.216.34')).toBeNull();
    expect(blockedAddressReason('not-an-ip')).toBeNull();
  });
});

describe('createGuardedLookup — connect-time (DNS rebinding)', () => {
  test('SR-05 a hostname that (re)resolves to the metadata service is refused with SSRF_BLOCKED_RESOLVED_ADDRESS', async () => {
    dns.lookup.mockImplementationOnce((h, o, cb) => cb(null, [{ address: '169.254.169.254', family: 4 }]));
    const lookup = createGuardedLookup({});
    const err = await new Promise((res) => lookup('model.example.test', { all: true }, (e) => res(e)));
    expect(err && err.code).toBe('SSRF_BLOCKED_RESOLVED_ADDRESS');
  });
  test('SR-06 an allowed answer is returned in the Node >= 20 shape ({all:true} array) and the legacy shape', async () => {
    dns.lookup.mockImplementation((h, o, cb) => cb(null, [{ address: '127.0.0.1', family: 4 }]));
    const lookup = createGuardedLookup({});
    const all = await new Promise((res) => lookup('localhost', { all: true }, (e, a) => res({ e, a })));
    expect(all).toEqual({ e: null, a: [{ address: '127.0.0.1', family: 4 }] });
    const one = await new Promise((res) => lookup('localhost', {}, (e, a, f) => res({ e, a, f })));
    expect(one).toEqual({ e: null, a: '127.0.0.1', f: 4 });
    dns.lookup.mockReset();
  });
  test('SR-07 a real request through the guarded agent reaches a local server, and is refused when the name resolves to a blocked address', async () => {
    const real = jest.requireActual('dns');
    dns.lookup.mockImplementation(real.lookup);
    const srv = http.createServer((_q, r) => r.end('ok'));
    await new Promise((res) => srv.listen(0, '127.0.0.1', res));
    const port = srv.address().port;
    try {
      const agent = createGuardedAgent(`http://localhost:${port}/`, {});
      const body = await new Promise((resolve, reject) => {
        http.get({ host: 'localhost', port, agent }, (r) => { let b = ''; r.on('data', (c) => { b += c; }); r.on('end', () => resolve(b)); }).on('error', reject);
      });
      expect(body).toBe('ok');
      dns.lookup.mockImplementationOnce((h, o, cb) => cb(null, [{ address: '169.254.169.254', family: 4 }]));
      const agent2 = createGuardedAgent(`http://rebind.example.test:${port}/`, {});
      await expect(new Promise((resolve, reject) => {
        http.get({ host: 'rebind.example.test', port, agent: agent2 }, resolve).on('error', reject);
      })).rejects.toMatchObject({ code: 'SSRF_BLOCKED_RESOLVED_ADDRESS' });
    } finally {
      await new Promise((res) => srv.close(res));
    }
  });
});
