'use strict';

/**
 * the custom `lookup` passed to https.request must honour Node >= 20's { all: true }
 * contract (an ARRAY of { address, family }). It answered with the single-address form, so every webhook to a normal
 * hostname failed on the project's runtime (Node 24) with ERR_INVALID_IP_ADDRESS. These tests drive a REAL http.request
 * (same net.connect lookup path as https.request) at a local server through the real secureLookup.
 */

const http = require('http');

// A public (non-blocked) address: the SSRF validator rightly refuses loopback/private ranges.
jest.mock('dns', () => ({ promises: { lookup: jest.fn(async () => [{ address: '93.184.216.34', family: 4 }]) } }));

const dns = require('dns').promises;
const { createSecureLookup } = require('../webhookSecurity');

describe('createSecureLookup — Node 24 lookup contract', () => {
  let server; let port;
  beforeAll(async () => {
    server = http.createServer((_q, r) => { r.end('ok'); });
    await new Promise((res) => server.listen(0, '127.0.0.1', res));
    port = server.address().port;
  });
  afterAll(() => new Promise((res) => server.close(res)));

  const KEY = '4:93.184.216.34'; // the set key format used by validateDestination (family:address, '|'-joined)

  // Wrap secureLookup only to point the (already validated) answer at the local test server, PRESERVING the callback shape
  // — Node itself rejects a wrong shape, which is exactly the Node 24 failure under test.
  function viaLocal(secure) {
    return (h, opts, cb) => secure(h, opts, (err, res, fam) => {
      if (err) return cb(err);
      if (Array.isArray(res)) return cb(null, res.map(() => ({ address: '127.0.0.1', family: 4 })));
      return cb(null, '127.0.0.1', fam || 4);
    });
  }

  function get(lookup) {
    return new Promise((resolve, reject) => {
      const req = http.request({ host: 'webhook.example.test', port, path: '/', lookup }, (res) => {
        let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve(b));
      });
      req.on('error', reject); req.end();
    });
  }

  test('SL-01 a real request to a normal hostname connects through secureLookup (was ERR_INVALID_IP_ADDRESS on Node 24)', async () => {
    await expect(get(viaLocal(createSecureLookup('webhook.example.test', KEY, {})))).resolves.toBe('ok');
  });

  test('SL-02 { all: true } is answered with an array; the (host, callback) form with a single address', async () => {
    const lookup = createSecureLookup('webhook.example.test', KEY, {});
    const all = await new Promise((res) => lookup('x', { all: true }, (err, a) => res({ err, a })));
    expect(all.err).toBeNull();
    expect(all.a).toEqual([{ address: '93.184.216.34', family: 4 }]);
    const one = await new Promise((res) => lookup('x', (err, a, f) => res({ err, a, f })));
    expect(one).toEqual({ err: null, a: '93.184.216.34', f: 4 });
  });

  test('SL-03 a changed address set (DNS rebinding) is still refused', async () => {
    dns.lookup.mockResolvedValueOnce([{ address: '93.184.216.35', family: 4 }]);
    const lookup = createSecureLookup('webhook.example.test', KEY, {});
    const out = await new Promise((res) => lookup('x', { all: true }, (err) => res(err)));
    expect(out && out.code).toMatch(/WEBHOOK_DNS_REBINDING_DETECTED|WEBHOOK_DNS_REVALIDATION_BLOCKED/);
  });
});
