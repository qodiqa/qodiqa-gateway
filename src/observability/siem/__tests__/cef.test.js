'use strict';

const { buildCEFLine, wrapSyslog, sendSyslog, cefEscapeHeader, cefEscapeExtensionValue } = require('../cef');
const dgram = require('dgram');
const net   = require('net');

describe('buildCEFLine', () => {
  it('builds a well-formed CEF:0 line with defaults', () => {
    const line = buildCEFLine({
      deviceVersion: '1.0.0',
      signatureId:   'TEST_SIG',
      name:          'Test Event',
      severity:      5,
      extension:     { foo: 'bar' },
    });
    expect(line).toBe('CEF:0|QODIQA|QODIQA Platform|1.0.0|TEST_SIG|Test Event|5|foo=bar');
  });

  it('respects custom vendor/product', () => {
    const line = buildCEFLine({
      deviceVendor:  'Acme',
      deviceProduct: 'Acme Widget',
      deviceVersion: '2.0',
      signatureId:   'SIG',
      name:          'N',
      severity:      1,
      extension:     {},
    });
    expect(line).toMatch(/^CEF:0\|Acme\|Acme Widget\|2\.0\|SIG\|N\|1\|/);
  });

  it('drops empty/null/undefined extension fields', () => {
    const line = buildCEFLine({
      deviceVersion: '1.0.0',
      signatureId:   'SIG',
      name:          'N',
      severity:      2,
      extension:     { a: 'x', b: '', c: null, d: undefined, e: 0 },
    });
    expect(line).toContain('a=x');
    expect(line).toContain('e=0');
    expect(line).not.toContain('b=');
    expect(line).not.toContain('c=');
    expect(line).not.toContain('d=');
  });

  it('escapes pipes and backslashes in the name (header field)', () => {
    const line = buildCEFLine({
      deviceVersion: '1.0.0',
      signatureId:   'SIG',
      name:          'a|b\\c',
      severity:      1,
      extension:     {},
    });
    expect(line).toContain('a\\|b\\\\c');
  });

  it('escapes =, newlines, and backslashes in extension values', () => {
    const line = buildCEFLine({
      deviceVersion: '1.0.0',
      signatureId:   'SIG',
      name:          'N',
      severity:      1,
      extension:     { msg: 'a=b\nc\rd\\e' },
    });
    expect(line).toContain('msg=a\\=b\\nc\\rd\\\\e');
  });
});

describe('cefEscapeHeader / cefEscapeExtensionValue', () => {
  it('escapes header pipes/backslashes only', () => {
    expect(cefEscapeHeader('a|b\\c')).toBe('a\\|b\\\\c');
  });

  it('escapes extension =, \\n, \\r, backslash', () => {
    expect(cefEscapeExtensionValue('a=b\nc\rd\\e')).toBe('a\\=b\\nc\\rd\\\\e');
  });
});

describe('wrapSyslog', () => {
  it('wraps a body in RFC 5424 format with defaults', () => {
    const ts   = new Date('2026-01-01T00:00:00.000Z');
    const line = wrapSyslog('BODY', { timestamp: ts });
    expect(line).toBe('<12>1 2026-01-01T00:00:00.000Z qodiqa QODIQA - - - BODY');
  });

  it('computes PRI from facility/severity', () => {
    const line = wrapSyslog('X', { facility: 1, severity: 4, timestamp: new Date(0) });
    expect(line.startsWith('<12>1 ')).toBe(true); // 1*8+4 = 12
  });

  it('respects custom host/appName', () => {
    const line = wrapSyslog('X', { host: 'myhost', appName: 'MYAPP', timestamp: new Date(0) });
    expect(line).toContain(' myhost MYAPP - - - X');
  });
});

describe('sendSyslog — UDP', () => {
  let server;
  let port;

  beforeEach((done) => {
    server = dgram.createSocket('udp4');
    server.bind(0, '127.0.0.1', () => {
      port = server.address().port;
      done();
    });
  });

  afterEach((done) => {
    server.close(done);
  });

  it('resolves { ok: true } on successful UDP send', async () => {
    const result = await sendSyslog('hello', '127.0.0.1', port, 'udp');
    expect(result.ok).toBe(true);
  });

  it('never throws — resolves an { ok } result even when the host cannot be reached', async () => {
    // Some resolvers (e.g. ISP/VPN NXDOMAIN interception) make DNS-failure
    // assertions environment-dependent; the property under test is that
    // sendSyslog() always resolves (never rejects/throws) with a well-formed
    // result, regardless of what the environment's resolver does.
    const result = await sendSyslog('hello', 'this-host-does-not-exist.invalid', 9999, 'udp');
    expect(typeof result.ok).toBe('boolean');
  });
});

describe('sendSyslog — TCP', () => {
  let server;
  let port;
  let received;
  let dataReceived;

  beforeEach((done) => {
    received = [];
    // remediation: a fixed setTimeout(50) before asserting on `received`
    // raced the TCP server's own 'data' event delivery under CPU/scheduler
    // contention (parallel Jest workers) — the send could genuinely succeed
    // while the event loop hadn't yet dispatched the 'data' callback by the
    // time the fixed wait elapsed. Replaced with a promise that resolves the
    // moment data actually arrives, created before the socket exists so
    // there is no window where an early 'data' event could resolve before
    // anything is listening.
    let resolveDataReceived;
    dataReceived = new Promise((resolve) => { resolveDataReceived = resolve; });
    server = net.createServer((socket) => {
      socket.on('data', (chunk) => {
        received.push(chunk.toString('utf8'));
        resolveDataReceived();
      });
    });
    server.listen(0, '127.0.0.1', () => {
      port = server.address().port;
      done();
    });
  });

  afterEach((done) => {
    server.close(done);
  });

  it('resolves { ok: true } and delivers the message on successful TCP send', async () => {
    const result = await sendSyslog('hello-tcp', '127.0.0.1', port, 'tcp');
    expect(result.ok).toBe(true);
    // 5s safety-net timeout: generous margin for genuine environmental
    // slowness, only matters if delivery is truly broken (in which case the
    // test should fail) — not a tight race against a fixed wall-clock guess.
    await Promise.race([
      dataReceived,
      new Promise((_, reject) => setTimeout(() => reject(new Error('TCP data was not received within 5000ms')), 5000)),
    ]);
    expect(received.join('')).toContain('hello-tcp');
  });

  it('resolves { ok: false } when connection is refused', async () => {
    const result = await sendSyslog('hello', '127.0.0.1', 1, 'tcp');
    expect(result.ok).toBe(false);
  });
});
