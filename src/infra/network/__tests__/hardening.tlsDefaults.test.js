'use strict';

/**
 * HTTP Server Transport Hardening Tests
 *
 * Validates that configureTlsDefaults() applies the correct timeout and
 * connection limit settings to an http.Server instance.
 */

const { configureTlsDefaults } = require('../tlsDefaults');

function makeServer(overrides = {}) {
  return {
    keepAliveTimeout: 5000,
    headersTimeout:   60000,
    requestTimeout:   0,
    maxHeadersCount:  2000,
    connectionsCheckingInterval: 30000,
    maxConnections:   undefined,
    ...overrides,
  };
}

describe('HTTP Transport Hardening', () => {
  let orig;

  beforeEach(() => {
    orig = {
      KEEP_ALIVE_TIMEOUT_MS: process.env.KEEP_ALIVE_TIMEOUT_MS,
      HEADERS_TIMEOUT_MS:    process.env.HEADERS_TIMEOUT_MS,
      REQUEST_TIMEOUT_MS:    process.env.REQUEST_TIMEOUT_MS,
      MAX_HEADERS_COUNT:     process.env.MAX_HEADERS_COUNT,
      MAX_HTTP_CONNECTIONS:  process.env.MAX_HTTP_CONNECTIONS,
      CONNECTIONS_CHECKING_INTERVAL_MS: process.env.CONNECTIONS_CHECKING_INTERVAL_MS,
    };
    delete process.env.KEEP_ALIVE_TIMEOUT_MS;
    delete process.env.HEADERS_TIMEOUT_MS;
    delete process.env.REQUEST_TIMEOUT_MS;
    delete process.env.MAX_HEADERS_COUNT;
    delete process.env.MAX_HTTP_CONNECTIONS;
    delete process.env.CONNECTIONS_CHECKING_INTERVAL_MS;
  });

  afterEach(() => {
    for (const [k, v] of Object.entries(orig)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  test('sets keepAliveTimeout to 65 000 ms by default', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.keepAliveTimeout).toBe(65_000);
  });

  test('sets headersTimeout to 66 000 ms by default', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.headersTimeout).toBe(66_000);
  });

  test('sets requestTimeout to 120 000 ms by default', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.requestTimeout).toBe(120_000);
  });

  test('sets maxHeadersCount to 100 by default', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.maxHeadersCount).toBe(100);
  });

  // connectionsCheckingInterval is the real enforcement mechanism
  // behind requestTimeout (Node closes an expired connection at the next
  // sweep tick, not at the precise deadline) — see
  // for the live-confirmed mechanism.
  test('sets connectionsCheckingInterval to 1 000 ms by default', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.connectionsCheckingInterval).toBe(1_000);
  });

  test('respects CONNECTIONS_CHECKING_INTERVAL_MS override', () => {
    process.env.CONNECTIONS_CHECKING_INTERVAL_MS = '5000';
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.connectionsCheckingInterval).toBe(5_000);
  });

  test('headersTimeout > keepAliveTimeout (Node.js requirement)', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.headersTimeout).toBeGreaterThan(server.keepAliveTimeout);
  });

  test('respects KEEP_ALIVE_TIMEOUT_MS override', () => {
    process.env.KEEP_ALIVE_TIMEOUT_MS = '30000';
    process.env.HEADERS_TIMEOUT_MS    = '31000';
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.keepAliveTimeout).toBe(30_000);
  });

  test('respects MAX_HEADERS_COUNT override', () => {
    process.env.MAX_HEADERS_COUNT = '50';
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.maxHeadersCount).toBe(50);
  });

  test('does not set maxConnections when MAX_HTTP_CONNECTIONS is not set', () => {
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.maxConnections).toBeUndefined();
  });

  test('sets maxConnections when MAX_HTTP_CONNECTIONS is set', () => {
    process.env.MAX_HTTP_CONNECTIONS = '500';
    process.env.KEEP_ALIVE_TIMEOUT_MS = '65000';
    process.env.HEADERS_TIMEOUT_MS    = '66000';
    const server = makeServer();
    configureTlsDefaults(server, () => {});
    expect(server.maxConnections).toBe(500);
  });

  test('throws when headersTimeout <= keepAliveTimeout', () => {
    process.env.KEEP_ALIVE_TIMEOUT_MS = '60000';
    process.env.HEADERS_TIMEOUT_MS    = '60000';
    const server = makeServer();
    expect(() => configureTlsDefaults(server, () => {})).toThrow(/headersTimeout.*keepAliveTimeout/);
  });

  test('throws when headersTimeout < keepAliveTimeout', () => {
    process.env.KEEP_ALIVE_TIMEOUT_MS = '66000';
    process.env.HEADERS_TIMEOUT_MS    = '65000';
    const server = makeServer();
    expect(() => configureTlsDefaults(server, () => {})).toThrow();
  });

  test('emits HTTP_SERVER_TRANSPORT_HARDENED event', () => {
    const events = [];
    const server = makeServer();
    configureTlsDefaults(server, (level, event, data) => events.push({ level, event, data }));
    const evt = events.find(e => e.event === 'HTTP_SERVER_TRANSPORT_HARDENED');
    expect(evt).toBeDefined();
    expect(evt.level).toBe('INFO');
  });

  test('emitted event contains all timeout values', () => {
    const events = [];
    const server = makeServer();
    configureTlsDefaults(server, (level, event, data) => events.push({ level, event, data }));
    const evt = events.find(e => e.event === 'HTTP_SERVER_TRANSPORT_HARDENED');
    expect(evt.data.keepAliveTimeoutMs).toBeDefined();
    expect(evt.data.headersTimeoutMs).toBeDefined();
    expect(evt.data.requestTimeoutMs).toBeDefined();
    expect(evt.data.maxHeadersCount).toBeDefined();
    expect(evt.data.connectionsCheckingIntervalMs).toBeDefined();
  });

  test('works without emit function (no throw)', () => {
    const server = makeServer();
    expect(() => configureTlsDefaults(server)).not.toThrow();
  });
});
