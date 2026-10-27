'use strict';

const { getConfigSummary, buildClientOptions, isAuthError, isTlsError } = require('./clientConfig');

// ── getConfigSummary() ────────────────────────────────────────────────────────

describe('getConfigSummary()', () => {
  const origEnv = {};
  const envKeys = ['REDIS_URL', 'REDIS_USERNAME', 'REDIS_PASSWORD', 'REDIS_TLS', 'REDIS_TLS_REJECT_UNAUTHORIZED'];

  beforeEach(() => {
    for (const k of envKeys) {
      origEnv[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of envKeys) {
      if (origEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = origEnv[k];
      }
    }
  });

  test('returns an object with the correct shape', () => {
    const summary = getConfigSummary();
    expect(typeof summary).toBe('object');
    expect(summary).toHaveProperty('authConfigured');
    expect(summary).toHaveProperty('tlsEnabled');
    expect(summary).toHaveProperty('tlsVerified');
    expect(summary).toHaveProperty('urlRedacted');
  });

  test('authConfigured is boolean', () => {
    const { authConfigured } = getConfigSummary();
    expect(typeof authConfigured).toBe('boolean');
  });

  test('tlsEnabled is boolean', () => {
    const { tlsEnabled } = getConfigSummary();
    expect(typeof tlsEnabled).toBe('boolean');
  });

  test('tlsVerified is boolean', () => {
    const { tlsVerified } = getConfigSummary();
    expect(typeof tlsVerified).toBe('boolean');
  });

  test('urlRedacted is a string', () => {
    const { urlRedacted } = getConfigSummary();
    expect(typeof urlRedacted).toBe('string');
  });

  test('with no env vars: uses default URL and authConfigured is false', () => {
    const { authConfigured, tlsEnabled } = getConfigSummary();
    expect(authConfigured).toBe(false);
    expect(tlsEnabled).toBe(false);
  });

  test('with REDIS_URL=rediss://...: tlsEnabled is true', () => {
    process.env.REDIS_URL = 'rediss://localhost:6380';
    const { tlsEnabled } = getConfigSummary();
    expect(tlsEnabled).toBe(true);
  });

  test('with REDIS_TLS=true: tlsEnabled is true', () => {
    process.env.REDIS_TLS = 'true';
    const { tlsEnabled } = getConfigSummary();
    expect(tlsEnabled).toBe(true);
  });

  test('with REDIS_PASSWORD set: authConfigured is true', () => {
    process.env.REDIS_PASSWORD = 'secret';
    const { authConfigured } = getConfigSummary();
    expect(authConfigured).toBe(true);
  });

  test('with REDIS_USERNAME set: authConfigured is true', () => {
    process.env.REDIS_USERNAME = 'user';
    const { authConfigured } = getConfigSummary();
    expect(authConfigured).toBe(true);
  });

  test('with TLS enabled and REDIS_TLS_REJECT_UNAUTHORIZED=false: tlsVerified is false', () => {
    process.env.REDIS_TLS = 'true';
    process.env.REDIS_TLS_REJECT_UNAUTHORIZED = 'false';
    const { tlsEnabled, tlsVerified } = getConfigSummary();
    expect(tlsEnabled).toBe(true);
    expect(tlsVerified).toBe(false);
  });

  test('URL with embedded credentials: authConfigured is true', () => {
    process.env.REDIS_URL = 'redis://user:pass@localhost:6379';
    const { authConfigured } = getConfigSummary();
    expect(authConfigured).toBe(true);
  });

  test('urlRedacted does not contain plaintext password', () => {
    process.env.REDIS_URL = 'redis://user:supersecret@localhost:6379';
    const { urlRedacted } = getConfigSummary();
    expect(urlRedacted).not.toContain('supersecret');
    // Implementation URL-encodes the placeholder ([ → %5B, ] → %5D)
    expect(urlRedacted).toMatch(/\[REDACTED\]|%5BREDACTED%5D/i);
  });
});

// ── isAuthError() ─────────────────────────────────────────────────────────────

describe('isAuthError()', () => {
  test('returns true for WRONGPASS', () => {
    expect(isAuthError(new Error('WRONGPASS'))).toBe(true);
  });

  test('returns true for NOAUTH', () => {
    expect(isAuthError(new Error('NOAUTH'))).toBe(true);
  });

  test('returns true for AUTHFAILED', () => {
    expect(isAuthError(new Error('AUTHFAILED'))).toBe(true);
  });

  test('returns true for "ERR invalid password"', () => {
    expect(isAuthError(new Error('ERR invalid password'))).toBe(true);
  });

  test('returns false for a generic connection error', () => {
    expect(isAuthError(new Error('ECONNREFUSED'))).toBe(false);
  });

  test('returns false for a timeout error', () => {
    expect(isAuthError(new Error('ETIMEDOUT'))).toBe(false);
  });

  test('returns false for null/undefined err', () => {
    expect(isAuthError(null)).toBe(false);
    expect(isAuthError(undefined)).toBe(false);
  });

  test('returns false for error with no message', () => {
    expect(isAuthError(new Error(''))).toBe(false);
  });

  test('is case-insensitive (lowercase wrongpass)', () => {
    expect(isAuthError(new Error('wrongpass'))).toBe(true);
  });
});

// ── isTlsError() ──────────────────────────────────────────────────────────────

describe('isTlsError()', () => {
  test('returns true for SSL in message', () => {
    expect(isTlsError(new Error('SSL handshake failed'))).toBe(true);
  });

  test('returns true for "certificate" in message', () => {
    expect(isTlsError(new Error('certificate verify failed'))).toBe(true);
  });

  test('returns true for TLS in message', () => {
    expect(isTlsError(new Error('TLS connection error'))).toBe(true);
  });

  test('returns true for "handshake" in message', () => {
    expect(isTlsError(new Error('handshake error'))).toBe(true);
  });

  test('returns false for a generic auth error', () => {
    expect(isTlsError(new Error('WRONGPASS'))).toBe(false);
  });

  test('returns false for a generic connection error', () => {
    expect(isTlsError(new Error('ECONNREFUSED'))).toBe(false);
  });

  test('returns false for null/undefined err', () => {
    expect(isTlsError(null)).toBe(false);
    expect(isTlsError(undefined)).toBe(false);
  });

  test('is case-insensitive (lowercase ssl)', () => {
    expect(isTlsError(new Error('ssl error'))).toBe(true);
  });
});

// ── buildClientOptions() ───────────────────────────────────────────────────────

describe('buildClientOptions()', () => {
  const origEnv = {};
  const envKeys = ['REDIS_URL', 'REDIS_USERNAME', 'REDIS_PASSWORD', 'REDIS_TLS',
    'REDIS_TLS_CA', 'REDIS_TLS_CERT', 'REDIS_TLS_KEY', 'REDIS_TLS_REJECT_UNAUTHORIZED'];

  beforeEach(() => {
    for (const k of envKeys) {
      origEnv[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of envKeys) {
      if (origEnv[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = origEnv[k];
      }
    }
  });

  test('with no env vars returns a valid options object', () => {
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    expect(typeof opts).toBe('object');
    expect(opts).toHaveProperty('url');
    expect(opts).toHaveProperty('socket');
  });

  test('socket.connectTimeout is set when passed', () => {
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: 5000 });
    expect(opts.socket.connectTimeout).toBe(5000);
  });

  test('default URL is redis://localhost:6379', () => {
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    expect(opts.url).toBe('redis://localhost:6379');
  });

  test('REDIS_USERNAME is added to opts when set', () => {
    process.env.REDIS_USERNAME = 'testuser';
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    expect(opts.username).toBe('testuser');
  });

  test('REDIS_PASSWORD is added to opts when set', () => {
    process.env.REDIS_PASSWORD = 'testpass';
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    expect(opts.password).toBe('testpass');
  });

  test('no TLS options in socket when TLS is not enabled', () => {
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    expect(opts.socket.tls).toBeUndefined();
  });

  test('socket.tls is set when REDIS_TLS=true', () => {
    process.env.REDIS_TLS = 'true';
    const opts = buildClientOptions({ reconnectStrategy: undefined, connectTimeout: undefined });
    // tls should be truthy (true or an object with options)
    expect(opts.socket.tls).toBeTruthy();
  });

  test('reconnectStrategy is passed through to socket', () => {
    const fn = () => 1000;
    const opts = buildClientOptions({ reconnectStrategy: fn, connectTimeout: undefined });
    expect(opts.socket.reconnectStrategy).toBe(fn);
  });

  // the `toBeTruthy()` check above let a nested `socket.tls = {ca,cert,key}`
  // pass, but @redis/client's own createClient() rejects anything other than
  // `tls: true` for a rediss:// URL ("tls socket option is set to [object Object]
  // which is mismatch with protocol..."), so the documented production mTLS
  // posture (docs/deployment/redis-tls.md, docker-compose.prod.yml) could never connect —
  // reproduced live as STRICT_REPLAY_PROTECTION_VIOLATION on every boot. Asserted
  // against the real client library, not a double.
  test('rediss:// + mTLS files: the options pass the real @redis/client createClient() validation, with CA/cert/key flat on socket', () => {
    const fs = require('fs');
    const os = require('os');
    const path = require('path');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h123-redis-tls-'));
    for (const f of ['ca', 'cert', 'key']) fs.writeFileSync(path.join(dir, f), `placeholder-${f}`);
    process.env.REDIS_URL      = 'rediss://redis:6380';
    process.env.REDIS_TLS      = 'true';
    process.env.REDIS_TLS_CA   = path.join(dir, 'ca');
    process.env.REDIS_TLS_CERT = path.join(dir, 'cert');
    process.env.REDIS_TLS_KEY  = path.join(dir, 'key');

    try {
      const opts = buildClientOptions({ reconnectStrategy: false, connectTimeout: 1000 });
      expect(opts.socket.tls).toBe(true);
      expect(opts.socket.ca.toString()).toBe('placeholder-ca');
      expect(opts.socket.cert.toString()).toBe('placeholder-cert');
      expect(opts.socket.key.toString()).toBe('placeholder-key');

      const { createClient } = jest.requireActual('redis');
      expect(() => createClient(opts)).not.toThrow();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
