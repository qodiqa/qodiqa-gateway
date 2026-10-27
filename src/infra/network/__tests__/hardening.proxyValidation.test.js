'use strict';

/**
 * Trusted Proxy Validation Tests
 *
 * Validates that the proxy validation middleware correctly:
 *   • Blocks requests with oversized X-Forwarded-For chains
 *   • Blocks requests with invalid IP entries in X-Forwarded-For
 *   • Blocks non-HTTPS protocol in production (when enforced)
 *   • Blocks invalid Host headers (when allowlist is configured)
 *   • Passes legitimate requests through
 *
 * Also tests validateProxyConfig() startup validation.
 */

const express   = require('express');
const supertest = require('supertest');
const { createProxyValidationMiddleware, validateProxyConfig } = require('../proxyValidation');

function makeApp(opts = {}) {
  const app = express();
  app.use(createProxyValidationMiddleware(opts));
  app.get('/test', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('Proxy Validation Middleware', () => {
  describe('X-Forwarded-For chain depth', () => {
    test('allows request without X-Forwarded-For', async () => {
      const res = await supertest(makeApp()).get('/test');
      expect(res.status).toBe(200);
    });

    test('allows single-entry X-Forwarded-For', async () => {
      const res = await supertest(makeApp())
        .get('/test')
        .set('X-Forwarded-For', '1.2.3.4');
      expect(res.status).toBe(200);
    });

    test('allows chain within max depth', async () => {
      const res = await supertest(makeApp({ maxForwardedDepth: 3 }))
        .get('/test')
        .set('X-Forwarded-For', '1.2.3.4, 10.0.0.1, 10.0.0.2');
      expect(res.status).toBe(200);
    });

    test('blocks chain exceeding max depth', async () => {
      const ips  = Array.from({ length: 11 }, (_, i) => `1.2.3.${i + 1}`).join(', ');
      const res  = await supertest(makeApp({ maxForwardedDepth: 10 }))
        .get('/test')
        .set('X-Forwarded-For', ips);
      expect(res.status).toBe(400);
      expect(res.body.reason).toBe('PROXY_CHAIN_TOO_DEEP');
    });

    test('PROXY_CHAIN_TOO_DEEP response has depth and max', async () => {
      const ips = Array.from({ length: 11 }, (_, i) => `1.2.3.${i + 1}`).join(', ');
      const res = await supertest(makeApp({ maxForwardedDepth: 10 }))
        .get('/test')
        .set('X-Forwarded-For', ips);
      expect(res.body.details.depth).toBe(11);
      expect(res.body.details.max).toBe(10);
    });
  });

  describe('X-Forwarded-For invalid IP validation', () => {
    test('blocks non-IP entry in X-Forwarded-For', async () => {
      const res = await supertest(makeApp())
        .get('/test')
        .set('X-Forwarded-For', '1.2.3.4, not-an-ip');
      expect(res.status).toBe(400);
      expect(res.body.reason).toBe('INVALID_FORWARDED_IP');
    });

    test('blocks hostname in X-Forwarded-For', async () => {
      const res = await supertest(makeApp())
        .get('/test')
        .set('X-Forwarded-For', 'evil.attacker.com');
      expect(res.status).toBe(400);
      expect(res.body.reason).toBe('INVALID_FORWARDED_IP');
    });

    test('allows valid IPv6 address', async () => {
      const res = await supertest(makeApp())
        .get('/test')
        .set('X-Forwarded-For', '::1');
      expect(res.status).toBe(200);
    });
  });

  describe('X-Forwarded-Proto enforcement', () => {
    const prodApp = makeApp({ enforceHttpsProto: true });

    test('allows https proto in production enforcement mode', async () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        const res = await supertest(prodApp)
          .get('/test')
          .set('X-Forwarded-Proto', 'https');
        expect(res.status).toBe(200);
      } finally {
        process.env.NODE_ENV = orig;
      }
    });

    test('blocks http proto in production enforcement mode', async () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        const res = await supertest(prodApp)
          .get('/test')
          .set('X-Forwarded-Proto', 'http');
        expect(res.status).toBe(400);
        expect(res.body.reason).toBe('INSECURE_PROTOCOL');
      } finally {
        process.env.NODE_ENV = orig;
      }
    });

    test('allows any proto in development', async () => {
      const devApp = makeApp({ enforceHttpsProto: false });
      const res = await supertest(devApp)
        .get('/test')
        .set('X-Forwarded-Proto', 'http');
      expect(res.status).toBe(200);
    });

    test('allows request without X-Forwarded-Proto header', async () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        const res = await supertest(prodApp).get('/test');
        expect(res.status).toBe(200);
      } finally {
        process.env.NODE_ENV = orig;
      }
    });
  });

  describe('Host header validation', () => {
    test('passes when allowedHosts is empty (any host allowed)', async () => {
      const res = await supertest(makeApp({ allowedHosts: [] }))
        .get('/test')
        .set('Host', 'arbitrary.host.com');
      expect(res.status).toBe(200);
    });

    test('passes when host is in allowlist', async () => {
      const res = await supertest(makeApp({ allowedHosts: ['api.qodiqa.com', 'localhost'] }))
        .get('/test')
        .set('Host', 'api.qodiqa.com');
      expect(res.status).toBe(200);
    });

    test('blocks host not in allowlist', async () => {
      const res = await supertest(makeApp({ allowedHosts: ['api.qodiqa.com'] }))
        .get('/test')
        .set('Host', 'evil.attacker.com');
      expect(res.status).toBe(400);
      expect(res.body.reason).toBe('INVALID_HOST_HEADER');
    });

    test('is case-insensitive', async () => {
      const res = await supertest(makeApp({ allowedHosts: ['api.qodiqa.com'] }))
        .get('/test')
        .set('Host', 'API.QODIQA.COM');
      expect(res.status).toBe(200);
    });

    test('strips port from Host before comparison', async () => {
      const res = await supertest(makeApp({ allowedHosts: ['localhost'] }))
        .get('/test')
        .set('Host', 'localhost:3000');
      expect(res.status).toBe(200);
    });
  });

  describe('response structure', () => {
    test('blocked responses have decision: BLOCK', async () => {
      const ips = Array.from({ length: 11 }, (_, i) => `1.2.3.${i + 1}`).join(', ');
      const res = await supertest(makeApp()).get('/test').set('X-Forwarded-For', ips);
      expect(res.body.decision).toBe('BLOCK');
    });
  });
});

describe('validateProxyConfig()', () => {
  test('warns about wildcard TRUSTED_PROXY', () => {
    const result = validateProxyConfig({ TRUSTED_PROXY: '*', NODE_ENV: 'production' });
    expect(result.warnings.some(w => w.includes('trusts all upstream IPs'))).toBe(true);
    expect(result.safe).toBe(false);
  });

  test('warns about 0.0.0.0/0', () => {
    const result = validateProxyConfig({ TRUSTED_PROXY: '0.0.0.0/0', NODE_ENV: 'production' });
    expect(result.warnings.length).toBeGreaterThan(0);
  });

  test('passes for specific IP in TRUSTED_PROXY', () => {
    const result = validateProxyConfig({
      TRUSTED_PROXY: '10.0.0.1',
      NODE_ENV: 'production',
      QODIQA_ALLOWED_HOSTS: 'api.example.com',
    });
    expect(result.warnings.filter(w => w.includes('trusts all upstream IPs'))).toHaveLength(0);
  });

  test('warns if TRUSTED_PROXY not set in production', () => {
    const result = validateProxyConfig({ NODE_ENV: 'production' });
    expect(result.warnings.some(w => w.includes('not set in production'))).toBe(true);
  });

  test('no warning for unset TRUSTED_PROXY in development', () => {
    const result = validateProxyConfig({ NODE_ENV: 'development' });
    expect(result.warnings.filter(w => w.includes('not set in production'))).toHaveLength(0);
  });

  test('summary contains proxy configuration', () => {
    const result = validateProxyConfig({ TRUSTED_PROXY: '10.0.0.1', NODE_ENV: 'development' });
    expect(result.summary).toBeDefined();
    expect(result.summary.trustedProxy).toBeDefined();
    expect(result.summary.maxForwardedDepth).toBeDefined();
  });

  test('warns when ENFORCE_HTTPS_PROTO=false in production', () => {
    const result = validateProxyConfig({
      NODE_ENV: 'production',
      TRUSTED_PROXY: '10.0.0.1',
      ENFORCE_HTTPS_PROTO: 'false',
      QODIQA_ALLOWED_HOSTS: 'example.com',
    });
    expect(result.warnings.some(w => w.includes('ENFORCE_HTTPS_PROTO=false'))).toBe(true);
  });
});
