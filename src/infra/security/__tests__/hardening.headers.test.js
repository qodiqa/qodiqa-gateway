'use strict';

/**
 * Security Headers Tests
 *
 * Validates that createSecurityHeaders() produces the correct HTTP security
 * headers for both production and non-production environments.
 */

const express    = require('express');
const supertest  = require('supertest');
const { createSecurityHeaders, PERMISSIONS_POLICY } = require('../headers');

function makeApp(env) {
  const app = express();
  app.use(createSecurityHeaders(env));
  app.get('/test', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('Security Headers', () => {
  describe('X-Frame-Options', () => {
    test('is DENY in production', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['x-frame-options']).toBe('DENY');
    });

    test('is DENY in development', async () => {
      const res = await supertest(makeApp('development')).get('/test');
      expect(res.headers['x-frame-options']).toBe('DENY');
    });
  });

  describe('Strict-Transport-Security', () => {
    test('includes max-age=31536000 in production', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      const hsts = res.headers['strict-transport-security'];
      expect(hsts).toMatch(/max-age=31536000/);
      expect(hsts).toMatch(/includeSubDomains/);
    });

    test('is not set in development', async () => {
      const res = await supertest(makeApp('development')).get('/test');
      expect(res.headers['strict-transport-security']).toBeUndefined();
    });

    test('does not set preload in production', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      const hsts = res.headers['strict-transport-security'];
      expect(hsts).not.toMatch(/preload/);
    });
  });

  describe('X-Content-Type-Options', () => {
    test('is nosniff', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });
  });

  describe('Referrer-Policy', () => {
    test('is strict-origin-when-cross-origin', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });
  });

  describe('X-Powered-By', () => {
    test('is removed', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });
  });

  describe('Permissions-Policy', () => {
    test('is present on all responses', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toBeDefined();
    });

    test('disables geolocation', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toContain('geolocation=()');
    });

    test('disables camera', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toContain('camera=()');
    });

    test('disables microphone', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toContain('microphone=()');
    });

    test('disables payment', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toContain('payment=()');
    });

    test('disables usb', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toContain('usb=()');
    });

    test('PERMISSIONS_POLICY export is the same string', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['permissions-policy']).toBe(PERMISSIONS_POLICY);
    });
  });

  describe('Content-Security-Policy (portal default)', () => {
    test('is set on all responses', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['content-security-policy']).toBeDefined();
    });

    test('includes frame-ancestors none', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    });
  });

  describe('Cross-Origin-Opener-Policy', () => {
    test('is same-origin (Helmet default)', async () => {
      const res = await supertest(makeApp('production')).get('/test');
      expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
    });
  });

  describe('environment defaults', () => {
    test('reads NODE_ENV when env param omitted', async () => {
      const orig = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      try {
        const res = await supertest(makeApp()).get('/test');
        expect(res.headers['strict-transport-security']).toMatch(/max-age=31536000/);
      } finally {
        process.env.NODE_ENV = orig;
      }
    });
  });
});
