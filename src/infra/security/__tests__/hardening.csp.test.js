'use strict';

/**
 * Content Security Policy Tests
 *
 * Validates that:
 *   • JSON API responses receive the strict API_CSP
 *   • HTML responses retain the PORTAL_CSP set by Helmet
 *   • The CSP middleware does not break existing res.json() behaviour
 */

const express   = require('express');
const supertest = require('supertest');
const { createCspMiddleware, API_CSP, PORTAL_CSP } = require('../csp');
const { createSecurityHeaders } = require('../headers');

function makeApp() {
  const app = express();
  app.use(createSecurityHeaders('production'));
  app.use(createCspMiddleware());
  app.get('/json', (_req, res) => res.json({ decision: 'ALLOW' }));
  app.get('/html', (_req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<html><body>test</body></html>');
  });
  return app;
}

describe('Content Security Policy', () => {
  describe('API_CSP constant', () => {
    test('includes default-src none', () => {
      expect(API_CSP).toContain("default-src 'none'");
    });

    test('includes frame-ancestors none', () => {
      expect(API_CSP).toContain("frame-ancestors 'none'");
    });

    test('includes base-uri none', () => {
      expect(API_CSP).toContain("base-uri 'none'");
    });

    test('includes form-action none', () => {
      expect(API_CSP).toContain("form-action 'none'");
    });

    test('denies scripts', () => {
      expect(API_CSP).toContain("script-src 'none'");
    });

    test('is a semicolon-delimited string', () => {
      expect(API_CSP.split(';').length).toBeGreaterThan(3);
    });
  });

  describe('PORTAL_CSP constant', () => {
    test('allows self script-src', () => {
      expect(PORTAL_CSP).toContain("script-src 'self'");
    });

    test('allows Google Fonts', () => {
      expect(PORTAL_CSP).toContain('https://fonts.googleapis.com');
      expect(PORTAL_CSP).toContain('https://fonts.gstatic.com');
    });

    test('allows same-origin connect-src', () => {
      expect(PORTAL_CSP).toContain("connect-src 'self'");
    });

    test('disallows object-src', () => {
      expect(PORTAL_CSP).toContain("object-src 'none'");
    });

    test('sets frame-ancestors none', () => {
      expect(PORTAL_CSP).toContain("frame-ancestors 'none'");
    });
  });

  describe('createCspMiddleware() with JSON routes', () => {
    let app;
    beforeAll(() => { app = makeApp(); });

    test('JSON response receives API_CSP', async () => {
      const res = await supertest(app).get('/json');
      expect(res.headers['content-security-policy']).toBe(API_CSP);
    });

    test('JSON response body is preserved', async () => {
      const res = await supertest(app).get('/json');
      expect(res.body).toEqual({ decision: 'ALLOW' });
    });

    test('JSON response Content-Type is application/json', async () => {
      const res = await supertest(app).get('/json');
      expect(res.headers['content-type']).toMatch(/application\/json/);
    });
  });

  describe('createCspMiddleware() with HTML routes', () => {
    let app;
    beforeAll(() => { app = makeApp(); });

    test('HTML response retains PORTAL_CSP from Helmet', async () => {
      const res = await supertest(app).get('/html');
      const csp = res.headers['content-security-policy'];
      // Should be PORTAL_CSP (from Helmet), NOT API_CSP
      expect(csp).toContain("script-src 'self'");
      expect(csp).not.toContain("script-src 'none'");
    });

    test('HTML response status is 200', async () => {
      const res = await supertest(app).get('/html');
      expect(res.status).toBe(200);
    });
  });

  describe('CSP policy differences', () => {
    test('API_CSP is stricter than PORTAL_CSP for scripts', () => {
      expect(API_CSP).toContain("script-src 'none'");
      expect(PORTAL_CSP).not.toContain("script-src 'none'");
    });

    test('both policies include frame-ancestors none', () => {
      expect(API_CSP).toContain("frame-ancestors 'none'");
      expect(PORTAL_CSP).toContain("frame-ancestors 'none'");
    });

    test('both policies include form-action none', () => {
      expect(API_CSP).toContain("form-action 'none'");
      expect(PORTAL_CSP).toContain("form-action 'none'");
    });
  });
});
