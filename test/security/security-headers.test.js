'use strict';

/**
 * Security headers validation tests.
 *
 * Covers:
 *   SH-01  X-Content-Type-Options: nosniff — development
 *   SH-02  X-Content-Type-Options: nosniff — production
 *   SH-03  X-Frame-Options: DENY — development
 *   SH-04  X-Frame-Options: DENY — production
 *   SH-05  Referrer-Policy: strict-origin-when-cross-origin — development
 *   SH-06  Referrer-Policy: strict-origin-when-cross-origin — production
 *   SH-07  HSTS absent in non-production
 *   SH-08  HSTS max-age >= 31536000 in production
 *   SH-09  HSTS includeSubDomains in production
 *   SH-10  HSTS preload NOT present in production
 *   SH-11  X-Powered-By absent (Express fingerprint removed)
 * SH-12 Content-Security-Policy set
 *   SH-13  X-DNS-Prefetch-Control: off
 *   SH-14  X-Download-Options: noopen
 *   SH-15  X-Permitted-Cross-Domain-Policies: none
 *   SH-16  Cross-Origin-Resource-Policy not set (cross-origin API access preserved)
 *   SH-17  Headers present on POST endpoints
 *   SH-18  Headers present on 404 responses
 *   SH-19  Origin-Agent-Cluster: ?1
 *   SH-20  Cross-Origin-Opener-Policy: same-origin
 *   SH-21  Headers present on all representative route types (JSON, file download)
 *   SH-22  HSTS exact value matches required policy in production
 */

const request = require('supertest');
const express = require('express');
const { createSecurityHeaders } = require('../../src/infra/security/headers');

// ── helpers ───────────────────────────────────────────────────────────────────

function buildApp(env) {
  const app = express();
  app.disable('x-powered-by'); // Express sets this; helmet also removes it — belt-and-suspenders
  app.use(createSecurityHeaders(env));
  app.get('/json',  (_req, res) => res.json({ ok: true }));
  app.post('/json', (_req, res) => res.status(201).json({ created: true }));
  app.get('/download', (_req, res) => {
    res.set('Content-Type', 'application/pdf');
    res.set('Content-Disposition', 'attachment; filename="report.pdf"');
    res.send(Buffer.from('PDF'));
  });
  return app;
}

// Build once — avoids supertest keep-alive overhead across 22 tests.
let appDev;
let appProd;

beforeAll(() => {
  appDev  = buildApp('development');
  appProd = buildApp('production');
});

// ── SH-01 / SH-02 — X-Content-Type-Options ───────────────────────────────────

describe('X-Content-Type-Options', () => {
  test('SH-01 nosniff in development', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  test('SH-02 nosniff in production', async () => {
    const res = await request(appProd).get('/json');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });
});

// ── SH-03 / SH-04 — X-Frame-Options ─────────────────────────────────────────

describe('X-Frame-Options', () => {
  test('SH-03 DENY in development', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });

  test('SH-04 DENY in production', async () => {
    const res = await request(appProd).get('/json');
    expect(res.headers['x-frame-options']).toBe('DENY');
  });
});

// ── SH-05 / SH-06 — Referrer-Policy ─────────────────────────────────────────

describe('Referrer-Policy', () => {
  test('SH-05 strict-origin-when-cross-origin in development', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });

  test('SH-06 strict-origin-when-cross-origin in production', async () => {
    const res = await request(appProd).get('/json');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });
});

// ── SH-07 … SH-10 — Strict-Transport-Security ────────────────────────────────

describe('Strict-Transport-Security', () => {
  test('SH-07 HSTS absent in non-production', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['strict-transport-security']).toBeUndefined();
  });

  test('SH-08 HSTS max-age >= 31536000 in production', async () => {
    const res = await request(appProd).get('/json');
    const hsts = res.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    const match = hsts.match(/max-age=(\d+)/);
    expect(match).not.toBeNull();
    expect(parseInt(match[1], 10)).toBeGreaterThanOrEqual(31536000);
  });

  test('SH-09 HSTS includes includeSubDomains in production', async () => {
    const res = await request(appProd).get('/json');
    expect(res.headers['strict-transport-security']).toContain('includeSubDomains');
  });

  test('SH-10 HSTS does not include preload directive', async () => {
    const res = await request(appProd).get('/json');
    const hsts = res.headers['strict-transport-security'];
    expect(hsts).toBeDefined();
    expect(hsts).not.toContain('preload');
  });
});

// ── SH-11 — X-Powered-By removed ─────────────────────────────────────────────

describe('X-Powered-By', () => {
  test('SH-11 X-Powered-By is absent (Express fingerprint removed)', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

// ── SH-12 — Content-Security-Policy ────────────────────────────
// CSP was previously disabled. enables it with PORTAL_CSP as the
// global default (allowing portal inline assets + Google Fonts), and the
// createCspMiddleware() further narrows it to API_CSP for JSON responses.

describe('Content-Security-Policy', () => {
  test('SH-12 CSP is set on all responses', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['content-security-policy']).toBeDefined();
  });

  test('SH-12a CSP includes frame-ancestors none', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
  });

  test('SH-12b CSP includes object-src none', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['content-security-policy']).toContain("object-src 'none'");
  });
});

// ── SH-13 … SH-16 — Supplementary defensive headers ─────────────────────────

describe('Supplementary defensive headers', () => {
  test('SH-13 X-DNS-Prefetch-Control: off', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-dns-prefetch-control']).toBe('off');
  });

  test('SH-14 X-Download-Options: noopen', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-download-options']).toBe('noopen');
  });

  test('SH-15 X-Permitted-Cross-Domain-Policies: none', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['x-permitted-cross-domain-policies']).toBe('none');
  });

  test('SH-16 Cross-Origin-Resource-Policy not set (cross-origin API access preserved)', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['cross-origin-resource-policy']).toBeUndefined();
  });
});

// ── SH-17 / SH-18 — Route coverage ──────────────────────────────────────────

describe('Headers present across route types', () => {
  test('SH-17 headers present on POST endpoints', async () => {
    const res = await request(appDev).post('/json').send({ data: 1 });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });

  test('SH-18 headers present on 404 responses', async () => {
    const res = await request(appDev).get('/nonexistent-route-xyz');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });
});

// ── SH-19 / SH-20 — Modern isolation headers ─────────────────────────────────

describe('Modern isolation headers', () => {
  test('SH-19 Origin-Agent-Cluster: ?1', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['origin-agent-cluster']).toBe('?1');
  });

  test('SH-20 Cross-Origin-Opener-Policy: same-origin', async () => {
    const res = await request(appDev).get('/json');
    expect(res.headers['cross-origin-opener-policy']).toBe('same-origin');
  });
});

// ── SH-21 / SH-22 — Representative route types & HSTS exact value ────────────

describe('Cross-route coverage and HSTS exactness', () => {
  test('SH-21 security headers present on file download endpoints', async () => {
    const res = await request(appDev).get('/download');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(res.headers['x-download-options']).toBe('noopen');
  });

  test('SH-22 HSTS exact value is max-age=31536000; includeSubDomains in production', async () => {
    const res = await request(appProd).get('/json');
    expect(res.headers['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');
  });
});
