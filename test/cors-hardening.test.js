'use strict';

/**
 * CORS hardening validation tests.
 *
 * Covers:
 *   CR-01  parseCorsOrigins — valid HTTPS origin
 *   CR-02  parseCorsOrigins — valid HTTP localhost origin
 *   CR-03  parseCorsOrigins — multiple origins, comma-separated
 *   CR-04  parseCorsOrigins — deduplicates repeated entries
 *   CR-05  parseCorsOrigins — rejects wildcard "*"
 *   CR-06  parseCorsOrigins — rejects schemeless origin
 *   CR-07  parseCorsOrigins — rejects origin with path segment
 *   CR-08  parseCorsOrigins — rejects origin with query string
 *   CR-09  parseCorsOrigins — rejects "null" string
 *   CR-10  parseCorsOrigins — handles whitespace around commas
 *   CR-11  parseCorsOrigins — empty string returns no origins, no errors
 *   CR-12  parseCorsOrigins — origin with port is valid
 *   CR-13  validateCorsConfiguration — unset in production → advisory, non-fatal
 *   CR-14  validateCorsConfiguration — unset in non-production → no findings
 *   CR-15  validateCorsConfiguration — malformed origin → fatal
 *   CR-16  validateCorsConfiguration — valid origins → no findings
 *   CR-17  validateCorsConfiguration — empty string after parsing → fatal
 *   CR-18  createCorsMiddleware — allowed origin receives specific ACAO header
 *   CR-19  createCorsMiddleware — ACAO reflects origin, never "*"
 *   CR-20  createCorsMiddleware — Vary: Origin set for allowed cross-origin
 *   CR-21  createCorsMiddleware — denied origin receives no ACAO header
 *   CR-22  createCorsMiddleware — missing Origin header (server-to-server) passes through
 *   CR-23  createCorsMiddleware — no credentials header (ACAC absent)
 *   CR-24  createCorsMiddleware — preflight from allowed origin: 204, ACAO set
 *   CR-25  createCorsMiddleware — preflight from allowed origin: ACAM includes methods
 *   CR-26  createCorsMiddleware — preflight from allowed origin: ACAH includes our headers
 *   CR-27  createCorsMiddleware — preflight from denied origin: no ACAO
 *   CR-28  createCorsMiddleware — dev defaults include localhost:3000 in non-production
 *   CR-29  createCorsMiddleware — production with no origins set → deny all
 *   CR-30  createCorsMiddleware — QODIQA_ALLOWED_ORIGINS env var used when set
 *   CR-31  createCorsMiddleware — exposed headers include X-Request-ID
 *   CR-32  runCorsValidation — malformed origin causes process.exit(1)
 */

const request = require('supertest');
const express = require('express');

const {
  parseCorsOrigins,
  validateCorsConfiguration,
  runCorsValidation,
  createCorsMiddleware,
  DEV_DEFAULTS,
} = require('../src/infra/cors/corsPolicy');

// ── helpers ───────────────────────────────────────────────────────────────────

function withEnv(overrides, deletions = []) {
  const saved = {};
  for (const k of Object.keys(overrides)) {
    saved[k] = process.env[k];
    process.env[k] = overrides[k];
  }
  for (const k of deletions) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
  return function restore() {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}

function buildApp(env, origins) {
  const app = express();
  const restore = origins !== undefined
    ? withEnv({ QODIQA_ALLOWED_ORIGINS: origins })
    : () => {};
  app.use(createCorsMiddleware(env));
  restore();
  app.get('/test',  (_req, res) => res.json({ ok: true }));
  app.post('/test', (_req, res) => res.status(201).json({ created: true }));
  return app;
}

// ── CR-01 … CR-12: parseCorsOrigins ──────────────────────────────────────────

describe('parseCorsOrigins', () => {
  test('CR-01 valid HTTPS origin is accepted', () => {
    const { origins, errors } = parseCorsOrigins('https://example.com');
    expect(errors).toHaveLength(0);
    expect(origins).toEqual(['https://example.com']);
  });

  test('CR-02 valid HTTP localhost origin is accepted', () => {
    const { origins, errors } = parseCorsOrigins('http://localhost:3000');
    expect(errors).toHaveLength(0);
    expect(origins).toEqual(['http://localhost:3000']);
  });

  test('CR-03 multiple comma-separated origins are all parsed', () => {
    const { origins, errors } = parseCorsOrigins(
      'https://portal.example.com,https://admin.example.com',
    );
    expect(errors).toHaveLength(0);
    expect(origins).toHaveLength(2);
    expect(origins).toContain('https://portal.example.com');
    expect(origins).toContain('https://admin.example.com');
  });

  test('CR-04 duplicate origins are silently deduplicated', () => {
    const { origins } = parseCorsOrigins(
      'https://example.com,https://example.com,https://example.com',
    );
    expect(origins).toHaveLength(1);
    expect(origins[0]).toBe('https://example.com');
  });

  test('CR-05 wildcard "*" is rejected', () => {
    const { origins, errors } = parseCorsOrigins('*');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/invalid origin "\*"/);
    expect(origins).toHaveLength(0);
  });

  test('CR-06 schemeless origin is rejected', () => {
    const { errors } = parseCorsOrigins('example.com');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/invalid origin "example.com"/);
  });

  test('CR-07 origin with path segment is rejected', () => {
    const { errors } = parseCorsOrigins('https://example.com/portal');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/invalid origin/);
  });

  test('CR-08 origin with query string is rejected', () => {
    const { errors } = parseCorsOrigins('https://example.com?foo=bar');
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/invalid origin/);
  });

  test('CR-09 "null" string is rejected', () => {
    const { errors } = parseCorsOrigins('null');
    expect(errors).toHaveLength(1);
  });

  test('CR-10 whitespace around commas is stripped', () => {
    const { origins, errors } = parseCorsOrigins(
      ' https://portal.example.com , https://admin.example.com ',
    );
    expect(errors).toHaveLength(0);
    expect(origins).toContain('https://portal.example.com');
    expect(origins).toContain('https://admin.example.com');
  });

  test('CR-11 empty string returns empty origins and no errors', () => {
    const { origins, errors } = parseCorsOrigins('');
    expect(origins).toHaveLength(0);
    expect(errors).toHaveLength(0);
  });

  test('CR-12 origin with explicit port is valid', () => {
    const { origins, errors } = parseCorsOrigins('https://portal.example.com:8443');
    expect(errors).toHaveLength(0);
    expect(origins).toEqual(['https://portal.example.com:8443']);
  });
});

// ── CR-13 … CR-17: validateCorsConfiguration ──────────────────────────────────

describe('validateCorsConfiguration', () => {
  test('CR-13 unset in production → advisory warning, non-fatal', () => {
    const restore = withEnv({ NODE_ENV: 'production' }, ['QODIQA_ALLOWED_ORIGINS']);
    try {
      const result = validateCorsConfiguration();
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatch(/QODIQA_ALLOWED_ORIGINS is not set/);
      expect(result.fatal).toBe(false);
    } finally {
      restore();
    }
  });

  test('CR-14 unset in non-production → no findings', () => {
    const restore = withEnv({ NODE_ENV: 'development' }, ['QODIQA_ALLOWED_ORIGINS']);
    try {
      const result = validateCorsConfiguration();
      expect(result.findings).toHaveLength(0);
      expect(result.fatal).toBe(false);
    } finally {
      restore();
    }
  });

  test('CR-15 malformed origin → fatal finding', () => {
    const restore = withEnv({
      NODE_ENV: 'development',
      QODIQA_ALLOWED_ORIGINS: 'not-a-url,https://good.com',
    });
    try {
      const result = validateCorsConfiguration();
      expect(result.fatal).toBe(true);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.findings.some(f => f.includes('not-a-url'))).toBe(true);
    } finally {
      restore();
    }
  });

  test('CR-16 valid origins → no findings', () => {
    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_ALLOWED_ORIGINS: 'https://portal.example.com,https://admin.example.com',
    });
    try {
      const result = validateCorsConfiguration();
      expect(result.findings).toHaveLength(0);
      expect(result.fatal).toBe(false);
    } finally {
      restore();
    }
  });

  test('CR-17 only-whitespace or empty value → fatal (no valid origins after parse)', () => {
    const restore = withEnv({
      NODE_ENV: 'production',
      QODIQA_ALLOWED_ORIGINS: '   ,   ',
    });
    try {
      const result = validateCorsConfiguration();
      // No valid origins after parsing blank tokens
      expect(result.fatal).toBe(true);
    } finally {
      restore();
    }
  });
});

// ── CR-18 … CR-22: allowed / denied / no-origin behavior ─────────────────────

describe('createCorsMiddleware — origin handling', () => {
  const allowedOrigin = 'https://portal.example.com';
  const deniedOrigin  = 'https://evil.example.com';

  let app;

  beforeAll(() => {
    app = buildApp('production', allowedOrigin);
  });

  test('CR-18 allowed origin receives Access-Control-Allow-Origin reflecting the origin', async () => {
    const res = await request(app).get('/test').set('Origin', allowedOrigin);
    expect(res.headers['access-control-allow-origin']).toBe(allowedOrigin);
  });

  test('CR-19 ACAO header is never the wildcard "*"', async () => {
    const res = await request(app).get('/test').set('Origin', allowedOrigin);
    expect(res.headers['access-control-allow-origin']).not.toBe('*');
  });

  test('CR-20 Vary: Origin is set for allowed cross-origin requests', async () => {
    const res = await request(app).get('/test').set('Origin', allowedOrigin);
    expect(res.headers['vary']).toContain('Origin');
  });

  test('CR-21 denied origin receives no Access-Control-Allow-Origin header', async () => {
    const res = await request(app).get('/test').set('Origin', deniedOrigin);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('CR-22 missing Origin header (server-to-server) — request passes through, no ACAO', async () => {
    const res = await request(app).get('/test'); // no Origin header
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

// ── CR-23: credentials ────────────────────────────────────────────────────────

describe('createCorsMiddleware — credentials', () => {
  test('CR-23 Access-Control-Allow-Credentials is not set (bearer-token model)', async () => {
    const app = buildApp('production', 'https://portal.example.com');
    const res = await request(app)
      .get('/test')
      .set('Origin', 'https://portal.example.com');
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
  });
});

// ── CR-24 … CR-27: preflight ──────────────────────────────────────────────────

describe('createCorsMiddleware — preflight (OPTIONS)', () => {
  const allowedOrigin = 'https://portal.example.com';
  const deniedOrigin  = 'https://evil.example.com';
  let app;

  beforeAll(() => {
    app = buildApp('production', allowedOrigin);
  });

  test('CR-24 preflight from allowed origin: 204 response with ACAO', async () => {
    const res = await request(app)
      .options('/test')
      .set('Origin', allowedOrigin)
      .set('Access-Control-Request-Method', 'POST');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe(allowedOrigin);
  });

  test('CR-25 preflight from allowed origin: Access-Control-Allow-Methods present', async () => {
    const res = await request(app)
      .options('/test')
      .set('Origin', allowedOrigin)
      .set('Access-Control-Request-Method', 'POST');
    const methods = res.headers['access-control-allow-methods'] ?? '';
    expect(methods.toUpperCase()).toContain('POST');
    expect(methods.toUpperCase()).toContain('GET');
  });

  test('CR-26 preflight from allowed origin: ACAH includes Authorization and Content-Type', async () => {
    const res = await request(app)
      .options('/test')
      .set('Origin', allowedOrigin)
      .set('Access-Control-Request-Method', 'POST')
      .set('Access-Control-Request-Headers', 'Authorization,Content-Type');
    const acah = (res.headers['access-control-allow-headers'] ?? '').toLowerCase();
    expect(acah).toContain('authorization');
    expect(acah).toContain('content-type');
  });

  test('CR-27 preflight from denied origin: no ACAO header', async () => {
    const res = await request(app)
      .options('/test')
      .set('Origin', deniedOrigin)
      .set('Access-Control-Request-Method', 'POST');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

// ── CR-28 / CR-29: environment defaults ──────────────────────────────────────

describe('createCorsMiddleware — environment defaults', () => {
  test('CR-28 non-production without env var allows DEV_DEFAULTS (localhost:3000)', async () => {
    // Build app without setting QODIQA_ALLOWED_ORIGINS — uses dev defaults
    const restore = withEnv({}, ['QODIQA_ALLOWED_ORIGINS']);
    let app;
    try {
      app = createCorsMiddleware('development');
    } finally {
      restore();
    }
    const miniApp = express();
    miniApp.use(app);
    miniApp.get('/test', (_req, res) => res.json({ ok: true }));

    const res = await request(miniApp).get('/test').set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
  });

  test('CR-29 production without env var denies all cross-origin requests', async () => {
    const restore = withEnv({ NODE_ENV: 'production' }, ['QODIQA_ALLOWED_ORIGINS']);
    let middleware;
    try {
      middleware = createCorsMiddleware('production');
    } finally {
      restore();
    }
    const miniApp = express();
    miniApp.use(middleware);
    miniApp.get('/test', (_req, res) => res.json({ ok: true }));

    const res = await request(miniApp)
      .get('/test')
      .set('Origin', 'https://any-origin.com');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

// ── CR-30 / CR-31: env var and exposed headers ────────────────────────────────

describe('createCorsMiddleware — env var and exposed headers', () => {
  test('CR-30 QODIQA_ALLOWED_ORIGINS env var is used when set', async () => {
    const origin  = 'https://custom-portal.example.com';
    const restore = withEnv({ QODIQA_ALLOWED_ORIGINS: origin });
    let middleware;
    try {
      middleware = createCorsMiddleware('production');
    } finally {
      restore();
    }
    const miniApp = express();
    miniApp.use(middleware);
    miniApp.get('/test', (_req, res) => res.json({ ok: true }));

    const res = await request(miniApp).get('/test').set('Origin', origin);
    expect(res.headers['access-control-allow-origin']).toBe(origin);
  });

  test('CR-31 exposed headers include X-Request-ID', async () => {
    const origin = 'https://portal.example.com';
    const app    = buildApp('production', origin);
    const res    = await request(app).get('/test').set('Origin', origin);
    const exposed = (res.headers['access-control-expose-headers'] ?? '').toLowerCase();
    expect(exposed).toContain('x-request-id');
  });
});

// ── CR-32: runCorsValidation process.exit ─────────────────────────────────────

describe('runCorsValidation — startup guard', () => {
  let exitSpy;

  beforeEach(() => {
    jest.resetModules();
    exitSpy = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('process.exit called');
    });
  });

  afterEach(() => {
    exitSpy.mockRestore();
  });

  test('CR-32 malformed QODIQA_ALLOWED_ORIGINS causes process.exit(1)', () => {
    const restore = withEnv({ QODIQA_ALLOWED_ORIGINS: 'not-valid,also-not-valid' });
    try {
      expect(() => runCorsValidation()).toThrow('process.exit called');
      expect(exitSpy).toHaveBeenCalledWith(1);
    } finally {
      restore();
    }
  });
});
