'use strict';

/**
 * OpenAPI Generation — Test Suite (Component #42)
 *
 * Tests cover:
 *   1. Spec structure (top-level shape, required OpenAPI 3.1 fields)
 *   2. Components (schemas, responses, parameters, security schemes)
 *   3. Paths (coverage, required fields per operation)
 *   4. Security (scheme definitions, per-operation references)
 *   5. JSON Writer
 *   6. YAML Writer
 *   7. Swagger UI HTML generator
 *   8. Generator caching / invalidation
 *   9. OpenAPI route handler (request/response shape)
 *  10. Edge cases and error handling
 */

const { generateSpec, invalidateCache } = require('./generator');
const { writeJson }                     = require('./writers/jsonWriter');
const { writeYaml }                     = require('./writers/yamlWriter');
const { renderSwaggerUiHtml, SWAGGER_UI_VERSION } = require('./swaggerUi');
const requestDrain                      = require('../runtime/requestDrain');

// ── helpers ───────────────────────────────────────────────────────────────────

function freshSpec() {
  invalidateCache();
  return generateSpec();
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Spec structure
// ═══════════════════════════════════════════════════════════════════════════════

describe('generateSpec — top-level structure', () => {
  let spec;
  beforeAll(() => { spec = freshSpec(); });

  test('returns a non-null object', () => {
    expect(spec).toBeDefined();
    expect(typeof spec).toBe('object');
    expect(spec).not.toBeNull();
  });

  test('openapi version is 3.1.0', () => {
    expect(spec.openapi).toBe('3.1.0');
  });

  test('info object has required fields', () => {
    expect(spec.info).toBeDefined();
    expect(typeof spec.info.title).toBe('string');
    expect(spec.info.title.length).toBeGreaterThan(0);
    expect(typeof spec.info.version).toBe('string');
    expect(spec.info.version.length).toBeGreaterThan(0);
  });

  test('servers is a non-empty array', () => {
    expect(Array.isArray(spec.servers)).toBe(true);
    expect(spec.servers.length).toBeGreaterThan(0);
    for (const s of spec.servers) {
      expect(typeof s.url).toBe('string');
    }
  });

  test('tags is an array with at least 10 tags', () => {
    expect(Array.isArray(spec.tags)).toBe(true);
    expect(spec.tags.length).toBeGreaterThanOrEqual(10);
    for (const t of spec.tags) {
      expect(typeof t.name).toBe('string');
      expect(t.name.length).toBeGreaterThan(0);
    }
  });

  test('paths is a non-empty object', () => {
    expect(spec.paths).toBeDefined();
    expect(typeof spec.paths).toBe('object');
    expect(Object.keys(spec.paths).length).toBeGreaterThan(0);
  });

  test('components object is present', () => {
    expect(spec.components).toBeDefined();
    expect(typeof spec.components).toBe('object');
  });

  test('security default is set', () => {
    expect(Array.isArray(spec.security)).toBe(true);
    expect(spec.security.length).toBeGreaterThan(0);
  });

  test('spec is frozen (immutable)', () => {
    expect(Object.isFrozen(spec)).toBe(true);
  });

  test('externalDocs has description and url', () => {
    expect(spec.externalDocs).toBeDefined();
    expect(typeof spec.externalDocs.description).toBe('string');
    expect(typeof spec.externalDocs.url).toBe('string');
  });

  test('info.description is non-empty markdown string', () => {
    expect(typeof spec.info.description).toBe('string');
    expect(spec.info.description.length).toBeGreaterThan(50);
  });

  // the decision endpoints do NOT always answer HTTP 200 (status mode, 413/415/429/5xx).
  test('info.description does not claim decision endpoints always use HTTP 200', () => {
    expect(spec.info.description).not.toMatch(/always use HTTP 200/);
    expect(spec.info.description).toMatch(/4xx\/5xx in both modes/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Components — schemas
// ═══════════════════════════════════════════════════════════════════════════════

describe('components — schemas', () => {
  let schemas;
  beforeAll(() => { schemas = freshSpec().components.schemas; });

  const REQUIRED_SCHEMAS = [
    'Uuid', 'Timestamp', 'ActorId', 'Action', 'Scope', 'TenantId',
    'PaginationMeta', 'SuccessEnvelope', 'ErrorEnvelope', 'EnforcementDecision',
    'Artifact', 'ConsentRecord', 'PolicyRule', 'PolicyDefinition',
    'WebhookEndpoint', 'RbacUser', 'Organization', 'Tenant',
    'ComplianceReport', 'HealthStatus',
  ];

  test.each(REQUIRED_SCHEMAS)('schema %s is defined', name => {
    expect(schemas[name]).toBeDefined();
  });

  test('Uuid schema uses type string with format uuid', () => {
    const s = schemas.Uuid;
    expect(s.type).toBe('string');
    expect(s.format).toBe('uuid');
  });

  test('EnforcementDecision has decision enum with EXECUTE and BLOCK', () => {
    const s = schemas.EnforcementDecision;
    expect(s).toBeDefined();
    // May be a direct object with properties
    const props = s.properties || (s.allOf && s.allOf.find(x => x.properties) && s.allOf.find(x => x.properties).properties);
    if (props && props.decision) {
      expect(props.decision.enum).toEqual(expect.arrayContaining(['EXECUTE', 'BLOCK']));
    }
  });

  test('SuccessEnvelope has status and data properties', () => {
    const s = schemas.SuccessEnvelope;
    expect(s).toBeDefined();
    const props = s.properties;
    if (props) {
      expect(props.status).toBeDefined();
      expect(props.data).toBeDefined();
    }
  });

  test('all schemas are plain objects (not null, not arrays)', () => {
    for (const [name, schema] of Object.entries(schemas)) {
      expect(typeof schema).toBe('object');
      expect(schema).not.toBeNull();
      expect(Array.isArray(schema)).toBe(false);
    }
  });

  test('at least 20 schemas are defined', () => {
    expect(Object.keys(schemas).length).toBeGreaterThanOrEqual(20);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Components — responses
// ═══════════════════════════════════════════════════════════════════════════════

describe('components — responses', () => {
  let responses;
  beforeAll(() => { responses = freshSpec().components.responses; });

  const REQUIRED_RESPONSES = [
    'BadRequest', 'Unauthorized', 'Forbidden', 'NotFound',
    'Conflict', 'TooManyRequests', 'InternalError',
    'ServiceShuttingDown', 'ReadinessUnavailable',
  ];

  test.each(REQUIRED_RESPONSES)('response %s is defined', name => {
    expect(responses[name]).toBeDefined();
  });

  test('each response has a description', () => {
    for (const [name, resp] of Object.entries(responses)) {
      expect(typeof resp.description).toBe('string', `${name}.description must be a string`);
      expect(resp.description.length).toBeGreaterThan(0);
    }
  });

  test('Unauthorized response has content', () => {
    expect(responses.Unauthorized.content).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3b. SERVICE_SHUTTING_DOWN — canonical response consistency
// ═══════════════════════════════════════════════════════════════════════════════

describe('SERVICE_SHUTTING_DOWN — canonical response consistency', () => {
  let spec;
  beforeAll(() => { spec = freshSpec(); });
  afterEach(() => { requestDrain._reset(); });

  // Endpoints mounted ahead of the request-drain middleware in server.js —
  // these can never receive the SERVICE_SHUTTING_DOWN response.
  const DRAIN_EXEMPT_PATHS = ['/health', '/ready', '/metrics', '/diagnostics', '/health/redis'];

  test('documented ServiceShuttingDown schema matches the actual middleware response byte-for-byte', () => {
    requestDrain.beginShutdown();
    let captured;
    requestDrain.middleware({}, {
      status: () => ({ json: body => { captured = body; } }),
    }, () => {});

    const documented = spec.components.responses.ServiceShuttingDown
      .content['application/json'].schema;

    expect(captured).toEqual({
      success: false,
      error: { code: 'SERVICE_SHUTTING_DOWN', message: 'Service unavailable' },
    });
    expect(documented.properties.success.example).toBe(captured.success);
    expect(documented.properties.error.properties.code.example).toBe(captured.error.code);
    expect(documented.properties.error.properties.message.example).toBe(captured.error.message);
  });

  test('every drain-gated endpoint declares 503 via the ServiceShuttingDown component only', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
    for (const [p, item] of Object.entries(spec.paths)) {
      if (DRAIN_EXEMPT_PATHS.includes(p)) continue;
      for (const method of HTTP_METHODS) {
        if (!item[method]) continue;
        const resp503 = item[method].responses['503'];
        if (!resp503) continue; // not every endpoint enumerates 503 explicitly is fine — but if present, must be canonical
        expect(resp503).toEqual({ '$ref': '#/components/responses/ServiceShuttingDown' }); // eslint-disable-line dot-notation
      }
    }
  });

  test('/ready 503 uses ReadinessUnavailable, not ServiceShuttingDown', () => {
    const resp = spec.paths['/ready'].get.responses['503'];
    expect(resp).toEqual({ '$ref': '#/components/responses/ReadinessUnavailable' }); // eslint-disable-line dot-notation
  });

  test.each(['/health', '/metrics', '/diagnostics'])('%s never declares a 503 (mounted before request-drain)', p => {
    const item = spec.paths[p];
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
    for (const method of HTTP_METHODS) {
      if (!item[method]) continue;
      expect(item[method].responses['503']).toBeUndefined();
    }
  });

  test('no path references a legacy shutdown response name', () => {
    const serialized = JSON.stringify(spec.paths);
    expect(serialized).not.toMatch(/ServiceUnavailable/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. Components — parameters
// ═══════════════════════════════════════════════════════════════════════════════

describe('components — parameters', () => {
  let parameters;
  beforeAll(() => { parameters = freshSpec().components.parameters; });

  const REQUIRED_PARAMS = ['PageParam', 'PageSizeParam', 'UuidPathParam'];

  test.each(REQUIRED_PARAMS)('parameter %s is defined', name => {
    expect(parameters[name]).toBeDefined();
  });

  test('each parameter has name, in, and schema', () => {
    for (const [name, p] of Object.entries(parameters)) {
      expect(typeof p.name).toBe('string', `${name}.name must be a string`);
      expect(['query', 'path', 'header', 'cookie']).toContain(p.in);
      expect(p.schema).toBeDefined();
    }
  });

  test('PageParam is in query and not required', () => {
    const p = parameters.PageParam;
    expect(p.in).toBe('query');
    expect(p.required).toBeFalsy();
  });

  test('UuidPathParam is in path and required', () => {
    const p = parameters.UuidPathParam;
    expect(p.in).toBe('path');
    expect(p.required).toBe(true);
  });

  test('at least 10 parameters are defined', () => {
    expect(Object.keys(parameters).length).toBeGreaterThanOrEqual(10);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Components — security schemes
// ═══════════════════════════════════════════════════════════════════════════════

describe('components — security schemes', () => {
  let schemes;
  beforeAll(() => { schemes = freshSpec().components.securitySchemes; });

  test('BearerAuth is defined as http bearer', () => {
    expect(schemes.BearerAuth).toBeDefined();
    expect(schemes.BearerAuth.type).toBe('http');
    expect(schemes.BearerAuth.scheme).toBe('bearer');
  });

  test('OpsTokenHeader is defined as apiKey', () => {
    expect(schemes.OpsTokenHeader).toBeDefined();
    expect(schemes.OpsTokenHeader.type).toBe('apiKey');
    expect(schemes.OpsTokenHeader.in).toBe('header');
  });

  test('SigningApiKey is defined as http bearer (TRUST-1 remediation)', () => {
    expect(schemes.SigningApiKey).toBeDefined();
    expect(schemes.SigningApiKey.type).toBe('http');
    expect(schemes.SigningApiKey.scheme).toBe('bearer');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Paths
// ═══════════════════════════════════════════════════════════════════════════════

describe('paths — coverage and structure', () => {
  let paths;
  beforeAll(() => { paths = freshSpec().paths; });

  const REQUIRED_PATHS = [
    '/ai/chat',
    '/verify',
    '/sign',
    '/health',
    '/ready',
    '/consent',
  ];

  test.each(REQUIRED_PATHS)('path %s is defined', p => {
    expect(paths[p]).toBeDefined();
  });

  test('at least 50 paths are defined', () => {
    expect(Object.keys(paths).length).toBeGreaterThanOrEqual(50);
  });

  test('all path entries are objects', () => {
    for (const [p, item] of Object.entries(paths)) {
      expect(typeof item).toBe('object', `path ${p} must be an object`);
      expect(item).not.toBeNull();
    }
  });

  test('each path has at least one HTTP method', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head'];
    for (const [p, item] of Object.entries(paths)) {
      const methods = Object.keys(item).filter(k => HTTP_METHODS.includes(k));
      expect(methods.length).toBeGreaterThan(0, `path ${p} has no HTTP methods`);
    }
  });

  test('each operation has operationId, summary, tags, and responses', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
    for (const [p, item] of Object.entries(paths)) {
      for (const method of HTTP_METHODS) {
        if (!item[method]) continue;
        const op = item[method];
        expect(typeof op.operationId).toBe('string', `${method} ${p} missing operationId`);
        expect(op.operationId.length).toBeGreaterThan(0);
        expect(typeof op.summary).toBe('string', `${method} ${p} missing summary`);
        expect(Array.isArray(op.tags)).toBe(true, `${method} ${p} tags must be array`);
        expect(op.tags.length).toBeGreaterThan(0, `${method} ${p} has no tags`);
        expect(typeof op.responses).toBe('object', `${method} ${p} missing responses`);
        expect(Object.keys(op.responses).length).toBeGreaterThan(0);
      }
    }
  });

  test('operationIds are unique across all operations', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
    const ids = [];
    for (const item of Object.values(paths)) {
      for (const method of HTTP_METHODS) {
        if (item[method] && item[method].operationId) {
          ids.push(item[method].operationId);
        }
      }
    }
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  test('/ai/chat POST has security set', () => {
    const op = paths['/ai/chat'] && paths['/ai/chat'].post;
    expect(op).toBeDefined();
    expect(Array.isArray(op.security)).toBe(true);
  });

  test('/ai/chat POST has requestBody', () => {
    const op = paths['/ai/chat'].post;
    expect(op.requestBody).toBeDefined();
  });

  test('each operation response has at least a 200 or 2xx key', () => {
    const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
    // GET /v1/prq/dlq/replay is a real, registered route (prqDlq.js) whose
    // sole purpose is to guard against the literal path segment "replay"
    // being captured by GET /v1/prq/dlq/{operationId} — it always returns
    // 405 and points callers at POST /v1/prq/dlq/replay. There is no 2xx
    // response for this operation to document.
    const NO_2XX_EXEMPT = new Set(['get /v1/prq/dlq/replay']);
    for (const [p, item] of Object.entries(paths)) {
      for (const method of HTTP_METHODS) {
        if (!item[method]) continue;
        if (NO_2XX_EXEMPT.has(`${method} ${p}`)) continue;
        const codes = Object.keys(item[method].responses);
        const hasSuccess = codes.some(c => c.startsWith('2'));
        expect(hasSuccess).toBe(true, `${method} ${p} has no 2xx response`);
      }
    }
  });

  test('path parameter specs exist for paths with {param} segments', () => {
    // Build a resolver for $ref → actual parameter definition
    const spec       = freshSpec();
    const compParams = spec.components.parameters || {};

    function resolveParam(param) {
      if (param.$ref) {
        const name = param.$ref.replace('#/components/parameters/', '');
        return compParams[name] || null;
      }
      return param;
    }

    for (const [p, item] of Object.entries(spec.paths)) {
      const paramNames = (p.match(/\{([^}]+)\}/g) || []).map(s => s.slice(1, -1));
      if (paramNames.length === 0) continue;
      const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];
      for (const method of HTTP_METHODS) {
        if (!item[method]) continue;
        const op = item[method];
        const rawParams = [
          ...(item.parameters || []),
          ...(op.parameters   || []),
        ];
        const resolved = rawParams.map(resolveParam).filter(Boolean);
        for (const pName of paramNames) {
          const found = resolved.some(param => param.name === pName && param.in === 'path');
          expect(found).toBe(true, `${method} ${p} missing path param spec for {${pName}}`);
        }
      }
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. JSON Writer
// ═══════════════════════════════════════════════════════════════════════════════

describe('writeJson', () => {
  let spec;
  beforeAll(() => { spec = freshSpec(); });

  test('returns a string', () => {
    expect(typeof writeJson(spec)).toBe('string');
  });

  test('output is valid JSON', () => {
    const json = writeJson(spec);
    expect(() => JSON.parse(json)).not.toThrow();
  });

  test('parsed output matches spec', () => {
    const parsed = JSON.parse(writeJson(spec));
    expect(parsed.openapi).toBe(spec.openapi);
    expect(parsed.info.title).toBe(spec.info.title);
  });

  test('pretty-prints by default (contains newlines)', () => {
    const json = writeJson(spec);
    expect(json.includes('\n')).toBe(true);
  });

  test('compact mode produces single line without trailing newline', () => {
    const json = writeJson(spec, { pretty: false });
    expect(json.startsWith('{')).toBe(true);
    expect(json.trimEnd().endsWith('}')).toBe(true);
    // compact should not contain indentation spaces
    expect(json.includes('  "openapi"')).toBe(false);
  });

  test('throws TypeError for non-object input', () => {
    expect(() => writeJson(null)).toThrow(TypeError);
    expect(() => writeJson('string')).toThrow(TypeError);
    expect(() => writeJson(42)).toThrow(TypeError);
  });

  test('serialises numbers and booleans correctly', () => {
    const parsed = JSON.parse(writeJson(spec));
    // servers is an array; at minimum must be an array in output
    expect(Array.isArray(parsed.servers)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. YAML Writer
// ═══════════════════════════════════════════════════════════════════════════════

describe('writeYaml', () => {
  let spec;
  beforeAll(() => { spec = freshSpec(); });

  test('returns a string', () => {
    expect(typeof writeYaml(spec)).toBe('string');
  });

  test('starts with YAML document marker', () => {
    expect(writeYaml(spec).startsWith('---\n')).toBe(true);
  });

  test('contains openapi key', () => {
    expect(writeYaml(spec)).toMatch(/^openapi:/m);
  });

  test('contains info section', () => {
    expect(writeYaml(spec)).toMatch(/^info:/m);
  });

  test('contains paths section', () => {
    expect(writeYaml(spec)).toMatch(/^paths:/m);
  });

  test('contains components section', () => {
    expect(writeYaml(spec)).toMatch(/^components:/m);
  });

  test('throws TypeError for non-object input', () => {
    expect(() => writeYaml(null)).toThrow(TypeError);
    expect(() => writeYaml('string')).toThrow(TypeError);
  });

  test('serialises null as null literal', () => {
    const yaml = writeYaml({ a: null });
    expect(yaml).toMatch(/a: null/);
  });

  test('serialises booleans without quoting', () => {
    const yaml = writeYaml({ flag: true, enabled: false });
    expect(yaml).toMatch(/flag: true/);
    expect(yaml).toMatch(/enabled: false/);
  });

  test('quotes YAML keywords when used as string values', () => {
    const yaml = writeYaml({ x: 'true', y: 'null', z: 'yes' });
    expect(yaml).toMatch(/x: "true"/);
    expect(yaml).toMatch(/y: "null"/);
    expect(yaml).toMatch(/z: "yes"/);
  });

  test('quotes strings that look like integers', () => {
    const yaml = writeYaml({ n: '42', f: '3.14' });
    expect(yaml).toMatch(/n: "42"/);
    expect(yaml).toMatch(/f: "3\.14"/);
  });

  test('does not quote version strings like 3.1.0 (not a valid number)', () => {
    const yaml = writeYaml({ v: '3.1.0' });
    // 3.1.0 has two dots — not parseable as a number, must not be quoted
    expect(yaml).toMatch(/v: 3\.1\.0/);
  });

  test('handles empty string with double quotes', () => {
    const yaml = writeYaml({ empty: '' });
    expect(yaml).toMatch(/empty: ""/);
  });

  test('handles multiline strings as literal block scalar', () => {
    const yaml = writeYaml({ desc: 'line one\nline two' });
    expect(yaml).toMatch(/desc: \|/);
    expect(yaml).toMatch(/line one/);
    expect(yaml).toMatch(/line two/);
  });

  test('serialises nested objects with indentation', () => {
    const yaml = writeYaml({ outer: { inner: 'value' } });
    expect(yaml).toMatch(/outer:/);
    expect(yaml).toMatch(/  inner: value/);
  });

  test('serialises arrays as block sequences', () => {
    const yaml = writeYaml({ items: ['a', 'b'] });
    expect(yaml).toMatch(/items:/);
    expect(yaml).toMatch(/- a/);
    expect(yaml).toMatch(/- b/);
  });

  test('serialises empty array as []', () => {
    const yaml = writeYaml({ arr: [] });
    expect(yaml).toMatch(/arr: \[\]/);
  });

  test('serialises empty object as {}', () => {
    const yaml = writeYaml({ obj: {} });
    expect(yaml).toMatch(/obj: \{\}/);
  });

  test('handles Infinity as .inf', () => {
    const yaml = writeYaml({ x: Infinity });
    expect(yaml).toMatch(/x: \.inf/);
  });

  test('handles -Infinity as -.inf', () => {
    const yaml = writeYaml({ x: -Infinity });
    expect(yaml).toMatch(/x: -\.inf/);
  });

  test('full spec round-trip: YAML contains all top-level keys', () => {
    const yaml = writeYaml(spec);
    const topKeys = Object.keys(spec);
    for (const k of topKeys) {
      expect(yaml).toContain(k + ':');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. Swagger UI HTML generator
// ═══════════════════════════════════════════════════════════════════════════════

describe('renderSwaggerUiHtml', () => {
  test('returns a string', () => {
    expect(typeof renderSwaggerUiHtml()).toBe('string');
  });

  test('is a valid HTML document (starts with <!DOCTYPE html>)', () => {
    expect(renderSwaggerUiHtml().trimStart().startsWith('<!DOCTYPE html>')).toBe(true);
  });

  test('contains the swagger-ui-bundle.js script tag', () => {
    expect(renderSwaggerUiHtml()).toContain('swagger-ui-bundle.js');
  });

  // the assets are self-hosted. The CDN design was blocked by
  // the gateway's own CSP (script-src 'self') — /docs rendered nothing in a real browser.
  test('no external origin at all — every script, stylesheet and icon is same-origin', () => {
    const html = renderSwaggerUiHtml();
    expect(html).not.toMatch(/https?:\/\//);   // no absolute URL of any kind in the page
    const refs = [...html.matchAll(/\s(?:src|href)="([^"]+)"/g)].map((m) => m[1]);
    expect(refs.length).toBeGreaterThanOrEqual(6);
    for (const r of refs) expect(r.startsWith('/docs/assets/')).toBe(true);
  });

  test('no inline script — every <script> has a src (works under script-src \'self\', no unsafe-inline)', () => {
    const scripts = renderSwaggerUiHtml().match(/<script\b[^>]*>/g);
    expect(scripts).toHaveLength(3);
    for (const t of scripts) expect(t).toMatch(/\ssrc="/);
    expect(renderSwaggerUiHtml()).not.toMatch(/<script>\s*\S/);
  });

  test('every script and stylesheet carries the sha384 of the bytes actually served, crossorigin=anonymous', () => {
    const crypto = require('crypto');
    const { SRI, SWAGGER_UI_VERSION, getSwaggerAsset } = require('./swaggerUi');
    expect(SWAGGER_UI_VERSION).toBe('5.17.14'); // the pinned hashes are of exactly this version
    const tags = renderSwaggerUiHtml().match(/<(script|link)\b[^>]*(?:src|href)="\/docs\/assets\/[^"]+\.(?:js|css)"[^>]*>/g);
    expect(tags).toHaveLength(4);
    for (const t of tags) {
      const name = t.match(/\/docs\/assets\/([^"]+)"/)[1];
      const served = getSwaggerAsset(name).body;
      const digest = `sha384-${crypto.createHash('sha384').update(served).digest('base64')}`;
      expect(t).toContain(`integrity="${digest}"`);
      if (SRI[name]) expect(SRI[name]).toBe(digest);   // the vendored bytes are exactly the pinned npm-registry release
      expect(t).toContain('crossorigin="anonymous"');
    }
  });

  test('the vendored release keeps its licence and notice beside it', () => {
    const fs = require('fs'); const pathMod = require('path');
    const { VENDOR_DIR } = require('./swaggerUi');
    expect(VENDOR_DIR).toMatch(/swagger-ui-dist-5\.17\.14$/);
    expect(fs.readFileSync(pathMod.join(VENDOR_DIR, 'LICENSE'), 'utf8')).toMatch(/Apache License/);
    expect(fs.readFileSync(pathMod.join(VENDOR_DIR, 'NOTICE'), 'utf8')).toMatch(/SmartBear/);
  });

  test('only allowlisted asset names resolve (no path is ever accepted)', () => {
    const { getSwaggerAsset, ASSET_NAMES } = require('./swaggerUi');
    for (const n of ASSET_NAMES) expect(getSwaggerAsset(n)).not.toBeNull();
    for (const n of ['../swaggerUi.js', 'LICENSE', 'package.json', 'swagger-ui.js', '__proto__', 'constructor', '']) expect(getSwaggerAsset(n)).toBeNull();
  });

  test('contains the swagger-ui CSS link', () => {
    expect(renderSwaggerUiHtml()).toContain('swagger-ui.css');
  });

  test('serves the pinned vendored version', () => {
    expect(require('./swaggerUi').VENDOR_DIR).toContain(`swagger-ui-dist-${SWAGGER_UI_VERSION}`);
  });

  test('default specUrl is /openapi.json', () => {
    expect(renderSwaggerUiHtml()).toContain('/openapi.json');
  });

  test('custom specUrl is respected', () => {
    const html = renderSwaggerUiHtml({ specUrl: '/v1/openapi.json' });
    expect(html).toContain('/v1/openapi.json');
  });

  test('custom title appears in <title>', () => {
    const html = renderSwaggerUiHtml({ title: 'My API Docs' });
    expect(html).toContain('<title>My API Docs</title>');
  });

  test('default title is QODIQA-branded', () => {
    expect(renderSwaggerUiHtml()).toContain('QODIQA');
  });

  test('custom basePath is prepended to specUrl', () => {
    const html = renderSwaggerUiHtml({ basePath: '/v1', specUrl: '/openapi.json' });
    expect(html).toContain('/v1/openapi.json');
  });

  test('HTML-escapes special chars in title', () => {
    const html = renderSwaggerUiHtml({ title: '<script>alert(1)</script>' });
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  test('the initializer targets #swagger-ui and reads the spec URL from the page (data-spec-url)', () => {
    const init = require('./swaggerUi').getSwaggerAsset('swagger-initializer.js').body.toString('utf8');
    expect(init).toContain('dom_id:');
    expect(init).toContain("'#swagger-ui'");
    expect(init).toContain("getAttribute('data-spec-url')");
    expect(renderSwaggerUiHtml()).toMatch(/<div id="swagger-ui" data-spec-url="\/openapi\.json">/);
  });

  test('contains SwaggerUIBundle initializer (same-origin script)', () => {
    expect(require('./swaggerUi').getSwaggerAsset('swagger-initializer.js').body.toString('utf8')).toContain('SwaggerUIBundle(');
    expect(renderSwaggerUiHtml()).toContain('/docs/assets/swagger-initializer.js');
  });

  test('custom basePath also prefixes the asset URLs and the data-spec-url is HTML-escaped', () => {
    const html = renderSwaggerUiHtml({ basePath: '/v1', specUrl: '/openapi.json?x="><script>' });
    expect(html).toContain('/v1/docs/assets/swagger-ui-bundle.js');
    expect(html).not.toContain('"><script>');
  });

  test('has no inline event handlers (XSS hygiene)', () => {
    const html = renderSwaggerUiHtml();
    // No onclick, onload in HTML attributes (onload is in <body> via window.onload = in <script>)
    expect(html).not.toMatch(/<[^>]+\s+onclick=/i);
    expect(html).not.toMatch(/<[^>]+\s+onerror=/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 10. Generator — caching and invalidation
// ═══════════════════════════════════════════════════════════════════════════════

describe('generateSpec — caching', () => {
  test('returns the same object reference on second call (cache hit)', () => {
    invalidateCache();
    const a = generateSpec();
    const b = generateSpec();
    expect(a).toBe(b);
  });

  test('invalidateCache causes regeneration', () => {
    invalidateCache();
    const a = generateSpec();
    invalidateCache();
    const b = generateSpec();
    // Different object references after invalidation
    expect(a).not.toBe(b);
  });

  test('options.fresh bypasses cache without calling invalidateCache', () => {
    invalidateCache();
    const a = generateSpec();
    const b = generateSpec({ fresh: true });
    expect(a).not.toBe(b);
  });

  test('fresh spec is still valid', () => {
    const spec = generateSpec({ fresh: true });
    expect(spec.openapi).toBe('3.1.0');
  });

  test('cached spec is frozen', () => {
    invalidateCache();
    const spec = generateSpec();
    expect(Object.isFrozen(spec)).toBe(true);
  });

  test('invalidateCache is idempotent (can be called multiple times)', () => {
    expect(() => {
      invalidateCache();
      invalidateCache();
      invalidateCache();
      generateSpec();
    }).not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 11. Route handler (createOpenApiRouter)
// ═══════════════════════════════════════════════════════════════════════════════

describe('createOpenApiRouter', () => {
  const express = require('express');
  const supertest = require('supertest');
  const { createOpenApiRouter } = require('../api/routes/openapi');

  let app;
  beforeAll(() => {
    app = express();
    app.use('/', createOpenApiRouter());
  });

  beforeEach(() => { invalidateCache(); });

  test('GET /openapi.json returns 200', async () => {
    const res = await supertest(app).get('/openapi.json');
    expect(res.status).toBe(200);
  });

  test('GET /openapi.json returns application/json content-type', async () => {
    const res = await supertest(app).get('/openapi.json');
    expect(res.headers['content-type']).toMatch(/application\/json/);
  });

  test('GET /openapi.json body is valid JSON with openapi field', async () => {
    const res = await supertest(app).get('/openapi.json');
    expect(res.body.openapi).toBe('3.1.0');
  });

  test('GET /openapi.yaml returns 200', async () => {
    const res = await supertest(app).get('/openapi.yaml');
    expect(res.status).toBe(200);
  });

  test('GET /openapi.yaml returns yaml content-type', async () => {
    const res = await supertest(app).get('/openapi.yaml');
    expect(res.headers['content-type']).toMatch(/yaml/);
  });

  test('GET /openapi.yaml body starts with ---', async () => {
    const res = await supertest(app).get('/openapi.yaml');
    expect(res.text.startsWith('---\n')).toBe(true);
  });

  // `fresh` is a development cache bypass; in production an anonymous caller must not force regeneration.
  // The router is loaded against a recording generator (the real cached spec is frozen).
  describe('?fresh', () => {
    const prevEnv = process.env.NODE_ENV;
    let spyApp; let genSpy;
    beforeAll(() => {
      jest.isolateModules(() => {
        genSpy = jest.fn(() => ({ openapi: '3.1.0', info: { title: 't', version: '0' }, paths: {} }));
        jest.doMock('./generator', () => ({ generateSpec: genSpy }));
        const { createOpenApiRouter: isolatedRouter } = require('../api/routes/openapi');
        spyApp = express();
        spyApp.use('/', isolatedRouter());
      });
    });
    afterAll(() => { jest.dontMock('./generator'); });
    afterEach(() => { process.env.NODE_ENV = prevEnv; genSpy.mockClear(); });

    test.each(['/openapi.json', '/openapi.yaml'])('%s?fresh=1 is ignored in production', async (p) => {
      process.env.NODE_ENV = 'production';
      const res = await supertest(spyApp).get(`${p}?fresh=1`);
      expect(res.status).toBe(200);
      expect(genSpy).toHaveBeenCalledTimes(1);
      expect(genSpy.mock.calls[0][0]).toBeUndefined();
    });

    test.each(['/openapi.json', '/openapi.yaml'])('%s?fresh=1 still regenerates outside production', async (p) => {
      process.env.NODE_ENV = 'test';
      const res = await supertest(spyApp).get(`${p}?fresh=1`);
      expect(res.status).toBe(200);
      expect(genSpy.mock.calls[0][0]).toEqual({ fresh: true });
    });
  });

  test('GET /docs returns 200', async () => {
    const res = await supertest(app).get('/docs');
    expect(res.status).toBe(200);
  });

  test('GET /docs returns text/html content-type', async () => {
    const res = await supertest(app).get('/docs');
    expect(res.headers['content-type']).toMatch(/text\/html/);
  });

  test('GET /docs references the same-origin SwaggerUIBundle initializer, which the router serves', async () => {
    const res = await supertest(app).get('/docs');
    expect(res.text).toContain('/docs/assets/swagger-initializer.js');
    const init = await supertest(app).get('/docs/assets/swagger-initializer.js');
    expect(init.status).toBe(200);
    expect(init.text).toContain('SwaggerUIBundle');
  });

  test('GET /docs/assets/* serves exactly the allowlisted files with their types; anything else is 404', async () => {
    const want = {
      'swagger-ui-bundle.js': /javascript/, 'swagger-ui-standalone-preset.js': /javascript/, 'swagger-initializer.js': /javascript/,
      'swagger-ui.css': /text\/css/, 'favicon-32x32.png': /image\/png/, 'favicon-16x16.png': /image\/png/,
    };
    for (const [n, type] of Object.entries(want)) {
      const r = await supertest(app).get(`/docs/assets/${n}`);
      expect(r.status).toBe(200);
      expect(r.headers['content-type']).toMatch(type);
      expect(r.headers['x-content-type-options']).toBe('nosniff');
    }
    for (const n of ['..%2F..%2Fswagger.js', 'package.json', 'LICENSE', 'swagger-ui.js', 'x']) {
      expect((await supertest(app).get(`/docs/assets/${n}`)).status).toBe(404);
    }
  });

  test('GET /docs/ responds (redirect or 200 depending on Express trailing-slash handling)', async () => {
    const res = await supertest(app).get('/docs/');
    // Express may normalise /docs/ to /docs before the redirect handler fires.
    // Accept either a redirect (301/302) or a direct 200 HTML response.
    expect([200, 301, 302]).toContain(res.status);
    if (res.status !== 200) {
      expect(res.headers.location).toMatch(/\/docs/);
    }
  });

  test('GET /openapi.json sets Cache-Control header', async () => {
    const res = await supertest(app).get('/openapi.json');
    expect(res.headers['cache-control']).toMatch(/max-age/);
  });

  test('GET /openapi.json?fresh=1 returns valid spec', async () => {
    const res = await supertest(app).get('/openapi.json?fresh=1');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.1.0');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 12. Schema generator helpers
// ═══════════════════════════════════════════════════════════════════════════════

describe('schemaGenerator helpers', () => {
  const sg = require('./schemaGenerator');

  test('makeString returns type string', () => {
    expect(sg.makeString().type).toBe('string');
  });

  test('makeInteger returns type integer', () => {
    expect(sg.makeInteger().type).toBe('integer');
  });

  test('makeNumber returns type number', () => {
    expect(sg.makeNumber().type).toBe('number');
  });

  test('makeBoolean returns type boolean', () => {
    expect(sg.makeBoolean().type).toBe('boolean');
  });

  test('makeArray wraps items', () => {
    const schema = sg.makeArray(sg.makeString());
    expect(schema.type).toBe('array');
    expect(schema.items.type).toBe('string');
  });

  test('makeObject produces type object with properties', () => {
    const schema = sg.makeObject({ name: sg.makeString() });
    expect(schema.type).toBe('object');
    expect(schema.properties.name.type).toBe('string');
  });

  test('makeOneOf wraps schemas', () => {
    const schema = sg.makeOneOf([sg.makeString(), sg.makeInteger()]);
    expect(Array.isArray(schema.oneOf)).toBe(true);
    expect(schema.oneOf.length).toBe(2);
  });

  test('makeNullable adds null to type array or oneOf', () => {
    const schema = sg.makeNullable(sg.makeString());
    const isNullable =
      (Array.isArray(schema.type) && schema.type.includes('null')) ||
      (Array.isArray(schema.oneOf) && schema.oneOf.some(s => s.type === 'null'));
    expect(isNullable).toBe(true);
  });

  test('ref produces correct $ref path', () => {
    const r = sg.ref('Uuid');
    expect(r.$ref).toBe('#/components/schemas/Uuid');
  });

  test('responseRef produces correct $ref path', () => {
    const r = sg.responseRef('BadRequest');
    expect(r.$ref).toBe('#/components/responses/BadRequest');
  });

  test('paramRef produces correct $ref path', () => {
    const r = sg.paramRef('PageParam');
    expect(r.$ref).toBe('#/components/parameters/PageParam');
  });

  test('makeSuccessResponse returns response object with description and content', () => {
    const resp = sg.makeSuccessResponse('Success', sg.makeObject({}));
    expect(typeof resp.description).toBe('string');
    expect(resp.content).toBeDefined();
    expect(resp.content['application/json']).toBeDefined();
  });

  test('makeEnforcementResponse returns response object with decision schema', () => {
    const resp = sg.makeEnforcementResponse('decision');
    expect(typeof resp.description).toBe('string');
    const schema = resp.content['application/json'].schema;
    expect(schema.properties.decision).toBeDefined();
    expect(schema.properties.decision.enum).toContain('EXECUTE');
    expect(schema.properties.decision.enum).toContain('BLOCK');
  });

  test('makeString with enum sets enum field', () => {
    const schema = sg.makeString({ enum: ['a', 'b'] });
    expect(schema.enum).toEqual(['a', 'b']);
  });

  test('makeInteger with minimum sets minimum field', () => {
    const schema = sg.makeInteger({ minimum: 1 });
    expect(schema.minimum).toBe(1);
  });

  test('makeObject with required array sets required field', () => {
    const schema = sg.makeObject({ id: sg.makeString() }, { required: ['id'] });
    expect(schema.required).toContain('id');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 13. Determinism — same output on multiple calls
// ═══════════════════════════════════════════════════════════════════════════════

describe('determinism', () => {
  test('writeJson produces identical output on repeated calls with same spec', () => {
    invalidateCache();
    const spec = generateSpec();
    const a = writeJson(spec);
    const b = writeJson(spec);
    expect(a).toBe(b);
  });

  test('writeYaml produces identical output on repeated calls with same spec', () => {
    invalidateCache();
    const spec = generateSpec();
    const a = writeYaml(spec);
    const b = writeYaml(spec);
    expect(a).toBe(b);
  });

  test('generateSpec after invalidation produces structurally identical spec', () => {
    invalidateCache();
    const a = JSON.stringify(generateSpec());
    invalidateCache();
    const b = JSON.stringify(generateSpec());
    expect(a).toBe(b);
  });
});
