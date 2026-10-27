'use strict';

/**
 * API-09 / API-10 — the error catalogue is complete against what the protocol surface
 * actually returns, and the published OpenAPI document carries it. Fails the build when a reason is added to the
 * BLOCK inventory, or a new literal is returned by a protocol route, without a catalogue entry.
 *
 *   EC-01 every reason in src/api/blockHttpStatus.js CLASSES has an ERROR_CATALOG entry
 *   EC-02 every reason literal returned by the protocol routes / their validators / admission is catalogued
 *         (source scan; metric labels and log-only details are excluded by shape, not by name)
 *   EC-03 the committed docs/api/openapi.json carries x-qodiqa-error-catalog equal to ERROR_CATALOG (+ status-mode
 *         class status for every BLOCK-inventory reason)
 *   EC-04 negative control: the scan really finds literals (a planted uncatalogued literal is reported)
 * EC-04b/c, EC-05: the scan also covers src/app.js and
 *         middleware/enforceContentType.js and the `case 'X':`, `.code = 'X'` and `|| 'X'` shapes, with planted
 *         negative controls for each; literals that never reach a response are an explicit, exact allow-list.
 * EC-06: the protocol rate limiter (src/core/rateLimit/middleware.js) answers /sign and the
 *         auth/admin surfaces with a flat 429 body whose machine code is a `code: 'X'` verdict field — that file and
 *         that shape were not scanned, so RATE_LIMIT_BACKEND_UNAVAILABLE was emitted but uncatalogued.
 */

const fs = require('fs');
const path = require('path');
const { ERROR_CATALOG } = require('../catalog');
const { CLASSES } = require('../../api/blockHttpStatus');

const ROOT = path.join(__dirname, '..', '..', '..');
const SCANNED = [
  'src/api/routes/aiChat.js', 'src/api/routes/sign.js', 'src/api/routes/verify.js', 'src/api/admission.js',
  'src/validation/schemas/aiChat.schema.js', 'src/validation/schemas/sign.schema.js', 'src/middleware/signAuth.js',
  'src/streaming/streamEnforcer.js',
  // the app-level body-parser / 404 BLOCK bodies and the content-type guard mounted on /ai/chat.
  'src/app.js', 'middleware/enforceContentType.js',
  // the protocol rate limiter's 429 bodies (flat `{ error: code, … }`, decision and management envelopes).
  'src/core/rateLimit/middleware.js',
];
const PATTERNS = [
  /qodiqaReason:\s*'([A-Z][A-Z0-9_]+)'/g,
  /\breason:\s*'([A-Z][A-Z0-9_]+)'/g,
  /_block\(\s*\d{3},\s*'([A-Z][A-Z0-9_]+)'/g,
  /_deny\(\s*res,\s*req,\s*\d{3},\s*'([A-Z][A-Z0-9_]+)'/g,
  // reasons that reach a response through a status-map switch arm, an error code, or a fallback.
  /\bcase\s+'([A-Z][A-Z0-9_]+)':/g,
  /\.code\s*=\s*'([A-Z][A-Z0-9_]+)'/g,
  /\|\|\s*'([A-Z][A-Z0-9_]+)'/g,
  // a limiter verdict / envelope `code: 'X'` field (src/core/rateLimit/middleware.js _decide / _deny429).
  /\bcode:\s*'([A-Z][A-Z0-9_]+)'/g,
];
// A line that only labels a metric or a log record is not a response reason. (`blocked(` = services/logger's BLOCK log
// record — src/app.js labels an unhandled error UNHANDLED_ERROR there; the response is INTERNAL_ERROR.)
const NOT_A_RESPONSE = /\.inc\(|\bemit\(|\bblocked\(|permissions:/;
// Literals the widened shapes find that never reach a response body, each with the reason it is not catalogued. Kept
// explicit and exact (EC-02 also fails if an entry here stops being found, so this list cannot rot into a blanket skip).
const NOT_RESPONSE_LITERALS = {
  // src/api/routes/aiChat.js _makeFailoverAuthorizer: a failover-authorization refusal is audited, and the client gets
  // the PRIMARY provider failure (see the comment above that function), never this code.
  'src/api/routes/aiChat.js:IDENTITY_UNAVAILABLE': 'failover-authorizer audit detail; the response carries the primary failure',
};

function scan(source) {
  const found = new Set();
  for (const line of source.split(/\r?\n/)) {
    if (NOT_A_RESPONSE.test(line)) continue;
    for (const re of PATTERNS) for (const m of line.matchAll(re)) found.add(m[1]);
  }
  return found;
}

describe('error catalogue completeness (API-09 / API-10)', () => {
  test('EC-01 every BLOCK-inventory reason is catalogued', () => {
    const missing = [];
    for (const [cls, { reasons }] of Object.entries(CLASSES)) for (const r of reasons) if (!ERROR_CATALOG[r]) missing.push(`${cls}:${r}`);
    expect(missing).toEqual([]);
  });

  test('EC-02 every reason literal returned by the protocol routes is catalogued', () => {
    const missing = [];
    const allowedSeen = new Set();
    for (const f of SCANNED) {
      for (const code of scan(fs.readFileSync(path.join(ROOT, f), 'utf8'))) {
        const key = `${f}:${code}`;
        if (NOT_RESPONSE_LITERALS[key]) { allowedSeen.add(key); continue; }
        if (!ERROR_CATALOG[code]) missing.push(key);
      }
    }
    expect(missing).toEqual([]);
    // every allow-list entry is still real (a stale exemption is removed, not kept)
    expect([...allowedSeen].sort()).toEqual(Object.keys(NOT_RESPONSE_LITERALS).sort());
  });

  test('EC-03 the committed OpenAPI document carries the full catalogue', () => {
    const spec = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs', 'api', 'openapi.json'), 'utf8'));
    const published = spec['x-qodiqa-error-catalog'];
    expect(published).toBeDefined();
    expect(Object.keys(published).sort()).toEqual(Object.keys(ERROR_CATALOG).sort());
    for (const [cls, { status, reasons }] of Object.entries(CLASSES)) {
      for (const r of reasons) expect(published[r]).toMatchObject({ blockClass: cls, statusModeHttpStatus: status });
    }
    for (const [code, e] of Object.entries(ERROR_CATALOG)) {
      expect(published[code]).toMatchObject({ httpStatus: e.httpStatus, category: e.category, retryable: e.retryable });
    }
  });

  test('EC-04 negative control: the scan reports a planted literal', () => {
    expect([...scan("return _block(400, 'PLANTED_UNCATALOGUED', {});")]).toEqual(['PLANTED_UNCATALOGUED']);
    expect([...scan("metric.inc({ reason: 'METRIC_ONLY' });")]).toEqual([]);
  });

  // each widened shape catches a planted literal (the 7 previously-missed codes were all of these
  // shapes or in the two files that were not scanned), and log-only shapes stay excluded.
  test('EC-04b negative control: the widened shapes report planted literals', () => {
    expect([...scan("    case 'PLANTED_CASE':      return 504;")]).toEqual(['PLANTED_CASE']);
    expect([...scan("    failure.code  = 'PLANTED_CODE';")]).toEqual(['PLANTED_CODE']);
    expect([...scan("      terminationReason = err?.code || 'PLANTED_FALLBACK';")]).toEqual(['PLANTED_FALLBACK']);
    expect([...scan("    return res.status(415).json({ decision: 'BLOCK', reason: 'PLANTED_REASON' });")]).toEqual(['PLANTED_REASON']);
    expect([...scan("    blocked(req.requestId, null, err?.message || 'PLANTED_LOG_ONLY', null);")]).toEqual([]);
    // lower-case / mixed literals are not reason codes
    expect([...scan("    case 'post':  x.code = 'abc'; y || 'Default';")]).toEqual([]);
  });

  test('EC-04c negative control: an uncatalogued planted literal in a scanned-shape file fails the EC-02 check', () => {
    const planted = ["switch (c) {", "  case 'PLANTED_UNCATALOGUED_CASE': return 504;", "}", "e.code = 'PLANTED_UNCATALOGUED_CODE';", "const r = x || 'PLANTED_UNCATALOGUED_OR';"].join('\n');
    const missing = [...scan(planted)].filter((c) => !ERROR_CATALOG[c]).sort();
    expect(missing).toEqual(['PLANTED_UNCATALOGUED_CASE', 'PLANTED_UNCATALOGUED_CODE', 'PLANTED_UNCATALOGUED_OR']);
  });

  test('EC-05 the two newly scanned files are part of the scan set and contribute their codes', () => {
    expect(SCANNED).toEqual(expect.arrayContaining(['src/app.js', 'middleware/enforceContentType.js']));
    const app = scan(fs.readFileSync(path.join(ROOT, 'src/app.js'), 'utf8'));
    expect(app.has('MALFORMED_JSON') && app.has('NOT_FOUND')).toBe(true);
    expect(scan(fs.readFileSync(path.join(ROOT, 'middleware/enforceContentType.js'), 'utf8')).has('UNSUPPORTED_MEDIA_TYPE')).toBe(true);
  });

  test('EC-06 the protocol rate limiter is scanned, its verdict codes are found, and a planted code: literal is reported', () => {
    expect(SCANNED).toContain('src/core/rateLimit/middleware.js');
    const rl = scan(fs.readFileSync(path.join(ROOT, 'src/core/rateLimit/middleware.js'), 'utf8'));
    for (const c of ['RATE_LIMIT_EXCEEDED', 'RATE_LIMIT_BACKEND_UNAVAILABLE', 'RATE_LIMITED']) {
      expect([c, rl.has(c)]).toEqual([c, true]);
      expect([c, Boolean(ERROR_CATALOG[c])]).toEqual([c, true]);
    }
    expect(ERROR_CATALOG.RATE_LIMIT_BACKEND_UNAVAILABLE).toMatchObject({ httpStatus: 429, retryable: true });
    const planted = scan("    return { outcome: 'deny', code: 'PLANTED_LIMITER_CODE', message: 'x' };");
    expect(planted.has('PLANTED_LIMITER_CODE')).toBe(true);
    expect(ERROR_CATALOG.PLANTED_LIMITER_CODE).toBeUndefined();
  });
});
