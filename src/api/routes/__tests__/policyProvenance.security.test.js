'use strict';

/**
 * Task #27 defense-in-depth regression: createPolicyProvenanceRouter() must
 * fail closed when requirePermission is not supplied, not silently grant
 * broader "isInvestigator" content visibility as it did before this fix.
 */

const createPolicyProvenanceRouter = require('../policyProvenance');

describe('createPolicyProvenanceRouter — requirePermission is mandatory (fail-closed)', () => {
  test('throws when called with no arguments at all', () => {
    expect(() => createPolicyProvenanceRouter()).toThrow();
  });

  test('throws when requirePermission is omitted from the options object', () => {
    expect(() => createPolicyProvenanceRouter({})).toThrow();
  });

  test('throws when requirePermission is explicitly undefined', () => {
    expect(() => createPolicyProvenanceRouter({ requirePermission: undefined })).toThrow();
  });

  test('constructs successfully when requirePermission is provided, and uses it for both gates', () => {
    const seen = [];
    const requirePermission = jest.fn(permission => {
      seen.push(permission);
      return (_req, _res, next) => next();
    });

    expect(() => createPolicyProvenanceRouter({ requirePermission })).not.toThrow();
    expect(seen).toEqual(expect.arrayContaining(['READ_POLICY_PROVENANCE', 'INVESTIGATE_POLICIES']));
  });
});

describe('createPolicyProvenanceRouter — 405 catch-all', () => {
  const express = require('express');
  const request = require('supertest');

  function makeApp() {
    const requirePermission = () => (_req, _res, next) => next();
    const router = createPolicyProvenanceRouter({ requirePermission });
    const app = express();
    app.use('/provenance', router);
    return app;
  }

  test('an unsupported method on a defined path is rejected with canonical 405, not a generic 404', async () => {
    const resp = await request(makeApp()).delete('/provenance/policies/search/history');
    expect(resp.status).toBe(405);
    expect(resp.body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: null,
      error: {
        code:    'METHOD_NOT_ALLOWED',
        message: 'Method not allowed',
      },
    });
  });
});

// ── INJ-8: Content-Disposition header injection via policyId ─────────────────
//
// GET /policies/:policyId/report?format=csv builds its Content-Disposition
// header from `policyId` directly with no validation. Before the fix, a
// crafted policyId containing CR/LF would either be silently written into
// the response as literal header-injection bytes, or (on modern Node, which
// validates header values) crash the request with an uncaught
// ERR_INVALID_CHAR — an unvalidated route parameter turning into a 500.
// Either outcome is closed by safeAttachmentHeader().

describe('GET /provenance/policies/:policyId/report?format=csv — INJ-8', () => {
  const express = require('express');
  const request = require('supertest');

  function makeApp() {
    jest.doMock('../../../core/policy/provenanceStore', () => ({
      generateReportData: jest.fn().mockResolvedValue({ versions: [] }),
    }));
    jest.resetModules();
    const freshRouterFactory = require('../policyProvenance');
    const requirePermission = () => (_req, _res, next) => next();
    const router = freshRouterFactory({ requirePermission });
    const app = express();
    app.use('/provenance', router);
    return app;
  }

  afterEach(() => {
    jest.dontMock('../../../core/policy/provenanceStore');
    jest.resetModules();
  });

  test('a policyId containing CRLF does not inject an extra header line, and does not 500', async () => {
    const crafted = encodeURIComponent('abc\r\nX-Injected: evil');
    const resp = await request(makeApp()).get(`/provenance/policies/${crafted}/report?format=csv`);
    expect(resp.status).toBe(200);
    expect(resp.headers['x-injected']).toBeUndefined();
    expect(resp.headers['content-disposition']).not.toMatch(/\r|\n/);
  });

  test('a policyId containing a double quote cannot prematurely terminate the filename parameter', async () => {
    const crafted = encodeURIComponent('abc"; evil="x');
    const resp = await request(makeApp()).get(`/provenance/policies/${crafted}/report?format=csv`);
    expect(resp.status).toBe(200);
    // The whole crafted value must appear as one escaped filename component,
    // not as a real second "evil" parameter on the header.
    expect(resp.headers['content-disposition']).toBe('attachment; filename="provenance-abc\\"; evil=\\"x.csv"');
  });

  test('an ordinary policyId still produces the expected filename', async () => {
    const resp = await request(makeApp()).get('/provenance/policies/pol-123/report?format=csv');
    expect(resp.status).toBe(200);
    expect(resp.headers['content-disposition']).toBe('attachment; filename="provenance-pol-123.csv"');
  });
});
