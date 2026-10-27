'use strict';

/**
 * Unit tests for middleware/requestId.js
 *
 * RAND-3 remediation: this diagnostic/tracing ID previously used only 32 bits
 * of randomness (Date.now() + randomBytes(4)). It now uses crypto.randomUUID()
 * (122 bits), matching the entropy standard used elsewhere in the codebase
 * for security-sensitive identifiers (src/validation/requestId.js).
 */

const requestId = require('../requestId');

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function makeRes() {
  const headers = {};
  return {
    locals: {},
    set: (name, value) => { headers[name] = value; },
    _headers: headers,
  };
}

describe('middleware/requestId', () => {
  test('attaches a UUID v4 request ID to req, res.locals, and the X-Request-ID header', () => {
    const req = {};
    const res = makeRes();
    let called = false;

    requestId(req, res, () => { called = true; });

    expect(called).toBe(true);
    expect(req.requestId).toMatch(UUID_V4_RE);
    expect(res.locals.requestId).toBe(req.requestId);
    expect(res._headers['X-Request-ID']).toBe(req.requestId);
  });

  test('generates a distinct ID on every call (no counter/timestamp collision)', () => {
    const ids = new Set();
    for (let i = 0; i < 100; i++) {
      const req = {};
      requestId(req, makeRes(), () => {});
      ids.add(req.requestId);
    }
    expect(ids.size).toBe(100);
  });

  test('no longer uses the low-entropy Date.now()-hex4 format', () => {
    const req = {};
    requestId(req, makeRes(), () => {});
    expect(req.requestId).not.toMatch(/^\d{10,}-[0-9a-f]{8}$/);
  });
});
