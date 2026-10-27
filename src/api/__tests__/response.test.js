'use strict';

/**
 * Canonical management/admin envelope — unit tests (API-1 remediation).
 *
 * src/api/response.js is the single source of truth for the JSON envelope
 * used by every management/admin/observability route (audit, RBAC,
 * compliance, dashboard, keys, policy management, webhooks, and similar —
 * see QODIQA-PROTOCOL-SPEC.md §14.7). This suite locks the exact shape down
 * so a future change to this one file can't silently drift every route that
 * depends on it.
 *
 * The core protocol surface (/ai/chat, /verify, /sign, /.well-known) uses
 * its own normative {decision, reason, details, requestId} shape and does
 * NOT use this module — that surface is covered separately by
 * errorCodeEndpointStatus.conformance.test.js and crossSurface.parity.test.js.
 */

const { success, failure, buildFailureBody } = require('../response');

function makeRes(locals = {}) {
  const res = {
    locals,
    _status: null,
    _body:   null,
    status(code) { this._status = code; return this; },
    json(body)   { this._body = body; return this; },
  };
  return res;
}

describe('response.js — success()', () => {
  it('returns the canonical success envelope with status 200 by default', () => {
    const res = makeRes({ requestId: 'req-1' });
    success(res, { foo: 'bar' });
    expect(res._status).toBe(200);
    expect(res._body).toEqual({
      status:    'success',
      timestamp: expect.any(String),
      requestId: 'req-1',
      data:      { foo: 'bar' },
    });
  });

  it('honors an explicit httpStatus', () => {
    const res = makeRes({ requestId: 'req-2' });
    success(res, { id: 1 }, 201);
    expect(res._status).toBe(201);
    expect(res._body.data).toEqual({ id: 1 });
  });

  it('falls back to requestId: null when res.locals has no requestId', () => {
    const res = makeRes({});
    success(res, {});
    expect(res._body.requestId).toBeNull();
  });

  it('falls back to requestId: null when res.locals itself is undefined', () => {
    const res = makeRes(undefined);
    success(res, {});
    expect(res._body.requestId).toBeNull();
  });

  it('emits an ISO-8601 timestamp', () => {
    const res = makeRes({});
    success(res, {});
    expect(() => new Date(res._body.timestamp).toISOString()).not.toThrow();
    expect(new Date(res._body.timestamp).toISOString()).toBe(res._body.timestamp);
  });
});

describe('response.js — failure()', () => {
  it('returns the canonical error envelope with status 400 by default', () => {
    const res = makeRes({ requestId: 'req-3' });
    failure(res, 'INVALID_INPUT', 'Something was wrong');
    expect(res._status).toBe(400);
    expect(res._body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: 'req-3',
      error:     { code: 'INVALID_INPUT', message: 'Something was wrong' },
    });
  });

  it('honors an explicit httpStatus', () => {
    const res = makeRes({});
    failure(res, 'NOT_FOUND', 'Resource not found', 404);
    expect(res._status).toBe(404);
    expect(res._body.error.code).toBe('NOT_FOUND');
  });

  it('includes details only when explicitly provided', () => {
    const withoutDetails = makeRes({});
    failure(withoutDetails, 'X', 'msg', 400);
    expect(withoutDetails._body.error).not.toHaveProperty('details');

    const withDetails = makeRes({});
    failure(withDetails, 'X', 'msg', 400, { field: 'artifactId' });
    expect(withDetails._body.error.details).toEqual({ field: 'artifactId' });
  });

  it('preserves a falsy-but-defined details value (e.g. an object with pass:false)', () => {
    const res = makeRes({});
    failure(res, 'CONSENT_DENIED', 'denied', 403, { pass: false, reason: 'REVOKED' });
    expect(res._body.error.details).toEqual({ pass: false, reason: 'REVOKED' });
  });

  it('falls back to requestId: null when res.locals has no requestId', () => {
    const res = makeRes({});
    failure(res, 'X', 'msg');
    expect(res._body.requestId).toBeNull();
  });

  it('falls back to requestId: null when res.locals itself is undefined (does not throw)', () => {
    const res = makeRes(undefined);
    expect(() => failure(res, 'X', 'msg')).not.toThrow();
    expect(res._body.requestId).toBeNull();
  });
});

describe('response.js — buildFailureBody()', () => {
  it('builds the identical error body shape used by failure(), without touching res', () => {
    const body = buildFailureBody('RATE_LIMITED', 'Too many requests', 'req-9');
    expect(body).toEqual({
      status:    'error',
      timestamp: expect.any(String),
      requestId: 'req-9',
      error:     { code: 'RATE_LIMITED', message: 'Too many requests' },
    });
  });

  it('defaults requestId to null when omitted', () => {
    const body = buildFailureBody('X', 'msg');
    expect(body.requestId).toBeNull();
  });

  it('includes details only when explicitly provided', () => {
    const body = buildFailureBody('X', 'msg', 'req-1', { retryAfterSec: '5' });
    expect(body.error.details).toEqual({ retryAfterSec: '5' });
  });

  it('is what every rate-limiter response: callback in the codebase uses to stay in sync with failure()', () => {
    // Simulates middleware/publicRateLimit.js's customResponse(retryAfterSecs, req)
    // pattern used by every admin-surface rate limiter (see server.js, audit.js,
    // auditViewer.js, keys.js, publicKeys.js, rbacAdmin.js, evidence.js,
    // evidenceChain.js, policyProvenance.js, policyManagement.js).
    const req = { requestId: 'race-1' };
    const { timestamp: _t1, ...body } = buildFailureBody('RATE_LIMITED', 'Too many requests', req.requestId ?? null);
    const { timestamp: _t2, ...reference } = buildFailureBody('RATE_LIMITED', 'Too many requests', 'race-1');
    // Each call stamps its own `new Date().toISOString()`, so the two calls
    // can legitimately land on different milliseconds under load — compare
    // structure, not wall-clock instant.
    expect(body).toEqual(reference);
  });
});
