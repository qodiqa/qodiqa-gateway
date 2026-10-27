'use strict';

/**
 * 2026-10-06 — app-wide qodiqa_http_responses_total{route_family,status_class}.
 *
 *   HR-01  route family is the first path segment only for mounted prefixes, else "other" (bounded cardinality)
 *   HR-02  every first path segment src/app.js mounts with app.use('/<segment>…') is a known family (stays in sync)
 *   HR-03  the middleware counts each finished response once, by status class
 */

const fs = require('fs');
const path = require('path');
const { EventEmitter } = require('events');
const metrics = require('../metrics');
const { createHttpResponseMetrics, routeFamily, ROUTE_FAMILIES } = require('../metricsMiddleware');

test('HR-01 bounded route families', () => {
  expect(routeFamily('/ai/chat/stream?x=1')).toBe('ai');
  expect(routeFamily('/sign')).toBe('sign');
  expect(routeFamily('/.well-known/jwks.json')).toBe('.well-known');
  expect(routeFamily('/v1/attestation/abc')).toBe('v1');
  expect(routeFamily('/does-not-exist/123')).toBe('other');
  expect(routeFamily('/' + 'x'.repeat(5000))).toBe('other');
  expect(routeFamily('')).toBe('other');
});

test('HR-02 every mounted first segment in src/app.js is a known family', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'app.js'), 'utf8');
  const mounted = [...new Set([...src.matchAll(/app\.use\('\/([^/'?]+)/g)].map((m) => m[1]))].filter((s) => s !== '__bench');
  expect(mounted.length).toBeGreaterThan(20);
  expect(mounted.filter((s) => !ROUTE_FAMILIES.has(s))).toEqual([]);
});

test('HR-03 counts each finished response once by status class', () => {
  const inc = jest.spyOn(metrics.httpResponsesTotal, 'inc');
  const mw = createHttpResponseMetrics();
  const run = (url, code) => { const req = { originalUrl: url }; const res = new EventEmitter(); res.statusCode = code; const next = jest.fn(); mw(req, res, next); expect(next).toHaveBeenCalledTimes(1); res.statusCode = code; res.emit('finish'); res.emit('finish'); };
  run('/ai/chat', 503); run('/sign', 200); run('/nope', 404);
  expect(inc.mock.calls.map((c) => c[0])).toEqual([
    { route_family: 'ai', status_class: '5xx' }, { route_family: 'sign', status_class: '2xx' }, { route_family: 'other', status_class: '4xx' }]);
  inc.mockRestore();
});
