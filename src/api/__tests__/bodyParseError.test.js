'use strict';

/**
 * Launch plan R-15 (A-1): the oversize-body predicate must match exactly the error express.json() raises for a body
 * over its limit, and nothing else (malformed JSON stays MALFORMED_JSON). The 413 HTTP behaviour of the real gateway is
 * asserted.
 */

const express = require('express');
const request = require('supertest');
const { isBodyTooLarge, assertUtf8Body } = require('../bodyParseError');

function probeApp() {
  const app = express();
  app.use((req, res, next) => express.json({ limit: '1kb' })(req, res, (err) => {
    if (err) return res.status(err.status || 500).json({ tooLarge: isBodyTooLarge(err), type: err.type });
    return next();
  }));
  app.post('/x', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('isBodyTooLarge (R-15)', () => {
  test('a body over the parser limit is recognised (body-parser type entity.too.large, status 413)', async () => {
    const res = await request(probeApp()).post('/x').set('content-type', 'application/json').send(JSON.stringify({ a: 'x'.repeat(4096) }));
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ tooLarge: true, type: 'entity.too.large' });
  });

  test('malformed JSON is NOT treated as too large', async () => {
    const res = await request(probeApp()).post('/x').set('content-type', 'application/json').send('{"a":');
    expect(res.status).toBe(400);
    expect(res.body.tooLarge).toBe(false);
  });

  test('a valid small body passes through', async () => {
    expect((await request(probeApp()).post('/x').send({ a: 1 })).body).toEqual({ ok: true });
  });

  test.each([null, undefined, 'entity.too.large', {}, { type: 'entity.parse.failed' }])('non-matching input %p → false', (v) => {
    expect(isBodyTooLarge(v)).toBe(false);
  });
});

describe('assertUtf8Body', () => {
  const http = require('http');
  // raw HTTP so the request bytes reach the parser untouched (supertest/superagent would re-encode a Buffer)
  function rawPost(app, bytes, contentType = 'application/json') {
    return new Promise((resolve, reject) => {
      const srv = app.listen(0, '127.0.0.1', () => {
        const req = http.request({ host: '127.0.0.1', port: srv.address().port, method: 'POST', path: '/x',
          headers: { 'content-type': contentType, 'content-length': bytes.length } }, (res) => {
          let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { srv.close(); resolve({ status: res.statusCode, body: JSON.parse(b) }); });
        });
        req.on('error', (e) => { srv.close(); reject(e); });
        req.end(bytes);
      });
    });
  }
  function utf8App() {
    const app = express();
    app.use((req, res, next) => express.json({ limit: '1kb', verify: assertUtf8Body })(req, res, (err) => (err ? res.status(400).json({ rejected: true }) : next())));
    app.post('/x', (req, res) => res.json({ body: req.body }));
    return app;
  }
  test('F2-UTF8-01 invalid UTF-8 inside a JSON string is rejected (it used to become U+FFFD)', async () => {
    const bad = Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}')]);
    expect(await rawPost(utf8App(), bad)).toEqual({ status: 400, body: { rejected: true } });
  });
  test('F2-UTF8-02 valid multi-byte UTF-8 still passes', async () => {
    const r = await rawPost(utf8App(), Buffer.from('{"a":"é中"}', 'utf8'));
    expect(r).toEqual({ status: 200, body: { body: { a: 'é中' } } });
  });
  test('F2-UTF8-03 a non-UTF-8 charset parameter is rejected (body-parser would decode utf-16le after the UTF-8 byte check)', async () => {
    const body = Buffer.from('{"a":"x"}', 'utf8');
    for (const ct of ['application/json; charset=utf-16le', 'application/json; charset=UTF-16', 'application/json;charset="utf-32"']) {
      expect({ ct, r: await rawPost(utf8App(), body, ct) }).toEqual({ ct, r: { status: 400, body: { rejected: true } } });
    }
  });
  test('F2-UTF8-04 an explicit UTF-8 charset (any case) and no charset still pass', async () => {
    const body = Buffer.from('{"a":"é"}', 'utf8');
    for (const ct of ['application/json; charset=utf-8', 'application/json; charset=UTF-8', 'application/json']) {
      expect((await rawPost(utf8App(), body, ct)).status).toBe(200);
    }
  });
});
