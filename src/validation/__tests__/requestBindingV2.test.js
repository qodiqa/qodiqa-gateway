'use strict';

/** V2 request binding (docs/protocol/PROTOCOL-V2.md section 3). */

const crypto = require('crypto');
const { computeRequestHashV2, verifyRequestBindingV2, buildDocument, BindingError, validateBindHeaders } = require('../requestBindingV2');
const { canonicalJcsP1 } = require('../jcsP1');

const req = (over = {}) => ({ method: 'POST', target: '/ai/chat', rawHeaders: [], body: Buffer.from('{"prompt":"hi"}'), ...over });
const hash = (r, bind = []) => computeRequestHashV2(r, bind);
const refusal = (r, bind = [], opts) => { try { computeRequestHashV2(r, bind, opts); return null; } catch (e) { if (e instanceof BindingError) return e.code; throw e; } };

test('F4-RB-01 the hash is SHA-256 over the V2 domain tag and the JCS-P1 document', () => {
  const doc = buildDocument(req(), []);
  expect(doc).toEqual({ v: 2, method: 'POST', path: '/ai/chat', query: [], headers: {}, body: { prompt: 'hi' } });
  const expected = crypto.createHash('sha256').update('QODIQA::REQUEST::V2' + canonicalJcsP1(doc)).digest('hex');
  expect(hash(req())).toBe(expected);
  expect(hash(req())).not.toBe(require('../requestHash').computeRequestHash('POST', '/ai/chat', { prompt: 'hi' }));   // never equal to the V1 hash
});

describe('method', () => {
  test('F4-RB-02 case-insensitive, normalized; unknown methods refused', () => {
    expect(hash(req({ method: 'post' }))).toBe(hash(req({ method: 'POST' })));
    expect(refusal(req({ method: 'TRACE' }))).toBe('REQUEST_MISMATCH');
    expect(refusal(req({ method: 'POST ' }))).toBe('REQUEST_MISMATCH');
    expect(refusal(req({ method: 'pſst' }))).toBe('REQUEST_MISMATCH');   // long s: not ASCII
  });
});

describe('path', () => {
  test('F4-RB-03 raw spelling is bound: dot segments, trailing and doubled slashes, percent-encoding differ', () => {
    const hs = ['/a/b', '/a/./b', '/a//b', '/a/b/', '/a/%62', '/A/b'].map((t) => hash(req({ target: t })));
    expect(new Set(hs).size).toBe(hs.length);
  });
  test.each(['ai/chat', '*', 'http://x/ai/chat', '/a b', '/a#f', '/a\tb', '/a\u0000b', '/a\u007fb', '/é', '/aéb'])('F4-RB-04 target %j refused', (t) => {
    expect(refusal(req({ target: t }))).toBe('REQUEST_MISMATCH');
  });
});

describe('query', () => {
  const q = (s) => buildDocument(req({ target: '/p' + s }), []).query;
  test('F4-RB-05 no query, empty query and empty segments', () => {
    expect(q('')).toEqual([]); expect(q('?')).toEqual([]); expect(q('?&&')).toEqual([]);
    expect(q('?a=1&&b=2')).toEqual([['a', '1'], ['b', '2']]);
    expect(q('?a=1&')).toEqual([['a', '1']]);
    expect(hash(req({ target: '/p?a=1&&b=2' }))).toBe(hash(req({ target: '/p?a=1&b=2' })));
  });
  test('F4-RB-06 value defaults, first = splits, percent-decoding as UTF-8, sort by name only keeping the order of equal names', () => {
    expect(q('?flag')).toEqual([['flag', '']]);
    expect(q('?a=b=c')).toEqual([['a', 'b=c']]);
    expect(q('?n=%C3%A9&%C3%A9=1')).toEqual([['n', 'é'], ['é', '1']].sort((x, y) => (x[0] < y[0] ? -1 : 1)));
    expect(q('?b=2&a=2&a=1')).toEqual([['a', '2'], ['a', '1'], ['b', '2']]);
    expect(hash(req({ target: '/p?a=1&a=2' }))).not.toBe(hash(req({ target: '/p?a=2&a=1' })));      // order of repeated names is bound
    expect(hash(req({ target: '/p?b=1&a=1' }))).toBe(hash(req({ target: '/p?a=1&b=1' })));           // distinct names: order is not
    expect(hash(req({ target: '/p?a=%41' }))).toBe(hash(req({ target: '/p?a=A' })));                 // decoded
    expect(hash(req({ target: '/p?a=%4a' }))).toBe(hash(req({ target: '/p?a=%4A' })));               // hex case irrelevant
  });
  test.each(['?a=%zz', '?a=%', '?a=%4', '?a=%FF', '?a=%C3', '?%E2%82=1', '?a=e%CC%81'])('F4-RB-07 %s refused (bad escape / invalid UTF-8 / not NFC)', (s) => {
    expect(refusal(req({ target: '/p' + s }))).toBe('REQUEST_MISMATCH');
  });
  test('F4-RB-08 raw "+" and ";" are refused; at issuance the code is QUERY_NOT_BINDABLE with a message', () => {
    for (const s of ['?a=b+c', '?a=1;b=2', '?a=%2B']) {
      if (s === '?a=%2B') { expect(refusal(req({ target: '/p' + s }))).toBeNull(); continue; }
      expect(refusal(req({ target: '/p' + s }))).toBe('REQUEST_MISMATCH');
      expect(refusal(req({ target: '/p' + s }), [], { issuance: true })).toBe('QUERY_NOT_BINDABLE');
    }
    try { hash(req({ target: '/p?a=b+c' }), []); } catch (e) { expect(e.reason).toMatch(/refused|contains|raw/); }
    try { computeRequestHashV2(req({ target: '/p?a=b+c' }), [], { issuance: true }); } catch (e) { expect(e.reason).toMatch(/use %2B or %20/); }
  });
});

describe('headers', () => {
  test('F4-RB-09 bound headers: trimmed, joined in order, absent = null, unbound ignored', () => {
    const raw = ['Accept', ' a ', 'X-Other', 'z', 'accept', '\tb\t', 'Content-Type', 'application/json'];
    expect(buildDocument(req({ rawHeaders: raw }), ['accept', 'x-missing']).headers).toEqual({ accept: 'a, b', 'x-missing': null });
    expect(hash(req({ rawHeaders: raw }), ['content-type'])).toBe(hash(req({ rawHeaders: ['content-type', 'application/json'] }), ['content-type']));
    expect(hash(req({ rawHeaders: ['content-type', 'text/plain'] }), ['content-type'])).not.toBe(hash(req({ rawHeaders: ['content-type', 'application/json'] }), ['content-type']));
    expect(hash(req({ rawHeaders: ['x-extra', '1'] }), [])).toBe(hash(req(), []));                     // unbound headers do not matter
  });
  test('F4-RB-10 header values are re-read as UTF-8 and must be NFC; NBSP/FF are not whitespace', () => {
    const utf8Latin1 = Buffer.from('é', 'utf8').toString('latin1');
    expect(buildDocument(req({ rawHeaders: ['x-n', utf8Latin1] }), ['x-n']).headers).toEqual({ 'x-n': 'é' });
    expect(refusal(req({ rawHeaders: ['x-n', 'ÿ'] }), ['x-n'])).toBe('REQUEST_MISMATCH');            // lone 0xFF is invalid UTF-8
    expect(refusal(req({ rawHeaders: ['x-n', Buffer.from('é', 'utf8').toString('latin1')] }), ['x-n'])).toBe('REQUEST_MISMATCH');
    const nb = Buffer.from(' v ', 'utf8').toString('latin1');
    expect(buildDocument(req({ rawHeaders: ['x-n', nb] }), ['x-n']).headers['x-n']).toBe(' v ');
  });
  test('F4-RB-11 bind.headers rules', () => {
    expect(() => validateBindHeaders(['accept', 'accept'])).toThrow(BindingError);
    expect(() => validateBindHeaders(['Accept'])).toThrow(BindingError);
    expect(() => validateBindHeaders(['authorization'])).toThrow(BindingError);
    expect(() => validateBindHeaders(['x-qodiqa-artifact'])).toThrow(BindingError);
    expect(() => validateBindHeaders(Array.from({ length: 17 }, (_, i) => `h${i}`))).toThrow(BindingError);
    expect(() => validateBindHeaders(['a'.repeat(65)])).toThrow(BindingError);
    expect(validateBindHeaders(['accept', 'x-request-id'])).toEqual(['accept', 'x-request-id']);
  });
});

describe('body', () => {
  test('F4-RB-12 absent/zero bytes is {}; whitespace-only, non-object, BOM, duplicate keys, unsafe numbers are refused', () => {
    expect(buildDocument(req({ body: Buffer.alloc(0) }), []).body).toEqual({});
    for (const b of [' ', '\n', '[]', '"x"', '1', 'null', '﻿{}', '{"a":1,"a":2}', '{"n":9007199254740993}']) {
      expect({ b, r: refusal(req({ body: Buffer.from(b, 'utf8') })) }).toEqual({ b, r: 'REQUEST_MISMATCH' });
    }
    expect(refusal(req({ body: Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]) }))).toBe('REQUEST_MISMATCH');
  });
  test('F4-RB-13 body key order and number spelling do not change the hash (the value is bound)', () => {
    expect(hash(req({ body: Buffer.from('{"b":1,"a":2.0}') }))).toBe(hash(req({ body: Buffer.from('{"a":2,"b":1e0}') })));
  });
});

describe('verification', () => {
  test('F4-RB-14 verify accepts the matching request and rejects every single-component change', () => {
    const good = req({ target: '/p?a=1', rawHeaders: ['accept', 'x'] });
    const h = hash(good, ['accept']);
    expect(verifyRequestBindingV2(good, ['accept'], h)).toBe(true);
    for (const bad of [
      req({ target: '/p?a=2', rawHeaders: ['accept', 'x'] }), req({ target: '/q?a=1', rawHeaders: ['accept', 'x'] }),
      req({ target: '/p?a=1', rawHeaders: ['accept', 'y'] }), req({ target: '/p?a=1', rawHeaders: ['accept', 'x'], method: 'PUT' }),
      req({ target: '/p?a=1', rawHeaders: ['accept', 'x'], body: Buffer.from('{"prompt":"other"}') }),
    ]) expect(verifyRequestBindingV2(bad, ['accept'], h)).toBe(false);
    expect(verifyRequestBindingV2(good, ['accept'], 'A'.repeat(64))).toBe(false);
    expect(verifyRequestBindingV2(good, ['accept'], undefined)).toBe(false);
    expect(verifyRequestBindingV2(good, ['x-other'], h)).toBe(false);          // different bound list = different document
  });
});
