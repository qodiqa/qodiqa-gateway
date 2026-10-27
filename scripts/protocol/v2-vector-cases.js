'use strict';

/**
 * Inputs of the protocol-V2 vector families (docs/protocol/PROTOCOL-V2.md sections 2 and 3). INPUTS ONLY: the expected values are produced
 * by gen-v2-vectors.js from the production implementation and re-derived by the two independent verifiers.
 *
 * Every input is BYTES, so no host-language string handling can influence it. A bytes value is either
 *   - a lower-case hex string, or
 *   - { "repeat": { "prefix": "<utf8>", "unit": "<utf8>", "count": N, "suffix": "<utf8>" } }  = prefix + unit x N + suffix (keeps the 64 KiB / 1 MiB / depth
 *     cases a few bytes long instead of megabytes).
 * Cases are append-only: a case never changes position or content once published (VECTORS-FORMAT.md section 1).
 */

const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
const raw = (arr) => Buffer.from(arr).toString('hex');
const rep = (prefix, unit, count, suffix = '') => ({ repeat: { prefix, unit, count, suffix } });

// ── V2-CANON: parse the bytes under JCS-P1 and return the canonical bytes, or the first rejection class ─────────────────────────────────────
const canon = [];
const C = (desc, bytes) => canon.push({ desc, bytes: typeof bytes === 'string' ? hex(bytes) : Array.isArray(bytes) ? raw(bytes) : bytes });

// numbers: every number is an IEEE-754 double; |value| > 2^53-1 is rejected however it is spelled
for (const [d, t] of [
  ['1.0 is 1', '{"n":1.0}'], ['1e2 is 100', '{"n":1e2}'], ['-0 is 0', '{"n":-0}'], ['-0.0 is 0', '{"n":-0.0}'], ['0e0 is 0', '{"n":0e0}'], ['1E+0 is 1', '{"n":1E+0}'],
  ['1e999 is not finite', '{"n":1e999}'], ['-1e999 is not finite', '{"n":-1e999}'],
  ['9007199254740993 integer literal is out of range', '{"n":9007199254740993}'], ['9007199254740994 is out of range', '{"n":9007199254740994}'],
  ['9007199254740991 (2^53-1) is accepted', '[9007199254740991]'], ['9007199254740992 (2^53) is out of range', '[9007199254740992]'],
  ['9007199254740992.0 is out of range', '[9007199254740992.0]'], ['-9007199254740991 is accepted', '[-9007199254740991]'], ['-9007199254740992 is out of range', '[-9007199254740992]'],
  ['1e17 is out of range', '[1e17]'], ['1e21 is out of range', '[1e21]'], ['1e300 is out of range', '[1e300]'], ['123456789012345680000 is out of range', '[123456789012345680000]'],
  ['12345678901234567890 is out of range', '[12345678901234567890]'], ['1.7976931348623157e308 is out of range', '[1.7976931348623157e308]'], ['9.999999999999999e22 is out of range', '[9.999999999999999e22]'],
  ['1e23 is out of range', '[1e23]'], ['1.5e300 is out of range', '[1.5e300]'],
  ['0.000001', '[0.000001]'], ['1e-7 keeps the exponent form', '[1e-7]'], ['0.0000001234 is 1.234e-7', '[0.0000001234]'], ['4.5', '[4.5]'], ['4.50 is 4.5', '[4.50]'],
  ['333333333.33333329 loses its last digits', '[333333333.33333329]'], ['0.1+0.2 literal', '[0.30000000000000004]'], ['5e-324 smallest denormal', '[5e-324]'],
  ['2e-324 underflows to 0', '[2e-324]'], ['-1e-7', '[-1e-7]'], ['1e-300 is accepted', '[1e-300]'], ['100', '[100]'], ['0.7 stays 0.7', '{"t":0.7}'], ['-5e-1 is -0.5', '[-5e-1]'],
  ['4294967296.5', '[4294967296.5]'], ['0.5e1 is 5', '[0.5e1]'], ['2e-3 is 0.002', '[2e-3]'], ['1e-27 keeps the exponent form', '[0.000000000000000000000000001]'],
  ['leading zero 01 is not JSON', '[01]'], ['plus sign is not JSON', '[+1]'], ['.5 is not JSON', '[.5]'], ['1. is not JSON', '[1.]'], ['NaN is not JSON', '[NaN]'], ['Infinity is not JSON', '[Infinity]'],
  ['hex number is not JSON', '[0x10]'], ['lone minus is not JSON', '[-]'], ['1e is not JSON', '[1e]'],
]) C(d, t);

// structure and strings
C('key order is UTF-16: U+1F600 sorts before U+FFFF', '{"￿":1,"\u{1F600}":2,"a":3}');
C('key order is by string, not by number', '{"10":1,"9":2,"1":3}');
C('duplicate key', '{"a":1,"a":2}');
C('duplicate key via escape', '{"a":1,"\\u0061":2}');
C('duplicate key in a nested object', '{"o":{"k":1,"k":2}}');
C('NFC composed value is accepted', '{"k":"é"}');
C('decomposed value is not NFC', '{"k":"é"}');
C('decomposed key is not NFC', '{"é":1}');
C('not NFC written with an escape', '{"k":"e\\u0301"}');
C('lone high surrogate escape in a value', '{"k":"\\ud800"}');
C('lone low surrogate escape in a key', '{"\\udc00":1}');
C('a valid surrogate pair written as two escapes', '{"k":"\\ud83d\\ude00"}');
C('a surrogate pair in the wrong order', '{"k":"\\ude00\\ud83d"}');
C('high surrogate followed by an ordinary character', '{"k":"\\ud83dx"}');
C('invalid UTF-8 byte 0xFF', [0x7b, 0x22, 0x6b, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
C('CESU-8 encoded surrogate ED A0 80', [0x5b, 0x22, 0xed, 0xa0, 0x80, 0x22, 0x5d]);
C('overlong encoding C0 80', [0x5b, 0x22, 0xc0, 0x80, 0x22, 0x5d]);
C('byte order mark', [0xef, 0xbb, 0xbf, 0x7b, 0x7d]);
C('forbidden key __proto__', '{"__proto__":1}');
C('forbidden key constructor, nested', '{"a":{"constructor":1}}');
C('forbidden key prototype, in an array element', '[{"prototype":1}]');
C('forbidden key written with an escape', '{"__pro\\u0074o__":1}');
C('the word prototype as a value is fine', '{"a":"prototype"}');
C('control characters written as escapes', '["\\u0000\\u001f\\u007f\\u2028\\b\\f\\n\\r\\t\\/\\"\\\\"]');
C('a raw control character inside a string', [0x5b, 0x22, 0x01, 0x22, 0x5d]);
C('a raw DEL character inside a string is fine', [0x5b, 0x22, 0x7f, 0x22, 0x5d]);
C('empty object and array', '[{},[]]');
C('whitespace around tokens', ' \t\n\r{ "a" : [ 1 , 2 ] } \n');
C('vertical tab is not JSON whitespace', [0x0b, 0x7b, 0x7d]);
C('trailing comma in an array', '[1,2,]');
C('trailing comma in an object', '{"a":1,}');
C('empty input', '');
C('a bare string at the top level', '"x"');
C('a bare number at the top level', '42');
C('true false null', '[true,false,null]');
C('literal True is not JSON', '[True]');
C('single quotes are not JSON', "{'a':1}");
C('unquoted key is not JSON', '{a:1}');
C('a comment is not JSON', '{"a":1}//x');
C('two documents', '{}{}');
C('a nested mix, keys sorted at every level', '{"b":[1,{"y":2,"x":[true,null,"s"]}],"a":{"k":-12.50}}');
C('an unpaired surrogate AND a duplicate key: the duplicate key is reported first', '{"a":"\\ud800","a":1}');
C('an out-of-range number AND a forbidden key: the number is reported first', '{"__proto__":1,"n":1e17}');
C('a non-NFC string AND a lone surrogate: not NFC is reported first', '{"a":"e\\u0301","b":"\\ud800"}');
C('a syntax error AND a duplicate key: the syntax error is reported first', '{"a":1,"a":2,}');
C('a forbidden key AND a non-NFC key: the forbidden key is reported first', '{"constructor":1,"é":2}');
// limits: depth 64 is accepted, 65 is not (a scalar has depth 0, an empty array or object has depth 1); canonical size <= 1 MiB (the 64 KiB claims limit is separate)
C('depth 64 arrays (accepted)', rep('', '[', 64, ']'.repeat(64)));
C('depth 65 arrays', rep('', '[', 65, ']'.repeat(65)));
C('depth 64: 63 objects around a scalar leaf object', rep('', '{"a":', 63, '{"z":1}' + '}'.repeat(63)));
C('depth 65: 64 objects around a scalar leaf object', rep('', '{"a":', 64, '{"z":1}' + '}'.repeat(64)));
C('depth 64: 63 arrays around [1]', rep('', '[', 63, '[1]' + ']'.repeat(63)));
C('depth 65: 64 arrays around [1]', rep('', '[', 64, '[1]' + ']'.repeat(64)));
C('canonical size 1048575 bytes (accepted)', rep('["', 'a', 1048571, '"]'));
C('canonical size 1048576 bytes (accepted)', rep('["', 'a', 1048572, '"]'));
C('canonical size 1048577 bytes', rep('["', 'a', 1048573, '"]'));
C('size counts the canonical form: spaces do not count', rep('[', ' ', 1048576, '1]'));

// appended after the second publication (cases are append-only): a text that ends in a backslash
C('a string that ends in a backslash', [0x22, 0x61, 0x5c]);
C('an array whose string ends in a backslash', [0x5b, 0x22, 0x5c]);

// ── V2-REQ: the hashed document { v, method, path, query, headers, body } of section 3 ─────────────────────────────────────────────────────
const req = [];
const H = (n, v) => [hex(n), typeof v === 'string' ? hex(v) : Array.isArray(v) ? raw(v) : v];
const R = (desc, o) => req.push({ desc, ...{ method: hex('POST'), target: hex('/v1/ai/chat'), headers: [], bind: [], body: null }, ...o });

R('baseline: POST, no query, absent body (is {})', {});
R('a chat body', { body: hex('{"model":"m","messages":[{"role":"user","content":"hi"}]}') });
R('empty body bytes are {}', { body: '' });
R('body {} explicit is the same document as no body', { body: hex('{}') });
R('whitespace-only body is invalid JSON', { body: hex('  ') });
R('body null literal is not an object', { body: hex('null') });
R('body array is not an object', { body: hex('[1]') });
R('body with a duplicate key', { body: hex('{"a":1,"a":2}') });
R('body decimals', { body: hex('{"temperature":0.7,"n":1.0}') });
R('body 1.0 and 1 hash alike', { body: hex('{"temperature":0.7,"n":1}') });
R('body with invalid UTF-8', { body: raw([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]) });
R('body starting with a BOM', { body: raw([0xef, 0xbb, 0xbf, 0x7b, 0x7d]) });
R('body key order does not matter', { body: hex('{"b":2,"a":1}') });
R('body with a number beyond 2^53-1', { body: hex('{"n":9007199254740993}') });
R('body with a non-NFC string', { body: hex('{"k":"é"}') });
R('body canonical size just over 1 MiB (the whole document counts)', { body: rep('{"a":"', 'x', 1048576, '"}') });
R('body well under 1 MiB', { body: rep('{"a":"', 'x', 1048000, '"}') });
R('method lower-case post is POST', { method: hex('post') });
R('method mixed case Post is POST', { method: hex('Post') });
R('method GET', { method: hex('GET') });
R('method OPTIONS', { method: hex('OPTIONS') });
R('method TRACE is not allowed', { method: hex('TRACE') });
R('method CONNECT is not allowed', { method: hex('CONNECT') });
R('method with a trailing space', { method: hex('POST ') });
R('method poSt with U+017F is not ASCII', { method: hex('Poſt') });
R('method with sharp s', { method: hex('ß') });
R('empty method', { method: '' });
R('query: nothing after ?', { target: hex('/p?') });
R('query: no ? at all', { target: hex('/p') });
R('query a=1&b=2', { target: hex('/p?a=1&b=2') });
R('query b=2&a=1 sorts to the same document', { target: hex('/p?b=2&a=1') });
R('query empty segments are ignored: a=1&&b=2', { target: hex('/p?a=1&&b=2') });
R('query trailing &', { target: hex('/p?a=1&') });
R('query leading &', { target: hex('/p?&a=1') });
R('query only &', { target: hex('/p?&') });
R('query repeated name keeps the order: a=1&a=2', { target: hex('/p?a=1&a=2') });
R('query repeated name keeps the order: a=2&a=1 (a different hash)', { target: hex('/p?a=2&a=1') });
R('query name without = and name with empty value are the same pair', { target: hex('/p?a&b=') });
R('query = alone is an empty name with an empty value', { target: hex('/p?=') });
R('query =v is an empty name', { target: hex('/p?=v') });
R('query a=b=c splits at the first =', { target: hex('/p?a=b=c') });
R('query raw + is refused', { target: hex('/p?a=b+c') });
R('query %2B is a plus sign', { target: hex('/p?a=b%2Bc') });
R('query %20 is a space', { target: hex('/p?a=b%20c') });
R('query raw ; is refused', { target: hex('/p?a=1;b=2') });
R('query %3B is a semicolon', { target: hex('/p?a=1%3Bb=2') });
R('query + in a name is refused', { target: hex('/p?a+b=1') });
R('query %e9 is invalid UTF-8', { target: hex('/p?a=%e9') });
R('query %C3%A9 is e acute', { target: hex('/p?a=%C3%A9') });
R('query %c3%a9 lower-case hex is the same value', { target: hex('/p?a=%c3%a9') });
R('query e + combining acute via % is not NFC', { target: hex('/p?a=e%CC%81') });
R('query %ED%A0%80 is an encoded surrogate', { target: hex('/p?a=%ED%A0%80') });
R('query % at the end', { target: hex('/p?a=%') });
R('query %zz', { target: hex('/p?a=%zz') });
R('query %00 is a NUL character', { target: hex('/p?a=%00') });
R('query raw non-ASCII is refused', { target: hex('/p?a=é') });
R('query ? inside a value is data', { target: hex('/p?a=b?c') });
R('query names sort by UTF-16: U+1F600 before U+FFFF', { target: hex('/p?%F0%9F%98%80=1&%EF%BF%BF=2') });
R('query names sort case-sensitively', { target: hex('/p?b=1&B=2&a=3') });
R('query sorts by name only: values keep their order', { target: hex('/p?a=9&b=1&a=1') });
R('fragment in the target is refused', { target: hex('/p?a=1#frag') });
R('fragment before ? is refused', { target: hex('/p#frag?a=1') });
R('path: doubled slashes, dot segments and a trailing slash are kept', { target: hex('/a//b/../c/./d/') });
R('path %2f lower-case is kept as received', { target: hex('/a%2fb') });
R('path %2F upper-case is a different path', { target: hex('/a%2Fb') });
R('path percent-encoded non-ASCII is kept as received', { target: hex('/caf%C3%A9') });
R('path raw non-ASCII is refused', { target: hex('/café') });
R('path raw invalid UTF-8 byte is refused', { target: raw([0x2f, 0xff]) });
R('path with a space is refused', { target: hex('/a b') });
R('path with a control character is refused', { target: raw([0x2f, 0x61, 0x09, 0x62]) });
R('path with DEL is refused', { target: raw([0x2f, 0x61, 0x7f, 0x62]) });
R('absolute-form target is refused', { target: hex('http://h/v1/x?y=1') });
R('asterisk-form target is refused', { target: hex('*') });
R('empty target is refused', { target: '' });
R('target without a leading slash is refused', { target: hex('v1/x') });
R('headers: a bound header that is absent is null', { bind: ['x-a'], headers: [] });
R('headers: a bound header that is present and empty is ""', { bind: ['x-a'], headers: [H('x-a', '')] });
R('headers: spaces only trim to ""', { bind: ['x-a'], headers: [H('x-a', '   ')] });
R('headers: leading and trailing SP and HTAB are trimmed', { bind: ['x-a'], headers: [H('x-a', ' \t v \t ')] });
R('headers: NBSP is not trimmed', { bind: ['x-a'], headers: [H('x-a', ' v ')] });
R('headers: form feed is not trimmed', { bind: ['x-a'], headers: [H('x-a', '\fv\f')] });
R('headers: two field lines are joined with ", " in order received', { bind: ['x-a'], headers: [H('x-a', 'a '), H('x-a', ' b')] });
R('headers: the same two lines in the other order are a different value', { bind: ['x-a'], headers: [H('x-a', ' b'), H('x-a', 'a ')] });
R('headers: received name case does not matter', { bind: ['x-a'], headers: [H('X-A', 'v')] });
R('headers: a name listed twice is refused', { bind: ['x-a', 'x-a'], headers: [H('x-a', 'v')] });
R('headers: an upper-case bound name is refused', { bind: ['X-A'], headers: [H('x-a', 'v')] });
R('headers: authorization cannot be bound', { bind: ['authorization'], headers: [H('authorization', 'v')] });
R('headers: cookie cannot be bound', { bind: ['cookie'], headers: [H('cookie', 'v')] });
R('headers: host cannot be bound', { bind: ['host'], headers: [H('host', 'h')] });
R('headers: x-qodiqa-artifact cannot be bound', { bind: ['x-qodiqa-artifact'], headers: [] });
R('headers: a hop-by-hop name (te) cannot be bound', { bind: ['te'], headers: [] });
R('headers: 17 names are too many', { bind: Array.from({ length: 17 }, (_, i) => `x-h${i}`), headers: [] });
R('headers: 16 names are allowed', { bind: Array.from({ length: 16 }, (_, i) => `x-h${i}`), headers: [] });
R('headers: a name of 65 characters is refused', { bind: [`x-${'a'.repeat(62)}`], headers: [] });
R('headers: a name of 64 characters is allowed', { bind: [`x-${'a'.repeat(61)}`], headers: [] });
R('headers: a name with an underscore is refused', { bind: ['x_a'], headers: [] });
R('headers: a value with invalid UTF-8', { bind: ['x-a'], headers: [H('x-a', [0xff])] });
R('headers: a non-NFC value', { bind: ['x-a'], headers: [H('x-a', 'é')] });
R('headers: an NFC value', { bind: ['x-a'], headers: [H('x-a', 'café')] });
R('headers: a comma inside a single line is data', { bind: ['x-a'], headers: [H('x-a', 'a, b')] });
R('headers: the order of the bound names does not matter', { bind: ['x-b', 'x-a'], headers: [H('x-a', '1'), H('x-b', '2')] });
R('headers: an unbound header is ignored', { bind: ['x-a'], headers: [H('x-a', '1'), H('x-zzz', '2')] });
R('headers: a BOM in a value is the character U+FEFF', { bind: ['x-a'], headers: [H('x-a', '﻿v')] });
R('headers: a value of astral characters', { bind: ['x-a'], headers: [H('x-a', '\u{1F600}')] });
R('a complete request: query, two headers and a body together', {
  method: hex('PUT'), target: hex('/v1/ai/chat?stream=true&model=m&a=2&a=1'),
  bind: ['x-tenant', 'x-trace'], headers: [H('x-trace', ' t-1 '), H('x-tenant', 'acme'), H('x-other', 'ignored')],
  body: hex('{"temperature":0.7,"messages":[{"content":"hi","role":"user"}],"n":1}'),
});

// appended after the first publication (cases are append-only)
R('headers: a bound name that is a JS prototype word makes a forbidden document key (constructor)', { bind: ['constructor'], headers: [H('constructor', 'v')] });
R('headers: a bound name that is a JS prototype word makes a forbidden document key (prototype)', { bind: ['prototype'], headers: [] });
R('headers: a bound name with underscores (__proto__) fails the name rule', { bind: ['__proto__'], headers: [] });
R('body nested 63 deep: the whole document is depth 64 (accepted)', { body: rep('', '{"a":', 62, '{}' + '}'.repeat(62)) });
R('body nested 64 deep: the whole document is depth 65 (refused)', { body: rep('', '{"a":', 63, '{}' + '}'.repeat(63)) });
R('body with an empty key and a unicode key', { body: hex('{"":1,"é":2}') });
R('body number -0 hashes as 0', { body: hex('{"n":-0}') });
R('body number 0 hashes alike', { body: hex('{"n":0}') });



// appended after the second publication (cases are append-only): a content-coded request body is refused
R('headers: content-encoding identity is accepted', { headers: [H('content-encoding', 'identity')], body: hex('{"a":1}') });
R('headers: content-encoding identity, any case and padding, is accepted', { headers: [H('Content-Encoding', ' IDENTITY ')], body: hex('{"a":1}') });
R('headers: content-encoding gzip is refused', { headers: [H('content-encoding', 'gzip')], body: hex('{"a":1}') });
R('headers: content-encoding with a second line that is not identity is refused', { headers: [H('content-encoding', 'identity'), H('Content-Encoding', 'br')], body: hex('{"a":1}') });
R('headers: an empty content-encoding is refused', { headers: [H('content-encoding', '')], body: hex('{"a":1}') });
R('headers: content-encoding is checked even when no header is bound', { bind: [], headers: [H('CONTENT-ENCODING', 'deflate')] });

module.exports = { canon, req };
