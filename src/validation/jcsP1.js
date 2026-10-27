'use strict';

/**
 * JCS-P1 - the canonicalization profile of protocol V2 (docs/protocol/PROTOCOL-V2.md section 2).
 *
 * RFC 8785 (JSON Canonicalization Scheme) restricted by input checks that only REJECT; for every accepted value the output is byte-identical to
 * RFC 8785 and to the V1 canonicalizer (src/utils/stableStringify.js). A hash is always over the VALUE, never over the text.
 *
 *   parseJcsP1(input)           strict parser over UTF-8 text/bytes: duplicate keys, number range, NFC, surrogates, depth, size
 *   canonicalJcsP1(value)       validates a programmatically built value and returns its canonical text
 *   JcsError.code               one of ERROR_CODES; when several rules are broken, the FIRST in ERROR_ORDER is reported
 *
 * JSON.parse is NOT used for untrusted input: it cannot report duplicate keys (and one Node release line mis-parses some keys).
 */

const MAX_SAFE = Number.MAX_SAFE_INTEGER;            // 2^53 - 1
const MAX_DEPTH = 64;
const MAX_CANONICAL_BYTES_DEFAULT = 1024 * 1024;     // 1 MiB (V2-FREEZE 2.5); signed claims use 64 KiB
const HARD_NESTING_STOP = 5000;                      // stack protection while parsing (reported as MAX_DEPTH_EXCEEDED)

// V2-FREEZE 2.7 - precedence when an input breaks several rules.
const ERROR_ORDER = Object.freeze([
  'INVALID_UTF8', 'INVALID_JSON', 'DUPLICATE_KEY', 'NON_FINITE_NUMBER', 'NUMBER_OUT_OF_RANGE', 'FORBIDDEN_KEY',
  'UNSUPPORTED_TYPE', 'STRING_NOT_NFC', 'LONE_SURROGATE', 'MAX_DEPTH_EXCEEDED', 'MAX_SIZE_EXCEEDED',
]);
const ERROR_CODES = Object.freeze(Object.fromEntries(ERROR_ORDER.map((c) => [c, c])));
const RANK = new Map(ERROR_ORDER.map((c, i) => [c, i]));
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

class JcsError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'JcsError';
    this.code = code;
  }
}

const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function best(codes) {
  let pick = null;
  for (const c of codes) if (pick === null || RANK.get(c) < RANK.get(pick)) pick = c;
  return pick;
}

// ── value analysis (everything except syntax and duplicate keys) ───────────────────────────────────────────────
function analyze(value, found) {
  const stack = [[value, 1]];
  while (stack.length) {
    const [v, depth] = stack.pop();
    if (v === null || typeof v === 'boolean') continue;
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) found.add('NON_FINITE_NUMBER');
      else if (Math.abs(v) > MAX_SAFE) found.add('NUMBER_OUT_OF_RANGE');
      continue;
    }
    if (typeof v === 'string') {
      if (v.normalize('NFC') !== v) found.add('STRING_NOT_NFC');
      if (LONE_SURROGATE_RE.test(v)) found.add('LONE_SURROGATE');
      continue;
    }
    if (Array.isArray(v)) {
      if (depth > MAX_DEPTH) found.add('MAX_DEPTH_EXCEEDED');
      if (depth > HARD_NESTING_STOP) return;
      for (const m of v) stack.push([m, depth + 1]);
      continue;
    }
    if (typeof v === 'object') {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) { found.add('UNSUPPORTED_TYPE'); continue; }
      if (depth > MAX_DEPTH) found.add('MAX_DEPTH_EXCEEDED');
      if (depth > HARD_NESTING_STOP) return;
      for (const k of Object.keys(v)) {
        if (FORBIDDEN_KEYS.has(k)) found.add('FORBIDDEN_KEY');
        if (k.normalize('NFC') !== k) found.add('STRING_NOT_NFC');
        if (LONE_SURROGATE_RE.test(k)) found.add('LONE_SURROGATE');
        stack.push([v[k], depth + 1]);
      }
      continue;
    }
    found.add('UNSUPPORTED_TYPE'); // undefined, function, symbol, bigint
  }
}

function serialize(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return Object.is(v, -0) ? '0' : String(v);   // ECMAScript Number::toString == RFC 8785 3.2.2.3
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(serialize).join(',')}]`;
  const keys = Object.keys(v).sort();                                      // UTF-16 code unit order (RFC 8785 3.2.3)
  return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(v[k])}`).join(',')}}`;
}

function finish(value, found, maxBytes) {
  analyze(value, found);
  if (found.size) throw new JcsError(best(found));
  const canonical = serialize(value);
  if (Buffer.byteLength(canonical, 'utf8') > maxBytes) throw new JcsError('MAX_SIZE_EXCEEDED', `canonical form exceeds ${maxBytes} bytes`);
  return canonical;
}

/** Validates a programmatically built value and returns its JCS-P1 canonical text. Throws JcsError. */
function canonicalJcsP1(value, { maxBytes = MAX_CANONICAL_BYTES_DEFAULT } = {}) {
  return finish(value, new Set(), maxBytes);
}

// ── strict parser ───────────────────────────────────────────────────────────────────────────────────────────────
const WS = new Set([0x20, 0x09, 0x0a, 0x0d]);
const NUM_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;

function parseText(text, found) {
  let i = 0;
  const n = text.length;
  const fail = (m) => { throw new JcsError('INVALID_JSON', m); };
  const ws = () => { while (i < n && WS.has(text.charCodeAt(i))) i++; };

  function str() {
    // text[i] === '"'
    i++;
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) { i++; return out; }
      if (c < 0x20) fail('control character in string');
      if (c === 0x5c) {
        const e = text[i + 1];
        i += 2;
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const h = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) fail('bad \\u escape');
            out += String.fromCharCode(parseInt(h, 16));
            i += 4;
            break;
          }
          default: fail('bad escape');
        }
      } else { out += text[i]; i++; }
    }
  }

  function value(depth) {
    if (depth > HARD_NESTING_STOP) throw new JcsError('MAX_DEPTH_EXCEEDED', 'nesting too deep to parse');
    ws();
    if (i >= n) fail('unexpected end');
    const c = text[i];
    if (c === '{') {
      i++;
      const obj = Object.create(null);
      const seen = new Set();
      ws();
      if (text[i] === '}') { i++; return obj; }
      for (;;) {
        ws();
        if (text[i] !== '"') fail('object key expected');
        const k = str();
        ws();
        if (text[i] !== ':') fail('colon expected');
        i++;
        const v = value(depth + 1);
        if (seen.has(k)) found.add('DUPLICATE_KEY'); else seen.add(k);
        obj[k] = v;
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return obj; }
        fail('comma or } expected');
      }
    }
    if (c === '[') {
      i++;
      const arr = [];
      ws();
      if (text[i] === ']') { i++; return arr; }
      for (;;) {
        arr.push(value(depth + 1));
        ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return arr; }
        fail('comma or ] expected');
      }
    }
    if (c === '"') return str();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    const m = NUM_RE.exec(text.slice(i, i + 400));
    if (!m) fail('unexpected token');
    i += m[0].length;
    return Number(m[0]);          // every number becomes an IEEE-754 double (V2-FREEZE 2.1)
  }

  const v = value(1);
  ws();
  if (i < n) fail('trailing characters');
  return v;
}

/**
 * Parses JSON text (string or UTF-8 bytes) under JCS-P1. Returns { value, canonical }. Throws JcsError.
 * A BOM, invalid UTF-8, syntax errors, duplicate keys, out-of-range numbers, non-NFC strings, lone surrogates, excess depth or size are refused.
 */
function parseJcsP1(input, { maxBytes = MAX_CANONICAL_BYTES_DEFAULT } = {}) {
  let text;
  if (typeof input === 'string') {
    text = input;
    if (text.charCodeAt(0) === 0xfeff) throw new JcsError('INVALID_UTF8', 'byte order mark');
  } else if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) throw new JcsError('INVALID_UTF8', 'byte order mark');
    try { text = utf8Strict.decode(input); } catch (_) { throw new JcsError('INVALID_UTF8', 'invalid UTF-8'); }
  } else {
    throw new JcsError('UNSUPPORTED_TYPE', 'input must be a string or bytes');
  }
  const found = new Set();
  const value = parseText(text, found);
  return { value, canonical: finish(value, found, maxBytes) };
}

module.exports = { parseJcsP1, canonicalJcsP1, JcsError, ERROR_CODES, ERROR_ORDER, MAX_SAFE, MAX_DEPTH, MAX_CANONICAL_BYTES_DEFAULT };
