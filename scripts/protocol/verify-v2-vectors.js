#!/usr/bin/env node
'use strict';

/**
 * INDEPENDENT verifier for the protocol-V2 vector families (docs/protocol/vectors/v2-canon.json, v2-request.json).
 *
 * Imports NOTHING from src/ or services/ — only node:crypto, node:fs and node:path. JCS-P1 (V2-FREEZE section 2), the V2 request binding
 * (section 3) and the signed receipt (section 6) are re-implemented here from the specification text alone, with their own parser, so this file can be read, audited and run without
 * trusting QODIQA's implementation. The Python counterpart (verify_v2_vectors.py) is a third, separately written implementation.
 *
 *   node scripts/protocol/verify-v2-vectors.js [file.json ...]     exit 1 on any mismatch
 *
 * Exported for tests: parseJcsP1, canonicalOf, requestBinding, expandBytes, verifyFile.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MAX_SAFE = 9007199254740991;
const MAX_DEPTH = 64;
const MAX_DOC_BYTES = 1048576;
const NEST_STOP = 10000;
// V2-FREEZE 2.7: when several rules are broken, the FIRST of this list is reported
const ORDER = ['INVALID_UTF8', 'INVALID_JSON', 'DUPLICATE_KEY', 'NON_FINITE_NUMBER', 'NUMBER_OUT_OF_RANGE', 'FORBIDDEN_KEY', 'UNSUPPORTED_TYPE', 'STRING_NOT_NFC', 'LONE_SURROGATE', 'MAX_DEPTH_EXCEEDED', 'MAX_SIZE_EXCEEDED'];
const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];

class Refusal extends Error { constructor(code) { super(code); this.code = code; } }
const firstOf = (set) => ORDER.find((c) => set.has(c));

// ── decoding ────────────────────────────────────────────────────────────────────────────────────────────────────
function utf8(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) throw new Refusal('INVALID_UTF8');   // a BOM is never stripped
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { throw new Refusal('INVALID_UTF8'); }
}

// ── a strict JSON parser that keeps duplicate keys visible ───────────────────────────────────────────────────────
// Tree nodes: { k: 'obj', members: [[key, node]] } | { k: 'arr', items } | { k: 'str', s } | { k: 'num', v, text } | { k: 'lit', v }
function parseTree(text) {
  let i = 0;
  const n = text.length;
  const bad = () => { throw new Refusal('INVALID_JSON'); };
  const skip = () => { while (i < n && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++; };
  function readString() {
    i++;                                   // opening quote
    const units = [];
    while (true) {
      if (i >= n) bad();
      const ch = text.charCodeAt(i);
      if (ch === 0x22) { i++; return units.map((u) => String.fromCharCode(u)).join(''); }
      if (ch < 0x20) bad();
      if (ch !== 0x5c) { units.push(ch); i++; continue; }
      const e = text[i + 1];
      i += 2;
      if (e === '"' || e === '\\' || e === '/') units.push(e.charCodeAt(0));
      else if (e === 'b') units.push(8); else if (e === 'f') units.push(12); else if (e === 'n') units.push(10);
      else if (e === 'r') units.push(13); else if (e === 't') units.push(9);
      else if (e === 'u') {
        const hx = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hx)) bad();
        units.push(parseInt(hx, 16));
        i += 4;
      } else bad();
    }
  }
  function readValue(depth) {
    if (depth > NEST_STOP) throw new Refusal('MAX_DEPTH_EXCEEDED');
    skip();
    if (i >= n) bad();
    const c = text[i];
    if (c === '{') {
      i++; const members = []; skip();
      if (text[i] === '}') { i++; return { k: 'obj', members }; }
      for (;;) {
        skip(); if (text[i] !== '"') bad();
        const key = readString(); skip();
        if (text[i] !== ':') bad(); i++;
        members.push([key, readValue(depth + 1)]); skip();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return { k: 'obj', members }; }
        bad();
      }
    }
    if (c === '[') {
      i++; const items = []; skip();
      if (text[i] === ']') { i++; return { k: 'arr', items }; }
      for (;;) {
        items.push(readValue(depth + 1)); skip();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === ']') { i++; return { k: 'arr', items }; }
        bad();
      }
    }
    if (c === '"') return { k: 'str', s: readString() };
    for (const [word, value] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, i)) { i += word.length; return { k: 'lit', v: value }; }
    }
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 500));
    if (!m) bad();
    i += m[0].length;
    return { k: 'num', v: Number(m[0]) };
  }
  const root = readValue(0);
  skip();
  if (i !== n) bad();
  return root;
}

// ── the rules that apply to a parsed tree: collected, then the first by precedence is reported ──────────────────────
function violations(node) {
  const found = new Set();
  const loneSurrogate = (s) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
  const checkString = (s) => { if (s.normalize('NFC') !== s) found.add('STRING_NOT_NFC'); if (loneSurrogate(s)) found.add('LONE_SURROGATE'); };
  let maxDepth = 0;
  const stack = [[node, 1]];
  while (stack.length) {
    const [nd, depth] = stack.pop();
    if (nd.k === 'num') {
      if (!Number.isFinite(nd.v)) found.add('NON_FINITE_NUMBER');
      else if (Math.abs(nd.v) > MAX_SAFE) found.add('NUMBER_OUT_OF_RANGE');
    } else if (nd.k === 'str') checkString(nd.s);
    else if (nd.k === 'arr') { maxDepth = Math.max(maxDepth, depth); for (const it of nd.items) stack.push([it, depth + 1]); }
    else if (nd.k === 'obj') {
      maxDepth = Math.max(maxDepth, depth);
      const seen = new Set();
      for (const [key, val] of nd.members) {
        if (seen.has(key)) found.add('DUPLICATE_KEY'); seen.add(key);
        if (FORBIDDEN.includes(key)) found.add('FORBIDDEN_KEY');
        checkString(key);
        stack.push([val, depth + 1]);
      }
    }
  }
  if (maxDepth > MAX_DEPTH) found.add('MAX_DEPTH_EXCEEDED');
  return found;
}

// ── canonical form (RFC 8785): keys by UTF-16 code units, ES number text, minimal string escapes ────────────────────
function cmpUtf16(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) { const d = a.charCodeAt(i) - b.charCodeAt(i); if (d !== 0) return d; }
  return a.length - b.length;
}
function quote(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"'; else if (c === 0x5c) out += '\\\\';
    else if (c === 8) out += '\\b'; else if (c === 12) out += '\\f'; else if (c === 10) out += '\\n'; else if (c === 13) out += '\\r'; else if (c === 9) out += '\\t';
    else if (c < 0x20) out += `\\u${c.toString(16).padStart(4, '0')}`;
    else out += s[i];
  }
  return `${out}"`;
}
function emit(node) {
  if (node.k === 'lit') return node.v === null ? 'null' : String(node.v);
  if (node.k === 'num') return node.v === 0 ? '0' : String(node.v);                  // -0 is 0; the ES Number::toString of a double
  if (node.k === 'str') return quote(node.s);
  if (node.k === 'arr') return `[${node.items.map(emit).join(',')}]`;
  const sorted = [...node.members].sort((x, y) => cmpUtf16(x[0], y[0]));
  return `{${sorted.map(([k, v]) => `${quote(k)}:${emit(v)}`).join(',')}}`;
}

/** Parses JSON bytes under JCS-P1 → { tree, canonical } or throws Refusal(code). */
function parseJcsP1(bytes) {
  const text = utf8(bytes);
  const tree = parseTree(text);
  const found = violations(tree);
  if (found.size) throw new Refusal(firstOf(found));
  const canonical = emit(tree);
  if (Buffer.byteLength(canonical, 'utf8') > MAX_DOC_BYTES) throw new Refusal('MAX_SIZE_EXCEEDED');
  return { tree, canonical };
}
const canonicalOf = (bytes) => parseJcsP1(bytes).canonical;

// ── V2 request binding (V2-FREEZE section 3) ─────────────────────────────────────────────────────────────────────────
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const NEVER_BOUND = ['x-qodiqa-artifact', 'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'host', 'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'te', 'trailer', 'upgrade', 'via', 'forwarded', 'x-forwarded-for'];
class Mismatch extends Error { constructor(detail = null) { super('REQUEST_MISMATCH'); this.code = 'REQUEST_MISMATCH'; this.detail = detail; } }
const mismatch = (detail) => { throw new Mismatch(detail); };

function strictUtf8(bytes) { try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Uint8Array.from(bytes)); } catch { return null; } }
function nfcOrRefuse(s) { if (s.normalize('NFC') !== s) mismatch('STRING_NOT_NFC'); return s; }

function decodePercent(raw) {
  const bytes = [];
  for (let i = 0; i < raw.length; i++) {
    const b = raw[i];
    if (b === 0x25) {
      const h = String.fromCharCode(raw[i + 1] || 0, raw[i + 2] || 0);
      if (i + 2 >= raw.length || !/^[0-9a-fA-F]{2}$/.test(h)) mismatch(null);
      bytes.push(parseInt(h, 16)); i += 2;
    } else bytes.push(b);
  }
  const s = strictUtf8(bytes);
  if (s === null) mismatch(null);
  return nfcOrRefuse(s);
}

/** input = the vector input with every bytes value already expanded to a Buffer; returns { hash, document } or throws Mismatch. */
function requestBinding(input) {
  const { method, target, headers, bind, body } = input;
  // the artifact's bound header names
  if (bind.length > 16) mismatch(null);
  const seenNames = new Set();
  for (const name of bind) {
    if (!/^[a-z0-9-]{1,64}$/.test(name) || NEVER_BOUND.includes(name) || seenNames.has(name)) mismatch(null);
    seenNames.add(name);
  }
  // method: ASCII letters only, matched case-insensitively
  if (!method.length || method.some((b) => !((b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a)))) mismatch(null);
  const m = Buffer.from(method).toString('latin1').toUpperCase();
  if (!METHODS.includes(m)) mismatch(null);
  // path and query out of the raw request-target (origin-form, ASCII, nothing but printable characters, no fragment)
  if (target.length === 0 || target[0] !== 0x2f) mismatch(null);
  for (const b of target) { if (b <= 0x20 || b >= 0x7f || b === 0x23) mismatch(null); }
  const qpos = target.indexOf(0x3f);
  const pathBytes = qpos < 0 ? target : target.subarray(0, qpos);
  const queryBytes = qpos < 0 ? Buffer.alloc(0) : target.subarray(qpos + 1);
  const path = Buffer.from(pathBytes).toString('latin1');
  let query = [];
  if (queryBytes.length) {
    if (queryBytes.includes(0x2b) || queryBytes.includes(0x3b)) mismatch(null);          // a raw + or ;
    const pairs = [];
    let from = 0;
    for (let i = 0; i <= queryBytes.length; i++) {
      if (i < queryBytes.length && queryBytes[i] !== 0x26) continue;
      const seg = queryBytes.subarray(from, i); from = i + 1;
      if (seg.length === 0) continue;                                                      // empty segments are ignored
      const eq = seg.indexOf(0x3d);
      pairs.push([decodePercent(eq < 0 ? seg : seg.subarray(0, eq)), decodePercent(eq < 0 ? Buffer.alloc(0) : seg.subarray(eq + 1))]);
    }
    query = pairs.map((p, idx) => ({ p, idx })).sort((a, b) => cmpUtf16(a.p[0], b.p[0]) || a.idx - b.idx).map((x) => x.p);   // by name only, stable
  }
  // a content-coded request body is refused: every field line named content-encoding must be `identity` (after trimming SP/HTAB, any case)
  for (const [hn, hv] of headers) {
    if (Buffer.from(hn).toString('latin1').toLowerCase() === 'content-encoding' && Buffer.from(hv).toString('latin1').replace(/^[ 	]+|[ 	]+$/g, '').toLowerCase() !== 'identity') mismatch(null);
  }
  // bound headers: the received field lines, trimmed of SP/HTAB, joined with ", " in order received; absent = null
  const headerValues = {};
  for (const name of bind) {
    const lines = [];
    for (const [hn, hv] of headers) {
      if (Buffer.from(hn).toString('latin1').toLowerCase() !== name) continue;
      const s = strictUtf8(hv);
      if (s === null) mismatch(null);
      lines.push(nfcOrRefuse(s.replace(/^[ \t]+|[ \t]+$/g, '')));
    }
    headerValues[name] = lines.length ? lines.join(', ') : null;
  }
  // body: absent or zero bytes is {}; otherwise a JSON object under JCS-P1
  let bodyNode;
  if (body === null || body.length === 0) bodyNode = { k: 'obj', members: [] };
  else {
    let parsed;
    try { parsed = parseJcsP1(body); } catch (e) { if (e instanceof Refusal) mismatch(e.code); throw e; }
    if (parsed.tree.k !== 'obj') mismatch(null);
    bodyNode = parsed.tree;
  }
  const doc = {
    k: 'obj',
    members: [
      ['v', { k: 'num', v: 2 }], ['method', { k: 'str', s: m }], ['path', { k: 'str', s: path }],
      ['query', { k: 'arr', items: query.map(([a, b]) => ({ k: 'arr', items: [{ k: 'str', s: a }, { k: 'str', s: b }] })) }],
      ['headers', { k: 'obj', members: bind.map((name) => [name, headerValues[name] === null ? { k: 'lit', v: null } : { k: 'str', s: headerValues[name] }]) }],
      ['body', bodyNode],
    ],
  };
  const found = violations(doc);                       // depth and size are limits of the WHOLE hashed document
  if (found.size) mismatch(firstOf(found));
  const document = emit(doc);
  if (Buffer.byteLength(document, 'utf8') > MAX_DOC_BYTES) mismatch('MAX_SIZE_EXCEEDED');
  const hash = crypto.createHash('sha256').update('QODIQA::REQUEST::V2', 'utf8').update(document, 'utf8').digest('hex');
  return { hash, document };
}

// ── signed receipt (V2-FREEZE section 6) ────────────────────────────────────────────────────────────────────────────────
const RECEIPT_FIELDS = ['v', 'requestId', 'decision', 'issuedAt', 'entryHash', 'leafHash', 'keyId', 'signature'];
function fromValue(v) {                                         // a JSON value -> a tree for emit()
  if (v === null || typeof v === 'boolean') return { k: 'lit', v };
  if (typeof v === 'number') return { k: 'num', v };
  if (typeof v === 'string') return { k: 'str', s: v };
  if (Array.isArray(v)) return { k: 'arr', items: v.map(fromValue) };
  return { k: 'obj', members: Object.keys(v).map((k) => [k, fromValue(v[k])]) };
}
function receiptVerdict(receipt, keys, trustedAt) {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return 'NOT_AN_OBJECT';
  if (Object.keys(receipt).sort().join(',') !== [...RECEIPT_FIELDS].sort().join(',')) return 'FIELD_SET';
  if (receipt.v !== 1) return 'UNSUPPORTED_VERSION';
  const hex64 = (x) => typeof x === 'string' && /^[0-9a-f]{64}$/.test(x);
  if (typeof receipt.requestId !== 'string' || receipt.requestId === '' || !['ALLOW', 'BLOCK'].includes(receipt.decision)
    || !Number.isInteger(receipt.issuedAt) || receipt.issuedAt < 0 || receipt.issuedAt > MAX_SAFE
    || !hex64(receipt.entryHash) || !hex64(receipt.leafHash)
    || typeof receipt.keyId !== 'string' || receipt.keyId === '' || typeof receipt.signature !== 'string' || receipt.signature === '') return 'INVALID_FIELD';
  const key = keys.find((k) => k.keyId === receipt.keyId);
  if (!key) return 'UNKNOWN_KEY';
  const unsigned = Object.fromEntries(Object.entries(receipt).filter(([k]) => k !== 'signature'));
  const digest = crypto.createHash('sha256').update('QODIQA::RECEIPT::V1', 'utf8').update(emit(fromValue(unsigned)), 'utf8').digest();
  const sig = Buffer.from(receipt.signature, 'base64');
  let good = false;
  if (sig.length === 64 && sig.toString('base64') === receipt.signature) {
    try { good = crypto.verify(null, digest, crypto.createPublicKey({ key: Buffer.from(key.publicKeySpkiB64, 'base64'), format: 'der', type: 'spki' }), sig); } catch { good = false; }
  }
  if (!good) return 'BAD_SIGNATURE';
  if (key.status === 'revoked' && !(Number.isFinite(trustedAt) && Number.isFinite(key.revokedAt) && trustedAt < key.revokedAt)) return 'REVOKED_KEY';
  return null;
}

// ── vectors ──────────────────────────────────────────────────────────────────────────────────────────────────────────
function expandBytes(b) {
  if (typeof b === 'string') return Buffer.from(b, 'hex');
  const { prefix, unit, count, suffix } = b.repeat;
  return Buffer.from(prefix + unit.repeat(count) + suffix, 'utf8');
}

function verifyCase(family, c, file = {}) {
  if (family === 'v2-receipt') {
    const got = receiptVerdict(c.input.receipt, file.keys || [], c.input.trustedAt);
    if (c.expectedError) return got === c.expectedError.code ? { ok: true } : { ok: false, why: `expected ${c.expectedError.code}, got ${got}` };
    return got === null ? { ok: true } : { ok: false, why: `expected ok, got ${got}` };
  }
  if (family === 'v2-canon') {
    let got;
    try { const canonical = canonicalOf(expandBytes(c.input.bytes)); got = { ok: true, bytes: Buffer.from(canonical, 'utf8'), text: canonical }; } catch (e) { if (!(e instanceof Refusal)) throw e; got = { ok: false, code: e.code }; }
    if (c.expectedError) return got.ok ? { ok: false, why: `expected ${c.expectedError.code}, got a canonical form` } : (got.code === c.expectedError.code ? { ok: true } : { ok: false, why: `expected ${c.expectedError.code}, got ${got.code}` });
    if (!got.ok) return { ok: false, why: `expected a canonical form, got ${got.code}` };
    const e = c.expected;
    if (e.value !== undefined) return got.bytes.toString('hex') === e.value ? { ok: true } : { ok: false, why: 'canonical bytes differ' };
    return (got.bytes.length === e.length && crypto.createHash('sha256').update(got.bytes).digest('hex') === e.sha256) ? { ok: true } : { ok: false, why: 'canonical length or sha256 differs' };
  }
  if (family === 'v2-request') {
    const inp = c.input;
    const input = { method: expandBytes(inp.method), target: expandBytes(inp.target), headers: inp.headers.map(([a, b]) => [expandBytes(a), expandBytes(b)]), bind: inp.bind, body: inp.body === null ? null : expandBytes(inp.body) };
    let got;
    try { const r = requestBinding(input); got = { ok: true, ...r }; } catch (e) { if (!(e instanceof Mismatch)) throw e; got = { ok: false, code: e.code, detail: e.detail }; }
    if (c.expectedError) {
      if (got.ok) return { ok: false, why: `expected ${c.expectedError.code}, got a hash` };
      if (got.code !== c.expectedError.code) return { ok: false, why: `expected ${c.expectedError.code}, got ${got.code}` };
      const wantDetail = c.expectedError.detail || null;
      return (got.detail || null) === wantDetail ? { ok: true } : { ok: false, why: `detail: expected ${wantDetail}, got ${got.detail}` };
    }
    if (!got.ok) return { ok: false, why: `expected a hash, got ${got.code}${got.detail ? `:${got.detail}` : ''}` };
    if (got.hash !== c.expected.value) return { ok: false, why: 'requestHash differs' };
    if (c.expected.document !== undefined && got.document !== c.expected.document) return { ok: false, why: 'hashed document differs' };
    return { ok: true };
  }
  throw new Error(`unknown family ${family}`);
}

function verifyFile(file) {
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  const failures = [];
  for (const c of v.cases) { const r = verifyCase(v.family, c, v); if (!r.ok) failures.push({ id: c.id, description: c.description, why: r.why }); }
  return { file: path.basename(file), family: v.family, cases: v.cases.length, failed: failures.length, failures };
}

module.exports = { parseJcsP1, canonicalOf, requestBinding, expandBytes, verifyFile, verifyCase, Refusal, Mismatch };

if (require.main === module) {
  const DIR = path.join(__dirname, '..', '..', 'docs', 'protocol', 'vectors');
  const files = process.argv.length > 2 ? process.argv.slice(2) : ['v2-canon.json', 'v2-request.json', 'receipt.json'].map((f) => path.join(DIR, f));
  const reports = files.map(verifyFile);
  const failed = reports.reduce((a, r) => a + r.failed, 0);
  process.stdout.write(`${JSON.stringify({ implementation: 'verify-v2-vectors.js (independent, node)', checks: reports.reduce((a, r) => a + r.cases, 0), failed, reports }, null, 2)}\n`);
  process.exit(failed ? 1 : 0);
}
