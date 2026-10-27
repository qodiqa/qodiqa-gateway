'use strict';

/**
 * Protocol V2 request binding (docs/protocol/PROTOCOL-V2.md section 3).
 *
 *   requestHash(V2) = SHA-256("QODIQA::REQUEST::V2" || JCS-P1({ v: 2, method, path, query, headers, body }))
 *
 * Every failure is a BindingError whose `code` is REQUEST_MISMATCH (or QUERY_NOT_BINDABLE at issuance) and whose `reason` is an internal
 * diagnostic for logs only: responses built from it MUST use constant details (V2-FREEZE 7.6).
 */

const crypto = require('crypto');
const { ARTIFACT_DOMAINS } = require('../infra/crypto/hashing');
const { parseJcsP1, canonicalJcsP1, JcsError } = require('./jcsP1');

const REQUEST_DOMAIN_V2 = ARTIFACT_DOMAINS.REQUEST_V2;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const HEADER_NAME_RE = /^[a-z0-9-]{1,64}$/;
const MAX_BOUND_HEADERS = 16;
const FORBIDDEN_BOUND_HEADERS = new Set([
  'x-qodiqa-artifact', 'authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'host', 'content-length', 'transfer-encoding',
  'connection', 'keep-alive', 'te', 'trailer', 'upgrade', 'via', 'forwarded', 'x-forwarded-for',
]);
const utf8Strict = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

class BindingError extends Error {
  constructor(reason, code = 'REQUEST_MISMATCH', jcsCode = null) {
    super(`${code}: ${reason}`);
    this.name = 'BindingError';
    this.code = code;
    this.reason = reason;      // internal only
    this.jcsCode = jcsCode;
  }
}
const refuse = (reason) => { throw new BindingError(reason); };

function nfc(s, what) {
  if (s.normalize('NFC') !== s) throw new BindingError(`${what} is not NFC`, 'REQUEST_MISMATCH', 'STRING_NOT_NFC');
  return s;
}

/** Validates the list of bound header names (artifact claim qodiqa.bind.headers). Returns the list. */
function validateBindHeaders(names) {
  if (!Array.isArray(names)) refuse('bind.headers is not an array');
  if (names.length > MAX_BOUND_HEADERS) refuse('too many bound headers');
  const seen = new Set();
  for (const n of names) {
    if (typeof n !== 'string' || !HEADER_NAME_RE.test(n)) refuse('bad bound header name');
    if (FORBIDDEN_BOUND_HEADERS.has(n)) refuse('forbidden bound header');
    if (seen.has(n)) refuse('duplicate bound header');
    seen.add(n);
  }
  return names;
}

function normalizeMethod(method) {
  if (typeof method !== 'string' || !/^[A-Za-z]+$/.test(method)) refuse('bad method');
  const m = method.toUpperCase();
  if (!METHODS.has(m)) refuse('method not allowed');
  return m;
}

function splitTarget(target) {
  if (typeof target !== 'string' || target[0] !== '/') refuse('request target is not in origin-form');
  for (let i = 0; i < target.length; i++) {
    const c = target.charCodeAt(i);
    if (c > 0x7e) refuse('non-ASCII or DEL in request target');      // > 0x7e covers non-ASCII (>0x7f) and DEL (0x7f)
    if (c <= 0x20) refuse('control character or space in request target');
    if (c === 0x23) refuse('fragment in request target');
  }
  const q = target.indexOf('?');
  return q < 0 ? { path: target, rawQuery: null } : { path: target.slice(0, q), rawQuery: target.slice(q + 1) };
}

function percentDecode(s, what) {
  if (/%(?![0-9A-Fa-f]{2})/.test(s)) refuse(`bad percent escape in ${what}`);
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x25) { bytes.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; } else bytes.push(c);   // target is ASCII (checked)
  }
  let out;
  try { out = utf8Strict.decode(Uint8Array.from(bytes)); } catch (_) { refuse(`invalid UTF-8 in ${what}`); }
  return nfc(out, what);
}

function parseQuery(rawQuery, { issuance }) {
  if (rawQuery === null || rawQuery === '') return [];
  const bad = rawQuery.match(/[+;]/);
  if (bad) {
    if (issuance) throw new BindingError(`the query contains a raw "${bad[0]}"; use %${bad[0] === '+' ? '2B or %20' : '3B'} instead`, 'QUERY_NOT_BINDABLE');
    refuse('raw + or ; in query');
  }
  const pairs = [];
  for (const seg of rawQuery.split('&')) {
    if (seg === '') continue;                                         // empty segments are ignored
    const eq = seg.indexOf('=');
    const name = percentDecode(eq < 0 ? seg : seg.slice(0, eq), 'query name');
    const value = percentDecode(eq < 0 ? '' : seg.slice(eq + 1), 'query value');
    pairs.push([name, value]);
  }
  return pairs
    .map((p, i) => ({ p, i }))
    .sort((a, b) => (a.p[0] < b.p[0] ? -1 : a.p[0] > b.p[0] ? 1 : a.i - b.i))   // stable, by name only, UTF-16 code units
    .map((x) => x.p);
}

/** A received request whose body is content-coded is refused: the hash covers the decoded JSON object, and nothing here decodes. Any field line named content-encoding must be `identity`. */
function refuseContentCoding(rawHeaders) {
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    if (String(rawHeaders[i]).toLowerCase() !== 'content-encoding') continue;
    if (String(rawHeaders[i + 1]).replace(/^[ 	]+|[ 	]+$/g, '').toLowerCase() !== 'identity') refuse('content-encoding other than identity');
  }
}

/** rawHeaders: Node's flat [name, value, name, value, ...] array (values are latin1 strings: their bytes are re-read as UTF-8). */
function pickHeaders(rawHeaders, bindHeaders) {
  const out = {};
  for (const name of bindHeaders) {
    const vals = [];
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      if (String(rawHeaders[i]).toLowerCase() !== name) continue;
      let v;
      try { v = utf8Strict.decode(Buffer.from(String(rawHeaders[i + 1]), 'latin1')); } catch (_) { refuse('invalid UTF-8 in a bound header'); }
      vals.push(nfc(v.replace(/^[ \t]+|[ \t]+$/g, ''), 'header value'));
    }
    out[name] = vals.length ? vals.join(', ') : null;
  }
  return out;
}

function parseBody(bodyBytes) {
  const buf = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(bodyBytes || []);
  if (buf.length === 0) return {};
  let parsed;
  try { parsed = parseJcsP1(buf).value; } catch (e) { if (e instanceof JcsError) throw new BindingError(`body: ${e.message}`, 'REQUEST_MISMATCH', e.code); throw e; }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) refuse('body is not a JSON object');
  return parsed;
}

/**
 * Builds the hashed document. `request` = { method, target, rawHeaders, body (bytes) } for a received request, with `bindHeaders` from the artifact.
 * For issuance pass { issuance: true }.
 */
function buildDocument({ method, target, rawHeaders = [], body = Buffer.alloc(0), bodyObject }, bindHeaders, { issuance = false } = {}) {
  validateBindHeaders(bindHeaders);
  const { path, rawQuery } = splitTarget(target);
  if (!issuance) refuseContentCoding(rawHeaders);
  return {
    v: 2,
    method: normalizeMethod(method),
    path,
    query: parseQuery(rawQuery, { issuance }),
    headers: pickHeaders(rawHeaders, bindHeaders),
    body: bodyObject !== undefined ? checkedBodyObject(bodyObject) : parseBody(body),
  };
}

// At issuance (/sign) the body arrives already parsed; it must be a plain JSON object that passes the JCS-P1 value checks.
function checkedBodyObject(o) {
  if (o === null || typeof o !== 'object' || Array.isArray(o)) refuse('body is not a JSON object');
  try { canonicalJcsP1(o); } catch (e) { if (e instanceof JcsError) throw new BindingError(`body: ${e.message}`, 'REQUEST_MISMATCH', e.code); throw e; }
  return o;
}

/**
 * Issuance side: the same document from the parts a /sign caller supplies - `path` (origin-form, no query), optional raw `query` string (no "?"),
 * optional `headers` object (bound names -> values) and the parsed `body` object.
 */
function computeRequestHashV2FromParts({ method, path, query, headers, body }, bindHeaders) {
  const rawHeaders = [];
  for (const [k, v] of Object.entries(headers || {})) rawHeaders.push(String(k), Buffer.from(String(v), 'utf8').toString('latin1'));
  const target = path + (query ? `?${query}` : '');
  return hashDocument(buildDocument({ method, target, rawHeaders, bodyObject: body }, bindHeaders, { issuance: true }));
}

function hashDocument(doc) {
  let canonical;
  try { canonical = canonicalJcsP1(doc); } catch (e) { if (e instanceof JcsError) throw new BindingError(`document: ${e.message}`, 'REQUEST_MISMATCH', e.code); throw e; }
  return crypto.createHash('sha256').update(REQUEST_DOMAIN_V2, 'utf8').update(canonical, 'utf8').digest('hex');
}

/** requestHash(V2) of a received request. Throws BindingError. */
function computeRequestHashV2(request, bindHeaders, opts) {
  return hashDocument(buildDocument(request, bindHeaders, opts));
}

/** Constant-time check of a request against the hash in an artifact. Returns true/false; throws nothing for a mismatch. */
function verifyRequestBindingV2(request, bindHeaders, expectedHashHex) {
  if (typeof expectedHashHex !== 'string' || !/^[0-9a-f]{64}$/.test(expectedHashHex)) return false;
  let actual;
  try { actual = computeRequestHashV2(request, bindHeaders); } catch (e) { if (e instanceof BindingError) return false; throw e; }
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expectedHashHex, 'hex'));
}

module.exports = { computeRequestHashV2FromParts, computeRequestHashV2, verifyRequestBindingV2, buildDocument, hashDocument, validateBindHeaders, BindingError, FORBIDDEN_BOUND_HEADERS, MAX_BOUND_HEADERS };
