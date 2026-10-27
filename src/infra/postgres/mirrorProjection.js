'use strict';

/**
 * Reversible Unicode projection for the PostgreSQL audit_chain MIRROR.
 *
 * Why: PostgreSQL per-field columns cannot hold the whole JS string domain — U+0000 is refused in TEXT and JSONB, a
 * lone UTF-16 surrogate is refused in JSONB and silently ALTERED in TEXT.
 * The file log (authoritative) and the `canonical` / `hash` / `prev_hash` columns are never projected: `canonical` is
 * JSON text that already escapes those code units, so the hashed bytes are untouched. Only the per-field copies are
 * projected, and every reader that rebuilds an entry from them decodes first (R-F3 / R-F4).
 *
 * P(s), one UTF-16 code unit at a time (§2):
 *   `\`  → `\\`        `"` → `\"` (R-F1)        U+0020–U+007E other than `\` and `"` → itself
 *   U+0000–U+001F, U+007F, U+0080–U+FFFF (every surrogate, paired or lone) → `\u` + 4 LOWERCASE hex digits
 * Always the 4-digit form (no `\n` / `\t` short forms) → one token per code unit → P is injective, prefix-free.
 *
 * P⁻¹(t) (§9): `\\` → `\`, `\"` → `"`, `\u` + exactly 4 lowercase hex → that code unit, any other character → itself;
 * any other backslash sequence, uppercase hex, a truncated `\u`, or a character P can never emit (non-printable / non-
 * ASCII) → MirrorDecodeError. A corrupt mirror value is reported, never guessed (R-F5).
 *
 * JSON (JSONB columns, §6): P / P⁻¹ applied recursively to every string value and every object key; numbers, booleans,
 * null and array order unchanged.
 *
 * Marker (R-F2): audit_chain.mirror_encoding — 0 = native (legacy, never back-filled), 1 = P applied to EVERY per-field
 * column of the row. Independent of schema_version.
 */

const MIRROR_ENCODING_NATIVE = 0;
const MIRROR_ENCODING_ESCAPED = 1;

class MirrorDecodeError extends Error {
  constructor(message, detail = {}) {
    super(`mirror_decode_error: ${message}`);
    this.name = 'MirrorDecodeError';
    this.code = 'MIRROR_DECODE_ERROR';
    Object.assign(this, detail);
  }
}

const HEX = '0123456789abcdef';
function _u(c) { return '\\u' + HEX[(c >> 12) & 15] + HEX[(c >> 8) & 15] + HEX[(c >> 4) & 15] + HEX[c & 15]; }

/** P: string → pure printable-ASCII string. */
function encodeString(s) {
  if (typeof s !== 'string') throw new TypeError('mirrorProjection.encodeString: expected a string');
  let out = '';
  let start = 0;                                     // run of literal characters, flushed lazily
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let tok = null;
    if (c === 0x5c) tok = '\\\\';
    else if (c === 0x22) tok = '\\"';
    else if (c < 0x20 || c >= 0x7f) tok = _u(c);
    if (tok !== null) { out += s.slice(start, i) + tok; start = i + 1; }
  }
  return start === 0 ? s : out + s.slice(start);
}

function _hexVal(ch) {
  const c = ch.charCodeAt(0);
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  return -1;                                         // uppercase is NOT a valid P token
}

/** P⁻¹: projected string → original string; throws MirrorDecodeError on anything P cannot have produced. */
function decodeString(t, where = null) {
  if (typeof t !== 'string') throw new MirrorDecodeError('expected a string', { where });
  let out = '';
  let start = 0;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c === 0x5c) {
      out += t.slice(start, i);
      const n = t[i + 1];
      if (n === '\\') { out += '\\'; i += 1; }
      else if (n === '"') { out += '"'; i += 1; }
      else if (n === 'u') {
        if (i + 6 > t.length) throw new MirrorDecodeError(`truncated \\u escape at ${i}`, { where, offset: i });
        let v = 0;
        for (let k = 2; k < 6; k++) {
          const h = _hexVal(t[i + k]);
          if (h < 0) throw new MirrorDecodeError(`invalid \\u escape at ${i}`, { where, offset: i });
          v = (v << 4) | h;
        }
        out += String.fromCharCode(v);
        i += 5;
      } else {
        throw new MirrorDecodeError(`invalid escape \\${n === undefined ? '<end>' : n} at ${i}`, { where, offset: i });
      }
      start = i + 1;
    } else if (c < 0x20 || c >= 0x7f || c === 0x22) {
      // P only ever emits printable ASCII and never a bare quote — anything else is not a P image
      throw new MirrorDecodeError(`character U+${c.toString(16).padStart(4, '0')} cannot appear in a projected value (offset ${i})`, { where, offset: i });
    }
  }
  return start === 0 ? t : out + t.slice(start);
}

/** P over a JSON value: every string value and object key, recursively. */
function encodeJson(v) {
  if (typeof v === 'string') return encodeString(v);
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(encodeJson);
  const o = {};
  for (const k of Object.keys(v)) Object.defineProperty(o, encodeString(k), { value: encodeJson(v[k]), enumerable: true, configurable: true, writable: true });
  return o;
}

/** P⁻¹ over a JSON value; throws MirrorDecodeError on any corrupt string or key, or a key collision. */
function decodeJson(v, where = null) {
  if (typeof v === 'string') return decodeString(v, where);
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => decodeJson(x, where));
  const o = {};
  for (const k of Object.keys(v)) {
    const dk = decodeString(k, where);
    if (Object.prototype.hasOwnProperty.call(o, dk)) throw new MirrorDecodeError(`duplicate key after decoding (${JSON.stringify(dk)})`, { where });
    // defineProperty: a decoded "__proto__" key stays an own data property, exactly as JSON.parse would leave it
    Object.defineProperty(o, dk, { value: decodeJson(v[k], where), enumerable: true, configurable: true, writable: true });
  }
  return o;
}

/** Interpret a row's mirror_encoding value: 0/1 (absent/null on a pre-075 row = 0). Anything else is undecodable. */
function encodingOf(raw, where = null) {
  if (raw === undefined || raw === null) return MIRROR_ENCODING_NATIVE;
  const n = Number(raw);
  if (n === MIRROR_ENCODING_NATIVE || n === MIRROR_ENCODING_ESCAPED) return n;
  throw new MirrorDecodeError(`unknown mirror_encoding ${JSON.stringify(raw)}`, { where });
}

// The audit_chain per-field columns (entry field names). §1: every TEXT/VARCHAR column and every JSONB column other
// than canonical / hash / prev_hash. Non-string columns (recorded_at, verification_result, schema_version, seq,
// mirror_encoding) are not projected.
const MIRROR_TEXT_FIELDS = Object.freeze([
  'artifactId', 'decision', 'highResTime', 'inputHash', 'signature', 'requestHash', 'policyHash', 'nonce', 'tenantId',
  'publicKeyId', 'provider', 'model', 'stage', 'reason', 'responseId',
  'entryType', 'outputHash', 'requestId', 'organizationId', 'executingProvider',
  // audit v8 (migration 083): the text-valued new fields; the numeric ones (issuedAt, protocolVersion, actionSeq, bytesDelivered) are native columns
  'agentId', 'sessionId', 'actionHash', 'approvalRef', 'completionStatus',
]);
const MIRROR_JSON_FIELDS = Object.freeze(['executionContext', 'consentProvenance', 'policyDecision', 'callerContext', 'semantic', 'tokenUsage', 'dlp']);

/**
 * Writer side: a shallow copy of `entry` whose per-field values are projected (P); null / undefined / non-string
 * scalars pass unchanged. canonical / hash / prevHash are untouched. Every row written with it is mirror_encoding = 1.
 */
function projectEntryForMirror(entry) {
  const m = { ...entry };
  for (const f of MIRROR_TEXT_FIELDS) if (typeof entry[f] === 'string') m[f] = encodeString(entry[f]);
  for (const f of MIRROR_JSON_FIELDS) if (entry[f] !== null && entry[f] !== undefined) m[f] = encodeJson(entry[f]);
  return m;
}

/**
 * Reader side (the PostgreSQL → entry boundary, R-F4): `row` carries camelCase entry fields plus `mirrorEncoding`
 * (the row's mirror_encoding). Returns a copy with `mirrorEncoding` removed and, when it is 1, every present per-field
 * value decoded (P⁻¹). Native (0 / absent) rows are returned as stored — never rewritten or guessed (R-F5). A corrupt
 * projected value or an unknown marker throws MirrorDecodeError naming the field and the row.
 */
// Audit v8 (migration 083): the ten new hashed fields exist only on schema_version 8 rows. A row of a lower version is
// returned without the keys (so hydrated entries keep exactly the shape entryBuilder built); a v8 row gets each field,
// null when not stated, with the BIGINT columns (pg returns them as strings) converted to numbers — every stored value is
// a safe integer by construction (the shape check refuses anything else).
const V8_ROW_FIELDS = Object.freeze(['issuedAt', 'protocolVersion', 'agentId', 'sessionId', 'actionSeq', 'actionHash', 'approvalRef', 'dlp', 'bytesDelivered', 'completionStatus']);
const V8_ROW_NUMERIC = Object.freeze(['issuedAt', 'protocolVersion', 'actionSeq', 'bytesDelivered']);
function _v8Row(rest) {
  if (Number(rest.schemaVersion) !== 8) { for (const f of V8_ROW_FIELDS) delete rest[f]; return rest; }
  for (const f of V8_ROW_FIELDS) {
    const v = rest[f] ?? null;
    rest[f] = v !== null && V8_ROW_NUMERIC.includes(f) ? Number(v) : v;
  }
  return rest;
}

function decodeMirrorRow(row, where = null) {
  const { mirrorEncoding, ...rest } = row;
  if (encodingOf(mirrorEncoding, where) === MIRROR_ENCODING_NATIVE) return _v8Row(rest);
  for (const f of MIRROR_TEXT_FIELDS) {
    if (typeof rest[f] === 'string') rest[f] = decodeString(rest[f], `${where || 'row'}.${f}`);
    else if (rest[f] !== null && rest[f] !== undefined) throw new MirrorDecodeError(`${f} is not a string`, { where });
  }
  for (const f of MIRROR_JSON_FIELDS) if (rest[f] !== null && rest[f] !== undefined) rest[f] = decodeJson(rest[f], `${where || 'row'}.${f}`);
  return _v8Row(rest);
}

module.exports = {
  MIRROR_ENCODING_NATIVE, MIRROR_ENCODING_ESCAPED, MirrorDecodeError, MIRROR_TEXT_FIELDS, MIRROR_JSON_FIELDS,
  encodeString, decodeString, encodeJson, decodeJson, encodingOf, projectEntryForMirror, decodeMirrorRow,
};
