'use strict';

/**
 * QODIQA Canonical JSON Serialization — Component #17
 *
 * Implements QODIQA-PROTOCOL-SPEC.md §6.1 CanonicalSerialize(V).
 *
 * Contract:
 *   • Object keys sorted lexicographically (ascending UTF-16 code unit order)
 *     at every depth
 *   • Array element order preserved
 *   • Zero whitespace
 *   • undefined values treated as null (not omitted) — keeps hash output
 *     identical for any code path that passes objects with missing/undefined
 *     fields
 *   • String encoding via JSON.stringify (all control characters escaped)
 *   • NaN / Infinity / -Infinity numbers are a protocol violation (spec
 *     §6.1: "if NaN or Infinity: ERROR") — throws CanonicalizationError
 *   • Object keys "__proto__", "constructor", "prototype" are a protocol
 *     violation (spec §6.1: "if any key is ... : ERROR") — throws
 *     CanonicalizationError rather than silently stripping or admitting the
 *     key, which would otherwise let a tampered payload hash-identical to
 *     the original (a silent security bypass)
 *   • Functions, symbols, and bigints are outside the CanonicalSerialize(V)
 *     value domain (spec §6.1: "Unsupported value types (function, symbol)
 *     MUST cause failure") — throws CanonicalizationError
 *   • Any other non-plain-object exotic value (Date, RegExp, Error, Map,
 *     Set, TypedArray, Buffer, ArrayBuffer, class instances, ...) has no
 *     defined canonical representation either — rather than silently
 *     degrading to `{}` or a lossy partial representation (which would let
 *     logically distinct inputs collide on the same hash), it throws
 *     CanonicalizationError
 *   • Circular references are detected and rejected explicitly — no stack
 *     overflow
 *   • Pathologically deep nesting is rejected explicitly at MAX_DEPTH — no
 *     stack overflow / recursion-exhaustion DoS
 *
 * All signing, verification, hashing, audit chains, transparency roots,
 * evidence packages, and policy fingerprints MUST import this module.
 * No duplicate serializers elsewhere.
 */

const fastStringify = require('fast-json-stable-stringify');

// Generous headroom over the deepest legitimate QODIQA structure (request
// bodies are capped at 10 levels — see MAX_BODY_DEPTH in
// src/validation/schemas/sign.schema.js — and existing adversarial coverage
// exercises payloads nested 200 levels deep expecting successful
// validation); this only exists to fail closed on pathological/attacker-
// supplied nesting well before native recursion limits are ever at risk
// (empirically, unguarded recursion over plain nested objects survives
// ~2000-4999 levels before RangeError; 1000 leaves a large safety margin).
const MAX_DEPTH = 1000;

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

class CanonicalizationError extends TypeError {
  constructor(code, message) {
    super(message);
    this.name = 'CanonicalizationError';
    this.code = code;
  }
}

function _isPlainObject(v) {
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype;
}

// Pre-process value tree: reject protocol-violating / unsupported inputs and
// normalize `undefined` to `null` before handing off to
// fast-json-stable-stringify (which only sorts keys and encodes leaves).
function _normalize(v, seen, depth) {
  if (v === undefined || v === null) return null;

  const t = typeof v;
  if (t === 'string' || t === 'boolean') return v;

  if (t === 'number') {
    if (!Number.isFinite(v)) {
      throw new CanonicalizationError(
        'NON_FINITE_NUMBER',
        'stableStringify: NaN/Infinity is not a valid canonical number (QODIQA-PROTOCOL-SPEC.md §6.1)',
      );
    }
    return v;
  }

  if (t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new CanonicalizationError(
      'UNSUPPORTED_TYPE',
      `stableStringify: cannot serialize a ${t} value (QODIQA-PROTOCOL-SPEC.md §6.1: ` +
      'unsupported value types MUST cause failure)',
    );
  }

  // t === 'object' from here on (arrays included).
  if (depth > MAX_DEPTH) {
    throw new CanonicalizationError(
      'MAX_DEPTH_EXCEEDED',
      `stableStringify: nesting exceeds maximum depth of ${MAX_DEPTH}`,
    );
  }

  if (seen.has(v)) {
    throw new CanonicalizationError('CIRCULAR_REFERENCE', 'stableStringify: circular reference detected');
  }

  if (Array.isArray(v)) {
    seen.add(v);
    const out = v.map((item) => _normalize(item, seen, depth + 1));
    seen.delete(v);
    return out;
  }

  if (!_isPlainObject(v)) {
    const label = (v && v.constructor && v.constructor.name) || Object.prototype.toString.call(v);
    throw new CanonicalizationError(
      'UNSUPPORTED_TYPE',
      `stableStringify: cannot serialize a non-plain-object value (${label}) — only plain objects, ` +
      'arrays, strings, finite numbers, booleans, and null are supported',
    );
  }

  seen.add(v);
  // Use a null-prototype accumulator so that (pre-rejection aside) key
  // enumeration never risks tripping the Object.prototype.__proto__ setter —
  // defense in depth alongside the explicit FORBIDDEN_KEYS check below.
  const out = Object.create(null);
  for (const k of Object.keys(v)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new CanonicalizationError(
        'FORBIDDEN_KEY',
        `stableStringify: object key "${k}" is forbidden (QODIQA-PROTOCOL-SPEC.md §6.1)`,
      );
    }
    out[k] = _normalize(v[k], seen, depth + 1);
  }
  seen.delete(v);
  return out;
}

function stableStringify(value) {
  return fastStringify(_normalize(value, new Set(), 0));
}

stableStringify.CanonicalizationError = CanonicalizationError;

module.exports = stableStringify;
