'use strict';

/**
 * independent verifier — canonical JSON.
 *
 * An independent implementation of the contract
 * (QODIQA-PROTOCOL-SPEC.md §6.1 CanonicalSerialize). It deliberately imports NOTHING from
 * src/ and no npm package: only ECMAScript built-ins. JSON.stringify is used for the two
 * leaf encodings the contract defines by reference to it (string escaping, and object-key
 * escaping); everything structural is implemented here.
 *
 *   null / undefined        → "null" (undefined is NOT omitted — also inside objects/arrays)
 *   boolean                 → "true" | "false"
 *   finite number           → String(n)   (ECMAScript Number::toString; -0 → "0")
 *   NaN / ±Infinity         → error NON_FINITE_NUMBER
 *   string                  → JSON.stringify(s)
 *   array                   → "[" + elements joined by "," + "]"   (order preserved)
 *   plain object            → "{" + "k":v pairs, keys sorted by UTF-16 code unit, joined by "," + "}"
 *   key __proto__/constructor/prototype      → error FORBIDDEN_KEY
 *   function / symbol / bigint               → error UNSUPPORTED_TYPE
 *   non-plain object (Date, Buffer, Map, …)  → error UNSUPPORTED_TYPE
 *   an object/array nested deeper than 1000  → error MAX_DEPTH_EXCEEDED
 *   a cycle                                   → error CIRCULAR_REFERENCE
 * Check order for an object/array value: depth, then cycle, then array/plain-object.
 */

const MAX_DEPTH = 1000;
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

class CanonicalError extends Error {
  constructor(code, message) { super(message); this.name = 'CanonicalError'; this.code = code; }
}

function encode(value, depth, ancestors) {
  if (value === undefined || value === null) return 'null';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new CanonicalError('NON_FINITE_NUMBER', 'NaN/Infinity has no canonical form');
    return String(value);
  }
  if (t === 'function' || t === 'symbol' || t === 'bigint') {
    throw new CanonicalError('UNSUPPORTED_TYPE', `a ${t} has no canonical form`);
  }
  if (depth > MAX_DEPTH) throw new CanonicalError('MAX_DEPTH_EXCEEDED', `nesting deeper than ${MAX_DEPTH}`);
  if (ancestors.has(value)) throw new CanonicalError('CIRCULAR_REFERENCE', 'circular reference');

  if (Array.isArray(value)) {
    ancestors.add(value);
    const parts = [];
    for (let i = 0; i < value.length; i++) parts.push(encode(value[i], depth + 1, ancestors));
    ancestors.delete(value);
    return '[' + parts.join(',') + ']';
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    throw new CanonicalError('UNSUPPORTED_TYPE', 'only plain objects have a canonical form');
  }
  ancestors.add(value);
  const keys = Object.keys(value);
  for (const k of keys) {
    if (FORBIDDEN_KEYS.has(k)) throw new CanonicalError('FORBIDDEN_KEY', `key "${k}" is forbidden`);
  }
  keys.sort(); // default comparator: UTF-16 code unit order
  const parts = [];
  for (const k of keys) parts.push(JSON.stringify(k) + ':' + encode(value[k], depth + 1, ancestors));
  ancestors.delete(value);
  return '{' + parts.join(',') + '}';
}

function canonicalize(value) {
  return encode(value, 0, new Set());
}

module.exports = { canonicalize, CanonicalError, MAX_DEPTH };
