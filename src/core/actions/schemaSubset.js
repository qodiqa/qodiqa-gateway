'use strict';

/**
 * A small, deterministic JSON Schema subset for tool arguments. It is NOT general JSON Schema: no $ref, no remote or dynamic loading, no `pattern`
 * (a caller-supplied regex is a denial-of-service risk), no format assertions. A schema that uses anything outside the subset is refused when the tool is
 * registered (SCHEMA_UNSUPPORTED_KEYWORD), never silently ignored - an unvalidated argument would be a hole in the allowlist.
 *
 * Supported: type (object|array|string|number|integer|boolean|null, or a list), properties, required, additionalProperties (boolean; DEFAULT FALSE - stricter
 * than JSON Schema: an argument the schema does not name is refused), items (a schema), enum, const, minimum, maximum, exclusiveMinimum, exclusiveMaximum,
 * minLength, maxLength, minItems, maxItems, uniqueItems, anyOf. Annotations (title, description, default, examples, $comment) are ignored.
 *
 * validate(schema, value) -> { ok: true } | { ok: false, path: '/a/b', code, message }   (the FIRST violation, depth-first in key order)
 */

const ANNOTATIONS = new Set(['title', 'description', 'default', 'examples', '$comment']);
const KEYWORDS = new Set(['type', 'properties', 'required', 'additionalProperties', 'items', 'enum', 'const', 'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum',
  'minLength', 'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'anyOf']);
const TYPES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);
const MAX_DEPTH = 16;
const MAX_NODES = 2000;

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

class SchemaError extends Error { constructor(code, detail) { super(`${code}: ${detail}`); this.name = 'SchemaError'; this.code = code; } }

/** Throws SchemaError when the schema leaves the subset. */
function assertSupported(schema, depth = 0, counter = { n: 0 }) {
  if (!isObj(schema)) throw new SchemaError('SCHEMA_INVALID', 'a schema is an object');
  if (depth > MAX_DEPTH) throw new SchemaError('SCHEMA_TOO_DEEP', `more than ${MAX_DEPTH} levels`);
  if (++counter.n > MAX_NODES) throw new SchemaError('SCHEMA_TOO_LARGE', `more than ${MAX_NODES} subschemas`);
  for (const k of Object.keys(schema)) {
    if (ANNOTATIONS.has(k)) continue;
    if (!KEYWORDS.has(k)) throw new SchemaError('SCHEMA_UNSUPPORTED_KEYWORD', k);
  }
  if (schema.type !== undefined) {
    const t = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!t.length || t.some((x) => !TYPES.has(x))) throw new SchemaError('SCHEMA_INVALID', 'type');
  }
  if (schema.properties !== undefined) {
    if (!isObj(schema.properties)) throw new SchemaError('SCHEMA_INVALID', 'properties');
    for (const [k, v] of Object.entries(schema.properties)) { if (['__proto__', 'constructor', 'prototype'].includes(k)) throw new SchemaError('SCHEMA_INVALID', 'forbidden property name'); assertSupported(v, depth + 1, counter); }
  }
  if (schema.required !== undefined && !(Array.isArray(schema.required) && schema.required.every((x) => typeof x === 'string') && new Set(schema.required).size === schema.required.length)) throw new SchemaError('SCHEMA_INVALID', 'required');
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== 'boolean') throw new SchemaError('SCHEMA_INVALID', 'additionalProperties must be a boolean');
  if (schema.items !== undefined) assertSupported(schema.items, depth + 1, counter);
  if (schema.anyOf !== undefined) { if (!Array.isArray(schema.anyOf) || !schema.anyOf.length) throw new SchemaError('SCHEMA_INVALID', 'anyOf'); for (const s of schema.anyOf) assertSupported(s, depth + 1, counter); }
  if (schema.enum !== undefined && !(Array.isArray(schema.enum) && schema.enum.length > 0)) throw new SchemaError('SCHEMA_INVALID', 'enum');
  for (const k of ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum']) if (schema[k] !== undefined && !Number.isFinite(schema[k])) throw new SchemaError('SCHEMA_INVALID', k);
  for (const k of ['minLength', 'maxLength', 'minItems', 'maxItems']) if (schema[k] !== undefined && !(Number.isInteger(schema[k]) && schema[k] >= 0)) throw new SchemaError('SCHEMA_INVALID', k);
  if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== 'boolean') throw new SchemaError('SCHEMA_INVALID', 'uniqueItems');
}

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v === 'number' ? (Number.isInteger(v) ? 'integer' : 'number') : typeof v);
const typeMatches = (want, v) => { const t = typeOf(v); return want === t || (want === 'number' && t === 'integer'); };
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  const ka = Object.keys(a).sort(); const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && deepEqual(a[k], b[k]));
}

function check(schema, value, path) {
  const fail = (code, message) => ({ ok: false, path: path || '/', code, message });
  if (schema.type !== undefined) {
    const want = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!want.some((t) => typeMatches(t, value))) return fail('TYPE', `expected ${want.join(' | ')}, got ${typeOf(value)}`);
  }
  if (schema.enum !== undefined && !schema.enum.some((e) => deepEqual(e, value))) return fail('ENUM', 'not one of the allowed values');
  if (schema.const !== undefined && !deepEqual(schema.const, value)) return fail('CONST', 'not the required value');
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) return fail('MINIMUM', `below ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) return fail('MAXIMUM', `above ${schema.maximum}`);
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) return fail('EXCLUSIVE_MINIMUM', `not above ${schema.exclusiveMinimum}`);
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) return fail('EXCLUSIVE_MAXIMUM', `not below ${schema.exclusiveMaximum}`);
  }
  if (typeof value === 'string') {
    const len = [...value].length;
    if (schema.minLength !== undefined && len < schema.minLength) return fail('MIN_LENGTH', `shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && len > schema.maxLength) return fail('MAX_LENGTH', `longer than ${schema.maxLength}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) return fail('MIN_ITEMS', `fewer than ${schema.minItems}`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) return fail('MAX_ITEMS', `more than ${schema.maxItems}`);
    if (schema.uniqueItems && value.some((x, i) => value.findIndex((y) => deepEqual(x, y)) !== i)) return fail('UNIQUE_ITEMS', 'items are not unique');
    if (schema.items !== undefined) for (let i = 0; i < value.length; i++) { const r = check(schema.items, value[i], `${path}/${i}`); if (!r.ok) return r; }
  }
  if (isObj(value)) {
    const props = schema.properties || {};
    for (const k of schema.required || []) if (!Object.prototype.hasOwnProperty.call(value, k)) return { ok: false, path: `${path}/${k}`, code: 'REQUIRED', message: 'missing required property' };
    for (const k of Object.keys(value)) {
      if (Object.prototype.hasOwnProperty.call(props, k)) { const r = check(props[k], value[k], `${path}/${k}`); if (!r.ok) return r; }
      else if (schema.additionalProperties !== true) return { ok: false, path: `${path}/${k}`, code: 'ADDITIONAL_PROPERTY', message: 'property not named by the schema' };
    }
  }
  if (schema.anyOf !== undefined && !schema.anyOf.some((s) => check(s, value, path).ok)) return fail('ANY_OF', 'matches none of the alternatives');
  return { ok: true };
}

/** Validate a value against a schema of the subset (the schema must already have passed assertSupported). */
function validate(schema, value) { return check(schema, value, ''); }

module.exports = { SchemaError, assertSupported, validate, KEYWORDS };
