/**
 * QODIQA Canonical JSON Serialization — SDK-side port
 *
 * A byte-identical client-side port of the server's own
 * `src/utils/stableStringify.js` (see QODIQA-PROTOCOL-SPEC.md §6.1
 * CanonicalSerialize(V)). Any artifact whose canonical form differs between
 * this implementation and the server's would silently verify against the
 * wrong bytes, so this module reuses the exact same `fast-json-stable-stringify`
 * package the server delegates to, wrapped in the same pre-normalization
 * guard the server applies before handing off to it.
 *
 * Contract (identical to the server):
 *   - Object keys sorted lexicographically (ascending UTF-16 code unit order)
 *     at every depth.
 *   - Array element order preserved.
 *   - Zero whitespace.
 *   - `undefined` values are treated as `null`, not omitted.
 *   - `NaN` / `Infinity` / `-Infinity` are a protocol violation — throws.
 *   - Object keys `__proto__`, `constructor`, `prototype` are a protocol
 *     violation — throws (rather than silently stripping/admitting them,
 *     which would let a tampered payload hash-identical to the original).
 *   - Functions, symbols, bigints, and any other non-plain-object exotic
 *     value (Date, RegExp, Map, Set, TypedArray, class instances, ...) have
 *     no defined canonical representation — throws.
 *   - Circular references are detected and rejected.
 *   - Nesting beyond MAX_DEPTH is rejected.
 *
 * @module
 */

import fastStringify from 'fast-json-stable-stringify';

const MAX_DEPTH = 1000;

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export type CanonicalizationErrorCode =
  | 'NON_FINITE_NUMBER'
  | 'UNSUPPORTED_TYPE'
  | 'MAX_DEPTH_EXCEEDED'
  | 'CIRCULAR_REFERENCE'
  | 'FORBIDDEN_KEY';

export class CanonicalizationError extends TypeError {
  readonly code: CanonicalizationErrorCode;

  constructor(code: CanonicalizationErrorCode, message: string) {
    super(message);
    this.name = 'CanonicalizationError';
    this.code = code;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

type Canonical = null | string | number | boolean | Canonical[] | { [key: string]: Canonical };

// Pre-process the value tree: reject protocol-violating / unsupported inputs
// and normalize `undefined` to `null`, exactly mirroring stableStringify.js's
// `_normalize`. `fast-json-stable-stringify` only sorts keys and encodes leaves.
function normalize(value: unknown, seen: Set<unknown>, depth: number): Canonical {
  if (value === undefined || value === null) return null;

  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value as string | boolean;

  if (t === 'number') {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new CanonicalizationError(
        'NON_FINITE_NUMBER',
        'stableStringify: NaN/Infinity is not a valid canonical number (QODIQA-PROTOCOL-SPEC.md §6.1)',
      );
    }
    return n;
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

  if (seen.has(value)) {
    throw new CanonicalizationError('CIRCULAR_REFERENCE', 'stableStringify: circular reference detected');
  }

  if (Array.isArray(value)) {
    seen.add(value);
    const out = value.map((item) => normalize(item, seen, depth + 1));
    seen.delete(value);
    return out;
  }

  if (!isPlainObject(value)) {
    const ctor = (value as { constructor?: { name?: string } })?.constructor;
    const label = ctor?.name || Object.prototype.toString.call(value);
    throw new CanonicalizationError(
      'UNSUPPORTED_TYPE',
      `stableStringify: cannot serialize a non-plain-object value (${label}) — only plain objects, ` +
        'arrays, strings, finite numbers, booleans, and null are supported',
    );
  }

  seen.add(value);
  const out: { [key: string]: Canonical } = Object.create(null);
  for (const k of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new CanonicalizationError(
        'FORBIDDEN_KEY',
        `stableStringify: object key "${k}" is forbidden (QODIQA-PROTOCOL-SPEC.md §6.1)`,
      );
    }
    out[k] = normalize(value[k], seen, depth + 1);
  }
  seen.delete(value);
  return out;
}

/**
 * Produce the canonical JSON string for `value`, matching the server's
 * `stableStringify` byte-for-byte.
 *
 * @throws {@link CanonicalizationError}
 */
export function stableStringify(value: unknown): string {
  return fastStringify(normalize(value, new Set(), 0));
}
