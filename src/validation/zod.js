'use strict';

/**
 * (dependency upgrade zod 3 -> 4): the ONE entry point every QODIQA module uses for zod.
 *
 * zod 4 changed two things QODIQA's HTTP/config contract depends on, and this module keeps both exactly as they were
 * under zod 3.25 (verified by the differential harness, ~25k inputs over every
 * exported schema):
 *
 *  1. Default issue MESSAGES. Routes return `error.issues[0].message` in 400 bodies, compliance.js branches on the
 *     literal 'Required', bootValidator/kmsConfig/rateLimit join messages into operator-facing errors. zod 4's English
 *     locale rewords every default message ("Invalid input: expected string, received undefined" for "Required", ...).
 *     `z.config({ customError })` installs the zod-3 English wording as the global default; messages a schema sets
 *     itself (`.min(1, 'x is required')`, `{ error }`, refine messages) take precedence over it exactly as before.
 *
 *  2. `.int()` semantics. zod 4's `.int()` also rejects integers outside the safe-integer range and aborts the rest of
 *     the object's validation; zod 3's accepted any integer and kept validating. `integer()` below is zod 3's check
 *     (same issue code/fields/message, non-aborting); schemas use `.check(integer())` where they used `.int()`.
 *     Any tightening (e.g. a safe-integer bound) is a product decision, not something a dependency bump may change.
 *
 * Issue `code` values follow zod 4 (e.g. `invalid_value` where zod 3 said `invalid_enum_value`); QODIQA code only
 * branches on `custom` and `unrecognized_keys`, which are unchanged.
 */

const { z } = require('zod');

// zod 3's ZodParsedType names (zod/v3 helpers/util getParsedType)
function parsedType(v) {
  switch (typeof v) {
    case 'undefined': return 'undefined';
    case 'string': return 'string';
    case 'number': return Number.isNaN(v) ? 'nan' : 'number';
    case 'boolean': return 'boolean';
    case 'function': return 'function';
    case 'bigint': return 'bigint';
    case 'symbol': return 'symbol';
    case 'object':
      if (Array.isArray(v)) return 'array';
      if (v === null) return 'null';
      if (typeof v.then === 'function' && typeof v.catch === 'function') return 'promise';
      if (typeof Map !== 'undefined' && v instanceof Map) return 'map';
      if (typeof Set !== 'undefined' && v instanceof Set) return 'set';
      if (typeof Date !== 'undefined' && v instanceof Date) return 'date';
      return 'object';
    default: return 'unknown';
  }
}
const joinValues = (arr, sep = ' | ') => arr.map((v) => (typeof v === 'string' ? `'${v}'` : v)).join(sep);
const jsonStringifyReplacer = (_, v) => (typeof v === 'bigint' ? v.toString() : v);
const EXPECTED = { record: 'object', int: 'integer' };

/** zod 3's `.int()` as a zod 4 check: any integer, non-aborting, issue { code: invalid_type, expected: integer, received: float }. Use `.check(integer())`. */
function integer() {
  const ch = z.superRefine((val, ctx) => {
    if (!Number.isInteger(val)) {
      ctx.addIssue({ code: 'invalid_type', expected: 'integer', received: 'float', message: 'Expected integer, received float' });
    }
  });
  /** @type {any} */ (ch._zod.def).qodiqaZod3Integer = true;
  return ch;
}

const tooSmall = (origin, min, inclusive, exact) => {
  if (origin === 'array' || origin === 'set') return `${origin === 'set' ? 'Set' : 'Array'} must contain ${exact ? 'exactly' : inclusive ? 'at least' : 'more than'} ${min} element(s)`;
  if (origin === 'string') return `String must contain ${exact ? 'exactly' : inclusive ? 'at least' : 'over'} ${min} character(s)`;
  if (origin === 'number' || origin === 'int' || origin === 'bigint') return `${origin === 'bigint' ? 'BigInt' : 'Number'} must be ${exact ? 'exactly equal to ' : inclusive ? 'greater than or equal to ' : 'greater than '}${min}`;
  if (origin === 'date') return `Date must be ${exact ? 'exactly equal to ' : inclusive ? 'greater than or equal to ' : 'greater than '}${new Date(Number(min))}`;
  return 'Invalid input';
};
const tooBig = (origin, max, inclusive, exact) => {
  if (origin === 'array' || origin === 'set') return `${origin === 'set' ? 'Set' : 'Array'} must contain ${exact ? 'exactly' : inclusive ? 'at most' : 'less than'} ${max} element(s)`;
  if (origin === 'string') return `String must contain ${exact ? 'exactly' : inclusive ? 'at most' : 'under'} ${max} character(s)`;
  if (origin === 'number' || origin === 'int' || origin === 'bigint') return `${origin === 'bigint' ? 'BigInt' : 'Number'} must be ${exact ? 'exactly' : inclusive ? 'less than or equal to' : 'less than'} ${max}`;
  if (origin === 'date') return `Date must be ${exact ? 'exactly' : inclusive ? 'smaller than or equal to' : 'smaller than'} ${new Date(Number(max))}`;
  return 'Invalid input';
};

/**
 * zod 3 accepted ±Infinity as a number and reported the first failing check instead (zod 4 rejects it at the type
 * level). Reachable only through z.coerce.number() on a query string like `?page=Infinity` (JSON has no Infinity);
 * every such QODIQA field rejects it under both versions — this keeps the message zod 3 gave.
 */
function infiniteNumberMessage(inst, v) {
  const checks = (inst && inst._zod && inst._zod.def && inst._zod.def.checks) || [];
  for (const c of checks) {
    const d = c && c._zod && c._zod.def;
    if (!d) continue;
    if (d.check === 'custom' && d.qodiqaZod3Integer) return 'Expected integer, received float';
    if (d.check === 'number_format') return 'Expected integer, received float';
    if (d.check === 'greater_than' && (d.inclusive ? v < d.value : v <= d.value)) return tooSmall('number', d.value, d.inclusive, false);
    if (d.check === 'less_than' && (d.inclusive ? v > d.value : v >= d.value)) return tooBig('number', d.value, d.inclusive, false);
  }
  return undefined; // zod 3 would have accepted it: fall back to zod 4's own message
}

/** zod 3.25 English default messages (zod/v3 locales/en), keyed off zod 4 raw issues. */
function zod3Message(iss) {
  const input = iss.input;
  const instType = iss.inst && iss.inst._zod && iss.inst._zod.def && iss.inst._zod.def.type;
  switch (iss.code) {
    case 'invalid_type': {
      if (iss.expected === 'number' && typeof input === 'number' && !Number.isNaN(input) && !Number.isFinite(input)) return infiniteNumberMessage(iss.inst, input);
      const received = parsedType(input);
      if (received === 'undefined') return 'Required';
      return `Expected ${EXPECTED[iss.expected] || iss.expected}, received ${received}`;
    }
    case 'invalid_value': {
      const values = iss.values || [];
      if (instType === 'literal') return `Invalid literal value, expected ${JSON.stringify(values[0], jsonStringifyReplacer)}`;
      // zod 3 enums type-checked strings first: a non-string is an invalid_type against the joined values
      if (instType === 'enum' && typeof input !== 'string') return input === undefined ? 'Required' : `Expected ${joinValues(values)}, received ${parsedType(input)}`;
      return `Invalid enum value. Expected ${joinValues(values)}, received '${input}'`;
    }
    case 'unrecognized_keys': return `Unrecognized key(s) in object: ${joinValues(iss.keys || [], ', ')}`;
    case 'invalid_union':
      if (iss.note === 'No matching discriminator') return `Invalid discriminator value. Expected ${joinValues(iss.options || [])}`;
      return 'Invalid input';
    case 'too_small': return tooSmall(iss.origin, iss.minimum, iss.inclusive, iss.exact);
    case 'too_big': return tooBig(iss.origin, iss.maximum, iss.inclusive, iss.exact);
    case 'invalid_format': {
      const f = iss.format;
      if (f === 'regex') return 'Invalid';
      if (f === 'starts_with') return `Invalid input: must start with "${iss.prefix}"`;
      if (f === 'ends_with') return `Invalid input: must end with "${iss.suffix}"`;
      if (f === 'includes') return `Invalid input: must include "${iss.includes}"`;
      return `Invalid ${f}`;
    }
    case 'not_multiple_of': return `Number must be a multiple of ${iss.divisor}`;
    case 'custom': return 'Invalid input';
    default: return undefined; // anything else: zod 4's own locale message
  }
}

z.config({ customError: zod3Message });

module.exports = { z, integer, zod3Message };
