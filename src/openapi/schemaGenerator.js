'use strict';

/**
 * Schema Generator — OpenAPI Component #42
 *
 * Utility functions that build JSON Schema / OpenAPI Schema Objects.
 * Each function returns a plain object — no classes, no state.
 *
 * These helpers eliminate repetition across the components builder and
 * route scanner, and keep schema definitions consistent.
 */

// ── Scalar helpers ────────────────────────────────────────────────────────────

function makeString(opts) {
  opts = opts || {};
  const s = { type: 'string' };
  if (opts.format)      s.format      = opts.format;
  if (opts.minLength !== undefined) s.minLength = opts.minLength;
  if (opts.maxLength !== undefined) s.maxLength = opts.maxLength;
  if (opts.pattern)     s.pattern     = opts.pattern;
  if (opts.enum)        s.enum        = opts.enum;
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  if (opts.default !== undefined) s.default = opts.default;
  return s;
}

function makeInteger(opts) {
  opts = opts || {};
  const s = { type: 'integer' };
  if (opts.minimum !== undefined) s.minimum = opts.minimum;
  if (opts.maximum !== undefined) s.maximum = opts.maximum;
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  if (opts.default !== undefined) s.default = opts.default;
  return s;
}

function makeNumber(opts) {
  opts = opts || {};
  const s = { type: 'number' };
  if (opts.minimum !== undefined) s.minimum = opts.minimum;
  if (opts.maximum !== undefined) s.maximum = opts.maximum;
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  if (opts.default !== undefined) s.default = opts.default;
  return s;
}

function makeBoolean(opts) {
  opts = opts || {};
  const s = { type: 'boolean' };
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  if (opts.default !== undefined) s.default = opts.default;
  return s;
}

// ── Composite helpers ─────────────────────────────────────────────────────────

function makeArray(items, opts) {
  opts = opts || {};
  const s = { type: 'array', items };
  if (opts.minItems !== undefined) s.minItems = opts.minItems;
  if (opts.maxItems !== undefined) s.maxItems = opts.maxItems;
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  return s;
}

function makeObject(properties, opts) {
  opts = opts || {};
  const s = { type: 'object', properties };
  if (opts.required && opts.required.length > 0) s.required = opts.required;
  if (opts.description) s.description = opts.description;
  if (opts.example !== undefined) s.example = opts.example;
  if (opts.additionalProperties !== undefined) s.additionalProperties = opts.additionalProperties;
  return s;
}

// ── Reference helper ──────────────────────────────────────────────────────────

function ref(name) {
  return { '$ref': `#/components/schemas/${name}` }; // eslint-disable-line dot-notation
}

function responseRef(name) {
  return { '$ref': `#/components/responses/${name}` }; // eslint-disable-line dot-notation
}

function paramRef(name) {
  return { '$ref': `#/components/parameters/${name}` }; // eslint-disable-line dot-notation
}

// ── Composition helpers ───────────────────────────────────────────────────────

function makeOneOf(schemas, opts) {
  opts = opts || {};
  const s = { oneOf: schemas };
  if (opts.description) s.description = opts.description;
  return s;
}

function makeNullable(schema) {
  return { oneOf: [schema, { type: 'null' }] };
}

// ── Common reusable schemas ───────────────────────────────────────────────────

const UUID_SCHEMA = Object.freeze(makeString({
  format: 'uuid',
  pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  description: 'UUID v4 identifier',
  example: '550e8400-e29b-41d4-a716-446655440000',
}));

const ISO8601_SCHEMA = Object.freeze(makeString({
  format: 'date-time',
  description: 'ISO 8601 timestamp',
  example: '2025-06-30T12:00:00.000Z',
}));

const ACTOR_ID_SCHEMA = Object.freeze(makeString({
  minLength: 1,
  maxLength: 256,
  pattern: '^[a-zA-Z0-9._:@/-]{1,256}$',
  description: 'Actor identifier — user, service, or system identity',
  example: 'user@example.com',
}));

const ACTION_SCHEMA = Object.freeze(makeString({
  minLength: 1,
  maxLength: 256,
  pattern: '^[a-zA-Z0-9 _:@/-]{1,256}$',
  description: 'Action name representing the AI operation',
  example: 'data:process',
}));

const SCOPE_SCHEMA = Object.freeze(makeString({
  minLength: 1,
  maxLength: 128,
  pattern: '^[a-zA-Z0-9_-]{1,128}$',
  description: 'Consent scope identifier',
  example: 'data_pii',
}));

const TENANT_ID_SCHEMA = Object.freeze(makeString({
  minLength: 1,
  maxLength: 128,
  pattern: '^[a-zA-Z0-9._:@/-]{1,128}$',
  description: 'Tenant identifier',
  example: 'tenant-acme',
}));

// ── Request body factory ──────────────────────────────────────────────────────

function makeRequestBody(schema, opts) {
  opts = opts || {};
  return {
    required: opts.required !== false,
    description: opts.description || null,
    content: {
      'application/json': { schema },
    },
  };
}

// ── Standard response factories ───────────────────────────────────────────────

function makeSuccessResponse(description, dataSchema) {
  return {
    description,
    content: {
      'application/json': {
        schema: makeObject({
          status:    makeString({ enum: ['success'], example: 'success' }),
          timestamp: ISO8601_SCHEMA,
          requestId: makeNullable(UUID_SCHEMA),
          data:      dataSchema,
        }, { required: ['status', 'timestamp', 'data'] }),
      },
    },
  };
}

function makeEnforcementResponse(description) {
  return {
    description,
    content: {
      'application/json': {
        schema: makeObject({
          decision:  makeString({ enum: ['EXECUTE', 'BLOCK'], description: 'Enforcement decision', example: 'EXECUTE' }),
          reason:    makeString({ description: 'Machine-readable reason code', example: 'RULES_MATCHED' }),
          requestId: makeNullable(UUID_SCHEMA),
          details:   makeObject({}, { additionalProperties: true }),
        }, { required: ['decision', 'requestId'] }),
      },
    },
  };
}

module.exports = {
  makeString,
  makeInteger,
  makeNumber,
  makeBoolean,
  makeArray,
  makeObject,
  makeOneOf,
  makeNullable,
  makeRequestBody,
  makeSuccessResponse,
  makeEnforcementResponse,
  ref,
  responseRef,
  paramRef,
  // Named schemas
  UUID_SCHEMA,
  ISO8601_SCHEMA,
  ACTOR_ID_SCHEMA,
  ACTION_SCHEMA,
  SCOPE_SCHEMA,
  TENANT_ID_SCHEMA,
};
