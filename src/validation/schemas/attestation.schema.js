'use strict';

const { z, integer } = require('../zod');
const { zodUuid } = require('./common.schema');

// Path parameter schemas
const attestationIdParamSchema = z.object({ attestationId: zodUuid });

// POST /verify body — accepts either { artifact } wrapper or a raw artifact object
const attestationVerifyBodySchema = z.record(z.string(), z.unknown())
  .superRefine((val, ctx) => {
    if (!val || Array.isArray(val)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Request body must be a JSON object' });
    }
  });

// POST /evidence/verify body
const evidenceVerifyBodySchema = z.record(z.string(), z.unknown())
  .superRefine((val, ctx) => {
    if (!val || Array.isArray(val)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Request body must be a JSON object' });
    }
  });

// H132-D: strict range ids — JSON numbers only (no booleans, numeric strings,
// fractions, negatives or values beyond Number.MAX_SAFE_INTEGER, all of which
// were previously coerced or reached PostgreSQL raw), startId <= endId, and an
// optional limit within the verifier's 1..10,000 bound.
const rangeId = z.number().check(integer()).min(1).max(Number.MAX_SAFE_INTEGER);
const chainRangeSchema = z.object({
  startId: rangeId,
  endId:   rangeId,
  limit:   z.number().check(integer()).min(1).max(10_000).optional(),
}).strict()
  .refine(r => r.startId <= r.endId, { message: 'range.startId must not exceed range.endId' });

// POST /chain/verify body
const chainVerifyBodySchema = z.object({
  evidenceIds: z.array(zodUuid).optional(),
  range:       chainRangeSchema.optional(),
}).strict()
  .superRefine((val, ctx) => {
    if (Array.isArray(val.evidenceIds) && new Set(val.evidenceIds).size !== val.evidenceIds.length) {
      ctx.addIssue({
        code:    z.ZodIssueCode.custom,
        message: 'evidenceIds must not contain duplicates',
      });
    }
    const hasIds   = Array.isArray(val.evidenceIds) && val.evidenceIds.length > 0;
    const hasRange = val.range && typeof val.range === 'object';
    if (!hasIds && !hasRange) {
      ctx.addIssue({
        code:    z.ZodIssueCode.custom,
        message: 'Request body must contain at least one of: evidenceIds (array) or range ({ startId, endId })',
      });
    }
    if (hasIds && val.evidenceIds.length > 50) {
      ctx.addIssue({
        code:    z.ZodIssueCode.custom,
        message: 'evidenceIds array may contain at most 50 entries per request',
      });
    }
  });

module.exports = {
  attestationIdParamSchema,
  attestationVerifyBodySchema,
  evidenceVerifyBodySchema,
  chainVerifyBodySchema,
};
