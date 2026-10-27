'use strict';

const { z } = require('../zod');
const { roughSize, exceedsDepth } = require('../helpers');

// These limits are read from env vars at runtime; the defaults here match
// the same defaults used in the verify route.
const MAX_ARTIFACT_BYTES = (() => {
  const v = parseInt(process.env.VERIFY_MAX_ARTIFACT_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 8_192;
})();

const MAX_REQUEST_BYTES = (() => {
  const v = parseInt(process.env.VERIFY_MAX_REQUEST_BYTES, 10);
  return Number.isFinite(v) && v > 0 ? v : 4_096;
})();

const MAX_OBJECT_DEPTH = (() => {
  const v = parseInt(process.env.VERIFY_MAX_OBJECT_DEPTH, 10);
  return Number.isFinite(v) && v > 0 ? v : 12;
})();

// Only these two top-level keys are permitted — reject parameter injection.
const verifyBodySchema = z.object({
  artifact: z.record(z.string(), z.unknown())
    .superRefine((val, ctx) => {
      if (roughSize(val) > MAX_ARTIFACT_BYTES) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `artifact serialised size exceeds ${MAX_ARTIFACT_BYTES} bytes`,
          params:  { qodiqaReason: 'INVALID_ARTIFACT' },
        });
      }
      if (exceedsDepth(val, MAX_OBJECT_DEPTH)) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `artifact nesting exceeds ${MAX_OBJECT_DEPTH} levels`,
          params:  { qodiqaReason: 'INVALID_ARTIFACT' },
        });
      }
    }),
  request: z.record(z.string(), z.unknown())
    .superRefine((val, ctx) => {
      if (roughSize(val) > MAX_REQUEST_BYTES) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `request serialised size exceeds ${MAX_REQUEST_BYTES} bytes`,
          params:  { qodiqaReason: 'INVALID_REQUEST' },
        });
      }
      if (exceedsDepth(val, MAX_OBJECT_DEPTH)) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `request nesting exceeds ${MAX_OBJECT_DEPTH} levels`,
          params:  { qodiqaReason: 'INVALID_REQUEST' },
        });
      }
    }),
}).strict();

// Separate schemas for specific early-exit error codes (missing / wrong type)
// so the route can produce exact reason codes before size/depth checks run.
const verifyArtifactPresentSchema = z.object({
  artifact: z.unknown().superRefine((val, ctx) => {
    if (val === null || val === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'artifact is required', params: { qodiqaReason: 'MISSING_ARTIFACT' } });
    } else if (typeof val !== 'object' || Array.isArray(val)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'artifact must be a plain object', params: { qodiqaReason: 'INVALID_ARTIFACT_TYPE' } });
    }
  }),
  request: z.unknown().superRefine((val, ctx) => {
    if (val === null || val === undefined) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'request is required', params: { qodiqaReason: 'MISSING_REQUEST' } });
    } else if (typeof val !== 'object' || Array.isArray(val)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'request must be a plain object', params: { qodiqaReason: 'INVALID_REQUEST_TYPE' } });
    }
  }),
}).strict();

module.exports = { verifyBodySchema, verifyArtifactPresentSchema };
