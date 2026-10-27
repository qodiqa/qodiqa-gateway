'use strict';

const { z } = require('../zod');
const { zodUuid } = require('./common.schema');

const MAX_ARTIFACTS     = 50;
const MAX_EVIDENCE_PKGS = 50;

// Path parameter schemas
const certificationIdParamSchema = z.object({ certificationId: zodUuid });

// POST /evaluate body
const certificationEvaluateBodySchema = z.object({
  artifacts:        z.array(z.record(z.string(), z.unknown())).optional().default([])
    .superRefine((arr, ctx) => {
      if (arr.length > MAX_ARTIFACTS) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `artifacts array may contain at most ${MAX_ARTIFACTS} entries per request`,
        });
      }
    }),
  evidencePackages: z.array(z.record(z.string(), z.unknown())).optional().default([])
    .superRefine((arr, ctx) => {
      if (arr.length > MAX_EVIDENCE_PKGS) {
        ctx.addIssue({
          code:    z.ZodIssueCode.custom,
          message: `evidencePackages array may contain at most ${MAX_EVIDENCE_PKGS} entries per request`,
        });
      }
    }),
  chain:   z.record(z.string(), z.unknown()).optional().nullable(),
  options: z.record(z.string(), z.unknown()).optional(),
}).strict();

module.exports = { certificationIdParamSchema, certificationEvaluateBodySchema };
