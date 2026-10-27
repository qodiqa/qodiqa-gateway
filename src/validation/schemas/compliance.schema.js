'use strict';

const { z } = require('../zod');

const FRAMEWORK_IDS = ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF'];

// Path parameter — frameworkId
const frameworkIdParamSchema = z.object({
  frameworkId: z.string().min(1),
});

// POST /compliance/report/generate body
const generateReportBodySchema = z.object({
  frameworkId:      z.string().min(1, 'frameworkId is required')
    .superRefine((val, ctx) => {
      if (!FRAMEWORK_IDS.includes(val)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: `Unknown framework: "${val}"`, params: { unknownFramework: true } });
      }
    }),
  periodStart: z.string().min(1, 'periodStart is required')
    .superRefine((val, ctx) => {
      if (isNaN(new Date(val).getTime())) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'periodStart must be a valid ISO 8601 timestamp' });
      }
    }),
  periodEnd: z.string().min(1, 'periodEnd is required')
    .superRefine((val, ctx) => {
      if (isNaN(new Date(val).getTime())) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'periodEnd must be a valid ISO 8601 timestamp' });
      }
    }),
  tenantId:        z.string().optional().nullable(),
  sign:            z.union([z.boolean(), z.literal('true'), z.literal('false')]).optional().default(false),
  // signingClientId is deliberately NOT an accepted field — it would let an
  // HTTP caller select which tenant's private key signs the report. See
  // src/api/routes/compliance.js's POST /report/generate handler. Previously
  // this was only enforced by the handler never reading it off parsed data
  // despite .passthrough() letting it through validation (item 9 audit) —
  // .strict() now backs that up at the schema layer too.
}).strict()
  .superRefine((val, ctx) => {
    const start = new Date(val.periodStart);
    const end   = new Date(val.periodEnd);
    if (!isNaN(start.getTime()) && !isNaN(end.getTime()) && start >= end) {
      ctx.addIssue({
        code:    z.ZodIssueCode.custom,
        message: 'periodStart must be before periodEnd',
        params:  { complianceCode: 'INVALID_PERIOD' },
      });
    }
  });

module.exports = { generateReportBodySchema, frameworkIdParamSchema, FRAMEWORK_IDS };
