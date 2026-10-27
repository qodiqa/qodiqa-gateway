'use strict';

const { z, integer } = require('../zod');
const { zodUuid } = require('./common.schema');

// Path parameter schemas
const eventIdParamSchema       = z.object({ eventId:    zodUuid });
const requestIdParamSchema     = z.object({ requestId:  zodUuid });
const artifactIdParamSchema    = z.object({ artifactId: z.string().min(1).max(128) });
const actorIdParamSchema       = z.object({ actorId:    z.string().min(1).max(128) });

// POST /retention/policies body
const retentionPolicyBodySchema = z.object({
  name:              z.string().min(1, 'name is required'),
  description:       z.string().optional(),
  eventCategory:     z.string().optional(),
  eventTypePattern:  z.string().optional(),
  tenantId:          z.string().optional(),
  severity:          z.string().optional(),
  retainDays:        z.number().check(integer()).min(0, 'retainDays must be a non-negative integer'),
  complianceProfile: z.string().optional(),
}).strict();

// POST /retention/holds body
const legalHoldBodySchema = z.object({
  holdName:      z.string().min(1, 'holdName is required'),
  reason:        z.string().min(1, 'reason is required'),
  artifactId:    z.string().optional(),
  tenantId:      z.string().optional(),
  eventCategory: z.string().optional(),
}).strict()
  .superRefine((val, ctx) => {
    if (!val.artifactId && !val.tenantId && !val.eventCategory) {
      ctx.addIssue({
        code:    z.ZodIssueCode.custom,
        message: 'Provide at least one of: artifactId, tenantId, eventCategory',
      });
    }
  });

// DELETE /retention/holds/:holdName query — optional tenantId so
// a tenant-scoped hold can actually be released; omitted keeps the existing
// platform-only-visibility behavior unchanged.
const releaseLegalHoldQuerySchema = z.object({
  tenantId: z.string().optional(),
}).strict();

module.exports = {
  eventIdParamSchema,
  requestIdParamSchema,
  artifactIdParamSchema,
  actorIdParamSchema,
  releaseLegalHoldQuerySchema,
  retentionPolicyBodySchema,
  legalHoldBodySchema,
};
