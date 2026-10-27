'use strict';

/**
 * Webhook Validation Schemas — Component #28
 *
 * Zod schemas for all webhook API endpoints.
 * Uses the canonical shared primitives from common.schema.js.
 */

const { z }       = require('../zod');
const { zodUuid, zodTenantId } = require('./common.schema');

// ── Supported event types ─────────────────────────────────────────────────────

const SUPPORTED_EVENT_TYPES = ['certification.completed', 'attestation.completed', 'approval.requested', 'approval.decided', 'approval.expired', 'approval.cancelled'];

// ── Path parameter schemas ────────────────────────────────────────────────────

const webhookIdParamSchema = z.object({ id: zodUuid });

// ── Request body schemas ──────────────────────────────────────────────────────

const webhookCreateSchema = z.object({
  tenantId:    zodTenantId,
  url:         z.string()
    .url('url must be a valid URL')
    .startsWith('https://', 'url must use HTTPS'),
  eventTypes:  z.array(z.enum(/** @type {any} */ (SUPPORTED_EVENT_TYPES)))
    .min(1, 'eventTypes must contain at least one event type')
    .max(SUPPORTED_EVENT_TYPES.length, `eventTypes may contain at most ${SUPPORTED_EVENT_TYPES.length} entries`),
  description: z.string().max(255).optional(),
}).strict();

const webhookUpdateSchema = z.object({
  url:         z.string().url().startsWith('https://').optional(),
  enabled:     z.boolean().optional(),
  eventTypes:  z.array(z.enum(/** @type {any} */ (SUPPORTED_EVENT_TYPES))).min(1).optional(),
  description: z.string().max(255).optional(),
}).strict().superRefine((val, ctx) => {
  if (Object.keys(val).length === 0) {
    ctx.addIssue({
      code:    z.ZodIssueCode.custom,
      message: 'At least one field (url, enabled, eventTypes, description) must be provided',
    });
  }
});

// ── Export ────────────────────────────────────────────────────────────────────

module.exports = {
  webhookIdParamSchema,
  webhookCreateSchema,
  webhookUpdateSchema,
  SUPPORTED_EVENT_TYPES,
};
