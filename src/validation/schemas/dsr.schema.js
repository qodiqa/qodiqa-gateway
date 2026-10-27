'use strict';

const { z, integer } = require('../zod');
const { zodUuid, zodActorId, zodTenantId } = require('./common.schema');
const { VERIFICATION_METHODS } = require('../../core/dsr/identityVerification');

// ── Request types / statuses (mirrors migration 028 CHECK constraints) ────────

const DSR_REQUEST_TYPES = ['RECTIFICATION', 'ERASURE', 'RESTRICTION', 'PORTABILITY'];
const DSR_STATUSES = [
  'RECEIVED', 'IDENTITY_VERIFIED', 'APPROVED', 'IN_PROGRESS',
  'COMPLETED', 'REJECTED', 'FAILED',
];

// ── POST /v1/admin/dsr — create request ────────────────────────────────────────

const dsrCreateRequestSchema = z.object({
  requestType:    z.enum(/** @type {any} */ (DSR_REQUEST_TYPES)),
  actorId:        zodActorId,
  tenantId:       zodTenantId.optional().nullable(),
  requestedBy:    z.string().trim().min(1).optional(),
  legalBasis:     z.string().trim().optional().nullable(),
  justification:  z.string().trim().optional().nullable(),
}).strict();

// ── POST /v1/admin/dsr/:id/verify-identity ─────────────────────────────────────

const dsrVerifyIdentitySchema = z.object({
  tenantId:    zodTenantId.optional().nullable(),
  method:      z.enum(/** @type {any} */ (VERIFICATION_METHODS)),
  result:      z.enum(['VERIFIED', 'FAILED']),
  evidence:    z.string().trim().optional().nullable(),
  verifiedBy:  z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/approve ──────────────────────────────────────────────

const dsrApproveSchema = z.object({
  tenantId:   zodTenantId.optional().nullable(),
  approvedBy: z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/rectify — Article 16 ─────────────────────────────────

const dsrRectifySchema = z.object({
  tenantId:    zodTenantId.optional().nullable(),
  consentId:   zodUuid,
  fields: z.object({
    subject_name: z.string().optional().nullable(),
    metadata:     z.record(z.string(), z.unknown()).optional(),
    tags:         z.array(z.string()).optional(),
  }).strict().refine((f) => Object.keys(f).length > 0, { message: 'fields must include at least one correctable field' }),
  rectifiedBy: z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/erase — Article 17 ───────────────────────────────────

const dsrEraseSchema = z.object({
  tenantId:            zodTenantId.optional().nullable(),
  pseudonymizeActorId: z.boolean().optional().default(false),
  erasedBy:            z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/restrict — Article 18 ────────────────────────────────

const dsrRestrictSchema = z.object({
  tenantId:     zodTenantId.optional().nullable(),
  reason:       z.string().trim().optional().nullable(),
  restrictedBy: z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/lift ─────────────────────────────────────────────────

const dsrLiftSchema = z.object({
  tenantId: zodTenantId.optional().nullable(),
  liftedBy: z.string().trim().min(1).optional(),
}).strict();

// ── POST /v1/admin/dsr/:id/export — Article 20 ──────────────────────────────────

const dsrExportSchema = z.object({
  tenantId:    zodTenantId.optional().nullable(),
  format:      z.enum(['JSON', 'CSV']).optional().default('JSON'),
  generatedBy: z.string().trim().min(1).optional(),
}).strict();

// ── Path / query schemas ────────────────────────────────────────────────────────

const dsrIdParamSchema = z.object({ id: zodUuid });

// GET /v1/admin/dsr/:id — optional tenantId query param so the
// detail/event-trail route can actually see a tenant-scoped request; omitted
// keeps the existing platform-only-visibility behavior unchanged.
const dsrIdQuerySchema = z.object({
  tenantId: zodTenantId.optional().nullable(),
}).strict();

const dsrListQuerySchema = z.object({
  actorId:     z.string().trim().optional(),
  tenantId:    z.string().trim().optional(),
  status:      z.enum(/** @type {any} */ (DSR_STATUSES)).optional(),
  requestType: z.enum(/** @type {any} */ (DSR_REQUEST_TYPES)).optional(),
  // Canonical pagination (API-4 remediation) — `limit`/`offset` remain the
  // documented-deprecated aliases below, unchanged, for backward compatibility.
  page:        z.coerce.number().check(integer()).min(1).optional(),
  pageSize:    z.coerce.number().check(integer()).min(1).max(200).optional(),
  limit:       z.coerce.number().check(integer()).min(0).optional().default(50),
  offset:      z.coerce.number().check(integer()).min(0).optional().default(0),
}).strict();

module.exports = {
  DSR_REQUEST_TYPES,
  DSR_STATUSES,
  dsrCreateRequestSchema,
  dsrVerifyIdentitySchema,
  dsrApproveSchema,
  dsrRectifySchema,
  dsrEraseSchema,
  dsrRestrictSchema,
  dsrLiftSchema,
  dsrExportSchema,
  dsrIdParamSchema,
  dsrIdQuerySchema,
  dsrListQuerySchema,
};
