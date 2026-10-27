'use strict';

const { z, integer } = require('../zod');
const { zodUuid, zodActorId, zodAction, zodScope, zodTenantId } = require('./common.schema');

// ── API-5 remediation: camelCase is now canonical ───────────────────
//
// Every consent request body below used to be snake_case only
// (actor_id, granted_by, ...) — the one resource family in this API that
// didn't match the camelCase convention used everywhere else (organizations,
// tenants, webhooks, DSR, ...). Following the exact precedent already set by
// `page`/`pageSize` superseding `limit`/`offset` in consentListQuerySchema
// below (API-4 remediation): camelCase fields are now what these schemas
// validate; the legacy snake_case names are still accepted, translated to
// their camelCase equivalent by src/validation/normalizeLegacyBody.js
// *before* reaching these `.strict()` schemas (see src/api/routes/consent.js)
// — so this file only ever needs to know about the canonical names.
// The alias maps below are exported so the route file can perform that
// translation without duplicating the field list here.

const CONSENT_GRANT_ALIASES = {
  actor_id:         'actorId',
  granted_by:       'grantedBy',
  required_scope:   'requiredScope',
  tenant_id:        'tenantId',
  grant_reference:  'grantReference',
  subject_name:     'subjectName',
  action_display:   'actionDisplay',
  policy_reference: 'policyReference',
  expires_at:       'expiresAt',
  duration_days:    'durationDays',
  // same deprecated snake_case convention as the fields above.
  lawful_basis:               'lawfulBasis',
  purpose_code:               'purposeCode',
  special_category_condition: 'specialCategoryCondition',
};

const CONSENT_VERIFY_ALIASES = {
  actor_id:       'actorId',
  tenant_id:      'tenantId',
  required_scope: 'requiredScope',
};

const CONSENT_REVOKE_ALIASES = {
  revoked_by:        'revokedBy',
  revocation_reason: 'revocationReason',
  tenant_id:         'tenantId',
};

const CONSENT_SUSPEND_ALIASES = {
  suspended_by:      'suspendedBy',
  suspension_reason: 'suspensionReason',
  suspended_until:   'suspendedUntil',
  tenant_id:         'tenantId',
};

const CONSENT_RESUME_ALIASES = {
  resumed_by: 'resumedBy',
  tenant_id:  'tenantId',
};

const CONSENT_LIST_QUERY_ALIASES = {
  actor_id:  'actorId',
  tenant_id: 'tenantId',
};

// ── Grant body ────────────────────────────────────────────────────────────────

// GDPR Art. 6(1) lawful bases and Art. 9(2) conditions.
const LAWFUL_BASES = Object.freeze(['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests']);
const SPECIAL_CATEGORY_CONDITIONS = Object.freeze(['art9_2_a', 'art9_2_b', 'art9_2_c', 'art9_2_d', 'art9_2_e',
  'art9_2_f', 'art9_2_g', 'art9_2_h', 'art9_2_i', 'art9_2_j']);

const consentGrantSchema = z.object({
  actorId:         zodActorId,
  action:          zodAction,
  // required on every new grant.
  lawfulBasis:     z.enum(/** @type {any} */ (LAWFUL_BASES)),
  purpose:         z.string().trim().min(1).max(500),
  purposeCode:     z.string().regex(/^[a-z0-9_.-]{1,64}$/, 'purposeCode must be 1-64 of [a-z0-9_.-]').optional().nullable(),
  specialCategoryCondition: z.enum(/** @type {any} */ (SPECIAL_CATEGORY_CONDITIONS)).optional().nullable(),
  grantedBy:       z.string().trim().optional(),
  scope:           zodScope.optional().nullable(),
  requiredScope:   zodScope.optional().nullable(),
  tenantId:        zodTenantId.optional().nullable(),
  grantReference:  z.string().optional().nullable(),
  subjectName:     z.string().optional().nullable(),
  actionDisplay:   z.string().optional().nullable(),
  policyReference: z.string().optional().nullable(),
  tags:            z.array(z.string()).optional().default([]),
  metadata:        z.record(z.string(), z.unknown()).optional().default({}),
  expiresAt:       z.string().optional().nullable()
    .superRefine((val, ctx) => {
      if (!val) return;
      const d = new Date(val);
      if (isNaN(d.getTime())) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid expiresAt' });
        return;
      }
      if (d <= new Date()) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'expiresAt must be in the future' });
      }
    }),
  durationDays: z.union([z.number(), z.string()]).optional().nullable()
    .superRefine((val, ctx) => {
      if (val === null || val === undefined) return;
      const n = parseInt(String(val), 10);
      if (!Number.isFinite(n) || n < 1) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid durationDays' });
      }
    }),
}).strict();

// ── Verify body ───────────────────────────────────────────────────────────────

const consentVerifySchema = z.object({
  actorId:       zodActorId,
  action:        zodAction,
  tenantId:      zodTenantId.optional().nullable(),
  requiredScope: zodScope.optional().nullable(),
}).strict();

// ── Revoke / suspend / resume body ────────────────────────────────────────────

// tenantId is optional on all three lifecycle transitions below: the route
// only has the record's UUID, not its tenant, so the caller (an operator who
// knows which tenant they're managing) supplies it explicitly. It is used to
// set the RLS tenant session context for the lookup/update — see
// ConsentStore.js's revoke/suspend/resume and the matching comment on
// create()/findByKey() for why plain, tenant-less transactions can never see
// a tenant-scoped row.

const consentRevokeSchema = z.object({
  revokedBy:        z.string().optional(),
  revocationReason: z.string().optional().nullable(),
  tenantId:         zodTenantId.optional().nullable(),
}).strict();

const consentSuspendSchema = z.object({
  suspendedBy:      z.string().optional(),
  suspensionReason: z.string().optional().nullable(),
  suspendedUntil:   z.string().optional().nullable()
    .superRefine((val, ctx) => {
      if (!val) return;
      const d = new Date(val);
      if (isNaN(d.getTime())) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid suspendedUntil' });
      }
    }),
  tenantId: zodTenantId.optional().nullable(),
}).strict();

const consentResumeSchema = z.object({
  resumedBy: z.string().optional(),
  tenantId:  zodTenantId.optional().nullable(),
}).strict();

// ── UUID path parameter ───────────────────────────────────────────────────────

const consentIdParamSchema = z.object({ id: zodUuid });

// ── Actor path parameter ──────────────────────────────────────────────────────

const consentActorParamSchema = z.object({ actorId: zodActorId });

// ── List query schema ─────────────────────────────────────────────────────────

const CONSENT_STATES = ['PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED'];

const consentListQuerySchema = z.object({
  actorId:   z.string().trim().optional(),
  action:    z.string().trim().optional(),
  tenantId:  z.string().trim().optional(),
  state:     z.enum(/** @type {any} */ (CONSENT_STATES)).optional(),
  // Canonical pagination (API-4 remediation) — `limit`/`offset` remain the
  // documented-deprecated aliases below, unchanged, for backward compatibility.
  page:      z.coerce.number().check(integer()).min(1).optional(),
  pageSize:  z.coerce.number().check(integer()).min(1).max(200).optional(),
  limit:     z.coerce.number().check(integer()).min(0).optional().default(50),
  offset:    z.coerce.number().check(integer()).min(0).optional().default(0),
}).strict();

module.exports = {
  LAWFUL_BASES, SPECIAL_CATEGORY_CONDITIONS,
  consentGrantSchema,
  consentVerifySchema,
  consentRevokeSchema,
  consentSuspendSchema,
  consentResumeSchema,
  consentIdParamSchema,
  consentActorParamSchema,
  consentListQuerySchema,
  CONSENT_STATES,
  CONSENT_GRANT_ALIASES,
  CONSENT_VERIFY_ALIASES,
  CONSENT_REVOKE_ALIASES,
  CONSENT_SUSPEND_ALIASES,
  CONSENT_RESUME_ALIASES,
  CONSENT_LIST_QUERY_ALIASES,
};
