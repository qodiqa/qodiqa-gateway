'use strict';

const { z, integer } = require('../zod');
const { zodUuid, zodTenantId } = require('./common.schema');

const POLICY_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const zodPolicyId  = z.string().trim().min(1).regex(POLICY_ID_RE, 'Invalid policyId format');

const REQUEST_TYPES = ['CREATE', 'UPDATE', 'ENABLE', 'DISABLE', 'ROLLBACK', 'ARCHIVE'];
const STATUSES = [
  'DRAFT', 'SUBMITTED', 'IN_REVIEW', 'REVIEWED', 'APPROVED',
  'SCHEDULED', 'PUBLISHED', 'REJECTED', 'WITHDRAWN', 'EXPIRED',
];

// ── POST /draft ──────────────────────────────────────────────────────────────

const draftSchema = z.object({
  policyId:     zodPolicyId,
  tenantId:     zodTenantId.optional().nullable(),
  requestType:  z.enum(/** @type {any} */ (REQUEST_TYPES)),
  payload:      z.record(z.string(), z.unknown()).optional().default({}),
  changeReason: z.string().trim().min(1, 'changeReason is required'),
}).strict();

// ── POST /:id/submit — no body required ─────────────────────────────────────

const submitSchema = z.object({}).strict();

// ── POST /:id/review ─────────────────────────────────────────────────────────

const reviewStartSchema = z.object({}).strict();

const reviewDecisionSchema = z.object({
  decision: z.enum(['APPROVED', 'CHANGES_REQUESTED']),
  notes:    z.string().trim().optional().nullable(),
}).strict();

// ── POST /:id/approve ────────────────────────────────────────────────────────

const approveSchema = z.object({
  notes: z.string().trim().optional().nullable(),
}).strict();

// ── POST /:id/reject ─────────────────────────────────────────────────────────

const rejectSchema = z.object({
  reason: z.string().trim().min(1, 'reason is required'),
}).strict();

// ── POST /:id/schedule ───────────────────────────────────────────────────────

const scheduleSchema = z.object({
  scheduledFor: z.string().refine((val) => !isNaN(new Date(val).getTime()), 'scheduledFor must be a valid timestamp'),
}).strict();

// ── POST /:id/publish — no body required ────────────────────────────────────

const publishSchema = z.object({}).strict();

// ── POST /:id/withdraw — no body required ───────────────────────────────────

const withdrawSchema = z.object({}).strict();

// ── POST /rollback — request a rollback ─────────────────────────────────────

const rollbackRequestSchema = z.object({
  policyId:  zodPolicyId,
  toVersion: z.coerce.number().check(integer()).min(1),
  reason:    z.string().trim().min(1, 'reason is required'),
}).strict();

// ── POST /:id/rollback/approve ───────────────────────────────────────────────

const rollbackApproveSchema = z.object({
  notes: z.string().trim().optional().nullable(),
}).strict();

// ── POST /emergency/activate ─────────────────────────────────────────────────

// policyStore.createPolicy()/updatePolicy() only ever read `config` (and,
// for CREATE, id/name/description/type/priority) off the payload it's given —
// a caller who sends config fields flat at the payload's top level (e.g.
// {"blocklist":[...],"cidrs":[...]}) instead of nested ({"config":{...}})
// previously passed schema validation untouched, then silently no-op'd:
// updatePolicy() only touches config when `'config' in updates`, so a flat
// payload updates nothing and still returns 201/PUBLISHED. Rejecting any
// payload key outside what the target store function actually reads turns
// that silent no-op into an immediate 400, for both CREATE and UPDATE — the
// two request types whose payload can carry a `config`. ENABLE/DISABLE never
// read payload at all (setEnabled() takes no config), so they stay unchecked.
const EMERGENCY_CREATE_PAYLOAD_KEYS = new Set(['id', 'name', 'description', 'type', 'priority', 'config']);
const EMERGENCY_UPDATE_PAYLOAD_KEYS = new Set(['name', 'description', 'priority', 'config']);

const emergencyActivateSchema = z.object({
  policyId:           zodPolicyId,
  tenantId:           zodTenantId.optional().nullable(),
  requestType:        z.enum(['CREATE', 'UPDATE', 'ENABLE', 'DISABLE']),
  payload:            z.record(z.string(), z.unknown()).optional().default({}),
  incidentReference:  z.string().trim().min(1, 'incidentReference is required'),
  justification:      z.string().trim().min(1, 'justification is required'),
  ttlHours:           z.coerce.number().positive().max(168).optional().default(24),
}).strict()
  .superRefine((data, ctx) => {
    if (data.requestType !== 'CREATE' && data.requestType !== 'UPDATE') return;

    const allowedKeys = data.requestType === 'CREATE' ? EMERGENCY_CREATE_PAYLOAD_KEYS : EMERGENCY_UPDATE_PAYLOAD_KEYS;
    const payload = data.payload ?? {};

    for (const key of Object.keys(payload)) {
      if (!allowedKeys.has(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['payload', key],
          message: `payload.${key} is not a recognized field for requestType ${data.requestType} — config fields must be nested under payload.config, e.g. {"payload":{"config":{"${key}":...}}}`,
        });
      }
    }

    if ('config' in payload) {
      const config = payload.config;
      if (config === null || typeof config !== 'object' || Array.isArray(config)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['payload', 'config'],
          message: 'payload.config must be a plain object',
        });
      }
    }
  });

// ── POST /emergency/:id/retro-approve ────────────────────────────────────────

const emergencyRetroApproveSchema = z.object({
  tenantId: zodTenantId.optional().nullable(),
  decision: z.enum(['APPROVED', 'REJECTED']),
  notes:    z.string().trim().optional().nullable(),
}).strict();

// ── Path / query schemas ────────────────────────────────────────────────────

const changeRequestIdParamSchema = z.object({ id: zodUuid });
const emergencyIdParamSchema     = z.object({ id: zodUuid });

const listQuerySchema = z.object({
  policyId:    z.string().trim().optional(),
  tenantId:    z.string().trim().optional(),
  status:      z.enum(/** @type {any} */ (STATUSES)).optional(),
  requestType: z.enum(/** @type {any} */ (REQUEST_TYPES)).optional(),
  authorId:    z.string().trim().optional(),
  // Canonical pagination (API-4 remediation) — `limit`/`offset` remain the
  // documented-deprecated aliases below, unchanged, for backward compatibility.
  page:        z.coerce.number().check(integer()).min(1).optional(),
  pageSize:    z.coerce.number().check(integer()).min(1).max(200).optional(),
  limit:       z.coerce.number().check(integer()).min(0).optional().default(50),
  offset:      z.coerce.number().check(integer()).min(0).optional().default(0),
}).strict();

module.exports = {
  REQUEST_TYPES,
  STATUSES,
  draftSchema,
  submitSchema,
  reviewStartSchema,
  reviewDecisionSchema,
  approveSchema,
  rejectSchema,
  scheduleSchema,
  publishSchema,
  withdrawSchema,
  rollbackRequestSchema,
  rollbackApproveSchema,
  emergencyActivateSchema,
  emergencyRetroApproveSchema,
  changeRequestIdParamSchema,
  emergencyIdParamSchema,
  listQuerySchema,
};
