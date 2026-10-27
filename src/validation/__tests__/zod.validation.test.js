'use strict';

/**
 * Zod validation layer test suite — Component #16.
 *
 * Coverage:
 *   1. Valid requests pass each schema
 *   2. Invalid requests are rejected with correct Zod errors
 *   3. Helpers (exceedsDepth, roughSize, firstQodiqaReason, formatZodDetails)
 *   4. Backward-compatibility: existing valid payloads still pass
 *
 * Middleware factory coverage (validateBody/validateParams/validateQuery)
 * removed item 27 — was dead
 * code (zero live callers) and was deleted, not registered.
 *
 * Does NOT test business logic (crypto, policy evaluation, AI execution).
 */

const { z } = require('../zod');

// ── Schemas ────────────────────────────────────────────────────────────────────

const { signBodySchema }               = require('../schemas/sign.schema');
const { aiChatBodySchema }             = require('../schemas/aiChat.schema');
const { verifyBodySchema, verifyArtifactPresentSchema } = require('../schemas/verify.schema');
const { consentGrantSchema, consentVerifySchema, consentIdParamSchema, consentListQuerySchema } = require('../schemas/consent.schema');
const { createUserSchema, updateUserSchema }           = require('../schemas/rbac.schema');
const { clientIdParamSchema, purgeExpiredBodySchema, revokeKeyBodySchema } = require('../schemas/keyAdmin.schema');
const { transparencyIdParamSchema, registerEntryBodySchema } = require('../schemas/transparency.schema');
const { attestationIdParamSchema, chainVerifyBodySchema }    = require('../schemas/attestation.schema');
const { certificationIdParamSchema, certificationEvaluateBodySchema } = require('../schemas/certification.schema');
const { eventIdParamSchema, retentionPolicyBodySchema, legalHoldBodySchema } = require('../schemas/auditStore.schema');
const { generateReportBodySchema }     = require('../schemas/compliance.schema');
const { zodUuid, zodClientId, zodKeyId, zodActorId, paginationQuerySchema } = require('../schemas/common.schema');
const {
  dsrCreateRequestSchema, dsrVerifyIdentitySchema, dsrApproveSchema, dsrRectifySchema,
  dsrEraseSchema, dsrRestrictSchema, dsrLiftSchema, dsrExportSchema, dsrListQuerySchema,
} = require('../schemas/dsr.schema');
const {
  draftSchema, submitSchema, reviewDecisionSchema, approveSchema, rejectSchema,
  scheduleSchema, publishSchema, withdrawSchema, rollbackRequestSchema, rollbackApproveSchema,
  emergencyActivateSchema, emergencyRetroApproveSchema, listQuerySchema: policyGovListQuerySchema,
} = require('../schemas/policyGovernance.schema');
const { createSigningIdentitySchema, updateSigningIdentitySchema } = require('../schemas/signingIdentity.schema');
const { webhookCreateSchema, webhookUpdateSchema } = require('../schemas/webhooks.schema');
const { createRoleSchema, updateRoleSchema, validatePermissionsSchema } = require('../schemas/rbac.schema');

// ── Helpers ────────────────────────────────────────────────────────────────────

const { exceedsDepth, roughSize, firstQodiqaReason, formatZodDetails } = require('../helpers');

// ─────────────────────────────────────────────────────────────────────────────
// Helper utilities
// ─────────────────────────────────────────────────────────────────────────────

describe('helpers', () => {
  describe('exceedsDepth', () => {
    it('returns false for shallow objects', () => {
      expect(exceedsDepth({ a: { b: 1 } }, 5)).toBe(false);
    });
    it('returns true when depth equals maxDepth', () => {
      // depth 3: { a: { b: { c: 1 } } }
      expect(exceedsDepth({ a: { b: { c: 1 } } }, 2)).toBe(true);
    });
    it('handles arrays', () => {
      expect(exceedsDepth([[1]], 1)).toBe(true);
    });
    it('handles null values inside objects', () => {
      expect(exceedsDepth({ a: null }, 5)).toBe(false);
    });
    it('returns false for primitive values', () => {
      expect(exceedsDepth('string', 0)).toBe(false);
    });
  });

  describe('roughSize', () => {
    it('returns the JSON string length', () => {
      expect(roughSize({ a: 1 })).toBe(JSON.stringify({ a: 1 }).length);
    });
    it('returns Infinity for circular references', () => {
      const obj = {};
      obj.self = obj;
      expect(roughSize(obj)).toBe(Infinity);
    });
  });

  describe('firstQodiqaReason', () => {
    it('returns custom qodiqaReason from first matching issue', () => {
      const schema = z.string().superRefine((_, ctx) => {
        ctx.addIssue({ code: z.ZodIssueCode.custom, params: { qodiqaReason: 'CUSTOM_CODE' } });
      });
      const r = schema.safeParse('x');
      expect(r.success).toBe(false);
      expect(firstQodiqaReason(r.error)).toBe('CUSTOM_CODE');
    });
    it('falls back to default when no custom reason', () => {
      const schema = z.string().min(100);
      const r = schema.safeParse('short');
      expect(r.success).toBe(false);
      expect(firstQodiqaReason(r.error, 'FALLBACK')).toBe('FALLBACK');
    });
  });

  describe('formatZodDetails', () => {
    it('returns field/message objects', () => {
      const schema = z.object({ name: z.string().min(1) });
      const r = schema.safeParse({ name: '' });
      expect(r.success).toBe(false);
      const details = formatZodDetails(r.error);
      expect(Array.isArray(details)).toBe(true);
      expect(details[0]).toHaveProperty('field');
      expect(details[0]).toHaveProperty('message');
    });
    it('uses (root) for root-level errors', () => {
      const schema = z.string();
      const r = schema.safeParse(123);
      expect(r.success).toBe(false);
      const details = formatZodDetails(r.error);
      expect(details[0].field).toBe('(root)');
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Common schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('common.schema', () => {
  const validUuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  test('zodUuid accepts valid UUID', () => {
    expect(zodUuid.safeParse(validUuid).success).toBe(true);
  });
  test('zodUuid rejects non-UUID', () => {
    expect(zodUuid.safeParse('not-a-uuid').success).toBe(false);
  });
  test('zodClientId accepts valid client ID', () => {
    expect(zodClientId.safeParse('myClient_1').success).toBe(true);
  });
  test('zodClientId rejects invalid chars', () => {
    expect(zodClientId.safeParse('my client!').success).toBe(false);
  });
  test('zodKeyId accepts valid key ID', () => {
    expect(zodKeyId.safeParse('myClient:key_v1').success).toBe(true);
  });
  test('zodKeyId rejects malformed key ID', () => {
    expect(zodKeyId.safeParse('myClient:v1').success).toBe(false);
  });
  test('zodActorId accepts valid actor', () => {
    expect(zodActorId.safeParse('user@example.com').success).toBe(true);
  });
  test('zodActorId rejects empty string', () => {
    expect(zodActorId.safeParse('').success).toBe(false);
  });
  test('paginationQuerySchema coerces strings', () => {
    const r = paginationQuerySchema.safeParse({ page: '2', pageSize: '25' });
    expect(r.success).toBe(true);
    expect(r.data.page).toBe(2);
    expect(r.data.pageSize).toBe(25);
  });
  test('paginationQuerySchema clamps pageSize to 500', () => {
    const r = paginationQuerySchema.safeParse({ pageSize: '9999' });
    expect(r.success).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Sign schema
// ─────────────────────────────────────────────────────────────────────────────

describe('sign.schema — signBodySchema', () => {
  const valid = {
    request: { method: 'POST', path: '/api/test', body: { key: 'value' } },
    payload: { provider: 'openai' },
    ttl:     60_000,
  };

  test('accepts valid sign body', () => {
    expect(signBodySchema.safeParse(valid).success).toBe(true);
  });
  test('rejects body without request', () => {
    expect(signBodySchema.safeParse({}).success).toBe(false);
  });
  test('rejects unexpected top-level key', () => {
    expect(signBodySchema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
  });
  test('rejects invalid HTTP method', () => {
    const r = signBodySchema.safeParse({ ...valid, request: { ...valid.request, method: 'FOOBAR' } });
    expect(r.success).toBe(false);
    expect(firstQodiqaReason(r.error)).toBe('INVALID_METHOD');
  });
  test('rejects path exceeding 2048 bytes', () => {
    const longPath = '/' + 'x'.repeat(2050);
    const r = signBodySchema.safeParse({ ...valid, request: { ...valid.request, path: longPath } });
    expect(r.success).toBe(false);
    expect(firstQodiqaReason(r.error)).toBe('PATH_TOO_LONG');
  });
  test('rejects request.body exceeding depth 10', () => {
    let deep = {};
    let cur = deep;
    for (let i = 0; i < 12; i++) { cur.child = {}; cur = cur.child; }
    const r = signBodySchema.safeParse({ ...valid, request: { ...valid.request, body: deep } });
    expect(r.success).toBe(false);
    expect(firstQodiqaReason(r.error)).toBe('BODY_TOO_DEEP');
  });
  test('rejects negative ttl', () => {
    const r = signBodySchema.safeParse({ ...valid, ttl: -1 });
    expect(r.success).toBe(false);
  });
  test('allows method case-insensitivity validation (lower case rejected)', () => {
    const r = signBodySchema.safeParse({ ...valid, request: { ...valid.request, method: 'post' } });
    // 'post' is not in VALID_HTTP_METHODS (which contains 'POST')
    expect(r.success).toBe(false);
    expect(firstQodiqaReason(r.error)).toBe('INVALID_METHOD');
  });
  test('allows optional ttl to be omitted', () => {
    const { ttl: _t, ...withoutTtl } = valid;
    expect(signBodySchema.safeParse(withoutTtl).success).toBe(true);
  });
  test('backward compat: existing valid payload passes', () => {
    const payload = {
      request: { method: 'POST', path: '/ai/chat', body: { prompt: 'hello' } },
      payload: { provider: 'openai', purpose: 'chat' },
      ttl: 300_000,
    };
    expect(signBodySchema.safeParse(payload).success).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AI Chat schema
// ─────────────────────────────────────────────────────────────────────────────

describe('aiChat.schema — aiChatBodySchema', () => {
  test('accepts valid body with prompt', () => {
    expect(aiChatBodySchema.safeParse({ prompt: 'Hello, AI!' }).success).toBe(true);
  });
  test('rejects missing prompt', () => {
    expect(aiChatBodySchema.safeParse({}).success).toBe(false);
  });
  test('rejects empty prompt', () => {
    expect(aiChatBodySchema.safeParse({ prompt: '' }).success).toBe(false);
  });
  test('rejects whitespace-only prompt', () => {
    expect(aiChatBodySchema.safeParse({ prompt: '   ' }).success).toBe(false);
  });
  test('rejects prompt exceeding 32KB', () => {
    const r = aiChatBodySchema.safeParse({ prompt: 'x'.repeat(33_000) });
    expect(r.success).toBe(false);
    expect(firstQodiqaReason(r.error)).toBe('PROMPT_TOO_LARGE');
  });
  test('allows optional model field', () => {
    expect(aiChatBodySchema.safeParse({ prompt: 'Hi', model: 'gpt-4' }).success).toBe(true);
  });
  test('backward compat: standard chat payload passes', () => {
    expect(aiChatBodySchema.safeParse({ prompt: 'What is QODIQA?' }).success).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Verify schema
// ─────────────────────────────────────────────────────────────────────────────

describe('verify.schema', () => {
  const validArtifact = { signature: 'abc', timestamp: 1700000000000, expiry: 9999999999999, publicKeyId: 'kid', payload: {} };
  const validRequest  = { method: 'POST', path: '/ai/chat', body: {} };
  const validBody     = { artifact: validArtifact, request: validRequest };

  describe('verifyArtifactPresentSchema', () => {
    test('accepts valid body', () => {
      expect(verifyArtifactPresentSchema.safeParse(validBody).success).toBe(true);
    });
    test('rejects missing artifact → MISSING_ARTIFACT', () => {
      const r = verifyArtifactPresentSchema.safeParse({ request: validRequest });
      expect(r.success).toBe(false);
      expect(firstQodiqaReason(r.error)).toBe('MISSING_ARTIFACT');
    });
    test('rejects array artifact → INVALID_ARTIFACT_TYPE', () => {
      const r = verifyArtifactPresentSchema.safeParse({ artifact: [], request: validRequest });
      expect(r.success).toBe(false);
      expect(firstQodiqaReason(r.error)).toBe('INVALID_ARTIFACT_TYPE');
    });
    test('rejects unexpected body keys → UNEXPECTED_FIELDS', () => {
      const r = verifyArtifactPresentSchema.safeParse({ ...validBody, extra: 'bad' });
      expect(r.success).toBe(false);
    });
    test('rejects missing request → MISSING_REQUEST', () => {
      const r = verifyArtifactPresentSchema.safeParse({ artifact: validArtifact });
      expect(r.success).toBe(false);
      expect(firstQodiqaReason(r.error)).toBe('MISSING_REQUEST');
    });
  });

  describe('verifyBodySchema', () => {
    test('accepts valid body', () => {
      expect(verifyBodySchema.safeParse(validBody).success).toBe(true);
    });
    test('rejects unexpected fields', () => {
      expect(verifyBodySchema.safeParse({ ...validBody, extra: 1 }).success).toBe(false);
    });
    test('backward compat: typical verify payload passes', () => {
      expect(verifyBodySchema.safeParse(validBody).success).toBe(true);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Consent schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('consent.schema', () => {
  // API-5 remediation: camelCase is canonical. These tests call
  // the schemas directly (bypassing src/validation/normalizeLegacyBody.js's
  // legacy-alias translation, which only runs at the route layer — see
  // src/validation/schemas/__tests__/consent.schema.strict.test.js for
  // dedicated legacy-alias coverage), so they use camelCase field names.
  const validGrant = {
    actorId: 'user@example.com',
    action:  'model:inference',
    lawfulBasis: 'consent',            // required
    purpose: 'Model inference for the user',
  };

  describe('consentGrantSchema', () => {
    test('accepts minimal valid grant', () => {
      expect(consentGrantSchema.safeParse(validGrant).success).toBe(true);
    });
    //
    test('rejects a grant without lawfulBasis or purpose', () => {
      const { lawfulBasis: _b, ...noBasis } = validGrant;
      const { purpose: _p, ...noPurpose } = validGrant;
      expect(consentGrantSchema.safeParse(noBasis).success).toBe(false);
      expect(consentGrantSchema.safeParse(noPurpose).success).toBe(false);
    });
    test('accepts only the six Art. 6(1) bases', () => {
      for (const b of ['consent', 'contract', 'legal_obligation', 'vital_interests', 'public_task', 'legitimate_interests']) {
        expect(consentGrantSchema.safeParse({ ...validGrant, lawfulBasis: b }).success).toBe(true);
      }
      expect(consentGrantSchema.safeParse({ ...validGrant, lawfulBasis: 'implied' }).success).toBe(false);
    });
    test('purpose is 1-500 characters; purposeCode and specialCategoryCondition are validated', () => {
      expect(consentGrantSchema.safeParse({ ...validGrant, purpose: '   ' }).success).toBe(false);
      expect(consentGrantSchema.safeParse({ ...validGrant, purpose: 'x'.repeat(501) }).success).toBe(false);
      expect(consentGrantSchema.safeParse({ ...validGrant, purposeCode: 'marketing.email_v2' }).success).toBe(true);
      expect(consentGrantSchema.safeParse({ ...validGrant, purposeCode: 'Has Spaces' }).success).toBe(false);
      expect(consentGrantSchema.safeParse({ ...validGrant, specialCategoryCondition: 'art9_2_a' }).success).toBe(true);
      expect(consentGrantSchema.safeParse({ ...validGrant, specialCategoryCondition: 'art9_2_k' }).success).toBe(false);
    });
    test('rejects invalid actorId', () => {
      expect(consentGrantSchema.safeParse({ ...validGrant, actorId: 'bad actor!' }).success).toBe(false);
    });
    test('rejects invalid action', () => {
      expect(consentGrantSchema.safeParse({ ...validGrant, action: '' }).success).toBe(false);
    });
    test('rejects past expiresAt', () => {
      const r = consentGrantSchema.safeParse({ ...validGrant, expiresAt: '2020-01-01T00:00:00Z' });
      expect(r.success).toBe(false);
    });
    test('rejects invalid durationDays', () => {
      expect(consentGrantSchema.safeParse({ ...validGrant, durationDays: -5 }).success).toBe(false);
    });
    test('accepts future expiresAt', () => {
      const future = new Date(Date.now() + 86_400_000 * 7).toISOString();
      expect(consentGrantSchema.safeParse({ ...validGrant, expiresAt: future }).success).toBe(true);
    });
  });

  describe('consentVerifySchema', () => {
    test('accepts valid verify request', () => {
      expect(consentVerifySchema.safeParse({ actorId: validGrant.actorId, action: validGrant.action }).success).toBe(true); // validGrant now carries grant-only fields
    });
    test('rejects missing actorId', () => {
      expect(consentVerifySchema.safeParse({ action: 'model:inference' }).success).toBe(false);
    });
  });

  describe('consentIdParamSchema', () => {
    test('accepts valid UUID', () => {
      expect(consentIdParamSchema.safeParse({ id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890' }).success).toBe(true);
    });
    test('rejects non-UUID', () => {
      expect(consentIdParamSchema.safeParse({ id: 'not-a-uuid' }).success).toBe(false);
    });
  });

  describe('consentListQuerySchema', () => {
    test('accepts empty query', () => {
      expect(consentListQuerySchema.safeParse({}).success).toBe(true);
    });
    test('rejects invalid state', () => {
      expect(consentListQuerySchema.safeParse({ state: 'INVALID_STATE' }).success).toBe(false);
    });
    test('coerces limit/offset', () => {
      const r = consentListQuerySchema.safeParse({ limit: '10', offset: '5' });
      expect(r.success).toBe(true);
      expect(r.data.limit).toBe(10);
      expect(r.data.offset).toBe(5);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// RBAC schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('rbac.schema', () => {
  describe('createUserSchema', () => {
    test('accepts valid create request', () => {
      expect(createUserSchema.safeParse({ username: 'alice', role: 'operator' }).success).toBe(true);
    });
    test('rejects missing username', () => {
      expect(createUserSchema.safeParse({ role: 'operator' }).success).toBe(false);
    });
    test('rejects missing role', () => {
      expect(createUserSchema.safeParse({ username: 'alice' }).success).toBe(false);
    });
    test('rejects empty username', () => {
      expect(createUserSchema.safeParse({ username: '', role: 'operator' }).success).toBe(false);
    });
  });

  describe('updateUserSchema', () => {
    test('accepts update with just role', () => {
      expect(updateUserSchema.safeParse({ role: 'admin' }).success).toBe(true);
    });
    test('accepts update with just enabled', () => {
      expect(updateUserSchema.safeParse({ enabled: false }).success).toBe(true);
    });
    test('rejects empty update (no fields)', () => {
      expect(updateUserSchema.safeParse({}).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Key Admin schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('keyAdmin.schema', () => {
  describe('clientIdParamSchema', () => {
    test('accepts valid clientId', () => {
      expect(clientIdParamSchema.safeParse({ clientId: 'my-client_1' }).success).toBe(true);
    });
    test('rejects invalid chars', () => {
      expect(clientIdParamSchema.safeParse({ clientId: 'my client!' }).success).toBe(false);
    });
    test('rejects empty string', () => {
      expect(clientIdParamSchema.safeParse({ clientId: '' }).success).toBe(false);
    });
  });

  describe('purgeExpiredBodySchema', () => {
    test('accepts empty body', () => {
      expect(purgeExpiredBodySchema.safeParse({}).success).toBe(true);
    });
    test('accepts valid clientId', () => {
      expect(purgeExpiredBodySchema.safeParse({ clientId: 'myClient' }).success).toBe(true);
    });
    test('rejects invalid clientId', () => {
      expect(purgeExpiredBodySchema.safeParse({ clientId: 'bad client!' }).success).toBe(false);
    });
  });

  describe('revokeKeyBodySchema', () => {
    test('accepts valid keyId', () => {
      expect(revokeKeyBodySchema.safeParse({ keyId: 'myClient:key_v1' }).success).toBe(true);
    });
    test('rejects missing keyId', () => {
      expect(revokeKeyBodySchema.safeParse({}).success).toBe(false);
    });
    test('rejects malformed keyId', () => {
      expect(revokeKeyBodySchema.safeParse({ keyId: 'myClient_v1' }).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Transparency schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('transparency.schema', () => {
  const validUuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  describe('transparencyIdParamSchema', () => {
    test('accepts valid UUID', () => {
      expect(transparencyIdParamSchema.safeParse({ transparencyId: validUuid }).success).toBe(true);
    });
    test('rejects non-UUID', () => {
      expect(transparencyIdParamSchema.safeParse({ transparencyId: 'bad' }).success).toBe(false);
    });
  });

  describe('registerEntryBodySchema', () => {
    test('accepts valid ARTIFACT entry', () => {
      expect(registerEntryBodySchema.safeParse({ entryType: 'ARTIFACT' }).success).toBe(true);
    });
    test('accepts all valid entry types', () => {
      for (const t of ['ARTIFACT', 'EVIDENCE', 'VERIFICATION', 'POLICY', 'AUDIT', 'SYSTEM']) {
        expect(registerEntryBodySchema.safeParse({ entryType: t }).success).toBe(true);
      }
    });
    test('rejects unknown entryType', () => {
      expect(registerEntryBodySchema.safeParse({ entryType: 'UNKNOWN' }).success).toBe(false);
    });
    test('rejects missing entryType', () => {
      expect(registerEntryBodySchema.safeParse({}).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Attestation schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('attestation.schema', () => {
  const validUuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  test('attestationIdParamSchema accepts valid UUID', () => {
    expect(attestationIdParamSchema.safeParse({ attestationId: validUuid }).success).toBe(true);
  });
  test('attestationIdParamSchema rejects non-UUID', () => {
    expect(attestationIdParamSchema.safeParse({ attestationId: 'bad' }).success).toBe(false);
  });

  describe('chainVerifyBodySchema', () => {
    // H132-D: evidenceIds are UUIDs (previously any string — a malformed id
    // reached PostgreSQL and its error text reached the caller).
    const U1 = '11111111-1111-4111-8111-111111111111';
    const U2 = '22222222-2222-4222-8222-222222222222';
    test('accepts evidenceIds array', () => {
      expect(chainVerifyBodySchema.safeParse({ evidenceIds: [U1, U2] }).success).toBe(true);
    });
    // H132-D: range ids are positive integers of JSON type number. The previous
    // fixture ({ startId: 'a', endId: 'b' }) pinned the coercion defect itself.
    test('accepts range object', () => {
      expect(chainVerifyBodySchema.safeParse({ range: { startId: 1, endId: 10 } }).success).toBe(true);
      expect(chainVerifyBodySchema.safeParse({ range: { startId: 1, endId: 10, limit: 10000 } }).success).toBe(true);
    });
    test.each([
      ['string ids', { startId: 'a', endId: 'b' }],
      ['numeric-string id', { startId: '1', endId: 5 }],
      ['boolean id', { startId: true, endId: 5 }],
      ['negative id', { startId: -3, endId: 5 }],
      ['zero id', { startId: 0, endId: 5 }],
      ['fractional id', { startId: 1.5, endId: 5 }],
      ['unsafe integer', { startId: 1e20, endId: 1e20 }],
      ['object id', { startId: { a: 1 }, endId: 5 }],
      ['startId > endId', { startId: 10, endId: 1 }],
      ['missing endId', { startId: 1 }],
      ['limit above 10,000', { startId: 1, endId: 5, limit: 20000 }],
      ['unknown key', { startId: 1, endId: 5, extra: 1 }],
    ])('H132-D rejects range with %s', (_n, range) => {
      expect(chainVerifyBodySchema.safeParse({ range }).success).toBe(false);
    });
    test('H132-D rejects non-UUID and duplicate evidenceIds', () => {
      expect(chainVerifyBodySchema.safeParse({ evidenceIds: ['id1'] }).success).toBe(false);
      expect(chainVerifyBodySchema.safeParse({ evidenceIds: [U1, U1] }).success).toBe(false);
    });
    test('rejects empty body (neither ids nor range)', () => {
      expect(chainVerifyBodySchema.safeParse({}).success).toBe(false);
    });
    test('rejects evidenceIds with more than 50 entries', () => {
      const ids = Array.from({ length: 51 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`);
      expect(chainVerifyBodySchema.safeParse({ evidenceIds: ids.slice(0, 50) }).success).toBe(true);
      expect(chainVerifyBodySchema.safeParse({ evidenceIds: ids }).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Certification schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('certification.schema', () => {
  const validUuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  test('certificationIdParamSchema accepts valid UUID', () => {
    expect(certificationIdParamSchema.safeParse({ certificationId: validUuid }).success).toBe(true);
  });

  describe('certificationEvaluateBodySchema', () => {
    test('accepts empty evaluate body', () => {
      expect(certificationEvaluateBodySchema.safeParse({}).success).toBe(true);
    });
    test('accepts artifacts array', () => {
      expect(certificationEvaluateBodySchema.safeParse({ artifacts: [{ sig: 'abc' }] }).success).toBe(true);
    });
    test('rejects artifacts array with more than 50 entries', () => {
      const arr = Array.from({ length: 51 }, () => ({ x: 1 }));
      expect(certificationEvaluateBodySchema.safeParse({ artifacts: arr }).success).toBe(false);
    });
    test('rejects evidencePackages array with more than 50 entries', () => {
      const arr = Array.from({ length: 51 }, () => ({ x: 1 }));
      expect(certificationEvaluateBodySchema.safeParse({ evidencePackages: arr }).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Audit Store schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('auditStore.schema', () => {
  const validUuid = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890';

  test('eventIdParamSchema accepts valid UUID', () => {
    expect(eventIdParamSchema.safeParse({ eventId: validUuid }).success).toBe(true);
  });
  test('eventIdParamSchema rejects non-UUID', () => {
    expect(eventIdParamSchema.safeParse({ eventId: 'bad' }).success).toBe(false);
  });

  describe('retentionPolicyBodySchema', () => {
    test('accepts valid policy', () => {
      expect(retentionPolicyBodySchema.safeParse({ name: 'default', retainDays: 90 }).success).toBe(true);
    });
    test('rejects missing name', () => {
      expect(retentionPolicyBodySchema.safeParse({ retainDays: 90 }).success).toBe(false);
    });
    test('rejects negative retainDays', () => {
      expect(retentionPolicyBodySchema.safeParse({ name: 'x', retainDays: -1 }).success).toBe(false);
    });
    test('accepts zero retainDays', () => {
      expect(retentionPolicyBodySchema.safeParse({ name: 'x', retainDays: 0 }).success).toBe(true);
    });
  });

  describe('legalHoldBodySchema', () => {
    test('accepts hold with artifactId scope', () => {
      expect(legalHoldBodySchema.safeParse({
        holdName: 'audit-hold', reason: 'Legal request', artifactId: 'abc123',
      }).success).toBe(true);
    });
    test('rejects hold without scope', () => {
      expect(legalHoldBodySchema.safeParse({ holdName: 'x', reason: 'y' }).success).toBe(false);
    });
    test('rejects missing holdName', () => {
      expect(legalHoldBodySchema.safeParse({ reason: 'y', artifactId: 'z' }).success).toBe(false);
    });
    test('rejects missing reason', () => {
      expect(legalHoldBodySchema.safeParse({ holdName: 'x', artifactId: 'z' }).success).toBe(false);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Compliance schemas
// ─────────────────────────────────────────────────────────────────────────────

describe('compliance.schema', () => {
  const validReport = {
    frameworkId:  'GDPR',
    periodStart:  '2024-01-01T00:00:00Z',
    periodEnd:    '2024-12-31T23:59:59Z',
  };

  test('accepts valid generate-report body', () => {
    expect(generateReportBodySchema.safeParse(validReport).success).toBe(true);
  });
  test('rejects missing frameworkId', () => {
    const { frameworkId: _f, ...rest } = validReport;
    expect(generateReportBodySchema.safeParse(rest).success).toBe(false);
  });
  test('rejects unknown frameworkId', () => {
    const r = generateReportBodySchema.safeParse({ ...validReport, frameworkId: 'UNKNOWN_FW' });
    expect(r.success).toBe(false);
    const issue = r.error.issues.find(i => i.params?.unknownFramework);
    expect(issue).toBeTruthy();
  });
  test('rejects missing periodStart', () => {
    const { periodStart: _ps, ...rest } = validReport;
    expect(generateReportBodySchema.safeParse(rest).success).toBe(false);
  });
  test('rejects periodStart not before periodEnd', () => {
    const r = generateReportBodySchema.safeParse({
      ...validReport,
      periodStart: '2024-12-31T00:00:00Z',
      periodEnd:   '2024-01-01T00:00:00Z',
    });
    expect(r.success).toBe(false);
    const issue = r.error.issues.find(i => i.params?.complianceCode === 'INVALID_PERIOD');
    expect(issue).toBeTruthy();
  });
  test('rejects invalid ISO date string', () => {
    expect(generateReportBodySchema.safeParse({ ...validReport, periodStart: 'not-a-date' }).success).toBe(false);
  });
  test('backward compat: all four valid frameworks pass', () => {
    for (const fw of ['GDPR', 'EU_AI_ACT', 'ISO_42001', 'NIST_AI_RMF']) {
      expect(generateReportBodySchema.safeParse({ ...validReport, frameworkId: fw }).success).toBe(true);
    }
  });
});

// Middleware describe block removed — item 27 (ITEM-26-RESPONSE-ENVELOPE-
// DECISION-RECORD.md, D26-3):
// (validateBody/validateParams/validateQuery) was dead code, zero live
// callers, deleted rather than registered as a 16th envelope type. This
// block tested only that file; the schema coverage below is unaffected.

// ── Item 9 audit — .passthrough()/default(strip) → .strict() conversion ────────
//
// Every schema below was converted from .passthrough() (or Zod's default
// "strip unknown keys silently" mode) to .strict() as part of the item 9
// repo-wide passthrough audit (see audit/remediation/ITEM-9-REMEDIATION-
// REPORT.md for the full inventory/classification). Each assertion here
// proves (a) a payload with one unrecognised extra key is now REJECTED
// (schema-level regression lock — an accidental future .passthrough()
// re-introduction would fail this test) and (b) the same payload without the
// extra key still validates successfully (happy path unaffected).
//
// aiChatBodySchema is DELIBERATELY excluded — it remains .passthrough() by
// design decision (category b, see the report): aiChat.test.js's BIND-02
// relies on an extra body key reaching the cryptographic request-binding
// check (403 REQUEST_MISMATCH) rather than being rejected at the schema
// layer. The negative assertion below documents and locks in that decision
// boundary so a future edit doesn't silently flip it.
describe('item 9 audit — .strict() unknown-key rejection', () => {
  function expectStrict(schema, validPayload) {
    expect(schema.safeParse(validPayload).success).toBe(true);
    expect(schema.safeParse({ ...validPayload, unexpectedKey: 'x' }).success).toBe(false);
  }

  test('aiChatBodySchema is INTENTIONALLY still .passthrough() (category b, not converted)', () => {
    expect(aiChatBodySchema.safeParse({ prompt: 'hi', unexpectedKey: 'x' }).success).toBe(true);
  });

  test('common.schema — paginationQuerySchema (unused by any live route, tightened anyway)', () => {
    expectStrict(paginationQuerySchema, {});
  });

  test('sign.schema — signBodySchema.request nested object (outer was already .strict())', () => {
    const valid = { request: { method: 'POST', path: '/orders/create', body: { sku: 'SKU-1' } } };
    expect(signBodySchema.safeParse(valid).success).toBe(true);
    const nestedExtra = { request: { ...valid.request, unexpectedKey: 'x' } };
    expect(signBodySchema.safeParse(nestedExtra).success).toBe(false);
  });

  test('attestation.schema — chainVerifyBodySchema', () => {
    expectStrict(chainVerifyBodySchema, { evidenceIds: ['11111111-1111-4111-8111-111111111111'] });
  });

  test('auditStore.schema — retentionPolicyBodySchema', () => {
    expectStrict(retentionPolicyBodySchema, { name: 'policy-1', retainDays: 30 });
  });

  test('auditStore.schema — legalHoldBodySchema', () => {
    expectStrict(legalHoldBodySchema, { holdName: 'hold-1', reason: 'litigation', artifactId: 'art-1' });
  });

  test('certification.schema — certificationEvaluateBodySchema', () => {
    expectStrict(certificationEvaluateBodySchema, {});
  });

  test('compliance.schema — generateReportBodySchema', () => {
    expectStrict(generateReportBodySchema, {
      frameworkId: 'GDPR', periodStart: '2026-01-01T00:00:00Z', periodEnd: '2026-02-01T00:00:00Z',
    });
  });

  test('compliance.schema — generateReportBodySchema still rejects signingClientId (the deliberately-excluded field)', () => {
    const withSigningClientId = {
      frameworkId: 'GDPR', periodStart: '2026-01-01T00:00:00Z', periodEnd: '2026-02-01T00:00:00Z',
      signingClientId: 'attacker-chosen-tenant',
    };
    expect(generateReportBodySchema.safeParse(withSigningClientId).success).toBe(false);
  });

  test('dsr.schema — dsrCreateRequestSchema', () => {
    expectStrict(dsrCreateRequestSchema, { requestType: 'ERASURE', actorId: 'actor-1' });
  });

  test('dsr.schema — dsrVerifyIdentitySchema', () => {
    expectStrict(dsrVerifyIdentitySchema, { method: 'OPERATOR_ATTESTATION', result: 'VERIFIED' });
  });

  test('dsr.schema — dsrApproveSchema', () => {
    expectStrict(dsrApproveSchema, {});
  });

  test('dsr.schema — dsrRectifySchema (including nested fields sub-object)', () => {
    const valid = { consentId: '11111111-1111-4111-8111-111111111111', fields: { subject_name: 'New Name' } };
    expectStrict(dsrRectifySchema, valid);
    // Nested `fields` sub-object also tightened — extra key there rejected too.
    const nestedExtra = { ...valid, fields: { ...valid.fields, unexpectedKey: 'x' } };
    expect(dsrRectifySchema.safeParse(nestedExtra).success).toBe(false);
  });

  test('dsr.schema — dsrEraseSchema / dsrRestrictSchema / dsrLiftSchema / dsrExportSchema', () => {
    expectStrict(dsrEraseSchema, {});
    expectStrict(dsrRestrictSchema, {});
    expectStrict(dsrLiftSchema, {});
    expectStrict(dsrExportSchema, {});
  });

  test('dsr.schema — dsrListQuerySchema', () => {
    expectStrict(dsrListQuerySchema, {});
  });

  test('keyAdmin.schema — purgeExpiredBodySchema / revokeKeyBodySchema', () => {
    expectStrict(purgeExpiredBodySchema, {});
    expectStrict(revokeKeyBodySchema, { keyId: 'default:key_v1' });
  });

  test('policyGovernance.schema — draftSchema', () => {
    expectStrict(draftSchema, { policyId: 'pol-1', requestType: 'CREATE', changeReason: 'onboarding' });
  });

  test('policyGovernance.schema — submitSchema / publishSchema / withdrawSchema (empty-body schemas)', () => {
    expectStrict(submitSchema, {});
    expectStrict(publishSchema, {});
    expectStrict(withdrawSchema, {});
  });

  test('policyGovernance.schema — reviewDecisionSchema / approveSchema / rejectSchema', () => {
    expectStrict(reviewDecisionSchema, { decision: 'APPROVED' });
    expectStrict(approveSchema, {});
    expectStrict(rejectSchema, { reason: 'not aligned with policy' });
  });

  test('policyGovernance.schema — scheduleSchema', () => {
    expectStrict(scheduleSchema, { scheduledFor: '2026-08-01T00:00:00Z' });
  });

  test('policyGovernance.schema — rollbackRequestSchema / rollbackApproveSchema', () => {
    expectStrict(rollbackRequestSchema, { policyId: 'pol-1', toVersion: 1, reason: 'incident' });
    expectStrict(rollbackApproveSchema, {});
  });

  test('policyGovernance.schema — emergencyActivateSchema / emergencyRetroApproveSchema', () => {
    expectStrict(emergencyActivateSchema, {
      policyId: 'pol-1', requestType: 'CREATE', incidentReference: 'INC-1', justification: 'active incident',
    });
    expectStrict(emergencyRetroApproveSchema, { decision: 'APPROVED' });
  });

  //:
  // POST /emergency/activate silently no-op'd on a flat payload shape — the
  // schema accepted it (z.record(z.unknown())), but updatePolicy() only
  // touches config when `'config' in updates`, so the caller's fields never
  // reached the policy and a 201/PUBLISHED response gave no signal anything
  // was wrong. These lock in the fix: reject the flat shape at the schema
  // layer instead of accepting it and silently doing nothing.
  test('emergencyActivateSchema rejects an UPDATE payload with flat (un-nested) config fields', () => {
    const result = emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'UPDATE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { blocklist: ['1.2.3.4'], cidrs: ['10.0.0.0/8'] },
    });
    expect(result.success).toBe(false);
    expect(result.error.issues.some(i => i.path.join('.') === 'payload.blocklist')).toBe(true);
  });

  test('emergencyActivateSchema accepts an UPDATE payload with config correctly nested', () => {
    const result = emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'UPDATE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { config: { blocklist: ['1.2.3.4'], cidrs: ['10.0.0.0/8'] } },
    });
    expect(result.success).toBe(true);
  });

  test('emergencyActivateSchema still accepts an UPDATE payload that only touches priority (no config)', () => {
    const result = emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'UPDATE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { priority: 5 },
    });
    expect(result.success).toBe(true);
  });

  test('emergencyActivateSchema rejects a CREATE payload with flat (un-nested) config fields', () => {
    const result = emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'CREATE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { type: 'BLOCK_IP', priority: 5, blocklist: ['1.2.3.4'] },
    });
    expect(result.success).toBe(false);
    expect(result.error.issues.some(i => i.path.join('.') === 'payload.blocklist')).toBe(true);
  });

  test('emergencyActivateSchema rejects payload.config that is not a plain object', () => {
    const result = emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'UPDATE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { config: ['not', 'an', 'object'] },
    });
    expect(result.success).toBe(false);
    expect(result.error.issues.some(i => i.path.join('.') === 'payload.config')).toBe(true);
  });

  test('emergencyActivateSchema leaves ENABLE/DISABLE payload unconstrained (no config semantics)', () => {
    expect(emergencyActivateSchema.safeParse({
      policyId: 'pol-1', requestType: 'ENABLE', incidentReference: 'INC-1', justification: 'active incident',
      payload: { anything: 'goes', because: 'setEnabled() never reads payload' },
    }).success).toBe(true);
  });

  test('policyGovernance.schema — listQuerySchema', () => {
    expectStrict(policyGovListQuerySchema, {});
  });

  test('rbac.schema — createUserSchema / updateUserSchema', () => {
    expectStrict(createUserSchema, { username: 'alice', role: 'admin' });
    expectStrict(updateUserSchema, { enabled: true });
  });

  test('rbac.schema — createRoleSchema / updateRoleSchema / validatePermissionsSchema (previously default-strip, not passthrough)', () => {
    expectStrict(createRoleSchema, { name: 'custom-role', permissions: ['READ_DSR'] });
    expectStrict(updateRoleSchema, { enabled: true });
    expectStrict(validatePermissionsSchema, { permissions: ['READ_DSR'] });
  });

  test('signingIdentity.schema — createSigningIdentitySchema / updateSigningIdentitySchema', () => {
    expectStrict(createSigningIdentitySchema, {
      name: 'ident-1', tenantId: 'default', environment: 'test', permissions: ['SIGN_ARTIFACT'],
    });
    expectStrict(updateSigningIdentitySchema, { enabled: true });
  });

  test('transparency.schema — registerEntryBodySchema', () => {
    expectStrict(registerEntryBodySchema, { entryType: 'AUDIT' });
  });

  test('webhooks.schema — webhookCreateSchema / webhookUpdateSchema (previously default-strip, not passthrough)', () => {
    expectStrict(webhookCreateSchema, {
      tenantId: 'default', url: 'https://example.com/hook', eventTypes: ['certification.completed'],
    });
    expectStrict(webhookUpdateSchema, { enabled: true });
  });
});
