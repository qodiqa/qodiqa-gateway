'use strict';

/**
 * AUTHZ-2 remediation — consent schemas reject unknown fields.
 *
 * Previously all six schemas used Zod's .passthrough(), so an unrecognized
 * request-body field survived validation and was retained on parsed.data.
 * The route handler currently destructures only known fields, so there was
 * no live exploit today — but any future refactor that spread parsed.data
 * directly into a store call would have persisted arbitrary attacker-
 * controlled fields verbatim. .strict() closes this by construction.
 *
 * API-5 remediation — camelCase is now canonical on every schema
 * below; snake_case field names are a legacy alias handled by
 * src/validation/normalizeLegacyBody.js *before* these `.strict()` schemas
 * ever see the body (see src/api/routes/consent.js). That means:
 *   - Calling a schema directly (as these tests do) with a raw snake_case
 *     body now correctly fails — `.strict()` doesn't know about aliases,
 *     only normalizeLegacyBody does. Tests below reflect that split:
 *     schema-level tests use camelCase; alias-translation is tested
 *     separately against normalizeLegacyBody() + the alias maps.
 *   - `evil_field`-style injected fields are rejected either way, before or
 *     after normalization, since they're never in any alias map.
 */

const {
  consentGrantSchema,
  consentVerifySchema,
  consentRevokeSchema,
  consentSuspendSchema,
  consentResumeSchema,
  consentListQuerySchema,
  CONSENT_GRANT_ALIASES,
  CONSENT_VERIFY_ALIASES,
  CONSENT_REVOKE_ALIASES,
  CONSENT_SUSPEND_ALIASES,
  CONSENT_RESUME_ALIASES,
  CONSENT_LIST_QUERY_ALIASES,
} = require('../consent.schema');
const { normalizeLegacyBody } = require('../../normalizeLegacyBody');

describe('AUTHZ-2 — consent schemas reject unknown fields', () => {
  test('consentGrantSchema rejects an unrecognized field', () => {
    const result = consentGrantSchema.safeParse({
      actorId: 'actor-1', action: 'read', evil_field: 'injected',
    });
    expect(result.success).toBe(false);
  });

  test('consentGrantSchema still accepts every field it legitimately declares (camelCase)', () => {
    const result = consentGrantSchema.safeParse({
      actorId: 'actor-1', action: 'read', grantedBy: 'op1', scope: 'read_x',
      requiredScope: 'read_x', tenantId: 'tenant-A', grantReference: 'ref-1',
      subjectName: 'Alice', actionDisplay: 'Read Data', policyReference: 'pol-1',
      tags: ['a', 'b'], metadata: { k: 'v' },
      lawfulBasis: 'contract', purpose: 'Service delivery', purposeCode: 'svc.core', specialCategoryCondition: 'art9_2_a',
    });
    expect(result.success).toBe(true);
  });

  test('consentVerifySchema rejects an unrecognized field', () => {
    const result = consentVerifySchema.safeParse({
      actorId: 'actor-1', action: 'read', evil_field: 'injected',
    });
    expect(result.success).toBe(false);
  });

  test('consentRevokeSchema rejects an unrecognized field', () => {
    const result = consentRevokeSchema.safeParse({ revokedBy: 'op1', evil_field: 'injected' });
    expect(result.success).toBe(false);
  });

  test('consentSuspendSchema rejects an unrecognized field', () => {
    const result = consentSuspendSchema.safeParse({ suspendedBy: 'op1', evil_field: 'injected' });
    expect(result.success).toBe(false);
  });

  test('consentResumeSchema rejects an unrecognized field', () => {
    const result = consentResumeSchema.safeParse({ resumedBy: 'op1', evil_field: 'injected' });
    expect(result.success).toBe(false);
  });

  test('consentListQuerySchema rejects an unrecognized field', () => {
    const result = consentListQuerySchema.safeParse({ actorId: 'actor-1', evil_field: 'injected' });
    expect(result.success).toBe(false);
  });

  test('a field that survives (mass-assignment style) attack no longer reaches parsed.data', () => {
    // Simulates the exact scenario the finding described: an attacker
    // attempting to inject a field like `is_admin` or `state` directly.
    const result = consentGrantSchema.safeParse({
      actorId: 'actor-1', action: 'read', state: 'ACTIVE', is_admin: true,
    });
    expect(result.success).toBe(false);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// API-5 remediation — legacy snake_case field aliases
// ─────────────────────────────────────────────────────────────────────────────

describe('API-5 — legacy snake_case fields are accepted via normalizeLegacyBody, not directly by the schema', () => {
  test('consentGrantSchema rejects a raw snake_case body directly (no alias translation applied)', () => {
    const result = consentGrantSchema.safeParse({ actor_id: 'actor-1', action: 'read' });
    expect(result.success).toBe(false);
  });

  test('normalizeLegacyBody + consentGrantSchema accepts an all-snake_case legacy body', () => {
    const { body, usedLegacyKeys } = normalizeLegacyBody(
      {
        actor_id: 'actor-1', action: 'read', granted_by: 'op1', scope: 'read_x',
        required_scope: 'read_x', tenant_id: 'tenant-A', grant_reference: 'ref-1',
        subject_name: 'Alice', action_display: 'Read Data', policy_reference: 'pol-1',
        tags: ['a', 'b'], metadata: { k: 'v' },
        lawful_basis: 'contract', purpose: 'Service delivery', purpose_code: 'svc.core', special_category_condition: 'art9_2_a',
      },
      CONSENT_GRANT_ALIASES,
    );
    expect(usedLegacyKeys.length).toBeGreaterThan(0);
    const result = consentGrantSchema.safeParse(body);
    expect(result.success).toBe(true);
    expect(result.data.actorId).toBe('actor-1');
    expect(result.data.tenantId).toBe('tenant-A');
  });

  test('normalizeLegacyBody accepts a mixed camelCase/snake_case body, canonical wins on conflict', () => {
    const { body, usedLegacyKeys } = normalizeLegacyBody(
      { actor_id: 'legacy-value', actorId: 'canonical-value', action: 'read', lawfulBasis: 'consent', purpose: 'p' },
      CONSENT_GRANT_ALIASES,
    );
    expect(usedLegacyKeys).toEqual(['actor_id']);
    expect(body.actorId).toBe('canonical-value'); // canonical value wins, legacy key removed
    expect(body.actor_id).toBeUndefined();
    const result = consentGrantSchema.safeParse(body);
    expect(result.success).toBe(true);
  });

  test('normalizeLegacyBody does not rescue a genuinely unknown field — .strict() still rejects it', () => {
    const { body } = normalizeLegacyBody(
      { actor_id: 'actor-1', action: 'read', evil_field: 'injected' },
      CONSENT_GRANT_ALIASES,
    );
    const result = consentGrantSchema.safeParse(body);
    expect(result.success).toBe(false);
  });

  test('normalizeLegacyBody + consentVerifySchema accepts legacy fields', () => {
    const { body } = normalizeLegacyBody(
      { actor_id: 'actor-1', action: 'read', tenant_id: 'tenant-A', required_scope: 'read_x' },
      CONSENT_VERIFY_ALIASES,
    );
    expect(consentVerifySchema.safeParse(body).success).toBe(true);
  });

  test('normalizeLegacyBody + consentRevokeSchema accepts legacy fields', () => {
    const { body } = normalizeLegacyBody(
      { revoked_by: 'op1', revocation_reason: 'no longer needed', tenant_id: 'tenant-A' },
      CONSENT_REVOKE_ALIASES,
    );
    expect(consentRevokeSchema.safeParse(body).success).toBe(true);
  });

  test('normalizeLegacyBody + consentSuspendSchema accepts legacy fields', () => {
    const { body } = normalizeLegacyBody(
      { suspended_by: 'op1', suspension_reason: 'investigation', tenant_id: 'tenant-A' },
      CONSENT_SUSPEND_ALIASES,
    );
    expect(consentSuspendSchema.safeParse(body).success).toBe(true);
  });

  test('normalizeLegacyBody + consentResumeSchema accepts legacy fields', () => {
    const { body } = normalizeLegacyBody(
      { resumed_by: 'op1', tenant_id: 'tenant-A' },
      CONSENT_RESUME_ALIASES,
    );
    expect(consentResumeSchema.safeParse(body).success).toBe(true);
  });

  test('normalizeLegacyBody + consentListQuerySchema accepts legacy fields', () => {
    const { body, usedLegacyKeys } = normalizeLegacyBody(
      { actor_id: 'actor-1', tenant_id: 'tenant-A', action: 'read' },
      CONSENT_LIST_QUERY_ALIASES,
    );
    expect(usedLegacyKeys.sort()).toEqual(['actor_id', 'tenant_id']);
    expect(consentListQuerySchema.safeParse(body).success).toBe(true);
  });

  test('normalizeLegacyBody is a no-op when no legacy keys are present', () => {
    const { body, usedLegacyKeys } = normalizeLegacyBody(
      { actorId: 'actor-1', action: 'read' },
      CONSENT_GRANT_ALIASES,
    );
    expect(usedLegacyKeys).toEqual([]);
    expect(body).toEqual({ actorId: 'actor-1', action: 'read' });
  });
});
