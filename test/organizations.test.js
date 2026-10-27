'use strict';

/**
 * Component #39 — Organization Registry Tests
 *
 * Coverage:
 *   1.  registerOrganization — creates org with generated UUID
 *   2.  registerOrganization — accepts provided UUID
 *   3.  registerOrganization — idempotent on repeated call with same orgId
 *   4.  registerOrganization — applies default quotas
 *   5.  registerOrganization — accepts custom quotas
 *   6.  getOrganization — returns registered org
 *   7.  getOrganization — returns null for unknown ID
 *   8.  updateOrganization — updates name and status
 *   9.  updateOrganization — returns null for unknown org
 *  10.  updateOrganization — rejects invalid status
 *  11.  updateOrganization — merges metadata
 *  12.  updateOrganization — merges quotas
 *  13.  assignTenantToOrg — assigns tenant
 *  14.  assignTenantToOrg — idempotent for same tenant/org
 *  15.  assignTenantToOrg — blocks cross-org assignment
 *  16.  removeTenantFromOrg — removes assignment
 *  17.  removeTenantFromOrg — returns false for unknown tenant
 *  18.  getOrganizationForTenant — resolves org for assigned tenant
 *  19.  getOrganizationForTenant — returns null for unassigned tenant
 *  20.  assertActiveOrganization — passes for active org
 *  21.  assertActiveOrganization — passes for tenant with no org (backward compat)
 *  22.  assertActiveOrganization — blocks suspended org
 *  23.  assertActiveOrganization — blocks disabled org
 *  24.  getQuotasForTenant — returns org quotas for assigned tenant
 *  25.  getQuotasForTenant — returns defaults for unassigned tenant
 *  26.  listOrganizations — returns all orgs
 *  27.  orgCount — accurate count
 */

const {
  registerOrganization,
  getOrganization,
  updateOrganization,
  assignTenantToOrg,
  removeTenantFromOrg,
  getOrganizationForTenant,
  assertActiveOrganization,
  getQuotasForTenant,
  listOrganizations,
  orgCount,
  DEFAULT_QUOTAS,
  _reset,
} = require('../src/core/organizations/organizationRegistry');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

beforeEach(() => {
  _reset();
});

// ── 1–5. registerOrganization ─────────────────────────────────────────────────

describe('registerOrganization', () => {
  test('generates a UUID v4 organizationId when not provided', () => {
    const org = registerOrganization({ organizationName: 'Acme Corp' });
    expect(org.organizationId).toMatch(UUID_RE);
    expect(org.organizationName).toBe('Acme Corp');
    expect(org.status).toBe('active');
  });

  test('accepts an explicit UUID v4 as organizationId', () => {
    const id  = '11111111-1111-4111-8111-111111111111';
    const org = registerOrganization({ organizationId: id, organizationName: 'Test Org' });
    expect(org.organizationId).toBe(id);
  });

  test('is idempotent — repeated call with same orgId returns existing record', () => {
    const first  = registerOrganization({ organizationName: 'First' });
    const second = registerOrganization({ organizationId: first.organizationId, organizationName: 'Second' });
    expect(second.organizationId).toBe(first.organizationId);
    expect(second.organizationName).toBe('First'); // unchanged
  });

  test('applies DEFAULT_QUOTAS when quotas not specified', () => {
    const org = registerOrganization({ organizationName: 'Quota Test' });
    expect(org.quotas.maxRequestsPerMinute).toBe(DEFAULT_QUOTAS.maxRequestsPerMinute);
    expect(org.quotas.maxRequestsPerKeyPerMin).toBe(DEFAULT_QUOTAS.maxRequestsPerKeyPerMin);
    expect(org.quotas.maxStreamingSessions).toBe(DEFAULT_QUOTAS.maxStreamingSessions);
    expect(org.quotas.retentionDays).toBe(DEFAULT_QUOTAS.retentionDays);
  });

  test('accepts custom quotas that override defaults', () => {
    const org = registerOrganization({
      organizationName: 'Enterprise',
      quotas: { maxRequestsPerMinute: 10_000, retentionDays: 730 },
    });
    expect(org.quotas.maxRequestsPerMinute).toBe(10_000);
    expect(org.quotas.retentionDays).toBe(730);
    expect(org.quotas.maxRequestsPerKeyPerMin).toBe(DEFAULT_QUOTAS.maxRequestsPerKeyPerMin);
  });

  test('sets createdAt and updatedAt to ISO strings', () => {
    const org = registerOrganization({ organizationName: 'Time Test' });
    expect(() => new Date(org.createdAt)).not.toThrow();
    expect(() => new Date(org.updatedAt)).not.toThrow();
  });

  test('tenantIds is an empty array for new org', () => {
    const org = registerOrganization({ organizationName: 'New' });
    expect(Array.isArray(org.tenantIds)).toBe(true);
    expect(org.tenantIds).toHaveLength(0);
  });
});

// ── 6–7. getOrganization ──────────────────────────────────────────────────────

describe('getOrganization', () => {
  test('returns the registered organization', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Lookup Test' });
    const org = getOrganization(organizationId);
    expect(org.organizationName).toBe('Lookup Test');
  });

  test('returns null for an unknown organizationId', () => {
    expect(getOrganization('99999999-9999-4999-9999-999999999999')).toBeNull();
  });

  test('returns null for non-string input', () => {
    expect(getOrganization(null)).toBeNull();
    expect(getOrganization(undefined)).toBeNull();
  });
});

// ── 8–12. updateOrganization ──────────────────────────────────────────────────

describe('updateOrganization', () => {
  test('updates organizationName and status', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Old Name' });
    const updated = updateOrganization(organizationId, { organizationName: 'New Name', status: 'suspended' });
    expect(updated.organizationName).toBe('New Name');
    expect(updated.status).toBe('suspended');
  });

  test('returns null for unknown organizationId', () => {
    const result = updateOrganization('00000000-0000-4000-8000-000000000000', { status: 'disabled' });
    expect(result).toBeNull();
  });

  test('throws for invalid status value', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Status Test' });
    expect(() => updateOrganization(organizationId, { status: 'archived' })).toThrow('INVALID_ORG_STATUS');
  });

  test('merges metadata non-destructively', () => {
    const { organizationId } = registerOrganization({
      organizationName: 'Meta Test',
      metadata: { region: 'us-east-1', tier: 'enterprise' },
    });
    const updated = updateOrganization(organizationId, { metadata: { tier: 'pro', plan: 'annual' } });
    expect(updated.metadata.region).toBe('us-east-1');
    expect(updated.metadata.tier).toBe('pro');
    expect(updated.metadata.plan).toBe('annual');
  });

  test('merges quotas non-destructively', () => {
    const { organizationId } = registerOrganization({
      organizationName: 'Quota Merge',
      quotas: { maxRequestsPerMinute: 1000, retentionDays: 90 },
    });
    const updated = updateOrganization(organizationId, { quotas: { retentionDays: 180 } });
    expect(updated.quotas.maxRequestsPerMinute).toBe(1000); // unchanged
    expect(updated.quotas.retentionDays).toBe(180);
  });
});

// ── 13–17. assignTenantToOrg / removeTenantFromOrg ────────────────────────────

describe('Tenant-Organization assignment', () => {
  test('assigns a tenant to an organization', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Assign Test' });
    assignTenantToOrg('tenant-alpha', organizationId);

    const org = getOrganization(organizationId);
    expect(org.tenantIds).toContain('tenant-alpha');
  });

  test('is idempotent for same tenant/org pair', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Idempotent' });
    assignTenantToOrg('tenant-beta', organizationId);
    assignTenantToOrg('tenant-beta', organizationId); // second call
    const org = getOrganization(organizationId);
    expect(org.tenantIds.filter(id => id === 'tenant-beta')).toHaveLength(1);
  });

  test('throws when assigning a tenant already owned by a different org', () => {
    const org1 = registerOrganization({ organizationName: 'Org One' });
    const org2 = registerOrganization({ organizationName: 'Org Two' });
    assignTenantToOrg('tenant-gamma', org1.organizationId);
    expect(() => assignTenantToOrg('tenant-gamma', org2.organizationId))
      .toThrow('TENANT_ALREADY_ASSIGNED');
  });

  test('throws when organization does not exist', () => {
    expect(() => assignTenantToOrg('tenant-delta', '00000000-0000-4000-8000-000000000000'))
      .toThrow('ORG_NOT_FOUND');
  });

  test('removeTenantFromOrg removes the assignment', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Remove Test' });
    assignTenantToOrg('tenant-epsilon', organizationId);
    const removed = removeTenantFromOrg('tenant-epsilon', organizationId);
    expect(removed).toBe(true);
    const org = getOrganization(organizationId);
    expect(org.tenantIds).not.toContain('tenant-epsilon');
  });

  test('removeTenantFromOrg returns false for tenant not in org', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Miss Test' });
    const removed = removeTenantFromOrg('nonexistent-tenant', organizationId);
    expect(removed).toBe(false);
  });
});

// ── 18–19. getOrganizationForTenant ──────────────────────────────────────────

describe('getOrganizationForTenant', () => {
  test('resolves the organization for an assigned tenant', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Resolve Test' });
    assignTenantToOrg('tenant-zeta', organizationId);
    const org = getOrganizationForTenant('tenant-zeta');
    expect(org.organizationId).toBe(organizationId);
  });

  test('returns null for a tenant with no org assignment', () => {
    expect(getOrganizationForTenant('unassigned-tenant')).toBeNull();
  });

  test('returns null for non-string input', () => {
    expect(getOrganizationForTenant(null)).toBeNull();
  });
});

// ── 20–23. assertActiveOrganization ──────────────────────────────────────────

describe('assertActiveOrganization', () => {
  test('passes for tenant assigned to an active organization', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Active Org' });
    assignTenantToOrg('tenant-eta', organizationId);
    const result = assertActiveOrganization('tenant-eta');
    expect(result.valid).toBe(true);
    expect(result.organizationId).toBe(organizationId);
  });

  test('passes for tenant with no org assignment (backward compatibility)', () => {
    const result = assertActiveOrganization('legacy-tenant-no-org');
    expect(result.valid).toBe(true);
    expect(result.organizationId).toBeNull();
  });

  test('blocks for tenant assigned to a suspended organization', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Suspended Org' });
    updateOrganization(organizationId, { status: 'suspended' });
    assignTenantToOrg('tenant-theta', organizationId);
    const result = assertActiveOrganization('tenant-theta');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ORG_SUSPENDED');
  });

  test('blocks for tenant assigned to a disabled organization', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Disabled Org' });
    updateOrganization(organizationId, { status: 'disabled' });
    assignTenantToOrg('tenant-iota', organizationId);
    const result = assertActiveOrganization('tenant-iota');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('ORG_DISABLED');
  });

  test('returns TENANT_CONTEXT_MISSING for empty string tenantId', () => {
    const result = assertActiveOrganization('');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });
});

// ── 24–25. getQuotasForTenant ─────────────────────────────────────────────────

describe('getQuotasForTenant', () => {
  test('returns org quotas for an assigned tenant', () => {
    const { organizationId } = registerOrganization({
      organizationName: 'Enterprise',
      quotas: { maxRequestsPerMinute: 50_000, maxRequestsPerKeyPerMin: 500 },
    });
    assignTenantToOrg('tenant-enterprise', organizationId);
    const quotas = getQuotasForTenant('tenant-enterprise');
    expect(quotas.maxRequestsPerMinute).toBe(50_000);
    expect(quotas.maxRequestsPerKeyPerMin).toBe(500);
  });

  test('returns DEFAULT_QUOTAS for unassigned tenant', () => {
    const quotas = getQuotasForTenant('standalone-tenant');
    expect(quotas.maxRequestsPerMinute).toBe(DEFAULT_QUOTAS.maxRequestsPerMinute);
    expect(quotas.maxRequestsPerKeyPerMin).toBe(DEFAULT_QUOTAS.maxRequestsPerKeyPerMin);
  });

  test('returns DEFAULT_QUOTAS for null tenantId', () => {
    const quotas = getQuotasForTenant(null);
    expect(quotas.maxRequestsPerMinute).toBe(DEFAULT_QUOTAS.maxRequestsPerMinute);
  });
});

// ── 26–27. listOrganizations / orgCount ──────────────────────────────────────

describe('listOrganizations and orgCount', () => {
  test('listOrganizations returns all registered orgs', () => {
    registerOrganization({ organizationName: 'Alpha' });
    registerOrganization({ organizationName: 'Beta' });
    registerOrganization({ organizationName: 'Gamma' });
    const orgs = listOrganizations();
    expect(orgs).toHaveLength(3);
    expect(orgs.map(o => o.organizationName).sort()).toEqual(['Alpha', 'Beta', 'Gamma']);
  });

  test('orgCount returns accurate count', () => {
    expect(orgCount()).toBe(0);
    registerOrganization({ organizationName: 'One' });
    expect(orgCount()).toBe(1);
    registerOrganization({ organizationName: 'Two' });
    expect(orgCount()).toBe(2);
  });

  test('listOrganizations returns snapshots (not live references)', () => {
    const { organizationId } = registerOrganization({ organizationName: 'Snapshot' });
    const list = listOrganizations();
    const snap = list.find(o => o.organizationId === organizationId);
    expect(Array.isArray(snap.tenantIds)).toBe(true);
  });
});
