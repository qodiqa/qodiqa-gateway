'use strict';

const {
  registerTenant,
  getTenant,
  assertActiveTenant,
  listTenants,
  _reset,
} = require('../tenantRegistry');

beforeEach(() => {
  _reset();
});

// ── registerTenant ────────────────────────────────────────────────────────────

describe('registerTenant', () => {
  test('registers a tenant with defaults and returns the record', () => {
    const rec = registerTenant('tenant-a');
    expect(rec.tenantId).toBe('tenant-a');
    expect(rec.tenantName).toBe('tenant-a');
    expect(rec.status).toBe('active');
    expect(typeof rec.createdAt).toBe('string');
    expect(new Date(rec.createdAt).getTime()).not.toBeNaN();
  });

  test('registers a tenant with opts.tenantName', () => {
    const rec = registerTenant('org-x', { tenantName: 'Organisation X' });
    expect(rec.tenantName).toBe('Organisation X');
  });

  test('registers a tenant with opts.status inactive', () => {
    const rec = registerTenant('org-y', { status: 'inactive' });
    expect(rec.status).toBe('inactive');
  });

  test('is idempotent — second registration returns same record', () => {
    const r1 = registerTenant('tenant-a');
    const r2 = registerTenant('tenant-a');
    expect(r1).toBe(r2); // same object reference
  });

  test('throws for empty tenantId', () => {
    expect(() => registerTenant('')).toThrow();
  });

  test('throws for null tenantId', () => {
    expect(() => registerTenant(null)).toThrow();
  });

  test('throws for undefined tenantId', () => {
    expect(() => registerTenant(undefined)).toThrow();
  });

  test('throws for numeric tenantId', () => {
    expect(() => registerTenant(42)).toThrow();
  });

  test('throws for tenantId with invalid characters', () => {
    expect(() => registerTenant('tenant with spaces')).toThrow();
  });

  test('throws for tenantId exceeding 64 characters', () => {
    expect(() => registerTenant('a'.repeat(65))).toThrow();
  });

  test('accepts tenantId at max length (64 chars)', () => {
    const id = 'a'.repeat(64);
    const rec = registerTenant(id);
    expect(rec.tenantId).toBe(id);
  });

  test('accepts tenantId with underscores and hyphens', () => {
    const rec = registerTenant('my_tenant-001');
    expect(rec.tenantId).toBe('my_tenant-001');
  });
});

// ── getTenant ─────────────────────────────────────────────────────────────────

describe('getTenant', () => {
  test('returns tenant record after registration', () => {
    registerTenant('tenant-a');
    const rec = getTenant('tenant-a');
    expect(rec).not.toBeNull();
    expect(rec.tenantId).toBe('tenant-a');
  });

  test('returns null for unknown tenantId', () => {
    expect(getTenant('unknown-tenant')).toBeNull();
  });

  test('returns null for empty string', () => {
    expect(getTenant('')).toBeNull();
  });

  test('returns null for null', () => {
    expect(getTenant(null)).toBeNull();
  });

  test('returns null for undefined', () => {
    expect(getTenant(undefined)).toBeNull();
  });
});

// ── assertActiveTenant ────────────────────────────────────────────────────────

describe('assertActiveTenant', () => {
  test('returns { valid: true, tenant } for active tenant', () => {
    registerTenant('tenant-a');
    const result = assertActiveTenant('tenant-a');
    expect(result.valid).toBe(true);
    expect(result.tenant.tenantId).toBe('tenant-a');
  });

  test('returns TENANT_CONTEXT_MISSING for empty string', () => {
    const result = assertActiveTenant('');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });

  test('returns TENANT_CONTEXT_MISSING for null', () => {
    const result = assertActiveTenant(null);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });

  test('returns TENANT_CONTEXT_MISSING for undefined', () => {
    const result = assertActiveTenant(undefined);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_CONTEXT_MISSING');
  });

  test('returns TENANT_UNKNOWN for unregistered tenantId', () => {
    const result = assertActiveTenant('not-registered');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_UNKNOWN');
  });

  test('returns TENANT_INACTIVE for inactive tenant', () => {
    registerTenant('org-y', { status: 'inactive' });
    const result = assertActiveTenant('org-y');
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('TENANT_INACTIVE');
  });
});

// ── listTenants ───────────────────────────────────────────────────────────────

describe('listTenants', () => {
  test('returns empty array when no tenants registered', () => {
    expect(listTenants()).toEqual([]);
  });

  test('returns all registered tenants', () => {
    registerTenant('tenant-a');
    registerTenant('tenant-b');
    const tenants = listTenants();
    expect(tenants).toHaveLength(2);
    const ids = tenants.map(t => t.tenantId);
    expect(ids).toContain('tenant-a');
    expect(ids).toContain('tenant-b');
  });

  test('returns a copy (not the internal map)', () => {
    registerTenant('tenant-a');
    const list1 = listTenants();
    list1.push({ fake: true });
    expect(listTenants()).toHaveLength(1);
  });
});

// ── _reset ────────────────────────────────────────────────────────────────────

describe('_reset', () => {
  test('clears all tenants', () => {
    registerTenant('tenant-a');
    registerTenant('tenant-b');
    _reset();
    expect(listTenants()).toHaveLength(0);
  });

  test('allows re-registration after reset', () => {
    registerTenant('tenant-a');
    _reset();
    const rec = registerTenant('tenant-a');
    expect(rec.tenantId).toBe('tenant-a');
  });
});
