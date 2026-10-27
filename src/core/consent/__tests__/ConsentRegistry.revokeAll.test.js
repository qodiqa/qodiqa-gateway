'use strict';

/**
 * revokeAll() must reach tenant-scoped consents (RLS) and page past 200 records.
 */

jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: () => true, isHealthy: () => true }));
jest.mock('../ConsentCache', () => ({ invalidate: jest.fn(async () => {}), invalidateActor: jest.fn(async () => {}), isReady: () => true }));
jest.mock('../ConsentVerifier', () => ({}));
jest.mock('../revocation/RevocationPublisher', () => ({ publish: jest.fn(async () => true) }));
jest.mock('../../tenancy/tenantRegistry', () => ({ listTenants: jest.fn(() => [{ tenantId: 'acme' }, { tenantId: 'globex' }]) }));

const mockRows = {
  // key: tenant scope ('' = platform) -> array of consent rows
  '': [{ id: 'p1', actor_id: 'a1', action: 'openai', tenant_id: null, state: 'ACTIVE', version: 1 }],
  acme: [{ id: 't1', actor_id: 'a1', action: 'local', tenant_id: 'acme', state: 'ACTIVE', version: 1 },
         { id: 't2', actor_id: 'a1', action: 'openai', tenant_id: 'acme', state: 'REVOKED', version: 2 }],
  globex: [],
};
jest.mock('../ConsentStore', () => ({
  list: jest.fn(async ({ tenant_id, limit, offset }) => {
    const all = mockRows[tenant_id || ''] || [];
    return { records: all.slice(offset, offset + limit), total: all.length };
  }),
  revoke: jest.fn(async ({ id, tenant_id }) => {
    const row = Object.values(mockRows).flat().find((r) => r.id === id);
    return { ...row, tenant_id: tenant_id ?? null, state: 'REVOKED', version: (row.version || 0) + 1 };
  }),
}));

const store = require('../ConsentStore');
const cache = require('../ConsentCache');
const registry = require('../ConsentRegistry');

beforeEach(() => { jest.clearAllMocks(); });

describe('ConsentRegistry.revokeAll — tenant scopes under RLS', () => {
  test('RA-01 revokes platform-level AND tenant-scoped active consents; each in its own tenant context', async () => {
    const out = await registry.revokeAll('a1', 'op-1', 'DECOMMISSIONED');
    expect(out.count).toBe(2); // p1 (platform) + t1 (acme); t2 already REVOKED is skipped
    const listScopes = store.list.mock.calls.map((c) => c[0].tenant_id);
    expect(listScopes).toEqual([undefined, 'acme', 'globex']); // platform + every registered tenant
    const revoked = store.revoke.mock.calls.map((c) => [c[0].id, c[0].tenant_id]);
    expect(revoked).toEqual([['p1', null], ['t1', 'acme']]); // tenant id is passed so the revoke runs inside the RLS context
    expect(cache.invalidate).toHaveBeenCalledTimes(2);
    expect(cache.invalidateActor).toHaveBeenCalledWith('a1');
  });

  test('RA-02 explicit tenantIds restrict the tenant scopes (platform scope is always covered)', async () => {
    await registry.revokeAll('a1', 'op-1', 'X', { tenantIds: ['globex'] });
    expect(store.list.mock.calls.map((c) => c[0].tenant_id)).toEqual([undefined, 'globex']);
  });

  test('RA-03 pages past 200 records instead of stopping at the first page', async () => {
    const many = Array.from({ length: 450 }, (_, i) => ({ id: `m${i}`, actor_id: 'a2', action: 'x', tenant_id: null, state: 'ACTIVE', version: 1 }));
    mockRows[''] = many;
    const out = await registry.revokeAll('a2', 'op-1', 'X', { tenantIds: [] });
    expect(out.count).toBe(450);
    expect(store.list.mock.calls.map((c) => c[0].offset)).toEqual([0, 200, 400]);
  });
});
