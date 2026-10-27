'use strict';

/**
 * ConsentStore — findById()/list() tenant scoping.
 *
 * Previously both functions always used a plain pool.query() — which never
 * sets the qodiqa.tenant_id RLS session variable — so the cr_tenant_select
 * RLS policy (`tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()`)
 * only ever admitted platform-level rows underneath them, regardless of any
 * tenant_id argument/filter the caller supplied. This was a functional bug
 * (a tenant-scoped record could never be found), not a cross-tenant leak —
 * RLS was still correctly hiding every tenant row from an unscoped caller.
 * The fix: route through pool.withTenantTransaction(tenant_id, ...) whenever
 * a tenant_id is supplied, exactly like findByKey()/revoke() already did.
 */

describe('ConsentStore — tenant-scoped queries route through withTenantTransaction', () => {
  let store;
  let mockTx;
  let pool;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = {
      query:                 jest.fn(),
      withTransaction:       jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn(mockTx)),
    };
    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
    store = require('../ConsentStore');
  });

  afterEach(() => jest.resetModules());

  describe('findById()', () => {
    test('with no tenant_id: uses a plain pool.query(), never withTenantTransaction', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'c1' }] });

      const result = await store.findById('c1');

      expect(result).toEqual({ id: 'c1' });
      expect(pool.query).toHaveBeenCalledTimes(1);
      expect(pool.withTenantTransaction).not.toHaveBeenCalled();
    });

    test('with tenant_id: routes through withTenantTransaction with that tenant', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [{ id: 'c1', tenant_id: 'tenant-A' }] });

      const result = await store.findById('c1', 'tenant-A');

      expect(result).toEqual({ id: 'c1', tenant_id: 'tenant-A' });
      expect(pool.withTenantTransaction).toHaveBeenCalledWith('tenant-A', expect.any(Function));
      expect(pool.query).not.toHaveBeenCalled();
      expect(mockTx.query).toHaveBeenCalledWith(
        expect.stringContaining('WHERE id = $1'),
        ['c1'],
      );
    });

    test('returns null when no row is found', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });
      expect(await store.findById('missing')).toBeNull();
    });
  });

  describe('list()', () => {
    test('with no tenant_id filter: uses plain pool.query() calls, never withTenantTransaction', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [{ id: 'c1' }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });

      const result = await store.list({});

      expect(result.records).toEqual([{ id: 'c1' }]);
      expect(result.total).toBe(1);
      expect(pool.withTenantTransaction).not.toHaveBeenCalled();
    });

    test('with a tenant_id filter: routes both the data and count queries through withTenantTransaction', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [{ id: 'c1', tenant_id: 'tenant-A' }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });

      const result = await store.list({ tenant_id: 'tenant-A' });

      expect(result.records).toEqual([{ id: 'c1', tenant_id: 'tenant-A' }]);
      expect(result.total).toBe(1);
      expect(pool.withTenantTransaction).toHaveBeenCalledWith('tenant-A', expect.any(Function));
      expect(pool.query).not.toHaveBeenCalled();
      expect(mockTx.query).toHaveBeenCalledTimes(2);
    });

    test('the tenant_id filter is still applied in the SQL WHERE clause, not just the RLS session context', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ total: '0' }] });

      await store.list({ tenant_id: 'tenant-B' });

      const [dataSql, dataParams] = mockTx.query.mock.calls[0];
      expect(dataSql).toContain('tenant_id = $');
      expect(dataParams).toContain('tenant-B');
    });
  });
});
