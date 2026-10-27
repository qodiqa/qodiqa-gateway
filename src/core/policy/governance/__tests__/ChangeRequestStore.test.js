'use strict';

/**
 * ChangeRequestStore — test suite (mocked pool)
 *
 * Covers: create, findById, list, updateStatus/updateStatusInTx including
 * the optimistic-lock ConcurrentModificationError path ('s guard
 * against two checkers approving the same stale proposal).
 */

describe('ChangeRequestStore', () => {
  let store;
  let mockTx;
  let pool;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = {
      query:                jest.fn(),
      withTransaction:      jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn(mockTx)),
    };
    jest.doMock('../../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../../infra/postgres/rolePools', () => require('../../../../../test/helpers/rolePoolsDelegate')(pool)); //
    jest.doMock('../../../../../services/logger', () => ({ emit: jest.fn() }));
    store = require('../ChangeRequestStore');
  });

  afterEach(() => jest.resetModules());

  const author = { id: 'author-1', username: 'alice', role: 'operator' };

  describe('create()', () => {
    test('inserts a request row', async () => {
      const row = { id: 'req-1', policy_id: 'p1', status: 'DRAFT', version: 1 };
      mockTx.query.mockResolvedValueOnce({ rows: [row] });

      const result = await store.create({
        policy_id: 'p1', request_type: 'CREATE', payload: {}, change_reason: 'test', author,
      });

      expect(result.id).toBe('req-1');
      expect(mockTx.query).toHaveBeenCalledTimes(1);
    });

    test('throws when policy_id missing', async () => {
      await expect(store.create({ request_type: 'CREATE', change_reason: 'x', author }))
        .rejects.toThrow('required');
    });

    test('throws when author is incomplete', async () => {
      await expect(store.create({
        policy_id: 'p1', request_type: 'CREATE', change_reason: 'x', author: { id: 'a' },
      })).rejects.toThrow('author');
    });
  });

  describe('findById()', () => {
    test('returns null when not found — after also consulting the cross-tenant definer read', async () => {
      // First call: the plain RLS-scoped read. Second call: the
      // qodiqa_policy_change_request_by_id() SECURITY DEFINER fallback that
      // finds TENANT-scoped rows the plain read cannot see.
      pool.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });
      expect(await store.findById('missing')).toBeNull();
      expect(pool.query).toHaveBeenCalledTimes(2);
      expect(pool.query.mock.calls[1][0]).toContain('qodiqa_policy_change_request_by_id');
    });
    test('returns the row when found on the plain read (no fallback issued)', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'req-1' }] });
      expect((await store.findById('req-1')).id).toBe('req-1');
      expect(pool.query).toHaveBeenCalledTimes(1);
    });
    test('returns a TENANT-scoped row via the definer fallback when the plain read is RLS-blind', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ id: 'req-t', tenant_id: 'tenant-a' }] });
      const row = await store.findById('req-t');
      expect(row.tenant_id).toBe('tenant-a');
    });
  });

  describe('list()', () => {
    test('returns requests and total', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [{ id: 'req-1' }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });
      const { requests, total } = await store.list({ policyId: 'p1' });
      expect(requests).toHaveLength(1);
      expect(total).toBe(1);
    });

    test('caps limit at 200', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [{ total: '0' }] });
      await store.list({ limit: 9999 });
      expect(pool.query.mock.calls[0][0]).toMatch(/LIMIT/);
    });

    // a tenantId filter must run under that tenant's own context
    // (pool.withTenantTransaction), never the plain contextless pool.query()
    // path — the plain path is RLS-blind to every tenant-scoped row (see
    // migration 029's nullable-tenant policy), which is the defect this item
    // fixes. No SECURITY DEFINER function involved.
    test('a tenantId filter runs under that tenant\'s own transaction context, not the plain contextless read', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [{ id: 'req-t', tenant_id: 'tenant-a' }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });

      const { requests, total } = await store.list({ tenantId: 'tenant-a' });

      expect(pool.withTenantTransaction).toHaveBeenCalledWith('tenant-a', expect.any(Function));
      expect(pool.query).not.toHaveBeenCalled(); // never the RLS-blind contextless path
      expect(requests).toEqual([{ id: 'req-t', tenant_id: 'tenant-a' }]);
      expect(total).toBe(1);
      // Both queries carry the explicit tenant_id filter — the union half of
      // RLS's (tenant_id IS NULL OR tenant_id = current_tenant()) policy is
      // never relied on to exclude platform rows; the WHERE clause does that.
      expect(mockTx.query.mock.calls[0][0]).toMatch(/tenant_id = \$1/);
      expect(mockTx.query.mock.calls[0][1]).toContain('tenant-a');
    });

    test('no tenantId filter: unchanged plain contextless read (platform-wide listing, backward compatible)', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [{ id: 'req-platform', tenant_id: null }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });

      const { requests } = await store.list({});

      expect(pool.withTenantTransaction).not.toHaveBeenCalled();
      expect(requests).toEqual([{ id: 'req-platform', tenant_id: null }]);
    });
  });

  describe('updateStatusInTx() / updateStatus()', () => {
    test('updates status with the expected version and returns the row', async () => {
      const updated = { id: 'req-1', status: 'SUBMITTED', version: 2 };
      mockTx.query.mockResolvedValueOnce({ rows: [updated] });

      const result = await store.updateStatusInTx(mockTx, {
        id: 'req-1', expectedVersion: 1, status: 'SUBMITTED', patch: { submitted_by: 'author-1' },
      });

      expect(result.status).toBe('SUBMITTED');
      const [sql, params] = mockTx.query.mock.calls[0];
      expect(sql).toMatch(/UPDATE policy_change_requests SET status = \$1/);
      expect(sql).toMatch(/AND version = \$/);
      expect(params).toContain(1); // expectedVersion
    });

    test('ignores patch fields not on the allow-list', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [{ id: 'req-1', status: 'SUBMITTED' }] });
      await store.updateStatusInTx(mockTx, {
        id: 'req-1', expectedVersion: 1, status: 'SUBMITTED', patch: { author_id: 'attacker-controlled' },
      });
      const [sql, params] = mockTx.query.mock.calls[0];
      expect(sql).not.toMatch(/author_id/);
      expect(params).not.toContain('attacker-controlled');
    });

    test('throws ConcurrentModificationError when the version no longer matches (row exists)', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] }) // UPDATE ... WHERE version=$n matched 0 rows
        .mockResolvedValueOnce({ rows: [{ id: 'req-1' }] }); // existence check confirms it still exists

      await expect(store.updateStatusInTx(mockTx, {
        id: 'req-1', expectedVersion: 1, status: 'SUBMITTED',
      })).rejects.toThrow(store.ConcurrentModificationError);
    });

    test('throws NOT_FOUND when the row genuinely does not exist', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [] })
        .mockResolvedValueOnce({ rows: [] });

      const err = await store.updateStatusInTx(mockTx, {
        id: 'missing', expectedVersion: 1, status: 'SUBMITTED',
      }).catch((e) => e);
      expect(err.code).toBe('NOT_FOUND');
    });

    test('updateStatus() wraps updateStatusInTx() in its own transaction', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [{ id: 'req-1', status: 'SUBMITTED' }] });
      await store.updateStatus({ id: 'req-1', expectedVersion: 1, status: 'SUBMITTED' });
      expect(pool.withTransaction).toHaveBeenCalledTimes(1);
    });
  });
});
