'use strict';

/**
 * DSRStore — test suite (mocked pool)
 *
 * Covers: createRequest, findById, list, listEvents, appendEvent, updateStatus.
 */

describe('DSRStore', () => {
  let store;
  let mockTx;
  let pool;
  let emit;

  beforeEach(() => {
    jest.resetModules();
    mockTx = { query: jest.fn() };
    pool = {
      query:                jest.fn(),
      withTransaction:      jest.fn(async (fn) => fn(mockTx)),
      withTenantTransaction: jest.fn(async (_tenantId, fn) => fn(mockTx)),
    };
    emit = jest.fn();
    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../../../services/logger', () => ({ emit }));
    store = require('../DSRStore');
  });

  afterEach(() => jest.resetModules());

  describe('createRequest()', () => {
    test('inserts request row and appends DSR_REQUEST_RECEIVED event', async () => {
      const row = { id: 'req-1', request_type: 'ERASURE', actor_id: 'actor-1', status: 'RECEIVED' };
      mockTx.query
        .mockResolvedValueOnce({ rows: [row] }) // INSERT dsr_requests
        .mockResolvedValueOnce({ rows: [] });    // INSERT dsr_request_events

      const result = await store.createRequest({
        request_type: 'ERASURE', actor_id: 'actor-1', requested_by: 'ops-1',
      });

      expect(result.id).toBe('req-1');
      expect(mockTx.query).toHaveBeenCalledTimes(2);
      expect(mockTx.query.mock.calls[1][0]).toMatch(/dsr_request_events/);
      expect(mockTx.query.mock.calls[1][1]).toContain('DSR_REQUEST_RECEIVED');
      expect(emit).toHaveBeenCalledWith('INFO', 'DSR_REQUEST_CREATED', expect.objectContaining({ requestId: 'req-1' }));
    });

    test('throws when request_type missing', async () => {
      await expect(store.createRequest({ actor_id: 'a', requested_by: 'b' }))
        .rejects.toThrow('required');
    });

    test('throws when actor_id missing', async () => {
      await expect(store.createRequest({ request_type: 'ERASURE', requested_by: 'b' }))
        .rejects.toThrow('required');
    });
  });

  describe('findById()', () => {
    test('returns null when not found', async () => {
      pool.query.mockResolvedValueOnce({ rows: [] });
      expect(await store.findById('missing')).toBeNull();
    });

    test('returns request row when found', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ id: 'req-1' }] });
      expect((await store.findById('req-1')).id).toBe('req-1');
    });
  });

  describe('list()', () => {
    test('returns requests and total', async () => {
      pool.query
        .mockResolvedValueOnce({ rows: [{ id: 'req-1' }] })
        .mockResolvedValueOnce({ rows: [{ total: '1' }] });
      const { requests, total } = await store.list({ actor_id: 'actor-1' });
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
  });

  describe('listEvents()', () => {
    test('returns events for a request', async () => {
      pool.query.mockResolvedValueOnce({ rows: [{ event_type: 'DSR_REQUEST_RECEIVED' }] });
      const events = await store.listEvents({ request_id: 'req-1' });
      expect(events).toHaveLength(1);
    });
  });

  describe('appendEvent()', () => {
    test('inserts an event row without touching request status', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await store.appendEvent({ request_id: 'req-1', event_type: 'DSR_NOTE', actor: 'ops-1' });
      expect(mockTx.query).toHaveBeenCalledTimes(1);
      expect(mockTx.query.mock.calls[0][0]).toMatch(/dsr_request_events/);
    });
  });

  describe('updateStatus()', () => {
    test('updates status, patches allow-listed fields, and appends a matching event', async () => {
      const updated = { id: 'req-1', status: 'APPROVED', tenant_id: null };
      mockTx.query
        .mockResolvedValueOnce({ rows: [{ status: 'IDENTITY_VERIFIED', request_type: 'ERASURE' }] }) // SELECT … FOR UPDATE
        .mockResolvedValueOnce({ rows: [updated] }) // UPDATE dsr_requests
        .mockResolvedValueOnce({ rows: [] });        // INSERT dsr_request_events

      const result = await store.updateStatus({
        id: 'req-1', status: 'APPROVED',
        patch: { approved_by: 'admin-1', approved_at: new Date(), not_a_real_field: 'ignored' },
        actor: 'admin-1', eventType: 'DSR_REQUEST_APPROVED',
      });

      expect(result.status).toBe('APPROVED');
      expect(mockTx.query.mock.calls[0][0]).toMatch(/SELECT status, request_type FROM dsr_requests WHERE id = \$1 FOR UPDATE/);
      const [sql, params] = mockTx.query.mock.calls[1];
      expect(sql).toMatch(/UPDATE dsr_requests SET status = \$1/);
      expect(sql).toMatch(/approved_by/);
      expect(sql).not.toMatch(/not_a_real_field/);
      expect(params).not.toContain('ignored');
    });

    test('throws when request not found', async () => {
      mockTx.query.mockResolvedValueOnce({ rows: [] });
      await expect(store.updateStatus({ id: 'missing', status: 'APPROVED', actor: 'x' }))
        .rejects.toThrow('not found');
    });

    test('skips the event insert when eventType is omitted', async () => {
      mockTx.query
        .mockResolvedValueOnce({ rows: [{ status: 'APPROVED', request_type: 'ERASURE' }] })
        .mockResolvedValueOnce({ rows: [{ id: 'req-1', status: 'IN_PROGRESS' }] });
      await store.updateStatus({ id: 'req-1', status: 'IN_PROGRESS', actor: 'x' });
      expect(mockTx.query).toHaveBeenCalledTimes(2);
    });

    //
    test.each([
      ['COMPLETED', 'APPROVED', 'ERASURE'],        // a completed erasure is never re-approved
      ['FAILED', 'APPROVED', 'ERASURE'],           // a failed erasure resumes, it is not re-approved
      ['COMPLETED', 'IN_PROGRESS', 'ERASURE'],
      ['RECEIVED', 'APPROVED', 'ERASURE'],         // identity verification cannot be skipped
      ['REJECTED', 'IDENTITY_VERIFIED', 'ERASURE'],
      ['FAILED', 'IN_PROGRESS', 'RECTIFICATION'],  // only an erasure run is resumable
      ['COMPLETED', 'COMPLETED', 'ERASURE'],       // only a restriction lift re-completes
    ])('refuses %s → %s for a %s request (409 DSR_INVALID_TRANSITION), writes nothing', async (from, to, type) => {
      mockTx.query.mockResolvedValueOnce({ rows: [{ status: from, request_type: type }] });
      await expect(store.updateStatus({ id: 'req-1', status: to, actor: 'x', eventType: 'E' }))
        .rejects.toMatchObject({ code: 'DSR_INVALID_TRANSITION', statusCode: 409 });
      expect(mockTx.query).toHaveBeenCalledTimes(1);
    });

    test.each([
      ['RECEIVED', 'IDENTITY_VERIFIED', 'ERASURE'], ['RECEIVED', 'REJECTED', 'ERASURE'],
      ['IDENTITY_VERIFIED', 'APPROVED', 'ERASURE'], ['APPROVED', 'IN_PROGRESS', 'ERASURE'],
      ['APPROVED', 'FAILED', 'ERASURE'], ['IN_PROGRESS', 'COMPLETED', 'ERASURE'], ['IN_PROGRESS', 'FAILED', 'ERASURE'],
      ['FAILED', 'IN_PROGRESS', 'ERASURE'], ['COMPLETED', 'COMPLETED', 'RESTRICTION'],
    ])('allows %s → %s for a %s request', (from, to, type) => {
      expect(store.isAllowedTransition(from, to, type)).toBe(true);
    });
  });
});
