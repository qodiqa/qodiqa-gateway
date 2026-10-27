'use strict';

/**
 * RectificationService — test suite (Article 16, mocked dependencies)
 */

describe('RectificationService', () => {
  let service;
  let pool;
  let ConsentStore;
  let DSRStore;

  beforeEach(() => {
    jest.resetModules();
    pool = { query: jest.fn().mockResolvedValue({ rows: [] }) };
    ConsentStore = { rectify: jest.fn() };
    DSRStore = { findById: jest.fn(), updateStatus: jest.fn() };

    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../consent/ConsentStore', () => ConsentStore);
    jest.doMock('../DSRStore', () => DSRStore);

    service = require('../RectificationService');
  });

  afterEach(() => jest.resetModules());

  function approvedRequest(overrides = {}) {
    return { id: 'req-1', request_type: 'RECTIFICATION', status: 'APPROVED', tenant_id: null, ...overrides };
  }

  test('rectifies a field, records a dsr_rectifications row, and completes the request', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    DSRStore.updateStatus
      .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
      .mockResolvedValueOnce({ status: 'COMPLETED' });
    ConsentStore.rectify.mockResolvedValue({
      record: { id: 'consent-1', actor_id: 'actor-1' },
      before: { subject_name: 'Old' },
      after:  { subject_name: 'New' },
    });

    const result = await service.rectify({
      requestId: 'req-1', consentId: 'consent-1', fields: { subject_name: 'New' }, rectifiedBy: 'compliance-1',
    });

    expect(result.status).toBe('COMPLETED');
    expect(ConsentStore.rectify).toHaveBeenCalledWith(expect.objectContaining({ id: 'consent-1' }));
    expect(pool.query).toHaveBeenCalledTimes(1);
    expect(pool.query.mock.calls[0][0]).toMatch(/dsr_rectifications/);
    expect(pool.query.mock.calls[0][1]).toContain('req-1');
    expect(DSRStore.updateStatus).toHaveBeenNthCalledWith(1, expect.objectContaining({ status: 'IN_PROGRESS' }));
    expect(DSRStore.updateStatus).toHaveBeenNthCalledWith(2, expect.objectContaining({ status: 'COMPLETED' }));
  });

  test('rejects a request that is not APPROVED', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest({ status: 'IDENTITY_VERIFIED' }));
    await expect(service.rectify({
      requestId: 'req-1', consentId: 'consent-1', fields: { subject_name: 'New' }, rectifiedBy: 'compliance-1',
    })).rejects.toThrow('is not approved for execution');
    expect(ConsentStore.rectify).not.toHaveBeenCalled();
  });

  test('rejects a request of the wrong type', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest({ request_type: 'ERASURE' }));
    await expect(service.rectify({
      requestId: 'req-1', consentId: 'consent-1', fields: { subject_name: 'New' }, rectifiedBy: 'compliance-1',
    })).rejects.toThrow('is not a RECTIFICATION request');
  });

  test('throws when the request does not exist', async () => {
    DSRStore.findById.mockResolvedValue(null);
    await expect(service.rectify({
      requestId: 'missing', consentId: 'consent-1', fields: { subject_name: 'New' }, rectifiedBy: 'compliance-1',
    })).rejects.toThrow('not found');
  });
});
