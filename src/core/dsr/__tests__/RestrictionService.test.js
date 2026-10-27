'use strict';

/**
 * RestrictionService — test suite (Article 18, mocked dependencies)
 *
 * Restriction reuses ConsentStore.suspend()/resume() — the real consent
 * state machine already gates enforcement on isActiveNow(), so these tests
 * verify the DSR-specific orchestration (tagging, idempotency, scoped lift)
 * rather than re-testing the state machine itself (covered in consent.test.js).
 */

describe('RestrictionService', () => {
  let service;
  let ConsentStore;
  let DSRStore;

  beforeEach(() => {
    jest.resetModules();
    ConsentStore = { list: jest.fn(), suspend: jest.fn(), resume: jest.fn() };
    DSRStore = { findById: jest.fn(), updateStatus: jest.fn() };

    jest.doMock('../../consent/ConsentStore', () => ConsentStore);
    jest.doMock('../DSRStore', () => DSRStore);

    service = require('../RestrictionService');
  });

  afterEach(() => jest.resetModules());

  function approvedRequest(overrides = {}) {
    return { id: 'req-1', request_type: 'RESTRICTION', status: 'APPROVED', actor_id: 'actor-1', tenant_id: null, ...overrides };
  }

  describe('restrict()', () => {
    test('suspends every ACTIVE consent record for the actor', async () => {
      DSRStore.findById.mockResolvedValue(approvedRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });
      ConsentStore.list.mockResolvedValue({
        records: [
          { id: 'c1', state: 'ACTIVE' },
          { id: 'c2', state: 'ACTIVE' },
          { id: 'c3', state: 'REVOKED' }, // terminal — must be skipped
        ],
      });
      ConsentStore.suspend.mockImplementation(async ({ id }) => ({ id, state: 'SUSPENDED' }));

      const result = await service.restrict({ requestId: 'req-1', reason: 'GDPR request', restrictedBy: 'compliance-1' });

      expect(ConsentStore.suspend).toHaveBeenCalledTimes(2);
      expect(ConsentStore.suspend.mock.calls[0][0].suspension_reason).toMatch(/^DSR_RESTRICTION:req-1/);
      expect(result.status).toBe('COMPLETED');
    });

    test('is idempotent — an already-SUSPENDED record is not re-suspended', async () => {
      DSRStore.findById.mockResolvedValue(approvedRequest());
      DSRStore.updateStatus.mockResolvedValue({ status: 'COMPLETED' });
      ConsentStore.list.mockResolvedValue({ records: [{ id: 'c1', state: 'SUSPENDED' }] });

      await service.restrict({ requestId: 'req-1', restrictedBy: 'compliance-1' });

      expect(ConsentStore.suspend).not.toHaveBeenCalled();
    });

    test('rejects a request that is not APPROVED', async () => {
      DSRStore.findById.mockResolvedValue(approvedRequest({ status: 'RECEIVED' }));
      await expect(service.restrict({ requestId: 'req-1', restrictedBy: 'compliance-1' }))
        .rejects.toThrow('is not approved for execution');
    });
  });

  describe('lift()', () => {
    test('resumes only records tagged with this exact request id', async () => {
      const request = approvedRequest({ status: 'COMPLETED' });
      DSRStore.findById.mockResolvedValue(request);
      DSRStore.updateStatus.mockResolvedValue({ status: 'COMPLETED' });
      ConsentStore.list.mockResolvedValue({
        records: [
          { id: 'c1', suspension_reason: 'DSR_RESTRICTION:req-1 — reason' },
          { id: 'c2', suspension_reason: 'DSR_RESTRICTION:req-OTHER' }, // different request — must not be touched
          { id: 'c3', suspension_reason: 'operator-manual-hold' },
        ],
      });
      ConsentStore.resume.mockImplementation(async ({ id }) => ({ id, state: 'ACTIVE' }));

      await service.lift({ requestId: 'req-1', liftedBy: 'compliance-1' });

      expect(ConsentStore.resume).toHaveBeenCalledTimes(1);
      expect(ConsentStore.resume).toHaveBeenCalledWith(expect.objectContaining({ id: 'c1' }));
    });

    test('throws when the restriction was never completed', async () => {
      DSRStore.findById.mockResolvedValue(approvedRequest({ status: 'APPROVED' }));
      await expect(service.lift({ requestId: 'req-1', liftedBy: 'compliance-1' }))
        .rejects.toThrow('has no active restriction to lift');
    });
  });
});
