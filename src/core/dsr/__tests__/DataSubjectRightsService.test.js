'use strict';

/**
 * DataSubjectRightsService — orchestrator test suite (mocked sub-services)
 *
 * Covers: approve() gating on prior identity verification, and the shared
 * _execute() failure-handling wrapper (every execution path must record a
 * FAILED lifecycle transition on error, then re-throw the original error).
 */

describe('DataSubjectRightsService', () => {
  let service;
  let DSRStore;
  let identityVerification;
  let RectificationService;
  let RestrictionService;
  let ErasureService;
  let PortabilityService;

  beforeEach(() => {
    jest.resetModules();
    DSRStore = { createRequest: jest.fn(), findById: jest.fn(), updateStatus: jest.fn(), list: jest.fn(), listEvents: jest.fn() };
    identityVerification = { verifyIdentity: jest.fn(), assertVerified: jest.fn() };
    RectificationService = { rectify: jest.fn() };
    RestrictionService   = { restrict: jest.fn(), lift: jest.fn() };
    ErasureService        = { erase: jest.fn() };
    PortabilityService    = { generateExport: jest.fn() };

    jest.doMock('../DSRStore', () => DSRStore);
    jest.doMock('../identityVerification', () => identityVerification);
    jest.doMock('../RectificationService', () => RectificationService);
    jest.doMock('../RestrictionService', () => RestrictionService);
    jest.doMock('../ErasureService', () => ErasureService);
    jest.doMock('../PortabilityService', () => PortabilityService);

    service = require('../DataSubjectRightsService');
  });

  afterEach(() => jest.resetModules());

  describe('approve()', () => {
    test('asserts identity was verified before transitioning to APPROVED', async () => {
      const request = { id: 'req-1', tenant_id: null, identity_verification_result: 'VERIFIED' };
      DSRStore.findById.mockResolvedValue(request);
      DSRStore.updateStatus.mockResolvedValue({ status: 'APPROVED' });

      const result = await service.approve({ requestId: 'req-1', approvedBy: 'admin-1' });

      expect(identityVerification.assertVerified).toHaveBeenCalledWith(request);
      expect(DSRStore.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'APPROVED' }));
      expect(result.status).toBe('APPROVED');
    });

    test('propagates the identity-verification gate failure', async () => {
      DSRStore.findById.mockResolvedValue({ id: 'req-1', identity_verification_result: null });
      identityVerification.assertVerified.mockImplementation(() => {
        throw new Error('has not passed identity verification');
      });

      await expect(service.approve({ requestId: 'req-1', approvedBy: 'admin-1' }))
        .rejects.toThrow('has not passed identity verification');
      expect(DSRStore.updateStatus).not.toHaveBeenCalled();
    });
  });

  describe('failure handling (_execute wrapper)', () => {
    test('rectify(): records a FAILED transition and re-throws on sub-service error', async () => {
      RectificationService.rectify.mockRejectedValue(new Error('consent record not found'));
      DSRStore.updateStatus.mockResolvedValue({ status: 'FAILED' });

      await expect(service.rectify({ requestId: 'req-1', consentId: 'c1', fields: {}, rectifiedBy: 'x' }))
        .rejects.toThrow('consent record not found');

      expect(DSRStore.updateStatus).toHaveBeenCalledWith(expect.objectContaining({
        id: 'req-1', status: 'FAILED', eventType: 'DSR_REQUEST_FAILED',
      }));
    });

    test('erase(): records a FAILED transition and re-throws on sub-service error', async () => {
      ErasureService.erase.mockRejectedValue(new Error('pepper not configured'));
      DSRStore.updateStatus.mockResolvedValue({ status: 'FAILED' });

      await expect(service.erase({ requestId: 'req-1', pseudonymizeActorId: true, erasedBy: 'x' }))
        .rejects.toThrow('pepper not configured');
      expect(DSRStore.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'FAILED' }));
    });

    test('a logging failure while recording FAILED never masks the original error', async () => {
      RestrictionService.restrict.mockRejectedValue(new Error('original failure'));
      DSRStore.updateStatus.mockRejectedValue(new Error('db unavailable while logging failure'));

      await expect(service.restrict({ requestId: 'req-1', restrictedBy: 'x' }))
        .rejects.toThrow('original failure');
    });

    test('generateExport(): success path does not touch the FAILED transition', async () => {
      PortabilityService.generateExport.mockResolvedValue({ checksum: 'abc', payload: '{}' });

      const result = await service.generateExport({ requestId: 'req-1', format: 'JSON', generatedBy: 'x' });

      expect(result.checksum).toBe('abc');
      expect(DSRStore.updateStatus).not.toHaveBeenCalled();
    });

    test('liftRestriction(): delegates to RestrictionService.lift', async () => {
      RestrictionService.lift.mockResolvedValue({ status: 'COMPLETED' });
      const result = await service.liftRestriction({ requestId: 'req-1', liftedBy: 'x' });
      // liftRestriction() now threads an (optional, defaulted)
      // tenantId into RestrictionService.lift() so a tenant-scoped request's
      // findById() lookup can actually see its own row — see DSR-INVENTORY.md.
      expect(RestrictionService.lift).toHaveBeenCalledWith({ requestId: 'req-1', tenantId: null, liftedBy: 'x' });
      expect(result.status).toBe('COMPLETED');
    });
  });

  describe('read passthroughs', () => {
    test('getRequest/listRequests/listEvents delegate to DSRStore', async () => {
      DSRStore.findById.mockResolvedValue({ id: 'req-1' });
      DSRStore.list.mockResolvedValue({ requests: [], total: 0 });
      DSRStore.listEvents.mockResolvedValue([]);

      expect((await service.getRequest('req-1')).id).toBe('req-1');
      expect(await service.listRequests({})).toEqual({ requests: [], total: 0 });
      expect(await service.listEvents('req-1')).toEqual([]);
    });
  });
});
