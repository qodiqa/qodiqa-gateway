'use strict';

/**
 * Operator Extension Interface for GDPR Erasure Scope.
 *
 * Integration coverage for ErasureTargetRegistry wired into
 * ErasureService.erase() and PortabilityService.generateExport(): a
 * registered target must be invoked with correct, actor-scoped context,
 * its result must land in both the DSR response and the dsr_request_events
 * audit trail (DSRStore.appendEvent), one target's failure must never abort
 * the request or the remaining targets, and — with zero targets registered
 * — behavior must be identical to pre-WP-026 (backward compatibility).
 */

describe('operator DSR extension targets', () => {
  let ConsentStore;
  let DSRStore;
  let pool;
  let rolePools;
  const finalResult = () => JSON.parse(rolePools.system.query.mock.calls.find(([q]) => /finalize/.test(q))[1][6]);
  let ErasureTargetRegistry;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...process.env, QODIQA_DSR_PSEUDONYM_PEPPER: 'test-pepper' };

    ConsentStore = {
      list: jest.fn().mockResolvedValue({ records: [] }),
      eraseSubjectBatch: jest.fn().mockResolvedValue({ erased: 0 }), //
      anonymize: jest.fn(),
      pseudonymizeActor: jest.fn(),
      getAuditLog: jest.fn().mockResolvedValue([]),
    };
    DSRStore = {
      findById: jest.fn(),
      updateStatus: jest.fn(),
      appendEvent: jest.fn().mockResolvedValue(undefined),
      list: jest.fn().mockResolvedValue({ requests: [] }),
      _eventChecksum: jest.requireActual('../DSRStore')._eventChecksum, // finalize event checksum
    };
    pool = { query: jest.fn().mockResolvedValue({ rows: [{ id: 'export-1' }] }) };

    jest.doMock('../../consent/ConsentStore', () => ConsentStore);
    jest.doMock('../DSRStore', () => DSRStore);
    jest.doMock('../../../infra/postgres/pool', () => pool);
    // erasure runs the owner-run SQL functions as qodiqa_system and
    // completes through qodiqa_erase_subject_finalize — the result the extension
    // targets land in is that call's p_result argument.
    rolePools = { system: { query: jest.fn(async (sql) => (/finalize/.test(sql)
      ? { rows: [{ id: 'req-1', status: 'COMPLETED' }] } : { rows: [] })) } };
    jest.doMock('../../../infra/postgres/rolePools', () => rolePools);
    jest.doMock('../subjectPseudonym', () => ({
      pseudonymFor: jest.fn().mockResolvedValue('ap1:' + 'a'.repeat(64)), subjectRef: jest.fn().mockReturnValue('b'.repeat(64)),
    }));
    jest.doMock('../../consent/ConsentCache', () => ({ invalidateActor: jest.fn() }));
    jest.doMock('../../consent/revocation/RevocationPublisher', () => ({ publish: jest.fn().mockResolvedValue(true) }));

    // Real registry — a pure in-memory module, safe to use directly and
    // reset between tests via clear().
    ErasureTargetRegistry = require('../ErasureTargetRegistry');
    ErasureTargetRegistry.clear();
  });

  afterEach(() => {
    ErasureTargetRegistry.clear();
    jest.resetModules();
  });

  function approvedErasureRequest(overrides = {}) {
    return {
      id: 'req-1', request_type: 'ERASURE', status: 'APPROVED', identity_verification_result: 'VERIFIED',
      actor_id: 'actor-1', tenant_id: 'tenant-1', ...overrides,
    };
  }

  function approvedPortabilityRequest(overrides = {}) {
    return {
      id: 'req-1', request_type: 'PORTABILITY', status: 'APPROVED',
      actor_id: 'actor-1', tenant_id: 'tenant-1', ...overrides,
    };
  }

  describe('ErasureService.erase()', () => {
    test('invokes a registered target exactly once with actor-scoped context and includes its result', async () => {
      const eraseCallback = jest.fn().mockResolvedValue({ rowsDeleted: 3 });
      ErasureTargetRegistry.registerTarget({ id: 'crm', name: 'CRM Database', erase: eraseCallback });

      const ErasureService = require('../ErasureService');
      DSRStore.findById.mockResolvedValue(approvedErasureRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      await ErasureService.erase({ requestId: 'req-1', erasedBy: 'compliance-1' });

      expect(eraseCallback).toHaveBeenCalledTimes(1);
      expect(eraseCallback).toHaveBeenCalledWith({
        actorId: 'actor-1',
        tenantId: 'tenant-1',
        requestId: 'req-1',
        requestType: 'ERASURE',
        performedBy: 'compliance-1',
      });

      // Result included in the final DSR response (persisted by the finalize step's result).
      expect(finalResult().customTargets).toEqual([
        expect.objectContaining({
          targetId: 'crm', targetName: 'CRM Database', operation: 'ERASE',
          status: 'COMPLETED', success: true, result: { rowsDeleted: 3 }, error: null,
        }),
      ]);

      // Audit evidence: a dedicated dsr_request_events row via the existing appendEvent trail.
      expect(DSRStore.appendEvent).toHaveBeenCalledWith(expect.objectContaining({
        request_id: 'req-1',
        tenant_id:  'tenant-1',
        event_type: 'DSR_EXTENSION_TARGET_ERASED',
        actor:      'compliance-1',
        detail: expect.objectContaining({ targetId: 'crm', status: 'COMPLETED' }),
      }));
    });

    test('isolates a failing target — remaining targets still run and the request still completes', async () => {
      const failing   = jest.fn().mockRejectedValue(new Error('CRM connection timeout'));
      const succeeding = jest.fn().mockResolvedValue({ ok: true });
      ErasureTargetRegistry.registerTarget({ id: 'flaky-crm', name: 'Flaky CRM', erase: failing });
      ErasureTargetRegistry.registerTarget({ id: 'ticketing', name: 'Ticketing System', erase: succeeding });

      const ErasureService = require('../ErasureService');
      DSRStore.findById.mockResolvedValue(approvedErasureRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      const result = await ErasureService.erase({ requestId: 'req-1', erasedBy: 'compliance-1' });

      expect(result.status).toBe('COMPLETED');
      expect(succeeding).toHaveBeenCalledTimes(1);

      const customTargets = finalResult().customTargets;
      expect(customTargets).toEqual([
        expect.objectContaining({ targetId: 'flaky-crm', status: 'FAILED', success: false, error: 'CRM connection timeout' }),
        expect.objectContaining({ targetId: 'ticketing', status: 'COMPLETED', success: true }),
      ]);

      // Failure is recorded as audit evidence too, not swallowed.
      expect(DSRStore.appendEvent).toHaveBeenCalledWith(expect.objectContaining({
        event_type: 'DSR_EXTENSION_TARGET_ERASED',
        detail: expect.objectContaining({ targetId: 'flaky-crm', status: 'FAILED', error: 'CRM connection timeout' }),
      }));
    });

    test('backward compatible: with zero targets registered, customTargets is an empty array', async () => {
      const ErasureService = require('../ErasureService');
      DSRStore.findById.mockResolvedValue(approvedErasureRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      await ErasureService.erase({ requestId: 'req-1', erasedBy: 'compliance-1' });

      expect(finalResult().customTargets).toEqual([]);
    });

    test('invokes targets in registration order', async () => {
      const order = [];
      ErasureTargetRegistry.registerTarget({ id: 'first', name: 'First', erase: async () => { order.push('first'); } });
      ErasureTargetRegistry.registerTarget({ id: 'second', name: 'Second', erase: async () => { order.push('second'); } });

      const ErasureService = require('../ErasureService');
      DSRStore.findById.mockResolvedValue(approvedErasureRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      await ErasureService.erase({ requestId: 'req-1', erasedBy: 'compliance-1' });

      expect(order).toEqual(['first', 'second']);
    });
  });

  describe('PortabilityService.generateExport()', () => {
    test('invokes a registered export-capable target and includes its result in the response', async () => {
      const exportCallback = jest.fn().mockResolvedValue({ ticketsExported: 5 });
      ErasureTargetRegistry.registerTarget({
        id: 'ticketing', name: 'Ticketing System', erase: jest.fn(), export: exportCallback,
      });

      const PortabilityService = require('../PortabilityService');
      DSRStore.findById.mockResolvedValue(approvedPortabilityRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      const result = await PortabilityService.generateExport({ requestId: 'req-1', format: 'JSON', generatedBy: 'compliance-1' });

      expect(exportCallback).toHaveBeenCalledTimes(1);
      expect(exportCallback).toHaveBeenCalledWith(expect.objectContaining({
        actorId: 'actor-1', tenantId: 'tenant-1', requestId: 'req-1', requestType: 'PORTABILITY', performedBy: 'compliance-1',
      }));

      expect(result.customTargets).toEqual([
        expect.objectContaining({ targetId: 'ticketing', operation: 'EXPORT', status: 'COMPLETED', result: { ticketsExported: 5 } }),
      ]);

      const completedCall = DSRStore.updateStatus.mock.calls[1][0];
      expect(completedCall.patch.result.customTargets).toEqual(result.customTargets);

      expect(DSRStore.appendEvent).toHaveBeenCalledWith(expect.objectContaining({
        event_type: 'DSR_EXTENSION_TARGET_EXPORTED',
        detail: expect.objectContaining({ targetId: 'ticketing', status: 'COMPLETED' }),
      }));
    });

    test('reports NOT_SUPPORTED explicitly for a target with no export callback, rather than skipping it', async () => {
      ErasureTargetRegistry.registerTarget({ id: 'crm', name: 'CRM Database', erase: jest.fn() });

      const PortabilityService = require('../PortabilityService');
      DSRStore.findById.mockResolvedValue(approvedPortabilityRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      const result = await PortabilityService.generateExport({ requestId: 'req-1', format: 'JSON', generatedBy: 'compliance-1' });

      expect(result.customTargets).toEqual([
        expect.objectContaining({ targetId: 'crm', operation: 'EXPORT', status: 'NOT_SUPPORTED', success: false, result: null }),
      ]);
    });

    test('a failing export target is isolated and does not prevent the export from completing', async () => {
      ErasureTargetRegistry.registerTarget({
        id: 'billing', name: 'Billing System', erase: jest.fn(),
        export: jest.fn().mockRejectedValue(new Error('billing API unreachable')),
      });

      const PortabilityService = require('../PortabilityService');
      DSRStore.findById.mockResolvedValue(approvedPortabilityRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      const result = await PortabilityService.generateExport({ requestId: 'req-1', format: 'CSV', generatedBy: 'compliance-1' });

      expect(result.customTargets).toEqual([
        expect.objectContaining({ targetId: 'billing', status: 'FAILED', success: false, error: 'billing API unreachable' }),
      ]);
    });

    test('backward compatible: with zero targets registered, customTargets is an empty array', async () => {
      const PortabilityService = require('../PortabilityService');
      DSRStore.findById.mockResolvedValue(approvedPortabilityRequest());
      DSRStore.updateStatus
        .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
        .mockResolvedValueOnce({ status: 'COMPLETED' });

      const result = await PortabilityService.generateExport({ requestId: 'req-1', format: 'JSON', generatedBy: 'compliance-1' });
      expect(result.customTargets).toEqual([]);
    });
  });

  describe('DataSubjectRightsService registration pass-through', () => {
    test('registerErasureTarget/listErasureTargets/unregisterErasureTarget delegate to the registry', () => {
      const DataSubjectRightsService = require('../DataSubjectRightsService');
      const t = { id: 'crm', name: 'CRM Database', erase: jest.fn() };

      DataSubjectRightsService.registerErasureTarget(t);
      expect(DataSubjectRightsService.listErasureTargets()).toEqual([t]);

      expect(DataSubjectRightsService.unregisterErasureTarget('crm')).toBe(true);
      expect(DataSubjectRightsService.listErasureTargets()).toEqual([]);
    });
  });
});
