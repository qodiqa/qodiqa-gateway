'use strict';

/**
 * PortabilityService — test suite (Article 20, mocked dependencies)
 */

describe('PortabilityService', () => {
  let service;
  let pool;
  let ConsentStore;
  let DSRStore;

  beforeEach(() => {
    jest.resetModules();
    pool = { query: jest.fn().mockResolvedValue({ rows: [{ id: 'export-1' }] }) };
    ConsentStore = { list: jest.fn(), getAuditLog: jest.fn() };
    DSRStore = { findById: jest.fn(), updateStatus: jest.fn(), list: jest.fn() };

    jest.doMock('../../../infra/postgres/pool', () => pool);
    jest.doMock('../../consent/ConsentStore', () => ConsentStore);
    jest.doMock('../DSRStore', () => DSRStore);

    service = require('../PortabilityService');
  });

  afterEach(() => jest.resetModules());

  function approvedRequest(overrides = {}) {
    return { id: 'req-1', request_type: 'PORTABILITY', status: 'APPROVED', actor_id: 'actor-1', tenant_id: null, ...overrides };
  }

  test('generates a JSON export whose checksum matches sha256 of the exact returned payload', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    DSRStore.updateStatus
      .mockResolvedValueOnce({ status: 'IN_PROGRESS' })
      .mockResolvedValueOnce({ status: 'COMPLETED' });
    ConsentStore.list.mockResolvedValue({ records: [{ id: 'c1', action: 'X', state: 'ACTIVE' }] });
    ConsentStore.getAuditLog.mockResolvedValue([{ event_type: 'CONSENT_GRANTED' }]);
    DSRStore.list.mockResolvedValue({ requests: [{ id: 'req-1' }] });

    const result = await service.generateExport({ requestId: 'req-1', format: 'JSON', generatedBy: 'compliance-1' });

    const crypto = require('crypto');
    const expectedChecksum = crypto.createHash('sha256').update(result.payload, 'utf8').digest('hex');
    expect(result.checksum).toBe(expectedChecksum);
    expect(result.sizeBytes).toBe(Buffer.byteLength(result.payload, 'utf8'));

    const parsed = JSON.parse(result.payload);
    expect(parsed.subject.actorId).toBe('actor-1');
    expect(parsed.consentRecords).toHaveLength(1);
    expect(parsed.consentHistory).toHaveLength(1);
    expect(parsed.dsrRequests).toHaveLength(1);
    // No private keys / signatures — these fields simply don't exist in the source data,
    // but assert the export never introduces any key-shaped field either.
    expect(JSON.stringify(parsed)).not.toMatch(/privateKey|signature/i);
  });

  test('generates a CSV export whose checksum matches sha256 of the exact returned payload', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    DSRStore.updateStatus.mockResolvedValue({ status: 'COMPLETED' });
    ConsentStore.list.mockResolvedValue({ records: [{ id: 'c1', action: 'X', state: 'ACTIVE', record_hash: 'h1' }] });
    ConsentStore.getAuditLog.mockResolvedValue([]);
    DSRStore.list.mockResolvedValue({ requests: [] });

    const result = await service.generateExport({ requestId: 'req-1', format: 'CSV', generatedBy: 'compliance-1' });

    const crypto = require('crypto');
    expect(result.checksum).toBe(crypto.createHash('sha256').update(result.payload, 'utf8').digest('hex'));
    expect(result.payload.split('\n')[0]).toBe('id,action,state,scope,granted_at,expires_at,record_hash');
  });

  test('INJ-7: a consent field starting with "=" is neutralized in the CSV export, not passed through as a live formula', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    DSRStore.updateStatus.mockResolvedValue({ status: 'COMPLETED' });
    ConsentStore.list.mockResolvedValue({
      records: [{ id: 'c1', action: '=cmd|\'/C calc\'!A0', state: 'ACTIVE', record_hash: 'h1' }],
    });
    ConsentStore.getAuditLog.mockResolvedValue([]);
    DSRStore.list.mockResolvedValue({ requests: [] });

    const result = await service.generateExport({ requestId: 'req-1', format: 'CSV', generatedBy: 'compliance-1' });
    const dataRow = result.payload.split('\n')[1];
    expect(dataRow).toContain('"\'=cmd');
  });

  test('persists only checksum/metadata to dsr_exports, never the payload', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    DSRStore.updateStatus.mockResolvedValue({ status: 'COMPLETED' });
    ConsentStore.list.mockResolvedValue({ records: [] });
    ConsentStore.getAuditLog.mockResolvedValue([]);
    DSRStore.list.mockResolvedValue({ requests: [] });

    await service.generateExport({ requestId: 'req-1', generatedBy: 'compliance-1' });

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = pool.query.mock.calls[0];
    expect(sql).toMatch(/INSERT INTO dsr_exports/);
    expect(sql).not.toMatch(/payload/);
    expect(params).toHaveLength(7); // request_id, actor_id, tenant_id, format, checksum, size_bytes, generated_by
  });

  test('rejects an unsupported format', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest());
    await expect(service.generateExport({ requestId: 'req-1', format: 'XML', generatedBy: 'compliance-1' }))
      .rejects.toThrow("format must be 'JSON' or 'CSV'");
  });

  test('rejects a request that is not APPROVED', async () => {
    DSRStore.findById.mockResolvedValue(approvedRequest({ status: 'RECEIVED' }));
    await expect(service.generateExport({ requestId: 'req-1', generatedBy: 'compliance-1' }))
      .rejects.toThrow('is not approved for execution');
  });
});
