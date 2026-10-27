'use strict';

/**
 * ErasureService — test suite (Article 17, mocked dependencies).
 *
 * paginated, resumable erasure through the
 * owner-run SQL functions, finalize gated in the database. The end-to-end
 * behaviour against real PostgreSQL (> 200 records, every table, the key
 * destroyed, ledger + restore replay) is test/integration/erasureComplete.integration.test.js.
 */

describe('ErasureService', () => {
  let service;
  let ConsentStore;
  let DSRStore;
  let rolePools;
  let subjectPseudonym;
  let cache;
  let publisher;
  const PSEUDO = 'ap1:' + 'a'.repeat(64);
  const REF = 'b'.repeat(64);
  const ORIGINAL_ENV = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV, QODIQA_DSR_PSEUDONYM_PEPPER: 'test-pepper' };
    ConsentStore = { list: jest.fn().mockResolvedValue({ records: [] }), eraseSubjectBatch: jest.fn().mockResolvedValue({ erased: 0 }) };
    DSRStore = {
      findById: jest.fn(), updateStatus: jest.fn().mockResolvedValue({ status: 'IN_PROGRESS' }), appendEvent: jest.fn(),
      _eventChecksum: jest.requireActual('../DSRStore')._eventChecksum,
    };
    rolePools = { system: { query: jest.fn() } };
    subjectPseudonym = { pseudonymFor: jest.fn().mockResolvedValue(PSEUDO), subjectRef: jest.fn().mockReturnValue(REF) };
    cache = { invalidateActor: jest.fn().mockResolvedValue(undefined) };
    publisher = { publish: jest.fn().mockResolvedValue(true) };

    jest.doMock('../../consent/ConsentStore', () => ConsentStore);
    jest.doMock('../DSRStore', () => DSRStore);
    jest.doMock('../../../infra/postgres/rolePools', () => rolePools);
    jest.doMock('../subjectPseudonym', () => subjectPseudonym);
    jest.doMock('../../consent/ConsentCache', () => cache);
    jest.doMock('../../consent/revocation/RevocationPublisher', () => publisher);

    service = require('../ErasureService');
  });

  afterEach(() => {
    process.env = ORIGINAL_ENV;
    jest.resetModules();
  });

  function request(overrides = {}) {
    return {
      id: 'req-1', request_type: 'ERASURE', status: 'APPROVED', actor_id: 'actor-1', tenant_id: null,
      identity_verification_result: 'VERIFIED', ...overrides,
    };
  }

  // qodiqa_erase_subject returns one row per target; the service loops until all remaining = 0.
  function eraseRounds(...rounds) {
    for (const r of rounds) rolePools.system.query.mockResolvedValueOnce({ rows: r });
    rolePools.system.query.mockResolvedValueOnce({ rows: [{ id: 'req-1', status: 'COMPLETED' }] }); // finalize
  }

  test('erases consent_records in batches until none remain (no 200-row ceiling)', async () => {
    DSRStore.findById.mockResolvedValue(request());
    ConsentStore.eraseSubjectBatch
      .mockResolvedValueOnce({ erased: 200 }).mockResolvedValueOnce({ erased: 200 })
      .mockResolvedValueOnce({ erased: 50 }).mockResolvedValueOnce({ erased: 0 });
    eraseRounds([{ target: 'consent_audit_log.actor_id', rows_updated: '3', remaining: '0' }]);

    const out = await service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' });
    expect(out.status).toBe('COMPLETED');
    expect(ConsentStore.eraseSubjectBatch).toHaveBeenCalledTimes(4);
    expect(ConsentStore.eraseSubjectBatch).toHaveBeenCalledWith(expect.objectContaining({ actor_id: 'actor-1', pseudonym: PSEUDO, erased_by: 'dpo-1' }));
  });

  test('loops qodiqa_erase_subject as qodiqa_system until every target reports 0 remaining, then finalizes', async () => {
    DSRStore.findById.mockResolvedValue(request({ tenant_id: 't1' }));
    eraseRounds(
      [{ target: 'revocation_events.subject_id', rows_updated: '500', remaining: '120' }, { target: 'qodiqa_alerts.actor_id', rows_updated: '2', remaining: '0' }],
      [{ target: 'revocation_events.subject_id', rows_updated: '120', remaining: '0' }, { target: 'qodiqa_alerts.actor_id', rows_updated: '0', remaining: '0' }],
    );

    await service.erase({ requestId: 'req-1', tenantId: 't1', erasedBy: 'dpo-1' });
    const calls = rolePools.system.query.mock.calls;
    expect(calls[0][0]).toMatch(/FROM qodiqa_erase_subject\(\$1, \$2, \$3, \$4\)/);
    expect(calls[0][1]).toEqual(['t1', 'actor-1', PSEUDO, 500]);
    expect(calls[1][0]).toMatch(/qodiqa_erase_subject\(/);
    const [finSql, finParams] = calls[2];
    expect(finSql).toMatch(/qodiqa_erase_subject_finalize/);
    expect(finParams.slice(0, 5)).toEqual(['req-1', 't1', 'actor-1', PSEUDO, REF]);
    const result = JSON.parse(finParams[6]);
    expect(result.tables).toMatchObject({ 'revocation_events.subject_id': 620, 'qodiqa_alerts.actor_id': 2, 'consent_records.actor_id': 0 });
    expect(result.actorIdPseudonymized).toBe(true);
    expect(result.subjectKeyDestroyed).toBe(true);
    // the finalize event checksum is DSRStore's own formula over the same detail
    const expected = DSRStore._eventChecksum({ request_id: 'req-1', event_type: 'DSR_ERASURE_COMPLETED', actor: 'dpo-1', detail: JSON.parse(finParams[8]) });
    expect(finParams[9]).toBe(expected.checksum);
  });

  test('NF-10: nothing written anywhere carries a hash of — or the plaintext — original identifier', async () => {
    DSRStore.findById.mockResolvedValue(request());
    eraseRounds([]);
    await service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' });
    const fin = rolePools.system.query.mock.calls.at(-1)[1];
    expect(fin[6]).not.toContain('actor-1');           // result
    expect(fin[8]).not.toContain('actor-1');           // event detail
    expect(fin[6]).not.toMatch(/originalActorIdHash/);
    expect(DSRStore.appendEvent).not.toHaveBeenCalledWith(expect.objectContaining({ event_type: 'DSR_ACTOR_PSEUDONYMIZED' }));
  });

  test('invalidates the consent cache locally and on every node (signed actor-level event)', async () => {
    DSRStore.findById.mockResolvedValue(request({ tenant_id: 't1' }));
    eraseRounds([]);
    await service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' });
    expect(cache.invalidateActor).toHaveBeenCalledWith('actor-1');
    expect(publisher.publish).toHaveBeenCalledWith(expect.objectContaining({
      subjectId: 'actor-1', action: null, tenantId: 't1', revocationReason: 'GDPR_ARTICLE_17_ERASURE',
    }));
  });

  test('D10: a FAILED erasure RESUMES (FAILED → IN_PROGRESS, event DSR_ERASURE_RESUMED)', async () => {
    DSRStore.findById.mockResolvedValue(request({ status: 'FAILED' }));
    eraseRounds([]);
    await service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' });
    expect(DSRStore.updateStatus).toHaveBeenCalledWith(expect.objectContaining({ status: 'IN_PROGRESS', eventType: 'DSR_ERASURE_RESUMED' }));
    expect(JSON.parse(rolePools.system.query.mock.calls.at(-1)[1][6]).resumed).toBe(true);
  });

  test.each(['RECEIVED', 'IDENTITY_VERIFIED', 'IN_PROGRESS', 'COMPLETED', 'REJECTED'])(
    'rejects a request in status %s before any mutation', async (status) => {
      DSRStore.findById.mockResolvedValue(request({ status }));
      await expect(service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' })).rejects.toThrow('is not approved for execution');
      expect(DSRStore.updateStatus).not.toHaveBeenCalled();
      expect(rolePools.system.query).not.toHaveBeenCalled();
    },
  );

  test('an active Article 18 restriction found on ANY page blocks the erasure before any mutation', async () => {
    DSRStore.findById.mockResolvedValue(request());
    const page = (n, hold) => Array.from({ length: n }, (_, i) => ({ id: `c${i}`, state: 'SUSPENDED', suspension_reason: hold && i === n - 1 ? 'DSR_RESTRICTION:req-9' : 'other' }));
    ConsentStore.list.mockResolvedValueOnce({ records: page(200, false) }).mockResolvedValueOnce({ records: page(10, true) });
    await expect(service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' })).rejects.toThrow('blocked: an active legal hold');
    expect(ConsentStore.list).toHaveBeenCalledWith(expect.objectContaining({ offset: 200 }));
    expect(DSRStore.updateStatus).not.toHaveBeenCalled();
  });

  test('a finalize refusal (rows still remain) propagates — the request is never marked COMPLETED by the service', async () => {
    DSRStore.findById.mockResolvedValue(request());
    rolePools.system.query.mockResolvedValueOnce({ rows: [] });
    rolePools.system.query.mockRejectedValueOnce(Object.assign(new Error('erasure incomplete: 1 row(s) remain in consent_records.actor_id'), { code: '55000' }));
    await expect(service.erase({ requestId: 'req-1', erasedBy: 'dpo-1' })).rejects.toThrow('erasure incomplete');
    expect(DSRStore.updateStatus).not.toHaveBeenCalledWith(expect.objectContaining({ status: 'COMPLETED' }));
  });

  test('recordsRetained is honest: hash-protected stores, checksum-protected detail, backups', () => {
    const stores = service.RECORDS_RETAINED.map((r) => r.store).join(' | ');
    expect(stores).toMatch(/audit chain/);
    expect(stores).toMatch(/transparency_log_entries/);
    expect(stores).toMatch(/consent_audit_log\.detail/);
    expect(stores).toMatch(/backups/);
    // the earlier claim "No actor_id or PII field exists in the chain schema" is gone
    expect(JSON.stringify(service.RECORDS_RETAINED)).not.toMatch(/No actor_id or PII field exists/);
  });
});
