'use strict';

/**
 * evidence-store boot readiness probe (unit).
 *
 * The production startup gate (server/startup.js, EVIDENCE_DURABILITY_VIOLATION)
 * trusts this module's verdict, so the verdict itself is pinned here:
 * PG disabled reports PG_DISABLED, a clean probe of all three store tables
 * reports ok, and any single store failure fails the whole probe with the
 * failing store named. The gate's wiring into startup.js is pinned separately
 * by test/evidenceDurabilityStartupGate.test.js (static + spawned-boot).
 */

jest.mock('../pool', () => ({
  isEnabled: jest.fn(),
  query:     jest.fn(),
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const pool = require('../pool');
const { probeEvidenceStores, STORE_TABLES } = require('../evidenceStoreReadiness');

beforeEach(() => jest.clearAllMocks());

describe('probeEvidenceStores()', () => {
  test('PG disabled → ok:false with cause PG_DISABLED and no queries issued', async () => {
    pool.isEnabled.mockReturnValue(false);
    const r = await probeEvidenceStores();
    expect(r).toEqual({ ok: false, cause: 'PG_DISABLED', stores: {}, failures: [] });
    expect(pool.query).not.toHaveBeenCalled();
  });

  test('all three stores probe clean → ok:true, every store true, no failures', async () => {
    pool.isEnabled.mockReturnValue(true);
    pool.query.mockResolvedValue({ rows: [] });
    const r = await probeEvidenceStores();
    expect(r.ok).toBe(true);
    expect(r.cause).toBeNull();
    expect(r.stores).toEqual({ consentStore: true, transparencyLog: true, evidenceChain: true });
    expect(r.failures).toEqual([]);
  });

  test('probes exactly the three tables the stores actually depend on, read-only', async () => {
    pool.isEnabled.mockReturnValue(true);
    pool.query.mockResolvedValue({ rows: [] });
    await probeEvidenceStores();
    const sqls = pool.query.mock.calls.map((c) => c[0]);
    expect(sqls).toEqual([
      'SELECT 1 FROM consent_records LIMIT 1',
      'SELECT 1 FROM transparency_log_entries LIMIT 1',
      'SELECT 1 FROM evidence_chain_records LIMIT 1',
    ]);
    // Contract: the probe never writes.
    for (const sql of sqls) expect(sql).toMatch(/^SELECT /);
    expect(STORE_TABLES).toEqual({
      consentStore:    'consent_records',
      transparencyLog: 'transparency_log_entries',
      evidenceChain:   'evidence_chain_records',
    });
  });

  test('one failing store fails the whole probe and names the store, table, and error', async () => {
    pool.isEnabled.mockReturnValue(true);
    pool.query.mockImplementation((sql) =>
      sql.includes('transparency_log_entries')
        ? Promise.reject(new Error('relation "transparency_log_entries" does not exist'))
        : Promise.resolve({ rows: [] }));
    const r = await probeEvidenceStores();
    expect(r.ok).toBe(false);
    expect(r.cause).toBe('STORE_NOT_READY');
    expect(r.stores).toEqual({ consentStore: true, transparencyLog: false, evidenceChain: true });
    expect(r.failures).toEqual([{
      store: 'transparencyLog',
      table: 'transparency_log_entries',
      error: 'relation "transparency_log_entries" does not exist',
    }]);
  });

  test('every store failing (PG reachable-but-empty database) reports all three failures', async () => {
    pool.isEnabled.mockReturnValue(true);
    pool.query.mockRejectedValue(new Error('permission denied'));
    const r = await probeEvidenceStores();
    expect(r.ok).toBe(false);
    expect(r.stores).toEqual({ consentStore: false, transparencyLog: false, evidenceChain: false });
    expect(r.failures).toHaveLength(3);
  });

  test('a failed probe emits EVIDENCE_STORE_READINESS_FAILED; a clean probe emits nothing', async () => {
    const { emit } = require('../../../../services/logger');
    pool.isEnabled.mockReturnValue(true);
    pool.query.mockResolvedValue({ rows: [] });
    await probeEvidenceStores();
    expect(emit).not.toHaveBeenCalled();

    pool.query.mockRejectedValue(new Error('boom'));
    await probeEvidenceStores();
    expect(emit).toHaveBeenCalledWith('ERROR', 'EVIDENCE_STORE_READINESS_FAILED', expect.objectContaining({
      failures: expect.any(Array),
    }));
  });
});
