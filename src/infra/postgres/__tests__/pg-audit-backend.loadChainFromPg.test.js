'use strict';

/**
 * pg-audit-backend.js loadChainFromPg() — timestamp round-trip fix
 *
 * LCP-01  timestamp is derived from the stored `canonical` JSON, not a
 *         separately-cast `recorded_at` column — a TIMESTAMPTZ::text cast
 *         does not reproduce the exact ISO-8601 string that was hashed, and
 *         a mismatch would make every hydrated entry fail
 *         _verifyCanonicalHash's `sortedJSON(coreFieldsOf(entry)) ===
 *         entry.canonical` check (falsely reporting tampering).
 * LCP-02  Rows are ordered by `seq ASC` (matches distributed mode's
 *         commit-order guarantee — see distributedOrdering.js).
 * LCP-03  Malformed `canonical` (unparseable JSON) yields timestamp: null
 *         rather than throwing — downstream chain validation reports it as
 *         invalid_field, not a hard crash during hydration.
 * LCP-04  Returns [] when PG is not enabled — no query issued.
 */

function loadModule({ queryResult }) {
  jest.resetModules();

  const mockQuery = jest.fn().mockResolvedValue(queryResult ?? { rows: [] });
  jest.doMock('../pool', () => ({
    isEnabled: jest.fn(() => true),
    query: mockQuery,
  }));
  jest.doMock('../rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../pool'))); //
  jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));
  jest.doMock('../../../core/persistenceRecovery/persistenceOperation', () => ({
    isPersistenceFailure: jest.fn(() => false),
  }));

  const backend = require('../pg-audit-backend');
  return { backend, mockQuery };
}

describe('pg-audit-backend.js — loadChainFromPg()', () => {
  afterEach(() => { jest.restoreAllMocks(); });

  test('LCP-01 timestamp comes from canonical JSON, not a recorded_at column', async () => {
    const canonical = JSON.stringify({
      artifactId: 'a1', decision: 'ALLOW', inputHash: 'x', policyHash: 'y',
      prevHash: 'GENESIS', publicKeyId: null, requestHash: 'z',
      schemaVersion: 2, signature: 's', timestamp: '2026-07-17T09:00:00.123Z',
      verificationResult: true,
    });

    const { backend, mockQuery } = loadModule({
      queryResult: {
        rows: [{
          hash: 'h1', prevHash: 'GENESIS', canonical,
          artifactId: 'a1', decision: 'ALLOW',
          highResTime: '123', inputHash: 'x', signature: 's',
          requestHash: 'z', policyHash: 'y', verificationResult: true,
          nonce: null, tenantId: null, executionContext: null,
          publicKeyId: null, schemaVersion: 2,
        }],
      },
    });

    const chain = await backend.loadChainFromPg();
    expect(chain).toHaveLength(1);
    // Must be the exact ISO string embedded in canonical — NOT any
    // Postgres-text-cast reformatting of a timestamptz column.
    expect(chain[0].timestamp).toBe('2026-07-17T09:00:00.123Z');

    // The SQL must not select recorded_at::text AS timestamp — that was
    // the source of the round-trip bug this fix closes.
    const sql = mockQuery.mock.calls[0][0];
    expect(sql).not.toMatch(/recorded_at::text\s+AS\s+"?timestamp"?/i);
  });

  test('LCP-02 selects ordered by seq ASC', async () => {
    const { backend, mockQuery } = loadModule({ queryResult: { rows: [] } });
    await backend.loadChainFromPg();
    const sql = mockQuery.mock.calls[0][0];
    expect(sql).toMatch(/ORDER BY seq ASC/);
  });

  test('LCP-03 malformed canonical yields timestamp: null, does not throw', async () => {
    const { backend } = loadModule({
      queryResult: { rows: [{ hash: 'h1', canonical: 'not-json{{{', artifactId: 'a1' }] },
    });
    const chain = await backend.loadChainFromPg();
    expect(chain).toHaveLength(1);
    expect(chain[0].timestamp).toBeNull();
  });

  test('LCP-04 returns [] and issues no query when PG is not enabled', async () => {
    jest.resetModules();
    const mockQuery = jest.fn();
    jest.doMock('../pool', () => ({ isEnabled: jest.fn(() => false), query: mockQuery }));
    jest.doMock('../rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../pool'))); //
    jest.doMock('../../../../services/logger', () => ({ emit: jest.fn() }));

    const backend = require('../pg-audit-backend');
    const chain = await backend.loadChainFromPg();
    expect(chain).toEqual([]);
    expect(mockQuery).not.toHaveBeenCalled();
  });
});
