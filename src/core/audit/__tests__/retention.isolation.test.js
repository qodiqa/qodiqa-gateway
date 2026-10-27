'use strict';

/**
 * Audit Retention Transaction Isolation Tests — Component #18
 *
 * RT-TX-01  placeLegalHold executes INSERT and UPDATE inside the same transaction
 * RT-TX-02  placeLegalHold propagates DB errors from the transaction (no swallowing)
 * RT-TX-03  placeLegalHold returns the correct eventsHeld count from the UPDATE
 * RT-TX-04  placeLegalHold throws when PG is not enabled
 */

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockTxQuery = jest.fn();

const mockPool = {
  _enabled: false,
  isEnabled:       function () { return this._enabled; },
  query:           jest.fn(),
  withTransaction: async function (fn) {
    if (!this._enabled) throw new Error('PG pool not initialized');
    return fn({ query: mockTxQuery });
  },
};

jest.mock('../../../infra/postgres/pool', () => mockPool);
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

// ── Load module under test ────────────────────────────────────────────────────

const retention = require('../retention');

// ── Helpers ───────────────────────────────────────────────────────────────────

const HOLD_OPTS = {
  holdName:  'hold-001',
  reason:    'regulatory request',
  heldBy:    'compliance-team',
  artifactId: 'art-001',
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('RT-TX-01 … RT-TX-04: retention.placeLegalHold', () => {
  beforeEach(() => {
    mockTxQuery.mockReset();
    mockPool._enabled = false;
  });

  test('RT-TX-01 routes both INSERT and UPDATE through the same transaction client', async () => {
    mockPool._enabled = true;

    const capturedSqls = [];
    mockTxQuery.mockImplementation((sql) => {
      capturedSqls.push(sql.trim().split('\n')[0].trim());
      return { rows: [], rowCount: 0 };
    });

    await retention.placeLegalHold(HOLD_OPTS);

    const hasInsert = capturedSqls.some(s => s.startsWith('INSERT INTO audit_legal_holds'));
    const hasUpdate = capturedSqls.some(s => s.startsWith('UPDATE platform_audit_events'));
    expect(hasInsert).toBe(true);
    expect(hasUpdate).toBe(true);
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  test('RT-TX-02 propagates DB errors from inside the transaction', async () => {
    mockPool._enabled = true;

    mockTxQuery
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })   // INSERT succeeds
      .mockRejectedValueOnce(new Error('UPDATE failed')); // UPDATE fails

    await expect(
      retention.placeLegalHold(HOLD_OPTS)
    ).rejects.toThrow('UPDATE failed');
  });

  test('RT-TX-03 returns the eventsHeld count from the UPDATE rowCount', async () => {
    mockPool._enabled = true;

    mockTxQuery
      .mockResolvedValueOnce({ rows: [], rowCount: 0 })  // INSERT
      .mockResolvedValueOnce({ rows: [], rowCount: 7 }); // UPDATE touched 7 rows

    const result = await retention.placeLegalHold(HOLD_OPTS);

    expect(result.eventsHeld).toBe(7);
  });

  test('RT-TX-04 throws when PG is not enabled', async () => {
    mockPool._enabled = false;

    await expect(
      retention.placeLegalHold(HOLD_OPTS)
    ).rejects.toThrow('PostgreSQL not enabled');
  });
});
