'use strict';

/**
 * Retention Role Separation Tests —
 *
 * Proves the automated cleanup cycle (stampRetentionDates/expireEvents/
 * runRetentionCycle) executes exclusively through retentionPool (the
 * dedicated qodiqa_retention role) and never touches the general-purpose
 * pgPool — and, symmetrically, that the human-triggered admin-API surface
 * (upsertPolicy/placeLegalHold/listPolicies/listLegalHolds/releaseLegalHold/
 * listRuns) stays on pgPool and never touches retentionPool. See
 * retention.js's module header for the rationale.
 *
 * RT-ROLE-01 … RT-ROLE-03  Automated cycle uses retentionPool only
 * RT-ROLE-04 … RT-ROLE-06  Admin-API functions use pgPool only
 */

const mockPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
  withTransaction: jest.fn(async (fn) => fn({ query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }) })),
};
// cross-tenant DEFINER reads now go through rolePools (qodiqa_system / qodiqa_reporting);
// the forwarder sends them to the same mocked pool and records which pool served each call.
jest.mock('../../../infra/postgres/rolePools', () => require('../../../../test/helpers/rolePoolsDelegate')(jest.requireMock('../../../infra/postgres/pool')));
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockRetentionPool = {
  _enabled: true,
  isEnabled: function () { return this._enabled; },
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
};
jest.mock('../../../infra/postgres/retentionPool', () => mockRetentionPool);

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const retention = require('../retention');

beforeEach(() => {
  mockPool.query.mockClear();
  mockPool.withTransaction.mockClear();
  mockRetentionPool.query.mockClear();
});

describe('RT-ROLE-01 … RT-ROLE-03: automated cleanup cycle uses retentionPool only', () => {
  test('RT-ROLE-01 stampRetentionDates never calls pgPool', async () => {
    await retention.stampRetentionDates();
    expect(mockPool.query).not.toHaveBeenCalled();
    expect(mockRetentionPool.query).toHaveBeenCalled();
  });

  test('RT-ROLE-02 expireEvents never calls pgPool', async () => {
    await retention.expireEvents();
    expect(mockPool.query).not.toHaveBeenCalled();
    expect(mockRetentionPool.query).toHaveBeenCalled();
  });

  test('RT-ROLE-03 runRetentionCycle (stamp + expire + run journal) never calls pgPool', async () => {
    await retention.runRetentionCycle();
    expect(mockPool.query).not.toHaveBeenCalled();
    expect(mockPool.withTransaction).not.toHaveBeenCalled();
    expect(mockRetentionPool.query).toHaveBeenCalled();
  });
});

describe('RT-ROLE-04 … RT-ROLE-06: human-triggered admin API stays on pgPool', () => {
  test('RT-ROLE-04 upsertPolicy never calls retentionPool', async () => {
    await retention.upsertPolicy({ name: 'test-policy', retainDays: 30 });
    expect(mockRetentionPool.query).not.toHaveBeenCalled();
    expect(mockPool.query).toHaveBeenCalled();
  });

  test('RT-ROLE-05 placeLegalHold never calls retentionPool', async () => {
    await retention.placeLegalHold({
      holdName: 'hold-x', reason: 'legal', heldBy: 'ops', artifactId: 'art-1',
    });
    expect(mockRetentionPool.query).not.toHaveBeenCalled();
    expect(mockPool.withTransaction).toHaveBeenCalled();
  });

  test('RT-ROLE-06 listPolicies/listRuns/listLegalHolds never call retentionPool', async () => {
    await retention.listPolicies();
    await retention.listRuns();
    await retention.listLegalHolds();
    expect(mockRetentionPool.query).not.toHaveBeenCalled();
    expect(mockPool.query).toHaveBeenCalled();
  });
});
