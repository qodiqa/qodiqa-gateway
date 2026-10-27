'use strict';

/** the correlation engine's in-memory maps are bounded (they only ever grew). */

jest.mock('../storage/AlertStore', () => ({ saveIncident: jest.fn(async () => {}), getIncident: jest.fn(async () => null), updateIncident: jest.fn(async () => {}) }), { virtual: false });

const engine = require('../correlation/CorrelationEngine');

describe('CorrelationEngine bounds', () => {
  test('CB-01 a stream of unrelated alerts cannot grow the window map past its cap', async () => {
    const { MAX_WINDOWS } = engine._limits;
    for (let i = 0; i < MAX_WINDOWS + 50; i++) {
      await engine.correlate({ id: `a-${i}`, type: 'POLICY_FAILURE', severity: 'HIGH', tenantId: `t-${i}`, requestId: `r-${i}`, publicKeyId: `k-${i}` });
    }
    expect(engine._stateForTests().windows).toBeLessThanOrEqual(MAX_WINDOWS);
  });
});
