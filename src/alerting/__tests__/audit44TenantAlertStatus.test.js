'use strict';

/**
 * acknowledging / resolving a TENANT-scoped alert ran its UPDATE without the tenant's RLS
 * context (qa_tenant_update) -> 0 rows -> the route answered 404. The engine already holds the alert (getAlert uses the full-read
 * bypass), so it now passes the alert's own tenant to the store.
 */

jest.mock('../storage/AlertStore', () => ({
  getAlert: jest.fn(),
  updateAlertStatus: jest.fn(async (id, status, meta) => ({ id, status, tenantId: meta.tenantId })),
}));

const store = require('../storage/AlertStore');
const engine = require('../engine/AlertEngine');

beforeEach(() => jest.clearAllMocks());

describe('AlertEngine — tenant context on status updates', () => {
  test('TA-01 acknowledge passes the alert\'s tenantId to the store', async () => {
    store.getAlert.mockResolvedValue({ id: 'a1', status: 'OPEN', tenantId: 'acme' });
    const out = await engine.acknowledgeAlert('a1', { actor: 'op' });
    expect(store.updateAlertStatus).toHaveBeenCalledWith('a1', 'ACKNOWLEDGED', expect.objectContaining({ actor: 'op', tenantId: 'acme' }));
    expect(out.tenantId).toBe('acme');
  });

  test('TA-02 resolve passes the alert\'s tenantId; a platform-level alert passes none', async () => {
    store.getAlert.mockResolvedValue({ id: 'a2', status: 'OPEN', tenantId: 'globex' });
    await engine.resolveAlert('a2', { actor: 'op', note: 'done' });
    expect(store.updateAlertStatus).toHaveBeenLastCalledWith('a2', 'RESOLVED', expect.objectContaining({ tenantId: 'globex', note: 'done' }));
    store.getAlert.mockResolvedValue({ id: 'a3', status: 'OPEN', tenantId: null });
    await engine.resolveAlert('a3', { actor: 'op' });
    expect(store.updateAlertStatus.mock.calls.at(-1)[2].tenantId).toBeUndefined();
  });

  test('TA-03 suppress / false-positive also look the tenant up; an explicit tenantId wins', async () => {
    store.getAlert.mockResolvedValue({ id: 'a4', status: 'OPEN', tenantId: 'acme' });
    await engine.suppressAlert('a4', { actor: 'op' });
    expect(store.updateAlertStatus).toHaveBeenLastCalledWith('a4', 'SUPPRESSED', expect.objectContaining({ tenantId: 'acme' }));
    await engine.markFalsePositive('a4', { actor: 'op', tenantId: 'explicit' });
    expect(store.updateAlertStatus).toHaveBeenLastCalledWith('a4', 'FALSE_POSITIVE', expect.objectContaining({ tenantId: 'explicit' }));
  });
});
