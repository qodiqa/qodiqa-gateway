'use strict';

/**
 * — REAL PostgreSQL (RLS): acknowledging / resolving a tenant-scoped alert through the engine works.
 * Before the fix the UPDATE carried no tenant context, qa_tenant_update matched 0 rows and the result was null (route: 404).
 * Needs a migrated DB — run through the disposable environment; self-skips otherwise.
 */

const RUN = process.env.QODIQA_PG_ENABLED === 'true' && process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true';
const crypto = require('crypto');

(RUN ? describe : describe.skip)('tenant-scoped alert status updates (real RLS)', () => {
  jest.setTimeout(60_000);
  const store = RUN ? require('../../src/alerting/storage/AlertStore') : null;
  const engine = RUN ? require('../../src/alerting/engine/AlertEngine') : null;

  const mk = (tenantId) => ({
    id: crypto.randomUUID(), type: 'AUDIT44_TEST', subtype: crypto.randomUUID(), severity: 'LOW', status: 'OPEN',
    riskScore: 10, confidence: 0.5, title: 't', description: 'd', tags: [], tenantId, detectedAt: new Date().toISOString(),
    nextEscalationAt: null, retainUntil: new Date(Date.now() + 86_400_000).toISOString(),
  });

  test('TA-IT-01 acknowledge then resolve an alert of tenant "acme" succeeds (was null/404)', async () => {
    const a = mk('acme');
    await store.saveAlert(a);
    const acked = await engine.acknowledgeAlert(a.id, { actor: 'op' });
    expect(acked && acked.status).toBe('ACKNOWLEDGED');
    const resolved = await engine.resolveAlert(a.id, { actor: 'op', note: 'fixed' });
    expect(resolved && resolved.status).toBe('RESOLVED');
  });

  test('TA-IT-02 a platform-level alert keeps working', async () => {
    const a = mk(null);
    await store.saveAlert(a);
    const acked = await engine.acknowledgeAlert(a.id, { actor: 'op' });
    expect(acked && acked.status).toBe('ACKNOWLEDGED');
  });
});
