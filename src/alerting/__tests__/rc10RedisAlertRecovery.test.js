'use strict';

// RC-10: during the RC 1-h soak a CRITICAL "Replay protection degraded —
// Redis nonce store unavailable" alert was raised at boot and escalated twice although
// all 266,400 requests passed the nonce stage. Two defects:
//   1. startup.js emits REPLAY_PROTECTION_DEGRADED{source:"PERSISTENCE"} when the store is
//      UP but AOF is not durable; the detector paged it as "store unavailable" CRITICAL.
//   2. GATEWAY_RUNTIME_RECOVERED had no consumer, so Redis-degraded alerts never resolved.

const operationalDetector = require('../detection/OperationalDetector');
const detectionEngine     = require('../detection/DetectionEngine');
const alertStore          = require('../storage/AlertStore');
const { emit }            = require('../../../services/logger');
const { ALERT_STATUS, OPERATIONAL_SUBTYPE, SEVERITY } = require('../constants');

async function settle(predicate, timeoutMs = 2000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return false;
}

async function alertsFor(sourceEvent) {
  const { alerts } = await alertStore.listAlerts({ pageSize: 200 });
  return alerts.filter((a) => a.sourceEvent === sourceEvent);
}

describe('RC-10 — persistence warning is not a "nonce store unavailable" page', () => {
  test('REPLAY_PROTECTION_DEGRADED with source PERSISTENCE does not trigger the CRITICAL rule', () => {
    const r = operationalDetector.analyze({ eventType: 'REPLAY_PROTECTION_DEGRADED', source: 'PERSISTENCE' });
    expect(r.triggered).toBe(false);
  });

  test.each(['STARTUP', 'NONCE_STORE', undefined])('source %s still pages CRITICAL', (source) => {
    const r = operationalDetector.analyze({ eventType: 'REPLAY_PROTECTION_DEGRADED', source });
    expect(r.triggered).toBe(true);
    expect(r.alert.severity).toBe(SEVERITY.CRITICAL);
    expect(r.alert.subtype).toBe(OPERATIONAL_SUBTYPE.REDIS_DEGRADED);
  });

  test('the persistence condition is still alerted, via REDIS_PERSISTENCE_UNSAFE (HIGH)', () => {
    const r = operationalDetector.analyze({ eventType: 'REDIS_PERSISTENCE_UNSAFE', aofEnabled: false });
    expect(r.triggered).toBe(true);
    expect(r.alert.severity).toBe(SEVERITY.HIGH);
  });
});

describe('RC-10 — GATEWAY_RUNTIME_RECOVERED resolves the gateway Redis alerts', () => {
  beforeAll(() => detectionEngine.initialize());
  afterAll(() => detectionEngine.shutdown());

  test('degraded → recovered: gateway alerts RESOLVED, Redis-HA alert left OPEN', async () => {
    emit('WARN', 'REPLAY_PROTECTION_DEGRADED', { source: 'NONCE_STORE', reason: 'ECONNREFUSED' });
    emit('WARN', 'GATEWAY_RUNTIME_PARTIAL_FAILURE', { source: 'NONCE_STORE', nonceStoreReady: false });
    emit('WARN', 'REDIS_HA_CONNECTION_LOST', { purpose: 'pubsub', mode: 'sentinel', error: 'x' });

    expect(await settle(async () =>
      (await alertsFor('REPLAY_PROTECTION_DEGRADED')).length === 1 &&
      (await alertsFor('GATEWAY_RUNTIME_PARTIAL_FAILURE')).length === 1 &&
      (await alertsFor('REDIS_HA_CONNECTION_LOST')).length === 1)).toBe(true);
    for (const ev of ['REPLAY_PROTECTION_DEGRADED', 'GATEWAY_RUNTIME_PARTIAL_FAILURE']) {
      expect((await alertsFor(ev))[0].status).toBe(ALERT_STATUS.OPEN);
    }

    emit('INFO', 'GATEWAY_RUNTIME_RECOVERED', { source: 'NONCE_STORE' });

    expect(await settle(async () =>
      (await alertsFor('REPLAY_PROTECTION_DEGRADED'))[0].status === ALERT_STATUS.RESOLVED &&
      (await alertsFor('GATEWAY_RUNTIME_PARTIAL_FAILURE'))[0].status === ALERT_STATUS.RESOLVED)).toBe(true);
    expect((await alertsFor('REDIS_HA_CONNECTION_LOST'))[0].status).toBe(ALERT_STATUS.OPEN);
  });

  test('a second recovery with nothing open is a no-op', async () => {
    emit('INFO', 'GATEWAY_RUNTIME_RECOVERED', { source: 'ANOMALY_STORE' });
    await new Promise((r) => setTimeout(r, 50));
    expect((await alertsFor('REPLAY_PROTECTION_DEGRADED'))[0].status).toBe(ALERT_STATUS.RESOLVED);
    expect((await alertsFor('REDIS_HA_CONNECTION_LOST'))[0].status).toBe(ALERT_STATUS.OPEN);
  });
});
