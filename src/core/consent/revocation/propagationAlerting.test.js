'use strict';

/**
 * Consent Revocation Propagation Alerting Tests —
 *
 * Proves the CONSENT_REVOCATION_PROPAGATION_FAILED / CONSENT_SUSPENSION_PROPAGATION_FAILED /
 * CONSENT_REVOCATION_ACTOR_PROPAGATION_FAILED events ConsentRegistry.js already emits at
 * 'CRITICAL' log level actually reach the alerting pipeline (previously confirmed,
 * by grep, that none of the three did) — end to end: ConsentRegistry emits the real payload
 * shape, and that exact payload is fed to OperationalDetector.analyze() and asserted CRITICAL.
 *
 * PA-01  revoke() propagation failure reaches OperationalDetector at CRITICAL
 * PA-02  suspend() propagation failure reaches OperationalDetector at CRITICAL
 * PA-03  revokeAll() bulk propagation failure reaches OperationalDetector at CRITICAL
 * PA-04  Evidence payload carries tenantId, correlationId, destination, failureReason, retryAttempts
 */

const mockStore = {
  revoke:  jest.fn(),
  suspend: jest.fn(),
  list:    jest.fn(),
};
const mockCache = {
  invalidate:      jest.fn().mockResolvedValue(undefined),
  invalidateActor: jest.fn().mockResolvedValue(undefined),
};
const mockPublisher = {
  publish: jest.fn().mockResolvedValue(false), // every test in this file forces propagation failure
};
const mockPool = { isEnabled: () => true };

jest.mock('../ConsentStore', () => mockStore);
jest.mock('../ConsentCache', () => mockCache);
jest.mock('./RevocationPublisher', () => mockPublisher);
jest.mock('../../../infra/postgres/pool', () => mockPool);

let mockCapturedEvents = [];
jest.mock('../../../../services/logger', () => ({
  emit: (severity, eventType, payload) => {
    mockCapturedEvents.push({ severity, eventType, ...payload });
  },
}));

const ConsentRegistry = require('../ConsentRegistry');
const operationalDetector = require('../../../alerting/detection/OperationalDetector');

// Multiple emit() calls can occur per operation (e.g. revokeAll() also emits
// an INFO summary after the CRITICAL failure) — always resolve to the
// CRITICAL propagation-failure event specifically, not just the last emit.
function capturedEvent() {
  return mockCapturedEvents.find(e => e.severity === 'CRITICAL') ?? null;
}

beforeEach(() => {
  mockCapturedEvents = [];
  mockStore.revoke.mockReset();
  mockStore.suspend.mockReset();
  mockStore.list.mockReset();
  mockPublisher.publish.mockReset().mockResolvedValue(false);
});

test('PA-01 revoke() propagation failure reaches OperationalDetector at CRITICAL', async () => {
  mockStore.revoke.mockResolvedValue({
    id: 'consent-1', actor_id: 'actor-1', action: 'READ', tenant_id: 'tenant-a', version: 2,
  });

  await ConsentRegistry.revoke({ id: 'consent-1', revoked_by: 'admin', request_id: 'req-123' });

  expect(capturedEvent().eventType).toBe('CONSENT_REVOCATION_PROPAGATION_FAILED');
  const result = operationalDetector.analyze(capturedEvent());
  expect(result.triggered).toBe(true);
  expect(result.alert.severity).toBe('CRITICAL');
});

test('PA-02 suspend() propagation failure reaches OperationalDetector at CRITICAL', async () => {
  mockStore.suspend.mockResolvedValue({
    id: 'consent-2', actor_id: 'actor-2', action: 'WRITE', tenant_id: 'tenant-b', version: 1,
  });

  await ConsentRegistry.suspend({ id: 'consent-2', suspended_by: 'admin' });

  expect(capturedEvent().eventType).toBe('CONSENT_SUSPENSION_PROPAGATION_FAILED');
  const result = operationalDetector.analyze(capturedEvent());
  expect(result.triggered).toBe(true);
  expect(result.alert.severity).toBe('CRITICAL');
});

test('PA-03 revokeAll() bulk propagation failure reaches OperationalDetector at CRITICAL', async () => {
  mockStore.list.mockResolvedValue({ records: [] });

  await ConsentRegistry.revokeAll('actor-3', 'admin');

  expect(capturedEvent().eventType).toBe('CONSENT_REVOCATION_ACTOR_PROPAGATION_FAILED');
  const result = operationalDetector.analyze(capturedEvent());
  expect(result.triggered).toBe(true);
  expect(result.alert.severity).toBe('CRITICAL');
});

test('PA-04 evidence payload carries tenantId, correlationId, destination, failureReason, retryAttempts', async () => {
  mockStore.revoke.mockResolvedValue({
    id: 'consent-4', actor_id: 'actor-4', action: 'READ', tenant_id: 'tenant-c', version: 3,
  });

  await ConsentRegistry.revoke({ id: 'consent-4', revoked_by: 'admin', request_id: 'req-456' });

  const result = operationalDetector.analyze(capturedEvent());
  expect(result.alert.evidence).toMatchObject({
    consentId:     'consent-4',
    actorId:       'actor-4',
    tenantId:      'tenant-c',
    correlationId: 'req-456',
    destination:   'redis-pubsub',
    retryAttempts: 0,
    willRetry:     false,
  });
  expect(typeof result.alert.evidence.failureReason).toBe('string');
});
