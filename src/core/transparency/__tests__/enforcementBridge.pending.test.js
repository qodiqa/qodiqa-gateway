'use strict';

// (D3): enforcementBridge.js durable fallback.
//
//   PEND-01  healthy path: the registration is returned untouched, with the
//            transparencyId the bridge pre-assigned
//   PEND-02  persistence failure + queue accepted → persisted:'pending',
//            payloadHash commits to the exact queued payload, entryHash null
//   PEND-03  persistence failure + journal fallback → still pending
//   PEND-04  persistence failure that nothing could record durably → throws
//            the original error (callers keep their fail-closed handling)
//   PEND-05  non-persistence failure (signing) → throws, nothing queued
//   PEND-06  PG disabled → throws, nothing queued
//   PEND-07  circuit-open (synthetic retryable) → pending

const mockRegister = jest.fn();
jest.mock('../registrar', () => ({ register: (...a) => mockRegister(...a) }));

const mockPg = { enabled: true };
jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: () => mockPg.enabled }));

const mockEnqueueWithOutcome = jest.fn();
jest.mock('../../persistenceRecovery', () => {
  const op = jest.requireActual('../../persistenceRecovery/persistenceOperation');
  return {
    isPersistenceFailure: op.isPersistenceFailure,
    OPERATION_TYPES:      op.OPERATION_TYPES,
    enqueueWithOutcome:   (...a) => mockEnqueueWithOutcome(...a),
  };
});
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const { registerEnforcementDecision } = require('../enforcementBridge');
const log = require('../log');
const { emit } = require('../../../../services/logger');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ARGS = { requestId: 'req-1', decision: 'ALLOW', reason: 'ALL_CHECKS_PASSED', stage: 'PROVIDER_EXECUTION', tenantId: 't1' };
const connErr = () => Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:5432'), { code: 'ECONNREFUSED' });

beforeEach(() => {
  jest.clearAllMocks();
  mockPg.enabled = true;
});

test('PEND-01 healthy path returns the registration, with the pre-assigned transparencyId', async () => {
  mockRegister.mockImplementation(async (a) => ({ transparencyId: a.transparencyId, entryHash: 'e'.repeat(64), signature: 's', keyId: 'k', persisted: true, row: { id: 1 } }));
  const r = await registerEnforcementDecision(ARGS);
  expect(r.persisted).toBe(true);
  expect(r.transparencyId).toMatch(UUID_RE);
  expect(mockRegister.mock.calls[0][0].transparencyId).toBe(r.transparencyId);
  expect(mockEnqueueWithOutcome).not.toHaveBeenCalled();
});

test('PEND-02 persistence failure + queue → pending, queued registration is the one that was attempted', async () => {
  mockRegister.mockRejectedValue(connErr());
  mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'queue' });
  const r = await registerEnforcementDecision(ARGS);

  const attempted = mockRegister.mock.calls[0][0];
  expect(mockEnqueueWithOutcome).toHaveBeenCalledTimes(1);
  const [type, payload, err] = mockEnqueueWithOutcome.mock.calls[0];
  expect(type).toBe('TRANSPARENCY_SAVE');
  // the queued registration is the attempted one plus the late/recovered marker inside the payload (hashed and signed with the leaf)
  expect(payload.registration).toEqual({ ...attempted, payload: { ...attempted.payload, recovery: expect.objectContaining({ late: true, seq: expect.any(Number), replica: expect.any(String), queuedAt: expect.any(String) }) } });
  const queuedPayload = payload.registration.payload;
  expect(err.code).toBe('ECONNREFUSED');

  expect(r).toEqual({
    transparencyId: attempted.transparencyId,
    payloadHash:    log.computePayloadHash(queuedPayload),     // the hash covers the marker, so the client's promise matches what is later signed
    entryHash:      null,
    signature:      null,
    keyId:          null,
    persisted:      'pending',
    durable:        'queue',
    row:            null,
  });
  expect(attempted.payload.decision).toBe('ALLOW');
  expect(attempted.tenantId).toBe('t1');
  expect(emit).toHaveBeenCalledWith('WARN', 'TRANSPARENCY_ENTRY_PENDING', expect.objectContaining({ transparencyId: attempted.transparencyId, durable: 'queue' }));
});

test('PEND-02b the queued registration survives a JSON round trip unchanged (queue/journal storage)', async () => {
  mockRegister.mockRejectedValue(connErr());
  mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'queue' });
  await registerEnforcementDecision({ ...ARGS, semantic: { decision: 'ALLOW', score: 0.12 } });
  const reg = mockEnqueueWithOutcome.mock.calls[0][1].registration;
  const rt = JSON.parse(JSON.stringify(reg));
  expect(rt).toEqual(reg);
  expect(log.computePayloadHash(rt.payload)).toBe(log.computePayloadHash(reg.payload));
  expect(rt.payload.recovery.late).toBe(true);
});

test('PEND-03 journal fallback is durable too', async () => {
  mockRegister.mockRejectedValue(connErr());
  mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'journal' });
  const r = await registerEnforcementDecision(ARGS);
  expect(r.persisted).toBe('pending');
});

test('PEND-04 nothing durable → the original error is thrown', async () => {
  const e = connErr();
  mockRegister.mockRejectedValue(e);
  mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: false });
  await expect(registerEnforcementDecision(ARGS)).rejects.toBe(e);
});

test('PEND-05 a non-persistence failure (signing) is NOT queued - the replay handler would send it to the DLQ - and is not reported pending: it is rethrown; a deterministic failure is rethrown too', async () => {
  const e = new Error('signing key unavailable');
  mockRegister.mockRejectedValue(e);
  await expect(registerEnforcementDecision(ARGS)).rejects.toBe(e);
  expect(mockEnqueueWithOutcome).not.toHaveBeenCalled();
  const bad = new TypeError('malformed registration');
  mockRegister.mockRejectedValue(bad);
  await expect(registerEnforcementDecision(ARGS)).rejects.toBe(bad);
  expect(mockEnqueueWithOutcome).not.toHaveBeenCalled();
});

test('PEND-06 PG disabled → throws, nothing queued', async () => {
  mockPg.enabled = false;
  const e = connErr();
  mockRegister.mockRejectedValue(e);
  await expect(registerEnforcementDecision(ARGS)).rejects.toBe(e);
  expect(mockEnqueueWithOutcome).not.toHaveBeenCalled();
});

test('PEND-07 circuit open (PG_CIRCUIT_OPEN) → pending', async () => {
  mockRegister.mockRejectedValue(Object.assign(new Error('circuit open'), { code: 'PG_CIRCUIT_OPEN' }));
  mockEnqueueWithOutcome.mockResolvedValue({ phantom: null, durable: 'queue' });
  expect((await registerEnforcementDecision(ARGS)).persisted).toBe('pending');
});

test('PEND-08 every call pre-assigns a distinct transparencyId', async () => {
  mockRegister.mockImplementation(async (a) => ({ transparencyId: a.transparencyId, persisted: true }));
  const ids = new Set();
  for (let i = 0; i < 50; i++) ids.add((await registerEnforcementDecision(ARGS)).transparencyId);
  expect(ids.size).toBe(50);
});
