'use strict';

/**
 * certification.completed is dispatched, to a verified tenant only.
 *
 * CW-01  all attested artifacts from one tenant → one event for that tenant
 * CW-02  attested artifacts from two tenants → no event
 * CW-03  a NOT_ATTESTED artifact naming another tenant does not change the tenant
 * CW-04  no attested artifact → no event
 * CW-05  persistence failure does not suppress the event
 */

jest.mock('../../attestation/attestor');
jest.mock('../../transparency/registrar');
jest.mock('../certificationStore');
jest.mock('../../../observability/metrics', () => ({
  certificationsTotal:               { inc: jest.fn() },
  certificationFailuresTotal:        { inc: jest.fn() },
  certificationPersistFailuresTotal: { inc: jest.fn() },
}));
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
jest.mock('../../../infra/postgres/pool', () => ({ isEnabled: jest.fn().mockReturnValue(false), query: jest.fn() }));
const mockDispatch = jest.fn();
jest.mock('../../webhooks/webhookDispatcher', () => {
  const actual = jest.requireActual('../../webhooks/webhookDispatcher');
  return { ...actual, dispatchEvent: (...a) => mockDispatch(...a) };
});

const attestor           = require('../../attestation/attestor');
const registrar          = require('../../transparency/registrar');
const certificationStore = require('../certificationStore');
const { emit }           = require('../../../../services/logger');
const { evaluate }       = require('../evaluationEngine');

let n = 0;
const art = (tenant) => ({ payload: { requestId: `r-${++n}` }, publicKeyId: `${tenant}:key_v1`, signature: 'sig' });
const att = (decision = 'ATTESTED') => ({
  attestationId: `att-${++n}`, attestationDecision: decision, attestationType: 'ARTIFACT_VERIFICATION',
  transparencyReferences: { transparencyId: `t-${n}` }, evidencePackage: { packageHash: 'a'.repeat(64) },
  cryptographicResult: { signatureVerification: { status: decision === 'NOT_ATTESTED' ? 'FAIL' : 'PASS' } },
  complianceResult: { policyCompliance: { status: 'COMPLIANT' }, conformanceStatus: 'CONFORMS' },
  verificationResult: { failedCheck: null, failureReason: null },
});
const settle = () => new Promise((r) => setImmediate(r));

beforeEach(() => {
  jest.clearAllMocks();
  registrar.register.mockResolvedValue({ transparencyId: 'trans-1' });
  certificationStore.recordCertification.mockResolvedValue({ id: 1 });
});

test('CW-01 one proven tenant → certification.completed for it', async () => {
  attestor.generateAttestation.mockResolvedValueOnce(att()).mockResolvedValueOnce(att('ATTESTED_WITH_WARNINGS'));
  const r = await evaluate({ artifacts: [art('tenant-a'), art('tenant-a')] });
  await settle();
  expect(mockDispatch).toHaveBeenCalledTimes(1);
  const [type, payload] = mockDispatch.mock.calls[0];
  expect(type).toBe('certification.completed');
  expect(payload).toEqual(expect.objectContaining({
    eventType: 'certification.completed', certificationId: r.certificationId, tenantId: 'tenant-a',
    level: r.certificationLevel, score: r.score, status: r.certificationDecision,
  }));
});

test('CW-02 two proven tenants → no event (no cross-tenant notification)', async () => {
  attestor.generateAttestation.mockResolvedValueOnce(att()).mockResolvedValueOnce(att());
  await evaluate({ artifacts: [art('tenant-a'), art('tenant-b')] });
  await settle();
  expect(mockDispatch).not.toHaveBeenCalled();
  expect(emit).toHaveBeenCalledWith('INFO', 'WEBHOOK_EVENT_NOT_DISPATCHED', expect.objectContaining({ eventType: 'certification.completed', reason: 'NO_PROVEN_TENANT' }));
});

test('CW-03 an unproven (NOT_ATTESTED) artifact naming another tenant is ignored', async () => {
  attestor.generateAttestation.mockResolvedValueOnce(att()).mockResolvedValueOnce(att('NOT_ATTESTED'));
  await evaluate({ artifacts: [art('tenant-a'), art('victim-tenant')] });
  await settle();
  expect(mockDispatch).toHaveBeenCalledWith('certification.completed', expect.objectContaining({ tenantId: 'tenant-a' }));
});

test('CW-04 nothing attested → no event', async () => {
  attestor.generateAttestation.mockResolvedValueOnce(att('NOT_ATTESTED'));
  await evaluate({ artifacts: [art('tenant-a')] });
  await settle();
  expect(mockDispatch).not.toHaveBeenCalled();
});

test('CW-05 persistence failure does not suppress the event', async () => {
  attestor.generateAttestation.mockResolvedValueOnce(att());
  certificationStore.recordCertification.mockRejectedValue(new Error('pg down'));
  await evaluate({ artifacts: [art('tenant-a')] });
  await settle();
  expect(mockDispatch).toHaveBeenCalledTimes(1);
});
