'use strict';

/**
 * attestation.completed is dispatched, to a verified tenant only.
 *
 * AW-01  artifact that passes the core checks → one event, tenant = signing-key tenant
 * AW-02  forged artifact (signature fails) naming another tenant's key → no event
 * AW-03  event is dispatched even when the attestation's persistence fails
 * AW-04  chain verification of one tenant's evidence records → event for that tenant
 * AW-05  chain verification spanning two tenants → no event
 * AW-06  evidence package not bound to a stored original → no event
 * AW-07  a throwing dispatcher never fails the attestation
 */

const mockPool = { _enabled: false, isEnabled() { return this._enabled; }, query: jest.fn() };
jest.mock('../../../infra/postgres/pool', () => mockPool);
jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
const mockValidateArtifact = jest.fn();
jest.mock('../../../validation/validateArtifact', () => ({
  validateArtifact: (...a) => mockValidateArtifact(...a),
}));
jest.mock('../../../core/transparency/registrar', () => ({ register: jest.fn(async () => ({ transparencyId: 't-1' })) }));
const mockVerifyEvidence = jest.fn();
const mockGetByEvidenceId = jest.fn();
jest.mock('../../../core/evidence/chainStore', () => ({
  verifyEvidence: (...a) => mockVerifyEvidence(...a),
  verifyChainRange: jest.fn(),
  getByArtifactId: jest.fn(async () => null),
  getByEvidenceId: (...a) => mockGetByEvidenceId(...a),
}));
const mockRecordAttestation = jest.fn();
jest.mock('../attestationStore', () => ({
  recordAttestation: (...a) => mockRecordAttestation(...a),
  getByAttestationId: jest.fn(async () => null),
  getByFingerprint: jest.fn(async () => null),
}));
const mockDispatch = jest.fn();
jest.mock('../../webhooks/webhookDispatcher', () => {
  const actual = jest.requireActual('../../webhooks/webhookDispatcher');
  return { ...actual, dispatchEvent: (...a) => mockDispatch(...a) };
});

const attestor = require('../attestor');
const { emit } = require('../../../../services/logger');

const EXECUTE = { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED', details: {} };
const BLOCK_SIG = { decision: 'BLOCK', reason: 'INVALID_SIGNATURE', details: { issue: 'Ed25519 signature is invalid' } };
const artifact = (keyId) => ({ payload: { action: 't', requestId: `r-${Math.random()}` }, timestamp: Date.now(), expiry: Date.now() + 60_000, publicKeyId: keyId, signature: 'c2ln' });
const settle = () => new Promise((r) => setImmediate(r));

beforeEach(() => {
  jest.clearAllMocks();
  mockRecordAttestation.mockResolvedValue({ attestation_id: 'x' });
});

test('AW-01 valid artifact → attestation.completed for the signing-key tenant', async () => {
  mockValidateArtifact.mockReturnValue(EXECUTE);
  const r = await attestor.generateAttestation(artifact('tenant-a:key_v1'));
  await settle();
  expect(mockDispatch).toHaveBeenCalledTimes(1);
  const [type, payload] = mockDispatch.mock.calls[0];
  expect(type).toBe('attestation.completed');
  expect(payload).toEqual(expect.objectContaining({ eventType: 'attestation.completed', attestationId: r.attestationId, decision: 'ATTESTED', tenantId: 'tenant-a' }));
  expect(payload.eventId).toMatch(/^[0-9a-f-]{36}$/);
});

test('AW-02 forged artifact naming another tenant\'s key → no event', async () => {
  mockValidateArtifact.mockReturnValue(BLOCK_SIG);
  const r = await attestor.generateAttestation(artifact('victim-tenant:key_v1'));
  await settle();
  expect(r.attestationDecision).toBe('NOT_ATTESTED');
  expect(mockDispatch).not.toHaveBeenCalled();
  expect(emit).toHaveBeenCalledWith('INFO', 'WEBHOOK_EVENT_NOT_DISPATCHED', expect.objectContaining({ eventType: 'attestation.completed', reason: 'NO_PROVEN_TENANT' }));
});

test('AW-03 persistence failure does not suppress the event', async () => {
  mockValidateArtifact.mockReturnValue(EXECUTE);
  mockRecordAttestation.mockRejectedValue(new Error('pg down'));
  await attestor.generateAttestation(artifact('tenant-a:key_v1'));
  await settle();
  expect(mockDispatch).toHaveBeenCalledTimes(1);
});

test('AW-04 chain of one tenant\'s records → event for that tenant', async () => {
  mockVerifyEvidence.mockResolvedValue({ result: 'VALID' });
  mockGetByEvidenceId.mockResolvedValue({ tenant_id: 'tenant-b' });
  const r = await attestor.verifyChain({ evidenceIds: ['e1', 'e2'] });
  await settle();
  expect(r.attestationDecision).toBe('ATTESTED');
  expect(mockDispatch).toHaveBeenCalledWith('attestation.completed', expect.objectContaining({ attestationId: r.attestationId, tenantId: 'tenant-b', decision: 'ATTESTED' }));
});

test('AW-05 chain spanning two tenants → no event', async () => {
  mockVerifyEvidence.mockResolvedValue({ result: 'VALID' });
  mockGetByEvidenceId.mockResolvedValueOnce({ tenant_id: 'tenant-a' }).mockResolvedValueOnce({ tenant_id: 'tenant-b' });
  await attestor.verifyChain({ evidenceIds: ['e1', 'e2'] });
  await settle();
  expect(mockDispatch).not.toHaveBeenCalled();
});

test('AW-06 evidence package not bound to a stored original → no event', async () => {
  await attestor.verifyEvidencePackage({ packageType: 'QODIQA::PORTAL_EVIDENCE::V1', verificationId: 'v1', artifactPublicKeyId: 'tenant-a:key_v1', packageHash: 'f'.repeat(64) });
  await settle();
  expect(mockDispatch).not.toHaveBeenCalled();
});

test('AW-07 a throwing dispatcher never fails the attestation', async () => {
  mockValidateArtifact.mockReturnValue(EXECUTE);
  mockDispatch.mockImplementation(() => { throw new Error('boom'); });
  const r = await attestor.generateAttestation(artifact('tenant-a:key_v1'));
  await settle();
  expect(r.attestationDecision).toBe('ATTESTED');
  expect(emit).toHaveBeenCalledWith('WARN', 'WEBHOOK_DISPATCH_FAILED', expect.objectContaining({ eventType: 'attestation.completed' }));
});
