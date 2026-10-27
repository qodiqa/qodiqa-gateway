'use strict';

/**
 * (design decision D7 = B) — public writing verification routes.
 *
 * Anonymous callers get the full verification result with NOTHING persisted:
 * no attestation row, no portal verification row, no transparency leaf, no
 * transparency verification record. Only a caller that passed the full admin
 * stack (optionalAuth sets req.rbacUser) persists. The optionalAuth stack
 * itself (credential presented but rejected → refused, never downgraded) is
 * tested in src/middleware/__tests__/optionalAuth.test.js.
 */

const mockPool = { _enabled: true, isEnabled() { return this._enabled; }, query: jest.fn() };
jest.mock('../../../infra/postgres/pool', () => mockPool);

const mockRegister = jest.fn();
jest.mock('../../../core/transparency/registrar', () => ({ register: mockRegister }));

jest.mock('../../../core/evidence/chainStore', () => ({
  verifyEvidence:   jest.fn(async () => ({ result: 'VALID', checks: [] })),
  verifyChainRange: jest.fn(async () => ({ valid: true, checkedCount: 5 })),
  getByArtifactId:  jest.fn(async () => ({ id: 'ev-1', artifact_id: 'a-1' })),
  getByEvidenceId:  jest.fn(async () => ({ tenant_id: 'tenant-a' })),
}));

const mockRecordAttestation = jest.fn();
jest.mock('../../../core/attestation/attestationStore', () => ({
  recordAttestation:  mockRecordAttestation,
  getByAttestationId: jest.fn(async () => null),
  getByFingerprint:   jest.fn(async () => null),
  listAttestations:   jest.fn(),
  aggregateStats:     jest.fn(),
}));

const mockRecordPortalVerification = jest.fn();
jest.mock('../../../core/verification/portalStore', () => ({
  getByVerificationId: jest.fn(async () => null),
  recordVerification:  mockRecordPortalVerification,
  getByFingerprint:    jest.fn(async () => null),
  listVerifications:   jest.fn(),
  aggregateStats:      jest.fn(),
}));

const mockRecordTransparencyVerification = jest.fn();
const mockGetByTransparencyId = jest.fn();
jest.mock('../../../core/transparency/logStore', () => ({
  getByTransparencyId: mockGetByTransparencyId,
  getForVerification:  mockGetByTransparencyId, // /verify reads its material as qodiqa_system
  getByEntryHash:      jest.fn(async () => null),
  recordVerification:  mockRecordTransparencyVerification,
}));

jest.mock('../../../../services/logger', () => ({
  emit: jest.fn(), allowed: jest.fn(), blocked: jest.fn(),
  eventBus: { emit: jest.fn(), on: jest.fn(), setMaxListeners: jest.fn() }, registerCentralStore: jest.fn(),
}));

const request = require('supertest');
const express = require('express');
const { randomUUID } = require('crypto');
const { createAttestationPublicRouter } = require('../attestation');
const { createVerificationPortalPublicRouter } = require('../verificationPortal');
const { createTransparencyPublicRouter } = require('../transparencyLog');
const { getActiveKey } = require('../../../../services/artifact/keyStore');
const { signArtifact } = require('../../../validation/signArtifact');

let KEY;
beforeAll(() => { KEY = getActiveKey('default'); });
beforeEach(() => {
  jest.clearAllMocks();
  mockRegister.mockResolvedValue({ transparencyId: randomUUID() });
  mockRecordAttestation.mockResolvedValue({ attestation_id: 'stub' });
  mockRecordPortalVerification.mockResolvedValue({ verification_id: 'stub' });
  mockRecordTransparencyVerification.mockResolvedValue(undefined);
});

const OPERATOR = (req, _res, next) => { req.rbacUser = Object.freeze({ id: 'op-1', username: 'op', role: 'admin', enabled: true }); next(); };
function makeApp(authed) {
  const optionalAuth = authed ? OPERATOR : (_q, _s, n) => n();
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => { req.requestId = 'r'; next(); });
  app.use('/v1/attestation', createAttestationPublicRouter({ optionalAuth }));
  app.use('/portal', createVerificationPortalPublicRouter({ optionalAuth }));
  app.use('/transparency', createTransparencyPublicRouter({ optionalAuth }));
  return app;
}
function artifact() {
  const now = Date.now();
  return signArtifact({ payload: { action: 'test', requestId: randomUUID() }, timestamp: now, expiry: now + 60_000, publicKeyId: KEY.keyId }, KEY.privDer);
}

describe('POST /v1/attestation/verify', () => {
  test('anonymous → full result, ephemeral: no attestation row, no transparency leaf', async () => {
    const r = await request(makeApp(false)).post('/v1/attestation/verify').send(artifact());
    expect(r.status).toBe(200);
    expect(r.body.data.attestation.attestationDecision).toBe('ATTESTED');
    expect(r.body.data.attestation.attestationId).toBeNull();
    expect(r.body.data.attestation.persisted).toBe(false);
    expect(mockRecordAttestation).not.toHaveBeenCalled();
    expect(mockRegister).not.toHaveBeenCalled();
  });

  test('authenticated operator → persisted (attestation row + transparency leaf)', async () => {
    const r = await request(makeApp(true)).post('/v1/attestation/verify').send(artifact());
    expect(r.status).toBe(200);
    expect(r.body.data.attestation.attestationId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(mockRecordAttestation).toHaveBeenCalledTimes(1);
    expect(mockRegister).toHaveBeenCalled();
  });

  test('a 50-request anonymous burst persists nothing', async () => {
    const app = makeApp(false);
    for (let i = 0; i < 50; i++) await request(app).post('/v1/attestation/verify').send(artifact());
    expect(mockRecordAttestation).not.toHaveBeenCalled();
    expect(mockRegister).not.toHaveBeenCalled();
  });
});

describe('POST /portal/verify', () => {
  test('anonymous → result, no verification row, no transparency leaf', async () => {
    const r = await request(makeApp(false)).post('/portal/verify').send(artifact());
    expect(r.status).toBe(200);
    expect(JSON.stringify(r.body)).toContain('"persisted":false');
    expect(mockRecordPortalVerification).not.toHaveBeenCalled();
    expect(mockRegister).not.toHaveBeenCalled();
  });

  test('authenticated operator → persisted', async () => {
    const r = await request(makeApp(true)).post('/portal/verify').send(artifact());
    expect(r.status).toBe(200);
    expect(mockRecordPortalVerification).toHaveBeenCalledTimes(1);
  });
});

describe('GET /transparency/verify/:id', () => {
  const entry = () => ({ transparency_id: randomUUID(), previous_entry_hash: null, signer_key_id: 'none', entry_hash: 'x', payload_hash: 'y' });

  test('anonymous → report, no verification record', async () => {
    const e = entry(); mockGetByTransparencyId.mockResolvedValue(e);
    const r = await request(makeApp(false)).get(`/transparency/verify/${e.transparency_id}`);
    expect(r.status).toBe(200);
    expect(mockRecordTransparencyVerification).not.toHaveBeenCalled();
  });

  test('authenticated operator → recorded, attributed to the operator', async () => {
    const e = entry(); mockGetByTransparencyId.mockResolvedValue(e);
    const r = await request(makeApp(true)).get(`/transparency/verify/${e.transparency_id}`);
    expect(r.status).toBe(200);
    expect(mockRecordTransparencyVerification).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(mockRecordTransparencyVerification.mock.calls[0][0])).toContain('op');
  });
});
