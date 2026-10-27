'use strict';

/**
 * GET /v1/proofs/:requestId (src/api/routes/proofs.js): validation, tenant isolation of the answer, the access log, the permission guard, failure handling.
 *
 *   PR-01  requestId must be a UUID; tenantId is required (400 each); the assembler is not called
 *   PR-02  served: the proof is `data` of the usual envelope, Cache-Control no-store, one PROOF_ACCESSED event with the operator and the parts
 *   PR-03  unknown request and another tenant's request answer identically (404 NOT_FOUND), both logged
 *   PR-04  an assembler failure is a 503 PROOF_UNAVAILABLE that leaks nothing, logged at ERROR
 *   PR-05  the permission READ_AUDIT_PROOFS is what the route asks for; a denied caller never reaches the assembler
 */

const mockEmit = jest.fn();
jest.mock('../../../../services/logger', () => ({ emit: (...a) => mockEmit(...a) }));

const express = require('express');
const request = require('supertest');
const { createProofsRouter } = require('../proofs');

const RID = '5b1c0a52-1d7e-4c25-9b0a-3a1d2e4f5a6b';
function app({ assemble, allow = true } = {}) {
  const asked = [];
  const requirePermission = (p) => (req, res, next) => { asked.push(p); return allow ? next() : res.status(403).json({ status: 'failure', error: { code: 'FORBIDDEN' } }); };
  const a = express();
  a.use((req, res, next) => { res.locals.requestId = 'req-1'; req.rbacUser = { id: 'op-7' }; next(); });
  a.use('/v1/proofs', createProofsRouter({ requirePermission, assemble }));
  return { a, asked };
}
beforeEach(() => mockEmit.mockClear());

describe('GET /v1/proofs/:requestId', () => {
  test('PR-01 validation: requestId and tenantId', async () => {
    const assemble = jest.fn();
    const { a } = app({ assemble });
    expect((await request(a).get('/v1/proofs/not-a-uuid?tenantId=t1')).status).toBe(400);
    const noTenant = await request(a).get(`/v1/proofs/${RID}`);
    expect(noTenant.status).toBe(400); expect(noTenant.body.error.code).toBe('TENANT_ID_REQUIRED');
    expect((await request(a).get(`/v1/proofs/${RID}?tenantId=${encodeURIComponent('a b;')}`)).status).toBe(400);
    expect(assemble).not.toHaveBeenCalled();
  });

  test('PR-02 served: envelope, no-store, one access event', async () => {
    const proof = { format: 'qodiqa-proof/1', subject: { tenantId: 't1', requestId: RID }, auditEntries: [], keys: [] };
    const assemble = jest.fn(async () => ({ ok: true, proof, parts: { entries: 3, transparency: true } }));
    const { a } = app({ assemble });
    const r = await request(a).get(`/v1/proofs/${RID}?tenantId=t1`);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: 'success', data: proof });
    expect(r.headers['cache-control']).toBe('no-store');
    expect(assemble).toHaveBeenCalledWith({ tenantId: 't1', requestId: RID, allowForeignEntries: false });
    const ev = mockEmit.mock.calls.filter((c) => c[1] === 'PROOF_ACCESSED');
    expect(ev).toHaveLength(1);
    expect(ev[0][2]).toMatchObject({ requestId: RID, tenantId: 't1', outcome: 'served', parts: { entries: 3, transparency: true } });
    expect(ev[0][2].actor).toBeTruthy();
  });

  test('PR-03 an unknown request and another tenant\'s request answer identically', async () => {
    const assemble = jest.fn(async () => ({ ok: false, code: 'NOT_FOUND' }));
    const { a } = app({ assemble });
    const one = await request(a).get(`/v1/proofs/${RID}?tenantId=t1`);
    const two = await request(a).get(`/v1/proofs/${RID.replace('5b1c', '9b1c')}?tenantId=other`);
    expect([one.status, two.status]).toEqual([404, 404]);
    expect(one.body.error).toEqual(two.body.error);
    expect(mockEmit.mock.calls.filter((c) => c[1] === 'PROOF_ACCESSED').map((c) => c[2].outcome)).toEqual(['not_found', 'not_found']);
  });

  test('PR-04 an assembler failure is a 503 that leaks nothing', async () => {
    const { a } = app({ assemble: async () => { throw new Error('connection to 10.0.0.5:5432 refused'); } });
    const r = await request(a).get(`/v1/proofs/${RID}?tenantId=t1`);
    expect(r.status).toBe(503);
    expect(JSON.stringify(r.body)).not.toMatch(/10\.0\.0\.5|5432/);
    expect(mockEmit.mock.calls.some((c) => c[0] === 'ERROR' && c[1] === 'PROOF_ASSEMBLY_FAILED')).toBe(true);
  });

  test('PR-05 the permission is READ_AUDIT_PROOFS; a denied caller never reaches the assembler', async () => {
    const assemble = jest.fn();
    const { a, asked } = app({ assemble, allow: false });
    const r = await request(a).get(`/v1/proofs/${RID}?tenantId=t1`);
    expect(r.status).toBe(403);
    expect(asked).toContain('READ_AUDIT_PROOFS');
    expect(assemble).not.toHaveBeenCalled();
    const { PERMISSIONS } = require('../../../core/rbac/roles');
    expect(PERMISSIONS.READ_AUDIT_PROOFS).toEqual(expect.arrayContaining(['admin', 'auditor', 'compliance']));
    expect(PERMISSIONS.READ_AUDIT_PROOFS).not.toContain('viewer');
  });

  test('PR-06 the platform-wide chain needs its own permission; an uppercase request id finds the lower-case request (D-13)', async () => {
    const assemble = jest.fn(async () => ({ ok: true, proof: {}, parts: {} }));
    const { a, asked } = app({ assemble });
    await request(a).get(`/v1/proofs/${RID}?tenantId=t1`);
    expect(assemble).toHaveBeenLastCalledWith(expect.objectContaining({ allowForeignEntries: false }));
    expect(asked).not.toContain('READ_AUDIT_PROOFS_FULL_CHAIN');
    await request(a).get(`/v1/proofs/${RID.toUpperCase()}?tenantId=t1&fullChain=true`);
    expect(asked).toContain('READ_AUDIT_PROOFS_FULL_CHAIN');
    expect(assemble).toHaveBeenLastCalledWith({ tenantId: 't1', requestId: RID, allowForeignEntries: true });
    const denied = app({ assemble, allow: false });
    const before = assemble.mock.calls.length;
    expect((await request(denied.a).get(`/v1/proofs/${RID}?tenantId=t1&fullChain=true`)).status).toBe(403);
    expect(assemble.mock.calls.length).toBe(before);
    const { PERMISSIONS } = require('../../../core/rbac/roles');
    expect(PERMISSIONS.READ_AUDIT_PROOFS_FULL_CHAIN).toEqual(['admin']);
  });
});

describe('PR-06 qodiqa_proof_requests_total is actually incremented', () => {
  it('the metrics module exports proofRequestsTotal and a served request increments it', async () => {
    const metrics = require('../../../observability/metrics');
    expect(metrics.proofRequestsTotal).toBeDefined();
    const before = metrics.proofRequestsTotal._values.get(Array.from(metrics.proofRequestsTotal._values.keys()).find((k) => k.includes('served'))) || 0;
    const { a } = app({ assemble: async () => ({ ok: true, parts: ['x'], proof: {} }) });
    await request(a).get(`/v1/proofs/${RID}`).query({ tenantId: 't1' });
    const key = Array.from(metrics.proofRequestsTotal._values.keys()).find((k) => k.includes('served'));
    expect(metrics.proofRequestsTotal._values.get(key)).toBe(before + 1);
  });
});
