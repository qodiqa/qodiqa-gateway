'use strict';

/**
 * consent lifecycle attribution is the AUTHENTICATED operator (req.rbacUser),
 * not a caller-supplied body value. Harness = consent.test.js's route section (mocked registry + logger), plus a tiny
 * middleware standing in for opsAuth that attaches req.rbacUser exactly as src/middleware/opsAuth.js does.
 *
 *   CA-01  grant: body grantedBy 'someone-else' → granted_by = operator username; the claim is logged, not recorded
 *   CA-02  revoke / suspend / resume / revoke-all-for-actor: same rule for revoked_by / suspended_by / resumed_by
 *   CA-03  body value equal to the operator, or absent → operator, no claim event (API compatibility)
 *   CA-04  rbacUser without username → its id
 *   CA-05  no rbacUser (router mounted without the admin stack) → previous behaviour (body value, else 'api')
 */

const ID = 'aaaaaaaa-0000-4000-8000-000000000001';

let mockRegistry; let mockEmit; let agent;

function build(rbacUser) {
  jest.resetModules();
  mockRegistry = {
    grant: jest.fn().mockResolvedValue({ id: ID }), revoke: jest.fn().mockResolvedValue({ id: ID }),
    suspend: jest.fn().mockResolvedValue({ id: ID }), resume: jest.fn().mockResolvedValue({ id: ID }),
    revokeAll: jest.fn().mockResolvedValue({ count: 1 }), list: jest.fn(), getById: jest.fn(), health: jest.fn(() => ({})),
  };
  mockEmit = jest.fn();
  jest.doMock('../../../core/consent', () => mockRegistry);
  jest.doMock('../../../../services/logger', () => ({ emit: mockEmit }));
  jest.doMock('../../../core/consent/ConsentStore', () => ({ isSpecialCategoryScope: jest.fn().mockResolvedValue(false) }));
  const { createConsentRouter } = require('../consent');
  const express = require('express');
  const app = express();
  app.use(express.json());
  if (rbacUser) app.use((req, _res, next) => { req.rbacUser = Object.freeze(rbacUser); req.requestId = 'rq-1'; next(); });
  app.use('/consent', createConsentRouter());
  agent = require('supertest')(app);
}
afterEach(() => jest.resetModules());

const GRANT = { actorId: 'agent', action: 'Facial Recognition', lawfulBasis: 'consent', purpose: 'p' };
const OP = { id: 'u-7', username: 'alice', role: 'admin', enabled: true };
const claims = () => mockEmit.mock.calls.filter((c) => c[1] === 'CONSENT_ACTOR_CLAIM_NOT_RECORDED').map((c) => c[2]);

test('CA-01 grant records the authenticated operator; a differing body claim is logged only', async () => {
  build(OP);
  const res = await agent.post('/consent').send({ ...GRANT, grantedBy: 'someone-else' });
  expect(res.status).toBe(201);
  expect(mockRegistry.grant.mock.calls[0][0].granted_by).toBe('alice');
  expect(claims()).toEqual([expect.objectContaining({ field: 'grantedBy', operator: 'alice', claimedOnBehalfOf: 'someone-else', requestId: 'rq-1' })]);
});

test('CA-02 revoke / suspend / resume / revoke-all record the operator', async () => {
  build(OP);
  expect((await agent.post(`/consent/${ID}/revoke`).send({ revokedBy: 'mallory' })).status).toBe(200);
  expect((await agent.post(`/consent/${ID}/suspend`).send({ suspendedBy: 'mallory' })).status).toBe(200);
  expect((await agent.post(`/consent/${ID}/resume`).send({ resumedBy: 'mallory' })).status).toBe(200);
  expect((await agent.post('/consent/actor/agent/revoke').send({ revoked_by: 'mallory' })).status).toBe(200);
  expect(mockRegistry.revoke.mock.calls[0][0].revoked_by).toBe('alice');
  expect(mockRegistry.suspend.mock.calls[0][0].suspended_by).toBe('alice');
  expect(mockRegistry.resume.mock.calls[0][0].resumed_by).toBe('alice');
  expect(mockRegistry.revokeAll.mock.calls[0][1]).toBe('alice');
  expect(claims().map((c) => c.field)).toEqual(['revokedBy', 'suspendedBy', 'resumedBy', 'revoked_by']);
});

test('CA-03 matching or absent body value → operator, no claim event', async () => {
  build(OP);
  await agent.post('/consent').send({ ...GRANT, grantedBy: 'alice' });
  await agent.post(`/consent/${ID}/revoke`).send({});
  expect(mockRegistry.grant.mock.calls[0][0].granted_by).toBe('alice');
  expect(mockRegistry.revoke.mock.calls[0][0].revoked_by).toBe('alice');
  expect(claims()).toEqual([]);
});

test('CA-04 operator without a username → id', async () => {
  build({ id: 'u-9', role: 'admin', enabled: true });
  await agent.post(`/consent/${ID}/revoke`).send({});
  expect(mockRegistry.revoke.mock.calls[0][0].revoked_by).toBe('u-9');
});

test('CA-05 unauthenticated mount keeps the previous behaviour', async () => {
  build(null);
  await agent.post('/consent').send({ ...GRANT, grantedBy: 'admin' });
  await agent.post(`/consent/${ID}/revoke`).send({});
  expect(mockRegistry.grant.mock.calls[0][0].granted_by).toBe('admin');
  expect(mockRegistry.revoke.mock.calls[0][0].revoked_by).toBe('api');
});

test('NF-1 re-granting a REVOKED consent is a 409 CONSENT_TERMINAL_STATE, not a 500', async () => {
  build(OP);
  mockRegistry.grant.mockRejectedValueOnce(new Error('Cannot grant consent: existing record for actor_id=agent, action=Facial Recognition is in terminal state REVOKED and cannot be reactivated'));
  const res = await agent.post('/consent').send(GRANT);
  expect(res.status).toBe(409);
  expect(JSON.stringify(res.body)).toMatch(/CONSENT_TERMINAL_STATE/);
  // an infrastructure error with a similar prefix must still be a 500
  mockRegistry.grant.mockRejectedValueOnce(new Error('Cannot use a pool after calling end on the pool'));
  expect((await agent.post('/consent').send(GRANT)).status).toBe(500);
});
