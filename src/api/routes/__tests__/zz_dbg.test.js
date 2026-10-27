'use strict';

/**
 * the lifetime of a child delegation (kept in a file of its own: it started as a debugging probe and was kept as the regression test it became).
 *
 *   DL-08  a child asked for without a lifetime lives as long as its parent at most; an explicit lifetime beyond the parent's is a violation, never silently shortened
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const request = require('supertest');

const T = 'default';
let apiKey; let app; let store; let del;

beforeEach(async () => {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T;
  store = require('../../../core/agents/agentStore');
  del = require('../../../core/delegation/delegationStore');
  const { createDelegationsRouter } = require('../delegations');
  app = express();
  app.use(express.json());
  app.use('/v1/delegations', createDelegationsRouter());
  ({ apiKey } = require('../../../../test/helpers/signingIdentity').provisionTestSigningIdentity({ tenantId: T }));
  store._resetForTests(); del._resetForTests();
});

const agent = async (classes = ['read', 'write', 'delegate']) => {
  const a = await store.createAgent(T, { displayName: 'Bot', allowedActionClasses: classes }, 'op');
  return { agentId: a.agentId, sessionId: (await store.startSession(T, a.agentId, {}, 'op')).sessionId };
};
const grant = (from, to, over) => request(app).post('/v1/delegations').set('Authorization', `Bearer ${apiKey}`)
  .send({ issuerAgentId: from.agentId, issuerSessionId: from.sessionId, subjectAgentId: to.agentId, classes: ['read'], ...over });

test('DL-08 child lifetime never exceeds the parent', async () => {
  const A = await agent(); const B = await agent(); const C = await agent();
  const g1 = await grant(A, B, { classes: ['read', 'delegate'], maxDepth: 3, ttlSeconds: 600 });
  expect(g1.status).toBe(201);
  const g2 = await grant(B, C, { parentId: g1.body.delegationId });                                  // no ttl: capped at the parent's expiry
  expect(g2.status).toBe(201);
  expect(g2.body.token.expiry).toBeLessThanOrEqual(g1.body.token.expiry);
  const g3 = await grant(B, C, { parentId: g1.body.delegationId, ttlSeconds: 601 });                  // explicit and longer: refused, not shortened
  expect(g3.status).toBe(403); expect(g3.body.reason).toBe('DELEGATION_ATTENUATION_VIOLATION');
  const g4 = await grant(B, C, { parentId: g1.body.delegationId, ttlSeconds: 60 });
  expect(g4.status).toBe(201); expect(g4.body.token.expiry - g4.body.token.timestamp).toBe(60_000);
});
