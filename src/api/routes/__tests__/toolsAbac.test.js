'use strict';

/**
 * ABAC rules of tool scope on the real authorisation: who may authorise which tool (by class, server, name), checked before anything is reserved.
 *   TA-01  a class deny-list refuses at authorise and leaves the session where it was
 *   TA-02  an allow-list (REQUIRE) refuses every tool that is not listed, including a tool of the same class
 *   TA-03  a request-scope ABAC rule does not apply to tools, and no rule means no change
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { startMcpTestServer } = require('../../../../test/helpers/mcpTestServer');

const T_ID = 'default';
const MAIL = 'jane.roe@example.org';
const ECHO = { type: 'object', required: ['text'], properties: { text: { type: 'string' } }, additionalProperties: false };
let apiKey; let app; let mods; let mcp; let policies; let dlpRule;

function boot() {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T_ID; process.env.QODIQA_MCP_ALLOW_LOCAL = 'true'; process.env.QODIQA_DLP_TOKEN_KEY = 'w'.repeat(40);
  mods = { agents: require('../../../core/agents/agentStore'), registry: require('../../../core/actions/toolRegistry'), servers: require('../../../core/mcp/mcpRegistry') };
  dlpRule = require('../../../../services/policy/evaluators/dlp');
  const { createActionsRouter } = require('../actions'); const { createToolsRouter } = require('../tools');
  const getPolicies = () => policies;
  app = express(); app.use(express.json());
  app.use('/v1/actions', createActionsRouter({ getPolicies }));
  app.use('/v1/tools', createToolsRouter({ getPolicies, screenDeps: { semantic: async () => ({ blocks: false }), embedding: async () => ({ blocks: false }) } }));
  ({ apiKey } = provisionTestSigningIdentity({ tenantId: T_ID }));
}
const rule = (config, id = 'DLP') => { const c = { dlpFormat: 1, action: 'BLOCK', rules: ['EMAIL'], ...config }; dlpRule.validate(c); return { id, type: 'DLP', priority: 1, enabled: true, config: dlpRule.preprocess(c) }; };
const bearer = { get Authorization() { return `Bearer ${apiKey}`; } };
const authorize = (w, name, args) => request(app).post('/v1/actions/authorize').set({ Authorization: bearer.Authorization }).send({ agentId: w.agentId, sessionId: w.sessionId, tool: { server: 'mcp1', name }, args });
const call = (artifact, name, args) => request(app).post('/v1/tools/call').set({ Authorization: bearer.Authorization }).send({ artifact, tool: { server: 'mcp1', name }, args });
async function agent() {
  const a = await mods.agents.createAgent(T_ID, { displayName: 'Bot', allowedActionClasses: ['read'] }, 'op');
  return { agentId: a.agentId, sessionId: (await mods.agents.startSession(T_ID, a.agentId, {}, 'op')).sessionId };
}
async function setup(handlers) {
  mcp = await startMcpTestServer({ handlers });
  await mods.servers.register(T_ID, { serverId: 'mcp1', url: mcp.url }, 'op');
  await mods.registry.register(T_ID, { server: 'mcp1', name: 'echo', schema: ECHO, actionClass: 'read', reversible: true }, 'alice');
}

beforeEach(() => { policies = []; boot(); });
afterEach(async () => { if (mcp) { await mcp.close(); mcp = null; } delete process.env.QODIQA_DLP_TOKEN_KEY; });


const abacRule = (r) => { const live = { ...r, config: require('../../../../services/policy/evaluators/abac').preprocess(r.config) }; return live; };
const T = () => require('../../../../services/policy/abac/templates');

describe('ABAC on tools', () => {
  test('TA-01 a class deny-list refuses at authorise', async () => {
    await setup(); policies = [abacRule(T().toolClassDeny(['read']))];
    const w = await agent();
    const r = await authorize(w, 'echo', { text: 'hi' });
    expect(r.status).toBe(403); expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_TOOL_CLASS_DENIED' });
    expect((await mods.agents.getSession(T_ID, w.sessionId)).nextSeq).toBe(1);
    expect(mcp.calls).toHaveLength(0);
  });
  test('TA-02 an allow-list refuses every tool that is not listed', async () => {
    await setup(); policies = [abacRule(T().toolAllowList([{ server: 'mcp1', name: 'other' }]))];
    const w = await agent();
    expect((await authorize(w, 'echo', { text: 'hi' })).body).toMatchObject({ decision: 'BLOCK', reason: 'ABAC_TOOL_NOT_ALLOWED' });
    policies = [abacRule(T().toolAllowList([{ server: 'mcp1', name: 'echo' }]))];
    expect((await authorize(w, 'echo', { text: 'hi' })).status).toBe(200);
  });
  test('TA-03 a request-scope rule does not apply to tools; no rule, no change', async () => {
    await setup(); policies = [abacRule(T().modelAllowList(['x']))];
    const w = await agent();
    expect((await authorize(w, 'echo', { text: 'hi' })).status).toBe(200);
    policies = [];
    expect((await authorize(w, 'echo', { text: 'again' })).status).toBe(200);
  });
});
