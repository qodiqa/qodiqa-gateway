'use strict';

/**
 * DLP on tool calls: the arguments are checked when the call is authorised (DETECT / BLOCK only - they are bound by the action hash), the result before it is screened
 * and delivered (all actions).
 *   TD-01  arguments: a BLOCK rule refuses at authorise, before a chain position is reserved (the session is not moved)
 *   TD-02  result: REDACT replaces the value before the caller sees it; the receipt hash is over what was delivered; the server did run
 *   TD-03  result: BLOCK withholds it like a screening block
 *   TD-04  no DLP rule: nothing changes
 *   TD-05  validation: a tool_input rule cannot REDACT
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const request = require('supertest');
const express = require('express');
const { provisionTestSigningIdentity } = require('../../../../test/helpers/signingIdentity');
const { startMcpTestServer } = require('../../../../test/helpers/mcpTestServer');

const T = 'default';
const MAIL = 'jane.roe@example.org';
const ECHO = { type: 'object', required: ['text'], properties: { text: { type: 'string' } }, additionalProperties: false };
let apiKey; let app; let mods; let mcp; let policies; let dlpRule;

function boot() {
  jest.resetModules();
  jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));
  process.env.QODIQA_CLIENT_ID = T; process.env.QODIQA_MCP_ALLOW_LOCAL = 'true'; process.env.QODIQA_DLP_TOKEN_KEY = 'w'.repeat(40);
  mods = { agents: require('../../../core/agents/agentStore'), registry: require('../../../core/actions/toolRegistry'), servers: require('../../../core/mcp/mcpRegistry') };
  dlpRule = require('../../../../services/policy/evaluators/dlp');
  const { createActionsRouter } = require('../actions'); const { createToolsRouter } = require('../tools');
  const getPolicies = () => policies;
  app = express(); app.use(express.json());
  app.use('/v1/actions', createActionsRouter({ getPolicies }));
  app.use('/v1/tools', createToolsRouter({ getPolicies, screenDeps: { semantic: async () => ({ blocks: false }), embedding: async () => ({ blocks: false }) } }));
  ({ apiKey } = provisionTestSigningIdentity({ tenantId: T }));
}
const rule = (config, id = 'DLP') => { const c = { dlpFormat: 1, action: 'BLOCK', rules: ['EMAIL'], ...config }; dlpRule.validate(c); return { id, type: 'DLP', priority: 1, enabled: true, config: dlpRule.preprocess(c) }; };
const bearer = { get Authorization() { return `Bearer ${apiKey}`; } };
const authorize = (w, name, args) => request(app).post('/v1/actions/authorize').set({ Authorization: bearer.Authorization }).send({ agentId: w.agentId, sessionId: w.sessionId, tool: { server: 'mcp1', name }, args });
const call = (artifact, name, args) => request(app).post('/v1/tools/call').set({ Authorization: bearer.Authorization }).send({ artifact, tool: { server: 'mcp1', name }, args });
async function agent() {
  const a = await mods.agents.createAgent(T, { displayName: 'Bot', allowedActionClasses: ['read'] }, 'op');
  return { agentId: a.agentId, sessionId: (await mods.agents.startSession(T, a.agentId, {}, 'op')).sessionId };
}
async function setup(handlers) {
  mcp = await startMcpTestServer({ handlers });
  await mods.servers.register(T, { serverId: 'mcp1', url: mcp.url }, 'op');
  await mods.registry.register(T, { server: 'mcp1', name: 'echo', schema: ECHO, actionClass: 'read', reversible: true }, 'alice');
}

beforeEach(() => { policies = []; boot(); });
afterEach(async () => { if (mcp) { await mcp.close(); mcp = null; } delete process.env.QODIQA_DLP_TOKEN_KEY; });

describe('DLP on tools', () => {
  test('TD-01 a BLOCK rule on the arguments refuses at authorise and leaves the session where it was', async () => {
    await setup(); policies = [rule({ direction: 'tool_input' })];
    const w = await agent();
    const bad = await authorize(w, 'echo', { text: `send to ${MAIL}` });
    expect(bad.status).toBe(403); expect(bad.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' });
    expect(JSON.stringify(bad.body)).not.toContain('jane.roe');
    expect((await mods.agents.getSession(T, w.sessionId)).nextSeq).toBe(1);                 // nothing was reserved
    const ok = await authorize(w, 'echo', { text: 'plain text' });
    expect(ok.status).toBe(200); expect(ok.body.action.seq).toBe(1);
    expect(mcp.calls).toHaveLength(0);
  });

  test('TD-02 a REDACT rule on the result: the caller never sees the value, the receipt hashes what was delivered', async () => {
    await setup({ echo: (a) => ({ content: [{ type: 'text', text: `result for ${a.text}: contact ${MAIL}` }] }) });
    policies = [rule({ direction: 'tool_output', action: 'REDACT' })];
    const w = await agent();
    const a = await authorize(w, 'echo', { text: 'q' }); expect(a.status).toBe(200);
    const r = await call(a.body.artifact, 'echo', { text: 'q' });
    expect(r.status).toBe(200); expect(r.body.decision).toBe('EXECUTE');
    const text = r.body.result.content[0].text;
    expect(text).toMatch(/^result for q: contact \[\[EMAIL:[0-9a-f]{12}\]\]$/);
    expect(JSON.stringify(r.body)).not.toContain('jane.roe');
    const { outputHashOf } = require('../../../core/audit/entryBuilder');
    expect(r.body.receipt.outputHash).toBe(outputHashOf(text));
    expect(mcp.calls).toHaveLength(1);                                                       // the tool did run
  });

  test('TD-03 a BLOCK rule on the result withholds it', async () => {
    await setup({ echo: () => ({ content: [{ type: 'text', text: `owner ${MAIL}` }] }) });
    policies = [rule({ direction: 'tool_output' })];
    const w = await agent();
    const a = await authorize(w, 'echo', { text: 'q' });
    const r = await call(a.body.artifact, 'echo', { text: 'q' });
    expect(r.status).toBe(200); expect(r.body).toMatchObject({ decision: 'BLOCK', reason: 'DLP_BLOCKED' });
    expect(r.body.receipt.status).toBe('RESULT_BLOCKED'); expect(JSON.stringify(r.body)).not.toContain('jane.roe');
  });

  test('TD-04 without a DLP rule nothing changes', async () => {
    await setup({ echo: () => ({ content: [{ type: 'text', text: `owner ${MAIL}` }] }) });
    const w = await agent();
    const a = await authorize(w, 'echo', { text: `x ${MAIL}` }); expect(a.status).toBe(200);
    const r = await call(a.body.artifact, 'echo', { text: `x ${MAIL}` });
    expect(r.body.decision).toBe('EXECUTE'); expect(r.body.result.content[0].text).toContain(MAIL);
  });

  test('TD-05 a tool_input rule cannot rewrite the arguments', () => {
    expect(() => rule({ direction: 'tool_input', action: 'REDACT' })).toThrow(/DETECT or BLOCK/);
    expect(() => rule({ direction: 'tool_input', action: 'MASK' })).toThrow(/DETECT or BLOCK/);
    expect(() => rule({ direction: 'tool_input', action: 'DETECT' })).not.toThrow();
    expect(() => rule({ direction: 'tool_output', action: 'REDACT' })).not.toThrow();
  });
});
