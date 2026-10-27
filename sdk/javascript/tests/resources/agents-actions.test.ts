import crypto from 'node:crypto';
import { MockServer } from '../mock-server';
import {
  QodiqaClient, AuthenticationError, AuthorizationError, NotFoundError, ValidationError, TimeoutError,
  isApprovalPending, signAgentProof, agentProofDigest, generateAgentKeyPair, AGENT_PROOF_DOMAIN,
} from '../../src/index';
import type { ActionAuthorizeResponse, ActionApprovalPending } from '../../src/index';

const OPS_KEY = 'ok_' + 'd'.repeat(64);
const SIGN_KEY = 'sk_' + 'e'.repeat(64);
const AGENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SESSION = 'bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb';
const REQ = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const HASH = 'a'.repeat(64);
const env = <T>(data: T) => ({ status: 'success', timestamp: new Date().toISOString(), requestId: 'req-1', data });

const ARTIFACT = {
  expiry: 2, timestamp: 1, publicKeyId: 'default:key_v1', signature: 'x'.repeat(86) + '==',
  payload: { requestId: REQ, tenantId: 'default', qodiqa: { v: 2 as const, kind: 'action' as const, bind: { headers: [] as string[] }, agentId: AGENT, sessionId: SESSION, seq: 1, actionHash: HASH } },
};
const AUTHORIZED: ActionAuthorizeResponse = { artifactId: REQ, artifact: ARTIFACT, action: { actionHash: HASH, seq: 1, prevActionHash: null, tool: { server: 'srv', name: 'echo', schemaHash: 'b'.repeat(64), version: 1 }, parentRequestHash: null }, meta: {}, requestId: null };
const PENDING: ActionApprovalPending = { status: 'pending', timestamp: new Date().toISOString(), requestId: null, data: { approvalId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', actionHash: HASH, seq: 1, expiresAt: '2030-01-01T00:00:00.000Z' } };
const view = (status: string) => env({ approvalId: PENDING.data.approvalId, status, actionHash: HASH, seq: 1, tool: { server: 'srv', name: 'echo' }, agentId: AGENT, sessionId: SESSION, requestedAt: 'a', expiresAt: 'b', approverId: null, decidedAt: null, decisionReason: null, notBefore: null, approvalExpiresAt: null, usedAt: null, cancelledAt: null });

describe('agents, sessions, actions, tools, delegations, approvals (protocol V2)', () => {
  let server: MockServer;
  let baseUrl: string;
  beforeAll(async () => { server = new MockServer(); baseUrl = await server.start(); });
  afterAll(async () => { await server.stop(); });
  beforeEach(() => server.reset());
  const client = (o: { ops?: boolean; sign?: boolean; otp?: () => string } = {}) => new QodiqaClient({ baseUrl, timeout: 5000, maxRetries: 0, ...(o.ops ? { apiKey: OPS_KEY } : {}), ...(o.sign ? { signToken: SIGN_KEY } : {}), ...(o.otp ? { otpProvider: o.otp } : {}) });
  const last = () => server.getCallLog().slice(-1)[0]!;

  describe('agents and sessions (operator key)', () => {
    it('need the operator key', async () => {
      await expect(client().agents.create({ tenantId: 't', displayName: 'Bot' })).rejects.toBeInstanceOf(AuthenticationError);
      await expect(client({ sign: true }).sessions.start({ tenantId: 't', agentId: AGENT })).rejects.toBeInstanceOf(AuthenticationError);
    });

    it('create / list / get / update / suspend / revoke', async () => {
      server.mock('POST', '/v1/agents', { status: 201, body: env({ agentId: AGENT, status: 'active' }) });
      server.mock('GET', '/v1/agents', { status: 200, body: env({ agents: [] }) });
      server.mock('GET', `/v1/agents/${AGENT}`, { status: 200, body: env({ agentId: AGENT }) });
      server.mock('PATCH', `/v1/agents/${AGENT}`, { status: 200, body: env({ agentId: AGENT, status: 'suspended' }) });
      const c = client({ ops: true });
      expect((await c.agents.create({ tenantId: 't', displayName: 'Bot', allowedActionClasses: ['read'] })).data.agentId).toBe(AGENT);
      expect(last().headers['authorization']).toBe(`Bearer ${OPS_KEY}`);
      expect(last().body).toMatchObject({ tenantId: 't', displayName: 'Bot' });
      await c.agents.list('t', { status: 'active' });
      expect(last().path).toContain('tenantId=t'); expect(last().path).toContain('status=active');
      await c.agents.get(AGENT, 't');
      await c.agents.suspend(AGENT, 't');
      expect(last().body).toEqual({ tenantId: 't', status: 'suspended' });
      await c.agents.revoke(AGENT, 't');
      expect(last().body).toEqual({ tenantId: 't', status: 'revoked' });
    });

    it('a 404 for another tenant\'s agent is a NotFoundError', async () => {
      server.mock('GET', `/v1/agents/${AGENT}`, { status: 404, body: { status: 'error', error: { code: 'NOT_FOUND', message: 'No such agent.' } } });
      await expect(client({ ops: true }).agents.get(AGENT, 'other')).rejects.toBeInstanceOf(NotFoundError);
    });

    it('sessions: start / get / list / end / kill', async () => {
      server.mock('POST', '/v1/sessions', { status: 201, body: env({ sessionId: SESSION, status: 'active', nextSeq: 1 }) });
      server.mock('GET', '/v1/sessions', { status: 200, body: env({ sessions: [] }) });
      server.mock('GET', `/v1/sessions/${SESSION}`, { status: 200, body: env({ sessionId: SESSION }) });
      server.mock('POST', `/v1/sessions/${SESSION}/end`, { status: 200, body: env({ status: 'ended' }) });
      server.mock('POST', `/v1/sessions/${SESSION}/kill`, { status: 200, body: env({ status: 'killed' }) });
      const c = client({ ops: true });
      expect((await c.sessions.start({ tenantId: 't', agentId: AGENT, ttlSeconds: 60 })).data.sessionId).toBe(SESSION);
      await c.sessions.list('t', { agentId: AGENT });
      await c.sessions.get(SESSION, 't');
      await c.sessions.end(SESSION, 't', 'done');
      expect(last().body).toEqual({ tenantId: 't', reason: 'done' });
      expect((await c.sessions.kill(SESSION, 't', 'loop')).data.status).toBe('killed');
    });

    it('the MFA step-up code is supplied by otpProvider and resent once', async () => {
      server.mockSequence('POST', '/v1/sessions', [
        { status: 401, body: { status: 'error', error: { code: 'MFA_REQUIRED', message: 'code needed' } } },
        { status: 201, body: env({ sessionId: SESSION }) },
      ]);
      const res = await client({ ops: true, otp: () => '123456' }).sessions.start({ tenantId: 't', agentId: AGENT });
      expect(res.data.sessionId).toBe(SESSION);
      expect(last().headers['x-qodiqa-otp']).toBe('123456');
    });
  });

  describe('actions (signing key)', () => {
    const req = { agentId: AGENT, sessionId: SESSION, tool: { server: 'srv', name: 'echo' }, args: { text: 'hi' } };

    it('authorize() returns the artifact', async () => {
      server.mock('POST', '/v1/actions/authorize', { status: 200, body: AUTHORIZED });
      const r = await client({ sign: true }).actions.authorize(req);
      expect(isApprovalPending(r)).toBe(false);
      expect((r as ActionAuthorizeResponse).artifact.payload.qodiqa.actionHash).toBe(HASH);
      expect(last().headers['authorization']).toBe(`Bearer ${SIGN_KEY}`);
      expect(last().body).toMatchObject({ agentId: AGENT, tool: { server: 'srv', name: 'echo' }, args: { text: 'hi' } });
    });

    it('authorize() needs the signing key and a well-formed request', async () => {
      await expect(client({ ops: true }).actions.authorize(req)).rejects.toBeInstanceOf(AuthenticationError);
      const c = client({ sign: true });
      await expect(c.actions.authorize({ ...req, agentId: '' })).rejects.toBeInstanceOf(ValidationError);
      await expect(c.actions.authorize({ ...req, args: [] as unknown as Record<string, unknown> })).rejects.toBeInstanceOf(ValidationError);
      await expect(c.actions.authorize({ ...req, tool: { server: '', name: 'x' } })).rejects.toBeInstanceOf(ValidationError);
    });

    it('a 202 is a pending approval, not an error', async () => {
      server.mock('POST', '/v1/actions/authorize', { status: 202, body: PENDING });
      const r = await client({ sign: true }).actions.authorize(req);
      expect(isApprovalPending(r)).toBe(true);
      if (isApprovalPending(r)) expect(r.data.approvalId).toBe(PENDING.data.approvalId);
    });

    it('a refusal is an AuthorizationError that keeps the reason', async () => {
      server.mock('POST', '/v1/actions/authorize', { status: 403, body: { decision: 'BLOCK', reason: 'TOOL_NOT_REGISTERED', details: {}, requestId: 'r' } });
      await expect(client({ sign: true }).actions.authorize(req)).rejects.toMatchObject({ name: 'AuthorizationError', reason: 'TOOL_NOT_REGISTERED' });
      server.mock('POST', '/v1/actions/authorize', { status: 409, body: { decision: 'BLOCK', reason: 'SESSION_AWAITING_APPROVAL', details: {}, requestId: 'r' } });
      await expect(client({ sign: true }).actions.authorize(req)).rejects.toMatchObject({ reason: 'SESSION_AWAITING_APPROVAL' });
    });

    it('authorizeAndWait() waits for the approval and asks again with it', async () => {
      server.mockSequence('POST', '/v1/actions/authorize', [{ status: 202, body: PENDING }, { status: 200, body: AUTHORIZED }]);
      server.mockSequence('GET', `/v1/actions/approvals/${PENDING.data.approvalId}`, [{ status: 200, body: view('PENDING') }, { status: 200, body: view('APPROVED') }]);
      const r = await client({ sign: true }).actions.authorizeAndWait(req, { pollMs: 5, timeoutMs: 2000 });
      expect(r.artifactId).toBe(REQ);
      const posts = server.getCallLog().filter((c) => c.method === 'POST');
      expect(posts[1]!.body).toMatchObject({ approvalId: PENDING.data.approvalId });
    });

    it('authorizeAndWait() surfaces a denial', async () => {
      server.mockSequence('POST', '/v1/actions/authorize', [
        { status: 202, body: PENDING },
        { status: 403, body: { decision: 'BLOCK', reason: 'APPROVAL_DENIED', details: {}, requestId: 'r' } },
      ]);
      server.mock('GET', `/v1/actions/approvals/${PENDING.data.approvalId}`, { status: 200, body: view('DENIED') });
      await expect(client({ sign: true }).actions.authorizeAndWait(req, { pollMs: 5 })).rejects.toBeInstanceOf(AuthorizationError);
    });

    it('waitForApproval() times out while pending', async () => {
      server.mock('GET', `/v1/actions/approvals/${PENDING.data.approvalId}`, { status: 200, body: view('PENDING') });
      await expect(client({ sign: true }).actions.waitForApproval(PENDING.data.approvalId, { timeoutMs: 40, pollMs: 20 })).rejects.toBeInstanceOf(TimeoutError);
    });

    it('getApproval() / cancelApproval() unwrap the view', async () => {
      server.mock('GET', `/v1/actions/approvals/${PENDING.data.approvalId}`, { status: 200, body: view('APPROVED') });
      server.mock('POST', `/v1/actions/approvals/${PENDING.data.approvalId}/cancel`, { status: 200, body: view('CANCELLED') });
      const c = client({ sign: true });
      expect((await c.actions.getApproval(PENDING.data.approvalId)).status).toBe('APPROVED');
      expect((await c.actions.cancelApproval(PENDING.data.approvalId, 'no longer needed')).status).toBe('CANCELLED');
      expect(last().body).toEqual({ reason: 'no longer needed' });
    });

    it('createPlan()', async () => {
      server.mock('POST', '/v1/actions/plans', { status: 201, body: { planId: 'p1', plan: { steps: [] }, requestId: null } });
      const r = await client({ sign: true }).actions.createPlan({ agentId: AGENT, sessionId: SESSION, steps: [{ server: 'srv', name: 'echo', maxCalls: 2 }] });
      expect(r.planId).toBe('p1');
      await expect(client({ sign: true }).actions.createPlan({ agentId: AGENT, sessionId: SESSION, steps: [] })).rejects.toBeInstanceOf(ValidationError);
    });
  });

  describe('tools.call()', () => {
    const call = { artifact: ARTIFACT, tool: { server: 'srv', name: 'echo' }, args: { text: 'hi' } };
    it('returns the screened result of an EXECUTE', async () => {
      server.mock('POST', '/v1/tools/call', { status: 200, body: { decision: 'EXECUTE', result: { isError: false, content: [{ type: 'text', text: 'hi' }], provenance: { untrusted: true }, delimited: '<qodiqa:untrusted-tool-result>hi</qodiqa:untrusted-tool-result>' }, receipt: { v: 1 }, requestId: 'r' } });
      const r = await client({ sign: true }).tools.call(call);
      expect(r.decision).toBe('EXECUTE');
      expect(r.result?.provenance).toEqual({ untrusted: true });
      expect(last().headers['authorization']).toBe(`Bearer ${SIGN_KEY}`);
    });
    it('returns a withheld result as a BLOCK (not an exception)', async () => {
      server.mock('POST', '/v1/tools/call', { status: 200, body: { decision: 'BLOCK', reason: 'TOOL_RESULT_INJECTION_SUSPECTED', details: { findings: [] }, receipt: {}, requestId: 'r' } });
      const r = await client({ sign: true }).tools.call(call);
      expect(r.decision).toBe('BLOCK'); expect(r.reason).toBe('TOOL_RESULT_INJECTION_SUSPECTED'); expect(r.result).toBeUndefined();
    });
    it('throws when the authorisation does not match', async () => {
      server.mock('POST', '/v1/tools/call', { status: 409, body: { decision: 'BLOCK', reason: 'ACTION_MISMATCH', details: {}, requestId: 'r' } });
      await expect(client({ sign: true }).tools.call(call)).rejects.toMatchObject({ reason: 'ACTION_MISMATCH' });
      await expect(client({ sign: true }).tools.call({ ...call, artifact: undefined as never })).rejects.toBeInstanceOf(ValidationError);
    });
    it('a server failure is a ServerError', async () => {
      server.mock('POST', '/v1/tools/call', { status: 502, body: { decision: 'ERROR', reason: 'TOOL_CALL_FAILED', details: { code: 'MCP_TIMEOUT' }, requestId: 'r' } });
      await expect(client({ sign: true }).tools.call(call)).rejects.toMatchObject({ name: 'ServerError', reason: 'TOOL_CALL_FAILED' });
    });
  });

  describe('delegations (signing key)', () => {
    it('issue / verify / get / revoke', async () => {
      server.mock('POST', '/v1/delegations', { status: 201, body: { delegationId: 'd1', delegation: {}, token: {}, chainHash: HASH, requestId: null } });
      server.mock('POST', '/v1/delegations/verify', { status: 200, body: { valid: false, reason: 'DELEGATION_REVOKED', requestId: null } });
      server.mock('GET', '/v1/delegations/d1', { status: 200, body: { delegation: {}, valid: true, requestId: null } });
      server.mock('POST', '/v1/delegations/d1/revoke', { status: 200, body: { revoked: ['d1'], abortedExecutions: 0, agentsRevoked: [], requestId: null } });
      const c = client({ sign: true });
      expect((await c.delegations.issue({ issuerAgentId: AGENT, issuerSessionId: SESSION, subjectAgentId: 'x', classes: ['read'] })).chainHash).toBe(HASH);
      expect((await c.delegations.verify({ delegationId: 'd1' })).valid).toBe(false);
      expect((await c.delegations.get('d1')).valid).toBe(true);
      expect((await c.delegations.revoke('d1', 'compromised', { revokeAgents: true })).revoked).toEqual(['d1']);
      expect(last().body).toEqual({ reason: 'compromised', revokeAgents: true });
      await expect(c.delegations.issue({ issuerAgentId: AGENT, issuerSessionId: SESSION, subjectAgentId: 'x', classes: [] })).rejects.toBeInstanceOf(ValidationError);
    });
  });

  describe('operator side: tool registry, MCP servers, approvals', () => {
    it('use the operator key and the documented paths', async () => {
      const ok = { status: 200, body: env({}) };
      server.mock('POST', '/v1/tool-registry', ok); server.mock('GET', '/v1/tool-registry', ok); server.mock('GET', '/v1/tool-registry/entry', ok);
      server.mock('POST', '/v1/tool-registry/approve', ok); server.mock('POST', '/v1/tool-registry/disable', ok); server.mock('POST', '/v1/tool-registry/policy', ok);
      server.mock('POST', '/v1/mcp/servers', ok); server.mock('GET', '/v1/mcp/servers', ok); server.mock('GET', '/v1/mcp/servers/s1', ok); server.mock('POST', '/v1/mcp/servers/s1/disable', ok);
      server.mock('POST', '/v1/mcp/servers/s1/enable', ok); server.mock('POST', '/v1/mcp/servers/s1/identity', ok); server.mock('POST', '/v1/mcp/servers/s1/tools/refresh', ok);
      server.mock('GET', '/v1/approvals', ok); server.mock('GET', '/v1/approvals/a1', ok); server.mock('POST', '/v1/approvals/a1/decision', ok);
      const c = client({ ops: true });
      await c.toolRegistry.register({ tenantId: 't', server: 'srv', name: 'echo', schema: { type: 'object' }, actionClass: 'read', reversible: true });
      await c.toolRegistry.list('t', { status: 'pending_review' });
      await c.toolRegistry.get('t', 'srv', 'echo');
      await c.toolRegistry.approve('t', 'srv', 'echo', 2);
      await c.toolRegistry.disable('t', 'srv', 'echo');
      await c.toolRegistry.updatePolicy('t', 'srv', 'echo', { policy: { maxCallsPerSession: 3 } });
      await c.mcpServers.register({ tenantId: 't', serverId: 's1', url: 'https://mcp.example.com/mcp', identity: { kind: 'tls-spki-pin', sha256: 'a'.repeat(64) } });
      await c.mcpServers.list('t'); await c.mcpServers.get('s1', 't'); await c.mcpServers.disable('s1', 't', 'audit'); await c.mcpServers.enable('s1', 't');
      await c.mcpServers.rotateIdentity('s1', 't', { kind: 'tls-spki-pin', sha256: 'b'.repeat(64) }); await c.mcpServers.refreshTools('s1', 't');
      await c.approvals.list('t', { status: 'PENDING' }); await c.approvals.get('a1', 't');
      await c.approvals.decide('a1', { tenantId: 't', decision: 'DENY', reason: 'no' });
      expect(last().body).toEqual({ tenantId: 't', decision: 'DENY', reason: 'no' });
      const paths = server.getCallLog().map((x) => `${x.method} ${x.path.split('?')[0]}`);
      expect(paths).toEqual(expect.arrayContaining(['POST /v1/tool-registry/approve', 'GET /v1/tool-registry/entry', 'POST /v1/mcp/servers/s1/tools/refresh', 'POST /v1/approvals/a1/decision']));
      expect(server.getCallLog().every((x) => x.headers['authorization'] === `Bearer ${OPS_KEY}`)).toBe(true);
      await expect(client({ sign: true }).approvals.list('t')).rejects.toBeInstanceOf(AuthenticationError);
    });
  });

  describe('agent proof of possession', () => {
    const ctx = { tenantId: 't1', agentId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sessionId: 'bbbbbbbb-bbbb-4bbb-9bbb-bbbbbbbbbbbb', requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
    it('the digest equals the gateway\'s (computed by src/core/agents/agentAuth.js)', () => {
      expect(AGENT_PROOF_DOMAIN).toBe('QODIQA::AGENT_REQUEST::V1');
      expect(agentProofDigest(ctx).toString('hex')).toBe('397af04cff3064767af39481294859af1cbcd00caaf1622062e6f8be5e3e4600');
    });
    it('a signed proof verifies with the public key, only for this request', () => {
      const kp = generateAgentKeyPair();
      const proof = signAgentProof(ctx, kp.privateKey);
      const pub = crypto.createPublicKey({ key: Buffer.from(kp.publicKey, 'base64'), format: 'der', type: 'spki' });
      expect(crypto.verify(null, agentProofDigest(ctx), pub, Buffer.from(proof, 'base64'))).toBe(true);
      expect(crypto.verify(null, agentProofDigest({ ...ctx, requestId: crypto.randomUUID() }), pub, Buffer.from(proof, 'base64'))).toBe(false);
      const pem = kp.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
      expect(signAgentProof(ctx, pem)).toBe(proof);                                            // Ed25519 is deterministic
      expect(signAgentProof(ctx, kp.privateKey.export({ format: 'der', type: 'pkcs8' }))).toBe(proof);
      expect(() => agentProofDigest({ ...ctx, requestId: '' })).toThrow(ValidationError);
    });
  });
});
