import { BaseResource } from './base.js';
import type { ApiResponse } from '../types.js';
import type { Agent, AgentCreateRequest, AgentUpdateRequest, AgentSession, SessionStartRequest, ActionClass } from '../types.agents.js';
import { assertNonEmpty } from '../utils/validation.js';

/**
 * Agent identities: `/v1/agents` (admin plane - an operator API key; every change needs the operator's MFA step-up, so configure `otpProvider`).
 *
 * The `agentId` is issued by the gateway (a UUID v4); a caller cannot choose it.
 */
export class AgentsResource extends BaseResource {
  /** Create an agent identity. `POST /v1/agents` */
  async create(request: AgentCreateRequest): Promise<ApiResponse<Agent>> {
    assertNonEmpty(request.tenantId, 'request.tenantId');
    assertNonEmpty(request.displayName, 'request.displayName');
    return this.http.post<ApiResponse<Agent>>('/v1/agents', request, { headers: this.auth.getAuthHeader() });
  }

  /** List a tenant's agents. `GET /v1/agents?tenantId=` */
  async list(tenantId: string, params?: { status?: 'active' | 'suspended' | 'revoked' }): Promise<ApiResponse<{ agents: Agent[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get<ApiResponse<{ agents: Agent[] }>>('/v1/agents', { headers: this.auth.getAuthHeader(), query: { tenantId, status: params?.status } });
  }

  /** One agent. `GET /v1/agents/:agentId?tenantId=` (another tenant's agent is a 404). */
  async get(agentId: string, tenantId: string): Promise<ApiResponse<Agent>> {
    assertNonEmpty(agentId, 'agentId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get<ApiResponse<Agent>>(`/v1/agents/${encodeURIComponent(agentId)}`, { headers: this.auth.getAuthHeader(), query: { tenantId } });
  }

  /** Change limits, suspend or revoke (revoked is absorbing; suspending or revoking ends the agent's active sessions and its delegations). `PATCH /v1/agents/:agentId` */
  async update(agentId: string, patch: AgentUpdateRequest): Promise<ApiResponse<Agent>> {
    assertNonEmpty(agentId, 'agentId');
    assertNonEmpty(patch.tenantId, 'patch.tenantId');
    return this.http.patch<ApiResponse<Agent>>(`/v1/agents/${encodeURIComponent(agentId)}`, patch, { headers: this.auth.getAuthHeader() });
  }

  /** Convenience: `update(agentId, { tenantId, status: 'suspended' })`. */
  suspend(agentId: string, tenantId: string): Promise<ApiResponse<Agent>> { return this.update(agentId, { tenantId, status: 'suspended' }); }

  /** Convenience: `update(agentId, { tenantId, status: 'revoked' })` - permanent. */
  revoke(agentId: string, tenantId: string): Promise<ApiResponse<Agent>> { return this.update(agentId, { tenantId, status: 'revoked' }); }
}

/** Agent sessions: `/v1/sessions` (admin plane, like agents). The effective limits are the lowest of the request, the agent's and the platform caps. */
export class SessionsResource extends BaseResource {
  /** Start a session. `POST /v1/sessions` */
  async start(request: SessionStartRequest): Promise<ApiResponse<AgentSession>> {
    assertNonEmpty(request.tenantId, 'request.tenantId');
    assertNonEmpty(request.agentId, 'request.agentId');
    return this.http.post<ApiResponse<AgentSession>>('/v1/sessions', request, { headers: this.auth.getAuthHeader() });
  }

  /** List sessions. `GET /v1/sessions?tenantId=` */
  async list(tenantId: string, params?: { agentId?: string; status?: AgentSession['status'] }): Promise<ApiResponse<{ sessions: AgentSession[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get<ApiResponse<{ sessions: AgentSession[] }>>('/v1/sessions', { headers: this.auth.getAuthHeader(), query: { tenantId, agentId: params?.agentId, status: params?.status } });
  }

  /** One session (expiry applied). `GET /v1/sessions/:sessionId?tenantId=` */
  async get(sessionId: string, tenantId: string): Promise<ApiResponse<AgentSession>> {
    assertNonEmpty(sessionId, 'sessionId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get<ApiResponse<AgentSession>>(`/v1/sessions/${encodeURIComponent(sessionId)}`, { headers: this.auth.getAuthHeader(), query: { tenantId } });
  }

  /** End a session normally. `POST /v1/sessions/:sessionId/end` */
  async end(sessionId: string, tenantId: string, reason?: string): Promise<ApiResponse<AgentSession>> {
    assertNonEmpty(sessionId, 'sessionId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.post<ApiResponse<AgentSession>>(`/v1/sessions/${encodeURIComponent(sessionId)}/end`, { tenantId, ...(reason ? { reason } : {}) }, { headers: this.auth.getAuthHeader() });
  }

  /** Force-stop a session: what runs under it is aborted at once. `POST /v1/sessions/:sessionId/kill` */
  async kill(sessionId: string, tenantId: string, reason?: string): Promise<ApiResponse<AgentSession>> {
    assertNonEmpty(sessionId, 'sessionId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.post<ApiResponse<AgentSession>>(`/v1/sessions/${encodeURIComponent(sessionId)}/kill`, { tenantId, ...(reason ? { reason } : {}) }, { headers: this.auth.getAuthHeader() });
  }
}

export type { ActionClass };
