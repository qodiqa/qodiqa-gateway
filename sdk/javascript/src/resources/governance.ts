import { BaseResource } from './base.js';
import type { ApiResponse } from '../types.js';
import type {
  ToolVersion, ToolRegisterRequest, McpServer, McpServerRegisterRequest, McpToolsRefreshResult, ApprovalRequest, ApprovalDecisionRequest, ApprovalStatus,
} from '../types.agents.js';
import { assertNonEmpty } from '../utils/validation.js';

/**
 * The tool registry: `/v1/tool-registry` (admin plane: operator API key + MFA step-up on every change). A tool is `(server, name)`; a changed definition is a NEW version in
 * `pending_review` that someone other than the registrant must approve.
 */
export class ToolRegistryResource extends BaseResource {
  /** Register a tool version. `POST /v1/tool-registry` */
  async register(request: ToolRegisterRequest): Promise<ApiResponse<{ change: 'NEW' | 'MODIFIED'; tool: ToolVersion }>> {
    assertNonEmpty(request.tenantId, 'request.tenantId');
    assertNonEmpty(request.server, 'request.server');
    assertNonEmpty(request.name, 'request.name');
    return this.http.post('/v1/tool-registry', request, { headers: this.auth.getAuthHeader() });
  }

  /** Every version of a tenant's tools. `GET /v1/tool-registry?tenantId=` */
  async list(tenantId: string, params?: { status?: ToolVersion['status'] }): Promise<ApiResponse<{ tools: ToolVersion[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get('/v1/tool-registry', { headers: this.auth.getAuthHeader(), query: { tenantId, status: params?.status } });
  }

  /** One tool with its versions. `GET /v1/tool-registry/entry?tenantId=&server=&name=` */
  async get(tenantId: string, server: string, name: string): Promise<ApiResponse<{ server: string; name: string; active: ToolVersion | null; versions: ToolVersion[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    assertNonEmpty(server, 'server');
    assertNonEmpty(name, 'name');
    return this.http.get('/v1/tool-registry/entry', { headers: this.auth.getAuthHeader(), query: { tenantId, server, name } });
  }

  /** Activate a pending version. `POST /v1/tool-registry/approve` */
  async approve(tenantId: string, server: string, name: string, version: number): Promise<ApiResponse<ToolVersion>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.post('/v1/tool-registry/approve', { tenantId, server, name, version }, { headers: this.auth.getAuthHeader() });
  }

  /** Disable the active version (calls through it are refused and the ones running are aborted). `POST /v1/tool-registry/disable` */
  async disable(tenantId: string, server: string, name: string): Promise<ApiResponse<{ disabled: number; abortedExecutions: number }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.post('/v1/tool-registry/disable', { tenantId, server, name }, { headers: this.auth.getAuthHeader() });
  }

  /** Change the policy (constraints, maxCallsPerSession) or `requiresApproval` of the active version. `POST /v1/tool-registry/policy` */
  async updatePolicy(tenantId: string, server: string, name: string, patch: { policy?: ToolRegisterRequest['policy']; requiresApproval?: boolean }): Promise<ApiResponse<ToolVersion>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.post('/v1/tool-registry/policy', { tenantId, server, name, ...patch }, { headers: this.auth.getAuthHeader() });
  }
}

/** MCP servers the gateway may call: `/v1/mcp/servers` (admin plane: operator API key + MFA step-up on every change). */
export class McpServersResource extends BaseResource {
  /** Register a server (https + pinned identity; http/local only where the operator allows it). `POST /v1/mcp/servers` */
  async register(request: McpServerRegisterRequest): Promise<ApiResponse<McpServer>> {
    assertNonEmpty(request.tenantId, 'request.tenantId');
    assertNonEmpty(request.serverId, 'request.serverId');
    assertNonEmpty(request.url, 'request.url');
    return this.http.post('/v1/mcp/servers', request, { headers: this.auth.getAuthHeader() });
  }

  async list(tenantId: string, params?: { status?: 'active' | 'disabled' }): Promise<ApiResponse<{ servers: McpServer[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get('/v1/mcp/servers', { headers: this.auth.getAuthHeader(), query: { tenantId, status: params?.status } });
  }

  async get(serverId: string, tenantId: string): Promise<ApiResponse<McpServer>> {
    assertNonEmpty(serverId, 'serverId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get(`/v1/mcp/servers/${encodeURIComponent(serverId)}`, { headers: this.auth.getAuthHeader(), query: { tenantId } });
  }

  /** Disable (the next call is refused everywhere; running ones are aborted). A reason is required. */
  async disable(serverId: string, tenantId: string, reason: string): Promise<ApiResponse<McpServer>> {
    assertNonEmpty(serverId, 'serverId');
    assertNonEmpty(reason, 'reason');
    return this.http.post(`/v1/mcp/servers/${encodeURIComponent(serverId)}/disable`, { tenantId, reason }, { headers: this.auth.getAuthHeader() });
  }

  async enable(serverId: string, tenantId: string): Promise<ApiResponse<McpServer>> {
    assertNonEmpty(serverId, 'serverId');
    return this.http.post(`/v1/mcp/servers/${encodeURIComponent(serverId)}/enable`, { tenantId }, { headers: this.auth.getAuthHeader() });
  }

  /** Rotate the pinned identity (the URL never changes). */
  async rotateIdentity(serverId: string, tenantId: string, identity: NonNullable<McpServerRegisterRequest['identity']>): Promise<ApiResponse<McpServer>> {
    assertNonEmpty(serverId, 'serverId');
    return this.http.post(`/v1/mcp/servers/${encodeURIComponent(serverId)}/identity`, { tenantId, identity }, { headers: this.auth.getAuthHeader() });
  }

  /** Ask the server for its tools and register what it offers as PROPOSALS (pending_review) in the tool registry. */
  async refreshTools(serverId: string, tenantId: string): Promise<ApiResponse<McpToolsRefreshResult>> {
    assertNonEmpty(serverId, 'serverId');
    return this.http.post(`/v1/mcp/servers/${encodeURIComponent(serverId)}/tools/refresh`, { tenantId }, { headers: this.auth.getAuthHeader() });
  }
}

/** Human approval of agent actions, the operator's side: `/v1/approvals` (operator API key; the decision needs the MFA step-up code - configure `otpProvider`). */
export class ApprovalsResource extends BaseResource {
  async list(tenantId: string, params?: { status?: ApprovalStatus; agentId?: string }): Promise<ApiResponse<{ approvals: ApprovalRequest[] }>> {
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get('/v1/approvals', { headers: this.auth.getAuthHeader(), query: { tenantId, status: params?.status, agentId: params?.agentId } });
  }

  /** One request WITH the exact tool and arguments the approver is asked to approve. */
  async get(approvalId: string, tenantId: string): Promise<ApiResponse<ApprovalRequest>> {
    assertNonEmpty(approvalId, 'approvalId');
    assertNonEmpty(tenantId, 'tenantId');
    return this.http.get(`/v1/approvals/${encodeURIComponent(approvalId)}`, { headers: this.auth.getAuthHeader(), query: { tenantId } });
  }

  /** Approve or deny. The approver is never the requester (`APPROVAL_NOT_INDEPENDENT`). The result carries the signed statement (`decisionToken`). */
  async decide(approvalId: string, request: ApprovalDecisionRequest): Promise<ApiResponse<ApprovalRequest>> {
    assertNonEmpty(approvalId, 'approvalId');
    assertNonEmpty(request.tenantId, 'request.tenantId');
    return this.http.post(`/v1/approvals/${encodeURIComponent(approvalId)}/decision`, request, { headers: this.auth.getAuthHeader() });
  }
}
