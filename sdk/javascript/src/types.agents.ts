// ---------------------------------------------------------------------------
// Agents, actions, tools, delegation, approvals
//
// Shapes follow docs/api/openapi.json (AgentIdentity, AgentSession, ToolVersion, ActionAuthorizeRequest/Response, ActionPlan, Delegation, DelegationToken, McpServer,
// ToolCallRequest/Response, ApprovalRequest). Management endpoints (agents, sessions, tool registry, MCP servers, approvals) answer the standard
// `{status,timestamp,requestId,data}` envelope (`ApiResponse<T>`); the signing-key endpoints (actions, tools, delegations) answer their own bodies.
// ---------------------------------------------------------------------------

export type ActionClass = 'read' | 'write' | 'file' | 'database' | 'external_api' | 'command' | 'communication' | 'financial' | 'delegate';

export interface Agent {
  tenantId: string;
  agentId: string;
  displayName: string;
  status: 'active' | 'suspended' | 'revoked';
  ownerUserId: string | null;
  publicKey: string | null;
  allowedActionClasses: ActionClass[];
  maxActionsPerSession: number | null;
  maxSessionSeconds: number | null;
  costBudgetMicros: number | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  revokedAt: string | null;
}

export interface AgentCreateRequest {
  tenantId: string;
  displayName: string;
  ownerUserId?: string;
  /** Base64 SPKI Ed25519 public key. When set, every request of the agent must carry a proof of possession (see `signAgentProof`). */
  publicKey?: string;
  allowedActionClasses?: ActionClass[];
  maxActionsPerSession?: number;
  maxSessionSeconds?: number;
  costBudgetMicros?: number;
}

export interface AgentUpdateRequest {
  tenantId: string;
  displayName?: string;
  status?: 'active' | 'suspended' | 'revoked';
  ownerUserId?: string | null;
  publicKey?: string | null;
  allowedActionClasses?: ActionClass[];
  maxActionsPerSession?: number | null;
  maxSessionSeconds?: number | null;
  costBudgetMicros?: number | null;
}

export interface AgentSession {
  tenantId: string;
  sessionId: string;
  agentId: string;
  status: 'active' | 'ended' | 'expired' | 'killed';
  startedAt: string;
  expiresAt: string;
  endedAt: string | null;
  endedReason: string | null;
  maxActions: number;
  actionsUsed: number;
  costBudgetMicros: number | null;
  costUsedMicros: number;
  nextSeq: number;
  lastActionHash: string | null;
  createdBy: string;
}

export interface SessionStartRequest {
  tenantId: string;
  agentId: string;
  ttlSeconds?: number;
  maxActions?: number;
  costBudgetMicros?: number;
}

export interface ToolRef { server: string; name: string }

export interface ToolVersion {
  tenantId: string;
  server: string;
  name: string;
  version: number;
  status: 'active' | 'pending_review' | 'superseded' | 'disabled';
  schema: Record<string, unknown>;
  schemaHash: string;
  actionClass: ActionClass;
  reversible: boolean;
  requiresApproval: boolean;
  policy: Record<string, unknown>;
  description: string | null;
  createdBy: string;
  createdAt: string;
  approvedBy: string | null;
  approvedAt: string | null;
}

export interface ToolRegisterRequest {
  tenantId: string;
  server: string;
  name: string;
  schema: Record<string, unknown>;
  actionClass: ActionClass;
  reversible: boolean;
  requiresApproval?: boolean;
  policy?: { maxCallsPerSession?: number; constraints?: Array<{ arg: string; kind: 'path_prefix' | 'url_host' | 'sql_operations' | 'command_allowlist'; values: string[] }> };
  description?: string;
}

export interface McpServer {
  tenantId: string;
  serverId: string;
  url: string;
  transport: 'streamable-http';
  identity: { kind: 'tls-spki-pin'; sha256: string; trust: 'ca-and-pin' | 'pin-only' } | { kind: 'none' };
  configHash: string;
  status: 'active' | 'disabled';
  localDestination: boolean;
  description: string | null;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  disabledAt: string | null;
  disabledReason: string | null;
  disabledBy: string | null;
  lastRefreshAt: string | null;
  lastRefreshTools: number | null;
  lastError: string | null;
}

export interface McpServerRegisterRequest {
  tenantId: string;
  serverId: string;
  url: string;
  /** Required for https servers: the SHA-256 (hex) of the certificate's public key (DER SubjectPublicKeyInfo). */
  identity?: { kind: 'tls-spki-pin'; sha256: string; trust?: 'ca-and-pin' | 'pin-only' };
  description?: string;
}

export interface McpToolsRefreshResult {
  serverId: string;
  discovered: number;
  NEW: Array<{ name: string; version?: number; status?: string; schemaHash?: string }>;
  MODIFIED: Array<{ name: string; version?: number; status?: string; schemaHash?: string }>;
  UNCHANGED: Array<{ name: string }>;
  SKIPPED: Array<{ name: string | null; reason: string }>;
}

/** The action artifact: `{ expiry, payload{ requestId, tenantId, qodiqa{ v:2, kind:'action', agentId, sessionId, seq, actionHash, approvalRef? } }, publicKeyId, signature, timestamp }`. */
export interface ActionArtifact {
  expiry: number;
  timestamp: number;
  publicKeyId: string;
  signature: string;
  payload: {
    requestId: string;
    tenantId: string;
    qodiqa: { v: 2; kind: 'action'; bind: { headers: string[] }; agentId: string; sessionId: string; seq: number; actionHash: string; approvalRef?: string };
  };
}

export interface ActionAuthorizeRequest {
  agentId: string;
  sessionId: string;
  tool: ToolRef;
  args: Record<string, unknown>;
  parentRequestHash?: string | null;
  /** Echoed into the artifact's requestId and the agent proof (UUID v4). Generated by the gateway when omitted. */
  requestId?: string;
  /** Ed25519 proof of possession, required when the agent has a registered key (see `signAgentProof`). */
  proof?: string;
  /** Artifact lifetime in ms, 1000-60000 (default 30000). */
  ttl?: number;
  planId?: string;
  delegationId?: string;
  /** The approval that answers an earlier 202 for exactly this action. */
  approvalId?: string;
}

export interface ActionAuthorizeResponse {
  artifactId: string;
  artifact: ActionArtifact;
  action: { actionHash: string; seq: number; prevActionHash: string | null; tool: ToolRef & { schemaHash: string; version: number }; parentRequestHash: string | null };
  meta: Record<string, unknown>;
  requestId: string | null;
}

/** HTTP 202 from `actions.authorize()`: the tool requires a human approval; poll `approvalId`, then call again with it. */
export interface ActionApprovalPending {
  status: 'pending';
  timestamp: string;
  requestId: string | null;
  data: { approvalId: string; actionHash: string; seq: number; expiresAt: string };
}

export interface ActionPlanStep { server: string; name: string; maxCalls: number }

export interface ActionPlan {
  tenantId: string;
  planId: string;
  sessionId: string;
  agentId: string;
  steps: ActionPlanStep[];
  used: number[];
  planHash: string;
  status: 'active' | 'closed';
  createdBy: string;
  createdAt: string;
  expiresAt: string;
  closedAt: string | null;
}

export interface ActionPlanRequest {
  agentId: string;
  sessionId: string;
  steps: ActionPlanStep[];
  ttlSeconds?: number;
  requestId?: string;
  proof?: string;
}

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'CANCELLED';

/** The requester's view of its own approval request (`GET /v1/actions/approvals/:id`). */
export interface ApprovalRequesterView {
  approvalId: string;
  status: ApprovalStatus;
  actionHash: string;
  seq: number;
  tool: ToolRef & { schemaHash?: string };
  agentId: string;
  sessionId: string;
  requestedAt: string;
  expiresAt: string;
  approverId: string | null;
  decidedAt: string | null;
  decisionReason: string | null;
  notBefore: string | null;
  approvalExpiresAt: string | null;
  usedAt: string | null;
  cancelledAt: string | null;
}

/** The operator's view: the same request WITH the exact arguments and the signed statement. */
export interface ApprovalRequest extends ApprovalRequesterView {
  tenantId: string;
  prevActionHash: string | null;
  actionClass: ActionClass;
  args: Record<string, unknown>;
  parentRequestHash: string | null;
  planId: string | null;
  delegationId: string | null;
  requesterId: string;
  requesterUserId: string | null;
  policyRuleId: string;
  decisionToken: Record<string, unknown> | null;
  mfa: string | null;
  usedRequestId: string | null;
  cancelledBy: string | null;
  expiredAt: string | null;
}

export interface ApprovalDecisionRequest {
  tenantId: string;
  decision: 'APPROVE' | 'DENY';
  /** Required to deny. */
  reason?: string;
  /** How long the approval can be spent, 1-3600 s (default 600). */
  ttlSeconds?: number;
  notBefore?: string;
}

export interface ToolCallRequest {
  artifact: ActionArtifact;
  tool: ToolRef;
  args: Record<string, unknown>;
  parentRequestHash?: string | null;
}

export interface ToolCallResponse {
  decision: 'EXECUTE' | 'BLOCK' | 'ERROR';
  /** Present when `decision` is `EXECUTE`. The content is UNTRUSTED DATA: place `delimited` between instructions and data, never into the instruction part of a prompt. */
  result?: {
    isError: boolean;
    content: Array<Record<string, unknown>>;
    provenance: Record<string, unknown>;
    delimited: string;
  };
  receipt?: Record<string, unknown>;
  reason?: string;
  details?: Record<string, unknown>;
  audit?: string;
  requestId: string | null;
}

export interface DelegationToken {
  expiry: number;
  timestamp: number;
  publicKeyId: string;
  signature: string;
  payload: Record<string, unknown>;
}

export interface Delegation {
  tenantId: string;
  delegationId: string;
  parentId: string | null;
  rootAgentId: string;
  issuerAgentId: string;
  subjectAgentId: string;
  depth: number;
  maxDepth: number;
  classes: ActionClass[];
  tools: ToolRef[] | null;
  maxActions: number | null;
  actionsUsed: number;
  status: 'active' | 'revoked';
  tokenDigest: string;
  issuedAt: string;
  expiresAt: string;
  createdBy: string;
  revokedAt: string | null;
  revokedReason: string | null;
  revokedBy: string | null;
  token: DelegationToken;
}

export interface DelegationIssueRequest {
  issuerAgentId: string;
  issuerSessionId: string;
  subjectAgentId: string;
  classes: ActionClass[];
  parentId?: string;
  tools?: ToolRef[];
  maxActions?: number;
  ttlSeconds?: number;
  /** Root grants only, 1-8 (default 3). */
  maxDepth?: number;
  requestId?: string;
  proof?: string;
}

export interface DelegationIssueResponse {
  delegationId: string;
  delegation: Delegation;
  token: DelegationToken;
  chainHash: string;
  requestId: string | null;
}

export interface DelegationVerifyResponse {
  valid: boolean;
  reason?: string;
  detail?: string;
  index?: number;
  state?: 'ACTIVE' | 'UNKNOWN';
  depth?: number;
  chainHash?: string;
  rootAgentId?: string;
  subjectAgentId?: string;
  classes?: ActionClass[];
  requestId: string | null;
  [key: string]: unknown;
}
