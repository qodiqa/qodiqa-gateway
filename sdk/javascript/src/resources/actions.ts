import { BaseResource } from './base.js';
import type {
  ActionAuthorizeRequest, ActionAuthorizeResponse, ActionApprovalPending, ActionPlan, ActionPlanRequest, ApprovalRequesterView, ApprovalStatus,
  ToolCallRequest, ToolCallResponse, Delegation, DelegationIssueRequest, DelegationIssueResponse, DelegationToken, DelegationVerifyResponse,
} from '../types.agents.js';
import { assertNonEmpty } from '../utils/validation.js';
import { ValidationError, TimeoutError } from '../errors.js';

/** True when `authorize()` answered 202: the tool needs a human approval before an artifact is issued. */
export function isApprovalPending(r: ActionAuthorizeResponse | ActionApprovalPending): r is ActionApprovalPending {
  return (r as ActionApprovalPending).status === 'pending';
}

/**
 * Per-action authorisation of an agent: `/v1/actions/*`. Authenticated with a signing key (`signToken`, like `sign.sign()`), tenant-scoped.
 *
 * Refusals are thrown (`AuthorizationError` with `.reason`, e.g. `TOOL_NOT_REGISTERED`, `ACTION_ARGS_INVALID`, `AGENT_SESSION_ENDED`, `ACTION_POLICY_DENIED`, `DELEGATION_REVOKED`,
 * `SESSION_AWAITING_APPROVAL`, `APPROVAL_DENIED` ...); a tool that requires approval returns a pending object instead - see `isApprovalPending`.
 */
export class ActionsResource extends BaseResource {
  /**
   * Ask permission for ONE action. `POST /v1/actions/authorize`
   *
   * Returns the action artifact (valid for at most 60 s; it authorises exactly this tool call with exactly these arguments) or, for a tool that needs approval, a pending
   * object whose `data.approvalId` you poll (`getApproval` / `waitForApproval`) and then pass back as `approvalId` with the SAME action.
   */
  async authorize(request: ActionAuthorizeRequest): Promise<ActionAuthorizeResponse | ActionApprovalPending> {
    assertNonEmpty(request.agentId, 'request.agentId');
    assertNonEmpty(request.sessionId, 'request.sessionId');
    assertNonEmpty(request.tool?.server, 'request.tool.server');
    assertNonEmpty(request.tool?.name, 'request.tool.name');
    if (request.args === null || typeof request.args !== 'object' || Array.isArray(request.args)) throw new ValidationError('"request.args" must be a JSON object.');
    return this.http.post<ActionAuthorizeResponse | ActionApprovalPending>('/v1/actions/authorize', request, { headers: this.auth.getSignTokenHeader() });
  }

  /**
   * `authorize()` for callers that want the artifact or an exception: a pending approval is waited for (polling `getApproval`), then the SAME action is authorised again with
   * the approval. Throws `TimeoutError` when the decision does not come in time, `AuthorizationError` (`APPROVAL_DENIED` / `APPROVAL_EXPIRED` / `APPROVAL_CANCELLED`) when it is refused.
   */
  async authorizeAndWait(request: ActionAuthorizeRequest, options: { timeoutMs?: number; pollMs?: number } = {}): Promise<ActionAuthorizeResponse> {
    const first = await this.authorize(request);
    if (!isApprovalPending(first)) return first;
    const status = await this.waitForApproval(first.data.approvalId, options);
    void status;
    const again = await this.authorize({ ...request, approvalId: first.data.approvalId });
    if (isApprovalPending(again)) throw new TimeoutError('The approval is still pending.');
    return again;
  }

  /** Authorise the execution plan of a session (steps = tool + maximum calls). `POST /v1/actions/plans` */
  async createPlan(request: ActionPlanRequest): Promise<{ planId: string; plan: ActionPlan; requestId: string | null }> {
    assertNonEmpty(request.agentId, 'request.agentId');
    assertNonEmpty(request.sessionId, 'request.sessionId');
    if (!Array.isArray(request.steps) || request.steps.length === 0) throw new ValidationError('"request.steps" must be a non-empty array.');
    return this.http.post('/v1/actions/plans', request, { headers: this.auth.getSignTokenHeader() });
  }

  /** The requester's view of its approval request. `GET /v1/actions/approvals/:approvalId` (only the identity that asked sees it). */
  async getApproval(approvalId: string): Promise<ApprovalRequesterView> {
    assertNonEmpty(approvalId, 'approvalId');
    const res = await this.http.get<{ data: ApprovalRequesterView }>(`/v1/actions/approvals/${encodeURIComponent(approvalId)}`, { headers: this.auth.getSignTokenHeader() });
    return res.data;
  }

  /** Withdraw an approval request (while pending, or approved and not yet spent). `POST /v1/actions/approvals/:approvalId/cancel` */
  async cancelApproval(approvalId: string, reason?: string): Promise<ApprovalRequesterView> {
    assertNonEmpty(approvalId, 'approvalId');
    const res = await this.http.post<{ data: ApprovalRequesterView }>(`/v1/actions/approvals/${encodeURIComponent(approvalId)}/cancel`, reason ? { reason } : {}, { headers: this.auth.getSignTokenHeader() });
    return res.data;
  }

  /** Poll until the request is no longer PENDING; returns its final view. Throws `TimeoutError` after `timeoutMs` (default 10 min). */
  async waitForApproval(approvalId: string, { timeoutMs = 600_000, pollMs = 2000 }: { timeoutMs?: number; pollMs?: number } = {}): Promise<ApprovalRequesterView> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const v = await this.getApproval(approvalId);
      if (v.status !== ('PENDING' as ApprovalStatus)) return v;
      if (Date.now() + pollMs > deadline) throw new TimeoutError(`The approval ${approvalId} is still pending after ${timeoutMs} ms.`);
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }
}

/** The tool gateway: `POST /v1/tools/call`. Authenticated with a signing key. */
export class ToolsResource extends BaseResource {
  /**
   * Run ONE authorised action against a registered MCP server and get the screened result.
   *
   * `decision: 'EXECUTE'` carries `result` - treat it as UNTRUSTED DATA (use `result.delimited` between instructions and data) - and a `receipt`. `decision: 'BLOCK'`
   * means the tool ran but its result was withheld (`reason`, `details.findings`). Refusals before the call (mismatch, replay, revoked ...) and server failures are thrown.
   */
  async call(request: ToolCallRequest): Promise<ToolCallResponse> {
    if (!request.artifact || typeof request.artifact !== 'object') throw new ValidationError('"request.artifact" must be the action artifact returned by actions.authorize().');
    assertNonEmpty(request.tool?.server, 'request.tool.server');
    assertNonEmpty(request.tool?.name, 'request.tool.name');
    if (request.args === null || typeof request.args !== 'object' || Array.isArray(request.args)) throw new ValidationError('"request.args" must be a JSON object.');
    return this.http.post<ToolCallResponse>('/v1/tools/call', request, { headers: this.auth.getSignTokenHeader() });
  }
}

/** Delegation of authority between agents: `/v1/delegations`. Authenticated with a signing key. */
export class DelegationsResource extends BaseResource {
  /** Issue a delegation (root grant, or a narrower child of one the issuer holds). `POST /v1/delegations` */
  async issue(request: DelegationIssueRequest): Promise<DelegationIssueResponse> {
    assertNonEmpty(request.issuerAgentId, 'request.issuerAgentId');
    assertNonEmpty(request.issuerSessionId, 'request.issuerSessionId');
    assertNonEmpty(request.subjectAgentId, 'request.subjectAgentId');
    if (!Array.isArray(request.classes) || request.classes.length === 0) throw new ValidationError('"request.classes" must be a non-empty array.');
    return this.http.post<DelegationIssueResponse>('/v1/delegations', request, { headers: this.auth.getSignTokenHeader() });
  }

  /** Verify a chain offline-style (`{ chain: [tokens, root first] }`) or a stored delegation (`{ delegationId }`). `POST /v1/delegations/verify` - `valid:false` is a normal answer. */
  async verify(input: { chain: DelegationToken[] } | { delegationId: string }): Promise<DelegationVerifyResponse> {
    return this.http.post<DelegationVerifyResponse>('/v1/delegations/verify', input, { headers: this.auth.getSignTokenHeader() });
  }

  /** One delegation with its chain of tokens. `GET /v1/delegations/:delegationId` */
  async get(delegationId: string): Promise<{ delegation: Delegation; chain?: DelegationToken[]; valid: boolean; reason?: string; requestId: string | null }> {
    assertNonEmpty(delegationId, 'delegationId');
    return this.http.get(`/v1/delegations/${encodeURIComponent(delegationId)}`, { headers: this.auth.getSignTokenHeader() });
  }

  /** Revoke a delegation and everything below it. `POST /v1/delegations/:delegationId/revoke` */
  async revoke(delegationId: string, reason: string, options: { revokeAgents?: boolean } = {}): Promise<{ revoked: string[]; abortedExecutions: number; agentsRevoked: string[]; requestId: string | null }> {
    assertNonEmpty(delegationId, 'delegationId');
    assertNonEmpty(reason, 'reason');
    return this.http.post(`/v1/delegations/${encodeURIComponent(delegationId)}/revoke`, { reason, ...(options.revokeAgents ? { revokeAgents: true } : {}) }, { headers: this.auth.getSignTokenHeader() });
  }
}
