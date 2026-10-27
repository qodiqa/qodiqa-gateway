import { resolveConfig, validateConfig } from './config.js';
import type { QodiqaClientConfig } from './config.js';
import { HttpClient } from './http.js';
import { AuthProvider } from './auth.js';

import { SignResource } from './resources/sign.js';
import { ChatResource } from './resources/chat.js';
import { VerifyResource } from './resources/verify.js';
import { PortalResource } from './resources/portal.js';
import { AttestationResource } from './resources/attestation.js';
import { TransparencyResource } from './resources/transparency.js';
import { EvidenceResource } from './resources/evidence.js';
import { CertificationResource } from './resources/certification.js';
import { WebhooksResource } from './resources/webhooks.js';
import { SimulationResource } from './resources/simulation.js';
import { AgentsResource, SessionsResource } from './resources/agents.js';
import { ActionsResource, ToolsResource, DelegationsResource } from './resources/actions.js';
import { ToolRegistryResource, McpServersResource, ApprovalsResource } from './resources/governance.js';
import { OperationsResource, type OperationsClient } from './resources/operations.js';

import type {
  HealthResponse,
  ReadyResponse,
  KeysResponse,
  PublicKey,
  AuditResponse,
  ApiResponse,
} from './types.js';

import { assertNonEmpty } from './utils/validation.js';

export class QodiqaClient {
  // ---------------------------------------------------------------------------
  // Resource accessors
  // ---------------------------------------------------------------------------

  /** Sign resource: POST /sign */
  readonly sign: SignResource;

  /** Chat resource: POST /ai/chat */
  readonly chat: ChatResource;

  /** Verify resource: POST /verify, POST /verify/v2 */
  readonly verify: VerifyResource;

  /** Portal resource: /v1/portal/* */
  readonly portal: PortalResource;

  /** Attestation resource: /v1/attestation/* */
  readonly attestation: AttestationResource;

  /** Transparency log resource: /v1/transparency/* */
  readonly transparency: TransparencyResource;

  /** Evidence resource: /v1/attestation/:id/evidence */
  readonly evidence: EvidenceResource;

  /** Certification resource: /v1/certification/* */
  readonly certification: CertificationResource;

  /** Webhooks resource: /v1/webhooks/* */
  readonly webhooks: WebhooksResource;

  /** Policy Simulation resource: /v1/policy/* */
  readonly simulation: SimulationResource;

  /** Agent identities: /v1/agents (operator key + MFA step-up) */
  readonly agents: AgentsResource;

  /** Agent sessions: /v1/sessions (operator key + MFA step-up) */
  readonly sessions: SessionsResource;

  /** Per-action authorisation of an agent: /v1/actions/* (signing key) */
  readonly actions: ActionsResource;

  /** The tool gateway: POST /v1/tools/call (signing key) */
  readonly tools: ToolsResource;

  /** Delegation of authority between agents: /v1/delegations (signing key) */
  readonly delegations: DelegationsResource;

  /** The tool registry: /v1/tool-registry (operator key + MFA step-up) */
  readonly toolRegistry: ToolRegistryResource;

  /** MCP servers the gateway may call: /v1/mcp/servers (operator key + MFA step-up) */
  readonly mcpServers: McpServersResource;

  /** Human approval of agent actions, the operator's side: /v1/approvals (operator key + MFA step-up) */
  readonly approvals: ApprovalsResource;

  /** Every documented operation of the HTTP contract, generated: `client.operations.<operationId>(args)` */
  readonly operations: OperationsClient;

  // ---------------------------------------------------------------------------
  // Internals (accessible via protected/private if subclassed)
  // ---------------------------------------------------------------------------

  private readonly http: HttpClient;
  private readonly auth: AuthProvider;

  // ---------------------------------------------------------------------------
  // Constructor
  // ---------------------------------------------------------------------------

  constructor(config: QodiqaClientConfig = {}) {
    const resolved = resolveConfig(config);
    validateConfig(resolved);

    this.http = new HttpClient(resolved);
    this.auth = new AuthProvider(resolved);

    this.sign = new SignResource(this.http, this.auth);
    this.chat = new ChatResource(this.http, this.auth);
    this.verify = new VerifyResource(this.http, this.auth);
    this.portal = new PortalResource(this.http, this.auth);
    this.attestation = new AttestationResource(this.http, this.auth);
    this.transparency = new TransparencyResource(this.http, this.auth);
    this.evidence = new EvidenceResource(this.http, this.auth);
    this.certification = new CertificationResource(this.http, this.auth);
    this.webhooks = new WebhooksResource(this.http, this.auth);
    this.simulation = new SimulationResource(this.http, this.auth);
    this.agents = new AgentsResource(this.http, this.auth);
    this.sessions = new SessionsResource(this.http, this.auth);
    this.actions = new ActionsResource(this.http, this.auth);
    this.tools = new ToolsResource(this.http, this.auth);
    this.delegations = new DelegationsResource(this.http, this.auth);
    this.toolRegistry = new ToolRegistryResource(this.http, this.auth);
    this.mcpServers = new McpServersResource(this.http, this.auth);
    this.approvals = new ApprovalsResource(this.http, this.auth);
    this.operations = new OperationsResource(this.http, this.auth) as OperationsClient;
  }

  // ---------------------------------------------------------------------------
  // Convenience methods
  // ---------------------------------------------------------------------------

  /**
   * Liveness probe. `GET /health`
   */
  async healthCheck(): Promise<HealthResponse> {
    return this.http.get<HealthResponse>('/health');
  }

  /**
   * Readiness probe. `GET /ready`
   */
  async readinessCheck(): Promise<ReadyResponse> {
    return this.http.get<ReadyResponse>('/ready');
  }

  /**
   * Get all active public signing keys. `GET /public-keys`
   *
   * The server wraps this in the standard `{status,timestamp,requestId,data}`
   * envelope — unwrapped here so callers can use `keys.keys` directly, as
   * documented.
   */
  async getPublicKeys(): Promise<KeysResponse> {
    const res = await this.http.get<ApiResponse<KeysResponse>>('/public-keys');
    return res.data;
  }

  /**
   * Get a single public key by ID.
   *
   * Tries the well-known discovery endpoint first:
   * `GET /.well-known/qodiqa/keys/:keyId`
   */
  async getPublicKey(keyId: string): Promise<PublicKey> {
    assertNonEmpty(keyId, 'keyId');
    return this.http.get<PublicKey>(
      `/.well-known/qodiqa/keys/${encodeURIComponent(keyId)}`,
    );
  }

  /**
   * Retrieve the full audit chain for an artifact. `GET /audit/:artifactId`
   *
   * Requires an ops API key — this route is mounted behind
   * `adminStack('READ_AUDIT')` server-side (`src/app.js`).
   */
  async getAuditChain(artifactId: string): Promise<ApiResponse<AuditResponse>> {
    // the route replies with the standard success envelope (src/api/routes/audit.js success()).
    assertNonEmpty(artifactId, 'artifactId');
    const headers = this.auth.getAuthHeader();
    return this.http.get<ApiResponse<AuditResponse>>(
      `/audit/${encodeURIComponent(artifactId)}`,
      { headers },
    );
  }
}
