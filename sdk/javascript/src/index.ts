// ---------------------------------------------------------------------------
// Main client
// ---------------------------------------------------------------------------
export { QodiqaClient } from './client.js';
export type { QodiqaClientConfig } from './config.js';

// ---------------------------------------------------------------------------
// Resource classes
// ---------------------------------------------------------------------------
export { SignResource } from './resources/sign.js';
export { ChatResource } from './resources/chat.js';
export type { ChatCreateOptions, ChatStreamOptions } from './resources/chat.js';
export { VerifyResource } from './resources/verify.js';
export { PortalResource } from './resources/portal.js';
export { AttestationResource } from './resources/attestation.js';
export { TransparencyResource } from './resources/transparency.js';
export { EvidenceResource } from './resources/evidence.js';
export { CertificationResource } from './resources/certification.js';
export { WebhooksResource } from './resources/webhooks.js';
export { SimulationResource } from './resources/simulation.js';
export { AgentsResource, SessionsResource } from './resources/agents.js';
export { ActionsResource, ToolsResource, DelegationsResource, isApprovalPending } from './resources/actions.js';
export { ToolRegistryResource, McpServersResource, ApprovalsResource } from './resources/governance.js';
export { OperationsResource } from './resources/operations.js';
export type { OperationsClient } from './resources/operations.js';
export { OPERATIONS } from './generated/operations.js';
export type { OperationDescriptor, OperationArgs, OperationMethods, OperationAuth } from './generated/operations.js';

// ---------------------------------------------------------------------------
// Agents, actions, tools, delegation, approvals (protocol V2): types and the agent's proof of possession
// ---------------------------------------------------------------------------
export type * from './types.agents.js';
export { signAgentProof, agentProofDigest, generateAgentKeyPair, AGENT_PROOF_DOMAIN } from './agents/proof.js';
export type { AgentProofContext } from './agents/proof.js';

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------
export {
  QodiqaError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  VerificationError,
  NotFoundError,
  RateLimitError,
  ServerError,
  KillSwitchError,
  NetworkError,
  TimeoutError,
  UnknownError,
  BlockedError,
  MfaRequiredError,
  MfaEnrollmentRequiredError,
  MfaLockedError,
  VERIFICATION_REASONS,
  // Webhook verification errors
  InvalidSignatureError,
  ExpiredSignatureError,
  MalformedSignatureError,
  InvalidTimestampError,
} from './errors.js';
export type { QodiqaErrorOptions } from './errors.js';

// ---------------------------------------------------------------------------
// Utility helpers (public API)
// ---------------------------------------------------------------------------
export { withRetry } from './utils/retry.js';
export type { RetryConfig } from './utils/retry.js';
export { PageIterator, PagePage } from './utils/pagination.js';
export type { PageFetcher } from './utils/pagination.js';

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------
export {
  verifyWebhookSignature,
  WebhookVerifier,
  DEFAULT_TOLERANCE_SECONDS,
} from './webhooks/verifier.js';
export type { WebhookVerifyOptions } from './webhooks/verifier.js';

// ---------------------------------------------------------------------------
// Local artifact & transparency-proof verification — fully
// offline, no dependency on the server's own /verify verdict.
// ---------------------------------------------------------------------------
export { ArtifactVerifier, verifyArtifact } from './verification/artifactVerifier.js';
export { requestHash } from './verification/domainHash.js';
export { artifactGuard } from './middleware/artifactGuard.js';
export type { ArtifactGuardOptions, GuardInfo, GuardRequest, GuardResponse } from './middleware/artifactGuard.js';
export type { ArtifactVerifierOptions, VerifyCallOptions } from './verification/artifactVerifier.js';
export { StaticKeyProvider, RemoteKeyProvider, createKeyProvider } from './verification/keyProviders.js';
export type { KeyProvider, ResolvedKey, StaticKeyEntry, RemoteKeyProviderOptions } from './verification/keyProviders.js';
export { stableStringify, CanonicalizationError } from './verification/canonicalJson.js';
export type { CanonicalizationErrorCode } from './verification/canonicalJson.js';
export { verifyInclusionPath } from './verification/merkle.js';
export type { MerklePathStep } from './verification/merkle.js';
export { verifyTransparencyProof, transparencyDetailAllPassed } from './verification/transparencyProof.js';
export { verifyReceipt, receiptBindsTo, receiptDigest, RECEIPT_DOMAIN } from './verification/receipt.js';
export { anchorStatementDigest, checkAnchorLine, ANCHOR_DOMAIN } from './verification/anchor.js';
export type { AnchorStatement, AnchorLineResult } from './verification/anchor.js';
export type { ReceiptKey, ReceiptVerifyResult, ReceiptVerifyReason, ReceiptVerifyOptions, ReceiptBinding } from './verification/receipt.js';
export type {
  ArtifactVerificationResult,
  TransparencyVerificationDetail,
  TransparencyInclusionProof,
  TransparencyProofEntry,
  TransparencyProofRoot,
  VerificationStatus,
  TransparencyVerifiedState,
  FailedStage,
} from './verification/types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export type {
  // Core
  Receipt,
  SignV2Options,
  HttpMethod,
  Decision,
  KeyStatus,
  ConsentState,
  LawfulBasis,
  SpecialCategoryCondition,
  LawfulBasisStatus,
  ConsentGrantRequest,
  ConsentRecord,
  // Artifact
  Artifact,
  ArtifactPayload,
  // Sign
  SignRequest,
  SignResponse,
  SignMeta,
  // Verify
  VerifyRequest,
  VerifyResponse,
  // Chat
  ChatRequest,
  ChatResponse,
  ChatTransparency,
  AiDisclosure,
  TokenUsage,
  // Chat streaming
  ChatStreamEvent,
  ChatStreamStartedEvent,
  ChatStreamChunkEvent,
  ChatStreamCompletedEvent,
  ChatStreamCancelledEvent,
  // Keys
  PublicKey,
  KeysResponse,
  // Audit
  AuditChainEntry,
  AuditResponse,
  // Health
  HealthResponse,
  ReadyResponse,
  // Attestation
  AttestationVerifyRequest,
  AttestationRecord,
  AttestationListResponse,
  // Certification
  CertificationEvaluateRequest,
  CertificationRecord,
  CertificationListResponse,
  BatchSubmitItem,
  BatchSubmitRequest,
  BatchRecord,
  // Transparency
  TransparencyEntry,
  TransparencyEntryEnvelope,
  TransparencyRegisterResult,
  TransparencyRoot,
  InclusionProof,
  TransparencyVerifyResult,
  // Portal
  PortalOverallResult,
  PortalCheckResult,
  PortalWarning,
  PortalVerifyMetadata,
  PortalVerifyResult,
  PortalVerificationRecord,
  // Webhooks
  WebhookCreateRequest,
  WebhookEndpoint,
  WebhookCreateResult,
  WebhookRecord,
  WebhookListResponse,
  WebhookUpdateRequest,
  // Pagination
  PaginationParams,
  PaginatedResponse,
  // API envelope
  ApiResponse,
  // Policy Simulation — Component #40
  RiskLevel,
  TraceOutcome,
  PolicyVersion,
  SimulationContext,
  PolicyDefinition,
  TraceEntry,
  MatchedRule,
  FailedRule,
  SimulationRequest,
  SimulationResult,
  PolicyComparisonRequest,
  PolicyComparisonSide,
  ChangedRule,
  PolicyComparisonResult,
  BatchSimulationItem,
  BatchSimulationRequest,
  BatchSimulationResult,
} from './types.js';

