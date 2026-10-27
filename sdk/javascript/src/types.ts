// ---------------------------------------------------------------------------
// Core primitives
// ---------------------------------------------------------------------------

export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'HEAD'
  | 'OPTIONS';

export type Decision = 'EXECUTE' | 'BLOCK';

export type KeyStatus = 'active' | 'deprecated' | 'revoked';

// (NF-11): the server's consent states (src/core/consent/ConsentStateModel.js).
// this listed a 'GRANTED' state the server never returns and omitted
// PENDING and EXPIRED.
export type ConsentState = 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED';

// GDPR Art. 6(1) lawful bases and Art. 9(2) conditions (a)–(j).
export type LawfulBasis =
  | 'consent' | 'contract' | 'legal_obligation' | 'vital_interests' | 'public_task' | 'legitimate_interests';
export type SpecialCategoryCondition =
  | 'art9_2_a' | 'art9_2_b' | 'art9_2_c' | 'art9_2_d' | 'art9_2_e'
  | 'art9_2_f' | 'art9_2_g' | 'art9_2_h' | 'art9_2_i' | 'art9_2_j';
export type LawfulBasisStatus = 'SPECIFIED' | 'LEGACY_UNSPECIFIED';

/** Body of POST /v1/consent (camelCase canonical). */
export interface ConsentGrantRequest {
  actorId: string;
  action: string;
  /** Required. */
  lawfulBasis: LawfulBasis;
  /** Required; 1–500 characters. */
  purpose: string;
  purposeCode?: string | null;
  /** Required when the scope is a GDPR Art. 9(1) special category. */
  specialCategoryCondition?: SpecialCategoryCondition | null;
  grantedBy?: string;
  scope?: string | null;
  requiredScope?: string | null;
  tenantId?: string | null;
  grantReference?: string | null;
  subjectName?: string | null;
  actionDisplay?: string | null;
  policyReference?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
  expiresAt?: string | null;
  durationDays?: number | null;
}

/** A consent record as the server returns it (snake_case, the store's own columns). */
export interface ConsentRecord {
  id: string;
  actor_id: string;
  action: string;
  state: ConsentState;
  scope: string | null;
  tenant_id: string | null;
  granted_by: string | null;
  granted_at: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown>;
  lawful_basis: LawfulBasis | null;
  purpose: string | null;
  purpose_code: string | null;
  special_category_condition: SpecialCategoryCondition | null;
  /** LEGACY_UNSPECIFIED: created or without a stated basis — never auto-labelled. */
  lawful_basis_status: LawfulBasisStatus;
}

// ---------------------------------------------------------------------------
// Artifact
// ---------------------------------------------------------------------------

// the authenticated caller identity /sign bound into the artifact
// payload — distinct from Artifact.publicKeyId, which only identifies which
// shared tenant signing key produced the artifact. Derived server-side from
// the caller's own sk_... signing credential; never client-suppliable. See
// NONREP-1-REMEDIATION-REPORT.md.
export interface CallerContext {
  callerId: string;
  callerName: string;
  environment: string;
  credentialType: string;
}

export interface ArtifactPayload {
  requestId: string;
  requestHash: string;
  policyHash: string;
  tenantId: string;
  callerContext?: CallerContext;
  [key: string]: unknown;
}

export interface Artifact {
  expiry: number;
  payload: ArtifactPayload;
  publicKeyId: string;
  timestamp: number;
  signature: string;
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

export interface SignRequest {
  request: {
    method: HttpMethod;
    path: string;
    body: Record<string, unknown>;
    /**
     * Protocol V2: the raw query string WITHOUT the leading `?`, bound into the artifact. A raw `+` or `;`
     * is refused (`QUERY_NOT_BINDABLE`) — write `%20`, `%2B`, `%3B`. Only with a `v2` block.
     */
    query?: string;
    /** Protocol V2: the values of the headers named in `v2.bind.headers` (lower-case names). Only with a `v2` block. */
    headers?: Record<string, string>;
  };
  payload?: Record<string, unknown>;
  ttl?: number;
  /**
   * Issue a protocol-V2 artifact (needs `QODIQA_PROTOCOL_V2_ISSUE=true` on the gateway). The artifact then binds the method, path, query, the listed
   * headers and the body (`requestHash` over JCS-P1), and optionally the model and limits it authorizes.
   */
  v2?: SignV2Options;
}

/** The `v2` block of `POST /sign` (V2-FREEZE section 4). */
export interface SignV2Options {
  /** Names (lower-case, at most 16, none of the never-bindable ones) of the request headers that are bound. May be empty. */
  bind: { headers: string[] };
  /** The one model the artifact authorizes; `/ai/chat` then refuses a body that names another. */
  model?: string | null;
  /** Limits the gateway enforces: `maxTokens` caps the provider's output for this request. */
  limits?: { maxTokens?: number };
  /** Claims a verifier MUST understand; an unknown critical claim is refused (`UNSUPPORTED_CRITICAL_CLAIM`). */
  crit?: string[];
}

export interface SignMeta {
  keyId: string;
  expiresAt: number;
  tenantId: string;
  /** the authenticated signing identity that produced this artifact. */
  callerId: string;
}

export interface SignResponse {
  artifactId: string;
  artifact: Artifact;
  meta: SignMeta;
  requestId: string;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export interface VerifyRequest {
  artifact: Artifact;
  request: {
    method: string;
    path: string;
    body: Record<string, unknown>;
  };
}

export interface VerifyResponse {
  decision: Decision;
  reason: string;
  details: Record<string, unknown>;
  requestId: string;
  artifactId?: string;
  keyId?: string;
  /** null for an artifact signed before this remediation shipped. */
  callerId?: string | null;
}

// ---------------------------------------------------------------------------
// Chat
// ---------------------------------------------------------------------------

/** One turn of a multi-turn request. */
export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface ChatRequest {
  /** The prompt of a single-turn request. Exactly one of `prompt` and `messages` is used (the gateway refuses both: `PROMPT_AND_MESSAGES`). */
  prompt?: string;
  /** The turns of a multi-turn request. */
  messages?: ChatMessage[];
  /** Optional system text for a multi-turn request. */
  system?: string;
  model?: string;
  /**
   * Request an SSE stream instead of a single JSON response. Must be set
   * consistently in both the body passed to `sign.sign()` and the body
   * passed to `chat.stream()` — the server binds the artifact to the exact
   * request body it was signed with (`requestHash`), so a mismatch here
   * fails closed with `REQUEST_MISMATCH`. `chat.stream()` sets this
   * automatically on the wire body it sends; it is exposed on the type so
   * the same object can be reused for both calls. Not used by `chat.create()`.
   */
  stream?: boolean;
}

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

/**
 * Signed receipt of a decision (V2-FREEZE section 6). It proves the gateway RECORDED the decision — the audit entry `entryHash` and the transparency leaf
 * `leafHash` — not that the decision was correct. Verify it offline with `verifyReceipt()` and the keys of `GET /.well-known/qodiqa/transparency-keys`.
 */
export interface Receipt {
  v: 1;
  requestId: string;
  decision: 'ALLOW' | 'BLOCK';
  /** When the receipt was signed (ms since epoch). */
  issuedAt: number;
  /** Hash of the audit DECISION entry (64 hex). */
  entryHash: string;
  /** RFC 6962 leaf hash of the transparency leaf registered for it (64 hex). */
  leafHash: string;
  /** A transparency key id. */
  keyId: string;
  /** base64 Ed25519 signature over SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature)). */
  signature: string;
}

export interface ChatResponse {
  decision: Decision;
  reason: string;
  aiText?: string;
  responseId?: string;
  model?: string;
  tokenUsage?: TokenUsage;
  requestId: string;
  /**
   * Transparency-log registration for this decision (present on EXECUTE
   * responses — see src/api/routes/aiChat.js). Check
   * `transparency.persisted`: `true` means the signed entry was
   * durably written to PostgreSQL; `false` means the deployment is
   * sign-only — the entry is signed but nothing survives the process and no
   * inclusion proof will ever cover it. the server's production
   * profile refuses to boot sign-only, so `persisted: false` only occurs
   * against non-production servers; assert on it in any evidentiary
   * workflow.
   */
  transparency?: ChatTransparency;
  /** (EU AI Act Art. 50): present on every EXECUTE response (header X-QODIQA-AI-Generated: true too); absent on BLOCK. */
  aiDisclosure?: AiDisclosure;
  /**
   * Signed receipt of this decision: present on an EXECUTE and on a post-authentication BLOCK, only when the audit entry and the transparency
   * leaf are persisted — otherwise ABSENT (never null). Keep it; verify it offline with `verifyReceipt()`. Also served for a bounded time by
   * `transparency.getReceipt(requestId)`.
   */
  receipt?: Receipt;
}

/**
 * End-user AI disclosure. `notice` is the tenant's published wording
 * or the platform default "This response was generated by an AI system." —
 * display it to the end user.
 */
export interface AiDisclosure {
  aiGenerated: true;
  provider: string | null;
  model: string | null;
  notice: string;
}

/** The `transparency` block on an EXECUTE ChatResponse. */
export interface ChatTransparency {
  transparencyId: string;
  entryHash: string;
  leafHash: string;
  signerKeyId: string;
  /** `true` = durably persisted (durable-evidence deployment); `false` = signed only (sign-only deployment). */
  persisted: boolean;
  merkleRoot: string | null;
  treeSize: number | null;
  signedTreeHeadRef: string | null;
  inclusionProofRef: string;
}

// ---------------------------------------------------------------------------
// Chat streaming — SSE events emitted by `POST /ai/chat` with
// `stream: true`. Field shapes mirror src/streaming/streamEnforcer.js and
// exactly (the source of truth — not the
// stale hand-written example, which predates a
// wire-format change and still shows a non-existent `stream_error` event
// and a `totalChunks` field that was renamed to `chunksTotal`).
// ---------------------------------------------------------------------------

/** Always the first event; emitted once enforcement passes and SSE headers are flushed. */
export interface ChatStreamStartedEvent {
  event: 'stream_started';
  streamId: string;
  requestId: string;
  artifactId: string;
  provider: string;
  model: string;
  /** (EU AI Act Art. 50): same disclosure as the JSON EXECUTE response. */
  aiDisclosure: AiDisclosure;
}

/** One per incremental delta from the provider, strictly ordered by `index` (0, 1, 2, …). */
export interface ChatStreamChunkEvent {
  event: 'chunk_forwarded';
  delta: string;
  index: number;
}

/** Terminal event on normal completion. */
export interface ChatStreamCompletedEvent {
  event: 'stream_completed';
  streamId: string;
  requestId: string;
  chunksTotal: number;
  bytesTotal: number;
  durationMs: number;
}

/** Terminal event on any non-normal termination — client disconnect, server-side stream timeout, or a provider error. */
export interface ChatStreamCancelledEvent {
  event: 'stream_cancelled';
  streamId: string;
  /** `'CLIENT_DISCONNECT'`, `'STREAM_TIMEOUT'`, or a provider error code (e.g. `'PROVIDER_UNAVAILABLE'`). */
  reason: string;
  requestId: string;
}

/**
 * Discriminated on `event`. Exactly one of `ChatStreamCompletedEvent` /
 * `ChatStreamCancelledEvent` is ever yielded, and it is always the last
 * event `chat.stream()` yields — the raw `[DONE]` sentinel that follows it
 * on the wire is consumed internally to end iteration, never yielded itself.
 */
export type ChatStreamEvent =
  | ChatStreamStartedEvent
  | ChatStreamChunkEvent
  | ChatStreamCompletedEvent
  | ChatStreamCancelledEvent;

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

export interface PublicKey {
  keyId: string;
  algorithm: string;
  publicKey: string;
  status: KeyStatus;
}

export interface KeysResponse {
  keys: PublicKey[];
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditChainEntry {
  hash: string;
  signature: string;
  payload: Record<string, unknown>;
}

export interface AuditResponse {
  artifactId: string;
  decision: string;
  reason: string;
  timestamp: string;
  chain: AuditChainEntry[];
  requestId: string;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

export interface HealthResponse {
  status: 'ok';
  uptime: number;
}

export interface ReadyResponse {
  ready: boolean;
  components: {
    nonceStore: boolean;
    anomalyStore: boolean;
    rateLimitStore: boolean;
    persistenceStore: boolean;
    consentSubscriber: boolean;
    consentCache: boolean;
    /** false while admission control's queue is full (src/api/routes/ready.js). Absent on older servers. */
    admission?: boolean;
    /** false while the audit mirror backlog is above its bound (new work answers 503 SERVER_OVERLOADED). Absent on older servers. */
    auditBacklog?: boolean;
  };
}

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

export interface AttestationVerifyRequest {
  artifact: Artifact;
}

export interface AttestationRecord {
  attestationId: string;
  status: 'VALID' | 'INVALID';
  artifact: Artifact;
  evidence: {
    chain: unknown[];
    verificationResult: boolean;
  };
  summary: Record<string, unknown>;
}

/** `attestation.list()`'s response — array key is `attestations`, not `entries`. */
export interface AttestationListResponse {
  attestations: AttestationRecord[];
  page: number;
  pageSize: number;
  total: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

// ---------------------------------------------------------------------------
// Certification
// ---------------------------------------------------------------------------

export interface CertificationEvaluateRequest {
  /** Signed artifacts to evaluate (server default: [], max 50 per request). */
  artifacts?: Array<Record<string, unknown>>;
  evidencePackages?: Array<Record<string, unknown>>;
  chain?: Record<string, unknown> | null;
  options?: Record<string, unknown>;
}

export interface CertificationRecord {
  id: string;
  status: string;
  score?: number;
  controls?: unknown[];
  summary: Record<string, unknown>;
  createdAt: string;
}

export interface BatchSubmitItem {
  /** Required — identifies the subject being certified within this batch item. */
  subjectId: string;
  artifacts?: Array<Record<string, unknown>>;
  evidencePackages?: Array<Record<string, unknown>>;
  controls?: Record<string, unknown>;
}

export interface BatchSubmitRequest {
  /** Required — the certification framework this batch is evaluated against. */
  frameworkId: string;
  items: BatchSubmitItem[];
}

export interface BatchRecord {
  batchId: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
  total: number;
  completed: number;
  failed: number;
  createdAt: string;
}

/** `certification.list()`'s response — array key is `certifications`, not `entries`. */
export interface CertificationListResponse {
  certifications: CertificationRecord[];
  page: number;
  pageSize: number;
  total: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

// ---------------------------------------------------------------------------
// Transparency
// ---------------------------------------------------------------------------

/**
 * A public transparency-log entry, exactly as `GET /v1/transparency/entry/:id`
 * (inside `{ entry }`) and `GET /v1/transparency/entries` (inside `entries`)
 * return it. verification fields only — the public API never
 * returns the payload, tenant, registering operator or key version; field names
 * are the server's own (snake_case).
 */
export interface TransparencyEntry {
  /** Log sequence number (a PostgreSQL bigint, serialized as a string). */
  id: string;
  transparency_id: string;
  entry_type: 'ARTIFACT' | 'EVIDENCE' | 'VERIFICATION' | 'POLICY' | 'AUDIT' | 'SYSTEM' | string;
  artifact_id: string | null;
  evidence_chain_id: string | null;
  verification_id: string | null;
  /** SHA-256 hex of the (never published) payload. */
  payload_hash: string;
  previous_entry_hash: string | null;
  entry_hash: string;
  signer_key_id: string;
  signature: string;
  created_at: string;
}

/** `GET /v1/transparency/entry/:id` response data. */
export interface TransparencyEntryEnvelope {
  entry: TransparencyEntry;
}

/** `POST /v1/transparency/register` response data (201). */
export interface TransparencyRegisterResult {
  transparencyId: string;
  entryHash: string;
  keyId: string;
  /**
   * `true` = the signed entry was durably persisted to PostgreSQL;
   * `false` = sign-only deployment, the entry will never be covered by a
   * proof or signed root.
   */
  persisted: boolean;
  createdAt: string;
}

/**
 * A signed transparency root row, exactly as `GET /v1/transparency/root` and `GET /v1/transparency/roots` return it
 * (snake_case server row; contract docs/api/openapi.json `TransparencyRootRow`). bigint columns are strings.
 * `signature` is present on `GET /root`, absent from list rows.
 */
export interface TransparencyRoot {
  id: string;
  root_id: string;
  seq_from: string;
  seq_to: string;
  entry_count: number;
  root_hash: string;
  previous_root_hash: string | null;
  signature?: string;
  signer_key_id: string;
  generated_by: string;
  generated_at: string;
}

/** `GET /v1/transparency/root` response data: `root` is null (with a message) before the first root exists. */
export interface TransparencyLatestRoot {
  root: TransparencyRoot | null;
  message?: string;
}

/** `GET /v1/transparency/roots` response data (pagination metadata flat beside the list). */
export interface TransparencyRootList {
  roots: TransparencyRoot[];
  page: number;
  pageSize: number;
  total: number;
  totalItems?: number;
  totalPages?: number;
  hasNextPage?: boolean;
  hasPreviousPage?: boolean;
}

/** `POST /v1/transparency/admin/roots/generate` response data (201). */
export interface TransparencyRootGenerated {
  rootId: string;
  seqFrom: number;
  seqTo: number;
  entryCount: number;
  rootHash: string;
  previousRootHash: string | null;
  keyId: string;
  persisted: boolean;
  generatedAt: string;
}

export interface TransparencyCheck {
  check: string;
  result: 'PASS' | 'FAIL' | 'SKIP' | string;
  [extra: string]: unknown;
}

/** The RFC 6962 inclusion proof document (`proofType: 'TRANSPARENCY_INCLUSION'`). */
export interface InclusionProofDocument {
  proofVersion: string;
  proofType: 'TRANSPARENCY_INCLUSION' | string;
  generatedAt?: string;
  /** The entry, camelCase. */
  entry: Record<string, unknown>;
  /** The covering signed root, camelCase. */
  root: Record<string, unknown>;
  proof: {
    leafIndex: number;
    treeSize: number;
    merklePath: Array<{ hash: string; side: 'left' | 'right' }>;
    merkleRoot: string;
  };
  verifiable: boolean;
}

export interface InclusionProof {
  transparencyId: string;
  /**
   * `null` when no transparency root covers this entry yet (roots are generated automatically every
   * `TRANSPARENCY_ROOT_INTERVAL_MS`, default 60 s, or on demand with `transparency.generateRoot()`).
   */
  proof: InclusionProofDocument | null;
  proofVerification?: { valid: boolean; checks: TransparencyCheck[]; failedCheck: string | null; failureReason: string | null };
  message?: string;
}

export interface TransparencyVerifyResult {
  transparencyId: string;
  verifiedAt: string;
  durationMs: number;
  result: 'VALID' | 'INVALID' | 'PARTIAL' | 'ERROR';
  signatureValid: boolean | null;
  signerKeyStatus: string | null;
  integrityChecks: TransparencyCheck[];
  firstFailure: TransparencyCheck | null;
}

/** `GET /v1/transparency/admin/chain/validate` response data. */
export interface TransparencyChainValidation {
  chainValidation: { valid: boolean; checkedCount: number; failureId: string | null; failureDetail: string | null };
  startId: string | null;
  endId: string | null;
  limit: number;
  validatedAt: string;
  validatedBy: string;
}

// ---------------------------------------------------------------------------
// Portal —: rewritten to match the real, synchronous
// `POST /v1/portal/verify` contract. There is no async submit/poll model on
// the server; these types replace an earlier aspirational shape that never
// matched any real route.
// ---------------------------------------------------------------------------

export type PortalOverallResult = 'VERIFIED' | 'VERIFIED_WITH_WARNINGS' | 'FAILED';

export interface PortalCheckResult {
  check: string;
  result: 'PASS' | 'FAIL' | 'WARN' | 'SKIP';
  reason?: string;
}

export interface PortalWarning {
  check: string;
  reason: string;
}

export interface PortalVerifyMetadata {
  publicKeyId: string | null;
  timestampMs: number | null;
  expiryMs: number | null;
  artifactId: string | null;
}

/** `POST /v1/portal/verify`'s `data` — a complete report, returned in one call. */
export interface PortalVerifyResult {
  verificationId: string;
  overallResult: PortalOverallResult;
  failedCheck: string | null;
  failureReason: string | null;
  warnings: PortalWarning[];
  checks: PortalCheckResult[];
  metadata: PortalVerifyMetadata;
  durationMs: number;
  verifiedAt: string;
}

/**
 * `GET /v1/portal/result/:id`'s `data.verification` — the persisted record,
 * a raw PostgreSQL row (snake_case columns, unlike `PortalVerifyResult`
 * above). Requires PostgreSQL to be enabled server-side; this route 404s
 * otherwise, even for a `verificationId` `verify()` itself just returned.
 * The submitter address (`submission_ip`) is internal audit data and is not
 * part of this public record.
 */
export interface PortalVerificationRecord {
  // BIGSERIAL/BIGINT columns — the pg driver serializes these as strings to
  // avoid silent precision loss above Number.MAX_SAFE_INTEGER; confirmed
  // live, not a typo.
  id: string;
  verification_id: string;
  artifact_fingerprint: string;
  artifact_public_key_id: string | null;
  artifact_timestamp_ms: string | null;
  artifact_expiry_ms: string | null;
  artifact_id: string | null;
  overall_result: PortalOverallResult;
  checks_performed: PortalCheckResult[];
  failed_check: string | null;
  failure_reason: string | null;
  warnings: PortalWarning[];
  transparency_id: string | null;
  submitted_by: string;
  duration_ms: number | null;
  verified_at: string;
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

export interface WebhookCreateRequest {
  tenantId: string;
  url: string;
  eventTypes: string[];
  description?: string;
}

export interface WebhookEndpoint {
  id: string;
  tenant_id: string;
  url: string;
  enabled: boolean;
  event_types: string[];
  description?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

/** `create()`'s response — the only call that returns the one-time secret. */
export interface WebhookCreateResult {
  endpoint: WebhookEndpoint;
  secret: string;
  notice: string;
}

/** `get()`/`update()`'s response — no secret (only returned once, at creation). */
export interface WebhookRecord {
  endpoint: WebhookEndpoint;
}

export interface WebhookUpdateRequest {
  url?: string;
  eventTypes?: string[];
  description?: string;
  /** Real field name accepted by the server — NOT `active`. */
  enabled?: boolean;
}

/** `list()`'s response — array key is `endpoints`, not the generic `PaginatedResponse.entries`. */
export interface WebhookListResponse {
  endpoints: WebhookEndpoint[];
  page: number;
  pageSize: number;
  total: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export interface PaginationParams {
  page?: number;
  pageSize?: number;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  /**
   * Field name confirmed against `src/utils/pagination.js`'s shared
   * `withPaginationMeta()` helper, used by `transparency.listEntries()`.
   * Some other list endpoints (e.g. `attestation.list()` -> `attestations`)
   * use a differently-named array under their own `data`, not this generic
   * shape — check the specific resource method's own return type.
   */
  entries: T[];
  page: number;
  pageSize: number;
  total: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

// ---------------------------------------------------------------------------
// API envelope
// ---------------------------------------------------------------------------

export interface ApiResponse<T> {
  status: 'success';
  timestamp: string;
  requestId: string;
  data: T;
}

// ---------------------------------------------------------------------------
// Policy Simulation — Component #40
// ---------------------------------------------------------------------------

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type TraceOutcome = 'PASSED' | 'BLOCKED' | 'SKIPPED' | 'UNKNOWN';
export type PolicyVersion = 'current' | 'provided' | 'unknown';

export interface SimulationContext {
  userId?:    string;
  action?:    string;
  tenantId?:  string;
  requestId?: string;
  ip?:        string;
  timestamp?: number;
}

export interface PolicyDefinition {
  id:       string;
  type:     string;
  priority: number;
  enabled:  boolean;
  config:   Record<string, unknown>;
}

export interface TraceEntry {
  policyId:  string;
  type:      string;
  priority:  number;
  outcome:   TraceOutcome;
  skipped:   boolean;
  reason?:   string;
}

export interface MatchedRule {
  policyId:  string;
  type:      string;
  priority:  number;
}

export interface FailedRule {
  policyId:  string;
  type:      string;
  priority:  number;
  reason:    string;
}

export interface SimulationRequest {
  context?:   SimulationContext;
  policies?:  PolicyDefinition[];
  scenario?:  string;
}

export interface SimulationResult {
  simulationId:       string;
  decision:           Decision;
  reason:             string;
  policyId:           string;
  policyVersion:      PolicyVersion;
  policyHash:         string | null;
  tenantId:           string | null;
  organizationId:     string | null;
  riskLevel:          RiskLevel;
  matchedRules:       MatchedRule[];
  failedRules:        FailedRule[];
  evaluationTrace:    TraceEntry[];
  explanation:        string;
  executionPrevented: true;
  durationMs:         number;
  scenario:           string | null;
}

export interface PolicyComparisonRequest {
  context?:           SimulationContext;
  currentPolicies?:   PolicyDefinition[];
  proposedPolicies:   PolicyDefinition[];
  scenario?:          string;
}

export interface PolicyComparisonSide {
  decision:    Decision;
  reason:      string;
  policyId:    string;
  policyHash:  string | null;
  riskLevel:   RiskLevel;
  explanation: string;
}

export interface ChangedRule {
  policyId:    string;
  change:      'ADDED' | 'REMOVED' | 'OUTCOME_CHANGED';
  oldOutcome:  TraceOutcome | null;
  newOutcome:  TraceOutcome | null;
}

export interface PolicyComparisonResult {
  comparison:         true;
  scenario:           string | null;
  decisionChanged:    boolean;
  old:                PolicyComparisonSide;
  proposed:           PolicyComparisonSide;
  changedRules:       ChangedRule[];
  tenantId:           string | null;
  organizationId:     string | null;
  executionPrevented: true;
}

export interface BatchSimulationItem {
  context?:   SimulationContext;
  policies?:  PolicyDefinition[];
  scenario?:  string;
}

export interface BatchSimulationRequest {
  simulations: BatchSimulationItem[];
  policies?:   PolicyDefinition[];
}

export interface BatchSimulationResult {
  batchId:            string;
  total:              number;
  allowed:            number;
  blocked:            number;
  totalDurationMs:    number;
  results:            SimulationResult[];
  executionPrevented: true;
}
