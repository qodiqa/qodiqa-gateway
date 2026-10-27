"""QODIQA SDK type definitions.

All public API response shapes are defined here as ``TypedDict`` classes.
These map directly to the JSON responses returned by the QODIQA server.

Client configuration is defined as a frozen ``dataclass`` so that values
cannot be accidentally mutated after client creation.
"""

from __future__ import annotations

from typing import Any, Dict, Generic, List, Literal, Optional, TypeVar, Union

# TypedDict is available in stdlib from 3.8 onwards
from typing import TypedDict

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Core primitives
# ---------------------------------------------------------------------------

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
Decision = Literal["EXECUTE", "BLOCK"]
KeyStatus = Literal["active", "deprecated", "revoked"]
# (NF-11): the server's consent states (src/core/consent/ConsentStateModel.js);
# the earlier list had a GRANTED state the server never returns and lacked PENDING/EXPIRED.
ConsentState = Literal["PENDING", "ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"]

# GDPR Art. 6(1) lawful bases and Art. 9(2) conditions (a)-(j).
LawfulBasis = Literal[
    "consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests",
]
SpecialCategoryCondition = Literal[
    "art9_2_a", "art9_2_b", "art9_2_c", "art9_2_d", "art9_2_e",
    "art9_2_f", "art9_2_g", "art9_2_h", "art9_2_i", "art9_2_j",
]
LawfulBasisStatus = Literal["SPECIFIED", "LEGACY_UNSPECIFIED"]

# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------


class CallerContext(TypedDict):
    """the authenticated caller identity /sign bound into the
    artifact payload — distinct from Artifact["publicKeyId"], which only
    identifies which shared tenant signing key produced the artifact.
    Derived server-side from the caller's own sk_... signing credential;
    never client-suppliable. See NONREP-1-REMEDIATION-REPORT.md.
    """

    callerId: str
    callerName: str
    environment: str
    credentialType: str


class ArtifactPayload(TypedDict, total=False):
    requestId: str
    requestHash: str
    policyHash: str
    tenantId: str
    callerContext: CallerContext


class Artifact(TypedDict):
    expiry: int
    payload: ArtifactPayload
    publicKeyId: str
    timestamp: int
    signature: str


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------


class _SignRequestBodyOptional(TypedDict, total=False):
    query: str
    """Protocol V2: the raw query string WITHOUT the leading ``?``, bound into the artifact. A raw ``+`` or
    ``;`` is refused (``QUERY_NOT_BINDABLE``) — write ``%20``, ``%2B``, ``%3B``. Only with a ``v2`` block."""
    headers: Dict[str, str]
    """Protocol V2: the values of the headers named in ``v2.bind.headers`` (lower-case names). Only with a ``v2`` block."""


class SignRequestBody(_SignRequestBodyOptional):
    method: str
    path: str
    body: Dict[str, Any]


class _SignV2Limits(TypedDict, total=False):
    maxTokens: int
    """Caps the provider's output for this request."""


class _SignV2Bind(TypedDict):
    headers: List[str]
    """Names (lower-case, at most 16, none of the never-bindable ones) of the request headers that are bound. May be empty."""


class SignV2Options(TypedDict, total=False):
    """The ``v2`` block of ``POST /sign`` (V2-FREEZE section 4); ``bind`` is required, the rest optional."""

    bind: _SignV2Bind
    model: Optional[str]
    """The one model the artifact authorizes; ``/ai/chat`` then refuses a body that names another."""
    limits: _SignV2Limits
    crit: List[str]
    """Claims a verifier MUST understand; an unknown critical claim is refused (``UNSUPPORTED_CRITICAL_CLAIM``)."""


class SignRequest(TypedDict, total=False):
    request: SignRequestBody
    payload: Dict[str, Any]
    ttl: int
    v2: SignV2Options
    """Issue a protocol-V2 artifact (needs ``QODIQA_PROTOCOL_V2_ISSUE=true`` on the gateway)."""


class SignMeta(TypedDict):
    keyId: str
    expiresAt: int
    tenantId: str
    callerId: str
    """the authenticated signing identity that produced this artifact."""


class SignResponse(TypedDict):
    artifactId: str
    artifact: Artifact
    meta: SignMeta
    requestId: str


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class VerifyRequestBody(TypedDict):
    method: str
    path: str
    body: Dict[str, Any]


class VerifyRequest(TypedDict):
    artifact: Artifact
    request: VerifyRequestBody


class VerifyResponse(TypedDict, total=False):
    decision: Decision
    reason: str
    details: Dict[str, Any]
    requestId: str
    artifactId: str
    keyId: str
    callerId: Optional[str]
    """None for an artifact signed before this remediation shipped."""


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


class ChatRequest(TypedDict, total=False):
    prompt: str
    """The prompt of a single-turn request. Exactly one of ``prompt`` and ``messages`` is used."""
    messages: List[Dict[str, str]]
    """The turns of a multi-turn request: ``{"role": "user"|"assistant"|"system", "content": "..."}``."""
    system: str
    model: str
    stream: bool
    """Request an SSE stream instead of a single JSON response. Must be set
    consistently in both the body passed to ``sign.sign()`` and the body sent
    on the wire — the server binds the artifact to the exact request body it
    was signed with (``requestHash``), so a mismatch fails closed with
    ``REQUEST_MISMATCH``. ``chat.stream()`` sets this automatically on the
    wire body it sends; it is exposed here so the same dict can be reused for
    both the ``sign.sign()`` call and ``chat.stream()``. Not used by
    ``chat.create()``.
    """


class TokenUsage(TypedDict):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatTransparency(TypedDict, total=False):
    """The ``transparency`` block on an EXECUTE ChatResponse.

    Check ``persisted``: ``True`` means the signed transparency entry
    was durably written to PostgreSQL (durable-evidence deployment);
    ``False`` means the deployment is sign-only — the entry is signed but
    nothing survives the process and no inclusion proof will ever cover it.
 the server's production profile refuses to boot sign-only, so
    ``persisted: False`` only occurs against non-production servers; assert
    on it in any evidentiary workflow.
    """

    transparencyId: str
    entryHash: str
    leafHash: str
    signerKeyId: str
    persisted: bool
    merkleRoot: Optional[str]
    treeSize: Optional[int]
    signedTreeHeadRef: Optional[str]
    inclusionProofRef: str


class Receipt(TypedDict):
    """Signed receipt of a decision (V2-FREEZE section 6).

    It proves the gateway RECORDED the decision — the audit entry ``entryHash`` and the transparency leaf ``leafHash`` — not that the decision was correct.
    Verify it offline with :func:`qodiqa.verify_receipt` and the keys of ``GET /.well-known/qodiqa/transparency-keys``.
    """

    v: int
    requestId: str
    decision: Literal["ALLOW", "BLOCK"]
    issuedAt: int
    """When the receipt was signed (ms since epoch)."""
    entryHash: str
    """Hash of the audit DECISION entry (64 hex)."""
    leafHash: str
    """RFC 6962 leaf hash of the transparency leaf registered for it (64 hex)."""
    keyId: str
    """A transparency key id."""
    signature: str
    """base64 Ed25519 signature over SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature))."""


class ChatResponse(TypedDict, total=False):
    decision: Decision
    reason: str
    aiText: str
    responseId: str
    model: str
    tokenUsage: TokenUsage
    requestId: str
    # Present on EXECUTE responses — see ChatTransparency's docstring.
    transparency: ChatTransparency
    # (EU AI Act Art. 50): present on every EXECUTE response; absent on BLOCK.
    aiDisclosure: "AiDisclosure"
    # signed receipt of this decision — present on an EXECUTE and on a post-authentication BLOCK, only when the audit entry and the transparency leaf
    # are persisted; otherwise ABSENT (never None). Keep it; verify it offline with verify_receipt().
    receipt: "Receipt"


class AiDisclosure(TypedDict):
    """End-user AI disclosure. Display ``notice`` to the end user."""

    aiGenerated: bool
    provider: Optional[str]
    model: Optional[str]
    notice: str


# ---------------------------------------------------------------------------
# Chat streaming — SSE events emitted by `POST /ai/chat` with
# `stream: true`. Field shapes mirror src/streaming/streamEnforcer.js and
# exactly (the source of truth — not the
# stale hand-written example, which predates a wire
# format change and still shows a non-existent `stream_error` event and a
# `totalChunks` field that was renamed to `chunksTotal`; see
# JS-4-REMEDIATION-REPORT.md §3, which documents the identical discrepancy
# for the JavaScript SDK).
# ---------------------------------------------------------------------------


class ChatStreamStartedEvent(TypedDict):
    """Always the first event; emitted once enforcement passes and SSE headers are flushed."""

    event: Literal["stream_started"]
    streamId: str
    requestId: str
    artifactId: str
    provider: str
    model: str
    aiDisclosure: AiDisclosure  # (EU AI Act Art. 50)


class ChatStreamChunkEvent(TypedDict):
    """One per incremental delta from the provider, strictly ordered by ``index`` (0, 1, 2, ...)."""

    event: Literal["chunk_forwarded"]
    delta: str
    index: int


class ChatStreamCompletedEvent(TypedDict):
    """Terminal event on normal completion."""

    event: Literal["stream_completed"]
    streamId: str
    requestId: str
    chunksTotal: int
    bytesTotal: int
    durationMs: int


class ChatStreamCancelledEvent(TypedDict):
    """Terminal event on any non-normal termination — client disconnect,
    server-side stream timeout, or a provider error.
    """

    event: Literal["stream_cancelled"]
    streamId: str
    reason: str
    """``'CLIENT_DISCONNECT'``, ``'STREAM_TIMEOUT'``, or a provider error code (e.g. ``'PROVIDER_UNAVAILABLE'``)."""
    requestId: str


# Discriminated on "event". Exactly one of ChatStreamCompletedEvent /
# ChatStreamCancelledEvent is ever yielded, and it is always the last event
# `chat.stream()` yields — the raw `[DONE]` sentinel that follows it on the
# wire is consumed internally to end iteration, never yielded itself.
ChatStreamEvent = Union[
    ChatStreamStartedEvent,
    ChatStreamChunkEvent,
    ChatStreamCompletedEvent,
    ChatStreamCancelledEvent,
]


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


class PublicKey(TypedDict):
    keyId: str
    algorithm: str
    publicKey: str
    status: KeyStatus


class KeysResponse(TypedDict):
    keys: List[PublicKey]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditChainEntry(TypedDict):
    hash: str
    signature: str
    payload: Dict[str, Any]


class AuditResponse(TypedDict):
    artifactId: str
    decision: str
    reason: str
    timestamp: str
    chain: List[AuditChainEntry]
    requestId: str


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class _HealthComponentsRequired(TypedDict):
    nonceStore: bool
    anomalyStore: bool
    rateLimitStore: bool
    persistenceStore: bool
    consentSubscriber: bool
    consentCache: bool


class HealthComponents(_HealthComponentsRequired, total=False):
    # (src/api/routes/ready.js): absent on older servers.
    admission: bool  # False while admission control's queue is full
    auditBacklog: bool  # False while the audit mirror backlog is above its bound (503 SERVER_OVERLOADED)


class HealthResponse(TypedDict):
    status: Literal["ok"]
    uptime: float


class ReadyResponse(TypedDict):
    ready: bool
    components: HealthComponents


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


class AttestationEvidence(TypedDict):
    chain: List[Any]
    verificationResult: bool


class AttestationRecord(TypedDict, total=False):
    attestationId: str
    status: Literal["VALID", "INVALID"]
    artifact: Artifact
    evidence: AttestationEvidence
    summary: Dict[str, Any]


# ---------------------------------------------------------------------------
# Certification
# ---------------------------------------------------------------------------


class CertificationRecord(TypedDict, total=False):
    id: str
    status: str
    score: float
    controls: List[Any]
    summary: Dict[str, Any]
    createdAt: str


class BatchRecord(TypedDict, total=False):
    batchId: str
    status: Literal["pending", "processing", "completed", "failed"]
    total: int
    completed: int
    failed: int
    createdAt: str


# ---------------------------------------------------------------------------
# Transparency
# ---------------------------------------------------------------------------


class TransparencyEntry(TypedDict, total=False):
    # the server's public entry, exactly as
    # GET /v1/transparency/entry/:id (inside "entry") and /entries return it —
    # verification fields only; the payload, tenant, registering operator and
    # key version are never public. Field names are the server's (snake_case).
    id: str  # log sequence number (PostgreSQL bigint, serialized as a string)
    transparency_id: str
    entry_type: str
    artifact_id: Optional[str]
    evidence_chain_id: Optional[str]
    verification_id: Optional[str]
    payload_hash: str
    previous_entry_hash: Optional[str]
    entry_hash: str
    signer_key_id: str
    signature: str
    created_at: str


class ConsentGrantRequest(TypedDict, total=False):
    # body of POST /v1/consent; lawfulBasis and purpose are required.
    actorId: str
    action: str
    lawfulBasis: LawfulBasis
    purpose: str
    purposeCode: Optional[str]
    specialCategoryCondition: Optional[SpecialCategoryCondition]
    grantedBy: str
    scope: Optional[str]
    requiredScope: Optional[str]
    tenantId: Optional[str]
    expiresAt: Optional[str]
    durationDays: Optional[int]


class ConsentRecord(TypedDict, total=False):
    # A consent record as the server returns it (snake_case columns).
    id: str
    actor_id: str
    action: str
    state: ConsentState
    scope: Optional[str]
    tenant_id: Optional[str]
    granted_by: Optional[str]
    granted_at: str
    expires_at: Optional[str]
    lawful_basis: Optional[LawfulBasis]
    purpose: Optional[str]
    purpose_code: Optional[str]
    special_category_condition: Optional[SpecialCategoryCondition]
    lawful_basis_status: LawfulBasisStatus


class TransparencyRegisterResult(TypedDict, total=False):
    # POST /v1/transparency/register response data (201).
    transparencyId: str
    entryHash: str
    keyId: str
    # True = durably persisted to PostgreSQL; False = sign-only
    # deployment (never covered by a proof or signed root).
    persisted: bool
    createdAt: str


class TransparencyRoot(TypedDict, total=False):
    """A signed transparency root row exactly as ``GET /v1/transparency/root`` and ``/roots`` return it.

    snake_case server row (contract docs/api/openapi.json ``TransparencyRootRow``); bigint
    columns are strings. ``signature`` is present on ``GET /root``, absent from list rows.
    """

    id: str
    root_id: str
    seq_from: str
    seq_to: str
    entry_count: int
    root_hash: str
    previous_root_hash: Optional[str]
    signature: str
    signer_key_id: str
    generated_by: str
    generated_at: str


class TransparencyLatestRoot(TypedDict, total=False):
    """``GET /v1/transparency/root`` data: ``root`` is None (with ``message``) before the first root."""

    root: Optional[TransparencyRoot]
    message: str


class TransparencyRootList(TypedDict, total=False):
    """``GET /v1/transparency/roots`` data (pagination metadata flat beside the list)."""

    roots: List[TransparencyRoot]
    page: int
    pageSize: int
    total: int
    totalItems: int
    totalPages: int
    hasNextPage: bool
    hasPreviousPage: bool


class TransparencyRootGenerated(TypedDict):
    """``POST /v1/transparency/admin/roots/generate`` data (201)."""

    rootId: str
    seqFrom: int
    seqTo: int
    entryCount: int
    rootHash: str
    previousRootHash: Optional[str]
    keyId: str
    persisted: bool
    generatedAt: str


class TransparencyCheck(TypedDict, total=False):
    check: str
    result: str


class InclusionProofDocument(TypedDict, total=False):
    """The RFC 6962 inclusion proof (``proofType: 'TRANSPARENCY_INCLUSION'``)."""

    proofVersion: str
    proofType: str
    generatedAt: str
    entry: Dict[str, Any]
    root: Dict[str, Any]
    proof: Dict[str, Any]  # {leafIndex, treeSize, merklePath: [{hash, side}], merkleRoot}
    verifiable: bool


class InclusionProof(TypedDict, total=False):
    transparencyId: str
    # `None` until a root covers this entry (roots are generated automatically every
    # TRANSPARENCY_ROOT_INTERVAL_MS, default 60 s, or on demand: transparency.generate_root()).
    proof: Optional[InclusionProofDocument]
    proofVerification: Dict[str, Any]
    message: str


class TransparencyVerifyResult(TypedDict, total=False):
    transparencyId: str
    verifiedAt: str
    durationMs: int
    result: Literal["VALID", "INVALID", "PARTIAL", "ERROR"]
    signatureValid: Optional[bool]
    signerKeyStatus: Optional[str]
    integrityChecks: List[TransparencyCheck]
    firstFailure: Optional[TransparencyCheck]


class TransparencyChainValidation(TypedDict, total=False):
    """``GET /v1/transparency/admin/chain/validate`` data."""

    chainValidation: Dict[str, Any]  # {valid, checkedCount, failureId, failureDetail}
    startId: Optional[str]
    endId: Optional[str]
    limit: int
    validatedAt: str
    validatedBy: str


# ---------------------------------------------------------------------------
# Portal —: rewritten to match the real, synchronous
# ``POST /v1/portal/verify`` contract. There is no async submit/poll model on
# the server; these types replace an earlier aspirational shape that never
# matched any real route.
# ---------------------------------------------------------------------------

PortalOverallResult = Literal["VERIFIED", "VERIFIED_WITH_WARNINGS", "FAILED"]


class PortalCheckResult(TypedDict, total=False):
    check: str
    result: Literal["PASS", "FAIL", "WARN", "SKIP"]
    reason: str


class PortalWarning(TypedDict):
    check: str
    reason: str


class PortalVerifyMetadata(TypedDict):
    publicKeyId: Optional[str]
    timestampMs: Optional[int]
    expiryMs: Optional[int]
    artifactId: Optional[str]


class PortalVerifyResult(TypedDict):
    """``POST /v1/portal/verify``'s ``data`` — a complete report, returned
    in one call."""

    verificationId: str
    overallResult: PortalOverallResult
    failedCheck: Optional[str]
    failureReason: Optional[str]
    warnings: List[PortalWarning]
    checks: List[PortalCheckResult]
    metadata: PortalVerifyMetadata
    durationMs: int
    verifiedAt: str


class PortalVerificationRecord(TypedDict):
    """``GET /v1/portal/result/:id``'s ``data.verification`` — the
    persisted record, a raw PostgreSQL row (snake_case columns, unlike
    :class:`PortalVerifyResult` above). Requires PostgreSQL to be enabled
    server-side; this route 404s otherwise, even for a ``verificationId``
    ``verify()`` itself just returned. The submitter address
    (``submission_ip``) is internal audit data and is not part of this public
    record."""

    # BIGSERIAL/BIGINT columns — the pg driver serializes these as strings to
    # avoid silent precision loss above Number.MAX_SAFE_INTEGER; confirmed
    # live, not a typo.
    id: str
    verification_id: str
    artifact_fingerprint: str
    artifact_public_key_id: Optional[str]
    artifact_timestamp_ms: Optional[str]
    artifact_expiry_ms: Optional[str]
    artifact_id: Optional[str]
    overall_result: PortalOverallResult
    checks_performed: List[PortalCheckResult]
    failed_check: Optional[str]
    failure_reason: Optional[str]
    warnings: List[PortalWarning]
    transparency_id: Optional[str]
    submitted_by: str
    duration_ms: Optional[int]
    verified_at: str


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


class WebhookCreateRequest(TypedDict, total=False):
    tenantId: str
    url: str
    eventTypes: List[str]
    description: str


class WebhookEndpoint(TypedDict, total=False):
    id: str
    tenant_id: str
    url: str
    enabled: bool
    event_types: List[str]
    description: str
    created_by: str
    created_at: str
    updated_at: str


class WebhookCreateResult(TypedDict, total=False):
    """`create()`'s response — the only call that returns the one-time secret."""
    endpoint: WebhookEndpoint
    secret: str
    notice: str


class WebhookRecord(TypedDict, total=False):
    """`get()`/`update()`'s response — no secret (only returned once, at creation)."""
    endpoint: WebhookEndpoint


class WebhookListResponse(TypedDict, total=False):
    """`list()`'s response — array key is `endpoints`, not a generic pagination `entries`."""
    endpoints: List[WebhookEndpoint]
    page: int
    pageSize: int
    total: int
    totalItems: int
    totalPages: int
    hasNextPage: bool
    hasPreviousPage: bool


class WebhookUpdateRequest(TypedDict, total=False):
    url: str
    eventTypes: List[str]
    description: str
    # Real field name accepted by the server — NOT `active`.
    enabled: bool


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class PaginationParams(TypedDict, total=False):
    page: int
    page_size: int
    sort_order: Literal["asc", "desc"]
    # camelCase spellings (the server's own names, used throughout the README and examples) — accepted as aliases
    pageSize: int
    sortOrder: Literal["asc", "desc"]


class PaginatedResponse(TypedDict, Generic[T]):
    """Matches `src/utils/pagination.js`'s shared `withPaginationMeta()` helper,
    used by `transparency.list_entries()`. Some other list endpoints (e.g.
    `webhooks.list()` -> `endpoints`, `certification.list()` -> `certifications`)
    use a differently-named array under their own response, not this generic
    shape — see `WebhookListResponse`/`CertificationListResponse`.
    """
    entries: List[T]
    page: int
    pageSize: int
    total: int
    totalItems: int
    totalPages: int
    hasNextPage: bool
    hasPreviousPage: bool


# ---------------------------------------------------------------------------
# API envelope
# ---------------------------------------------------------------------------


class ApiResponse(TypedDict, Generic[T]):
    status: Literal["success"]
    timestamp: str
    requestId: str
    data: T
