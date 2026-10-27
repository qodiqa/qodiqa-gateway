"""QODIQA Python SDK.

Official Python client for the QODIQA AI enforcement platform.

Quick start::

    from qodiqa import QodiqaClient

    client = QodiqaClient(
        sign_token="your-sign-token",
        base_url="http://localhost:3000",
    )

    # Health check
    health = client.health_check()

    # Sign a request
    signed = client.sign.sign({
        "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "Hello"}},
        "payload": {"userId": "user_123"},
        "ttl": 300_000,
    })

    # Enforced AI chat
    import base64, json
    artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
    chat = client.chat.create(artifact_b64, {"prompt": "Hello"})
    if chat["decision"] == "EXECUTE":
        print(chat.get("aiText"))
"""

from ._version import __version__

from .client import AsyncQodiqaClient, QodiqaClient

from .agent_proof import (
    AGENT_PROOF_DOMAIN,
    agent_proof_digest,
    generate_agent_key_pair,
    sign_agent_proof,
)
from .resources.agents_actions import is_approval_pending

from .exceptions import (
    VERIFICATION_REASONS,
    AuthenticationError,
    AuthorizationError,
    BlockedError,
    MfaEnrollmentRequiredError,
    MfaLockedError,
    MfaRequiredError,
    CryptoKeyError,
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTimestampError,
    MalformedSignatureError,
    NetworkError,
    NotFoundError,
    QodiqaError,
    RateLimitError,
    SerializationError,
    ServerError,
    KillSwitchError,
    SigningError,
    TimeoutError,
    UnknownError,
    ValidationError,
    VerificationError,
)

from .webhook_verifier import (
    verify_webhook_signature,
    WebhookVerifier,
    DEFAULT_TOLERANCE_SECONDS,
)

from ._verification import (
    ArtifactVerificationResult,
    ArtifactVerifier,
    AsyncArtifactVerifier,
    AsyncKeyProvider,
    AsyncRemoteKeyProvider,
    CanonicalizationError,
    FailedStage,
    KeyProvider,
    RemoteKeyProvider,
    ResolvedKey,
    StaticKeyProvider,
    TransparencyVerificationDetail,
    TransparencyVerifiedState,
    VerificationStatus,
    create_async_key_provider,
    create_key_provider,
    request_hash,
    stable_stringify,
    verify_artifact,
    verify_inclusion_path,
    verify_receipt,
    ANCHOR_DOMAIN,
    anchor_statement_digest,
    check_anchor_line,
    receipt_binds_to,
    receipt_digest,
    RECEIPT_DOMAIN,
    ReceiptVerifyResult,
)

from .models import (
    ApiResponse,
    Artifact,
    ArtifactPayload,
    AuditChainEntry,
    AuditResponse,
    BatchRecord,
    ChatRequest,
    ChatResponse,
    ChatTransparency,
    AiDisclosure,
    Receipt,
    SignV2Options,
    ChatStreamCancelledEvent,
    ChatStreamChunkEvent,
    ChatStreamCompletedEvent,
    ChatStreamEvent,
    ChatStreamStartedEvent,
    CertificationRecord,
    AttestationRecord,
    HealthResponse,
    HttpMethod,
    InclusionProof,
    KeysResponse,
    KeyStatus,
    PaginatedResponse,
    PaginationParams,
    PortalOverallResult,
    PortalCheckResult,
    PortalWarning,
    PortalVerifyMetadata,
    PortalVerifyResult,
    PortalVerificationRecord,
    PublicKey,
    ReadyResponse,
    SignMeta,
    SignRequest,
    SignResponse,
    TokenUsage,
    TransparencyEntry,
    TransparencyRegisterResult,
    ConsentGrantRequest,
    ConsentRecord,
    LawfulBasis,
    LawfulBasisStatus,
    SpecialCategoryCondition,
    TransparencyRoot,
    TransparencyVerifyResult,
    VerifyRequest,
    VerifyResponse,
    WebhookCreateRequest,
    WebhookRecord,
    WebhookUpdateRequest,
)

from ._pagination import (
    AsyncPageIterator,
    AsyncPagePage,
    PageIterator,
    PagePage,
)

from .config import ClientConfig

__all__ = [
    'AGENT_PROOF_DOMAIN',
    'agent_proof_digest',
    'generate_agent_key_pair',
    'sign_agent_proof',
    'is_approval_pending',
    # Version
    "__version__",
    # Clients
    "QodiqaClient",
    "AsyncQodiqaClient",
    # Configuration
    "ClientConfig",
    # Exceptions
    "QodiqaError",
    "BlockedError",
    "MfaRequiredError",
    "MfaEnrollmentRequiredError",
    "MfaLockedError",
    "VERIFICATION_REASONS",
    "AuthenticationError",
    "AuthorizationError",
    "ValidationError",
    "VerificationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "KillSwitchError",
    "NetworkError",
    "TimeoutError",
    "UnknownError",
    "SigningError",
    "SerializationError",
    "CryptoKeyError",
    # Webhook verification errors
    "InvalidSignatureError",
    "ExpiredSignatureError",
    "MalformedSignatureError",
    "InvalidTimestampError",
    # Webhook verification helpers
    "verify_webhook_signature",
    "WebhookVerifier",
    "DEFAULT_TOLERANCE_SECONDS",
    # Local artifact & transparency-proof verification — fully
    # offline, no dependency on the server's own /verify verdict.
    "ArtifactVerifier",
    "AsyncArtifactVerifier",
    "verify_artifact",
    "ArtifactVerificationResult",
    "TransparencyVerificationDetail",
    "VerificationStatus",
    "TransparencyVerifiedState",
    "FailedStage",
    "KeyProvider",
    "AsyncKeyProvider",
    "StaticKeyProvider",
    "RemoteKeyProvider",
    "AsyncRemoteKeyProvider",
    "ResolvedKey",
    "create_key_provider",
    "create_async_key_provider",
    "CanonicalizationError",
    "stable_stringify",
    "request_hash",
    "verify_inclusion_path",
    "verify_receipt",
    "ANCHOR_DOMAIN",
    "anchor_statement_digest",
    "check_anchor_line",
    "receipt_binds_to",
    "receipt_digest",
    "RECEIPT_DOMAIN",
    "ReceiptVerifyResult",
    # Models / types
    "ApiResponse",
    "Artifact",
    "ArtifactPayload",
    "AuditChainEntry",
    "AuditResponse",
    "AttestationRecord",
    "BatchRecord",
    "CertificationRecord",
    "ChatRequest",
    "ChatResponse",
    "ChatTransparency",
    "AiDisclosure",
    "Receipt",
    "SignV2Options",
    "ChatStreamEvent",
    "ChatStreamStartedEvent",
    "ChatStreamChunkEvent",
    "ChatStreamCompletedEvent",
    "ChatStreamCancelledEvent",
    "HealthResponse",
    "HttpMethod",
    "InclusionProof",
    "KeysResponse",
    "KeyStatus",
    "PaginatedResponse",
    "PaginationParams",
    "PortalOverallResult",
    "PortalCheckResult",
    "PortalWarning",
    "PortalVerifyMetadata",
    "PortalVerifyResult",
    "PortalVerificationRecord",
    "PublicKey",
    "ReadyResponse",
    "SignMeta",
    "SignRequest",
    "SignResponse",
    "TokenUsage",
    "TransparencyEntry",
    "TransparencyRegisterResult",
    "ConsentGrantRequest",
    "ConsentRecord",
    "LawfulBasis",
    "LawfulBasisStatus",
    "SpecialCategoryCondition",
    "TransparencyRoot",
    "TransparencyVerifyResult",
    "VerifyRequest",
    "VerifyResponse",
    "WebhookCreateRequest",
    "WebhookRecord",
    "WebhookUpdateRequest",
    # Pagination helpers
    "PageIterator",
    "PagePage",
    "AsyncPageIterator",
    "AsyncPagePage",
]
