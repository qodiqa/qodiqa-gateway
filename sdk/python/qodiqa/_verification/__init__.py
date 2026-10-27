"""Local, offline cryptographic verification of QODIQA execution artifacts
. Internal implementation package — the public surface is
re-exported flatly from :mod:`qodiqa`, matching this SDK's existing
``_http.py`` / ``_pagination.py`` "private implementation, flat public
re-export" convention.
"""

from ._artifact_verifier import ArtifactVerifier, AsyncArtifactVerifier, verify_artifact
from ._canonical_json import CanonicalizationError, stable_stringify
from ._domain_hash import request_hash
from ._key_providers import (
    AsyncKeyProvider,
    AsyncRemoteKeyProvider,
    KeyProvider,
    RemoteKeyProvider,
    ResolvedKey,
    StaticKeyProvider,
    create_async_key_provider,
    create_key_provider,
)
from ._merkle import verify_inclusion_path
from ._anchor import ANCHOR_DOMAIN, anchor_statement_digest, check_anchor_line
from ._receipt import RECEIPT_DOMAIN, ReceiptVerifyResult, receipt_binds_to, receipt_digest, verify_receipt
from ._result_types import (
    ArtifactVerificationResult,
    FailedStage,
    TransparencyVerificationDetail,
    TransparencyVerifiedState,
    VerificationStatus,
)

__all__ = [
    "ArtifactVerifier",
    "AsyncArtifactVerifier",
    "verify_artifact",
    "CanonicalizationError",
    "stable_stringify",
    "request_hash",
    "KeyProvider",
    "AsyncKeyProvider",
    "StaticKeyProvider",
    "RemoteKeyProvider",
    "AsyncRemoteKeyProvider",
    "ResolvedKey",
    "create_key_provider",
    "create_async_key_provider",
    "verify_inclusion_path",
    "verify_receipt",
    "ANCHOR_DOMAIN",
    "anchor_statement_digest",
    "check_anchor_line",
    "receipt_binds_to",
    "receipt_digest",
    "RECEIPT_DOMAIN",
    "ReceiptVerifyResult",
    "ArtifactVerificationResult",
    "TransparencyVerificationDetail",
    "VerificationStatus",
    "TransparencyVerifiedState",
    "FailedStage",
]
