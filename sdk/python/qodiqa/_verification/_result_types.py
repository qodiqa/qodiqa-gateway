"""Structured result types for local artifact/transparency verification.

Constructed entirely by SDK code (never round-tripped from a raw server
JSON body), so these are frozen ``dataclasses`` rather than ``TypedDict`` —
better ergonomics and immutability guarantees for a locally-computed result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Literal, Optional

from ..models import KeyStatus

VerificationStatus = Literal["valid", "invalid", "error"]

TransparencyVerifiedState = Literal["verified", "failed", "unavailable"]

FailedStage = Optional[
    Literal[
        "STRUCTURE",
        "CANONICALIZATION",
        "KEY_RESOLUTION",
        "FUTURE_TIMESTAMP",
        "EXPIRED",
        "INVALID_SIGNATURE",
        "TRANSPARENCY",
    ]
]


@dataclass(frozen=True)
class TransparencyVerificationDetail:
    entry_hash_valid: bool
    merkle_path_valid: bool
    entry_signature_valid: bool
    root_signature_valid: bool
    leaf_index_valid: bool
    key_valid: bool
    key_status: Optional[KeyStatus]

    def all_passed(self) -> bool:
        return (
            self.entry_hash_valid
            and self.merkle_path_valid
            and self.leaf_index_valid
            and self.key_valid
            and self.entry_signature_valid
            and self.root_signature_valid
        )


@dataclass
class ArtifactVerificationResult:
    """Structured result of a fully local, offline artifact verification.

    ``payload_hash_valid`` / ``canonicalization_valid`` deliberately do NOT
    represent an independent stored-hash comparison — the real QODIQA
    artifact envelope has no separately-stored payload hash field; the
    recomputed hash only ever serves as the Ed25519 verification message.
    These two fields instead mean "canonicalization and envelope-hash
    computation completed without a structural/protocol error" (no
    forbidden keys, no non-finite numbers, no non-plain-object payload,
    etc). ``signature_valid`` is the field that actually detects tampering,
    since any change to the canonical payload changes the Ed25519 message
    and the signature stops verifying.
    """

    verification_status: VerificationStatus = "invalid"
    signature_valid: bool = False
    payload_hash_valid: bool = False
    canonicalization_valid: bool = False
    key_valid: bool = False
    key_id: Optional[str] = None
    key_status: Optional[KeyStatus] = None
    #: Which discovery tier resolved `key_id`: "live" (the ordinary case) or
    #: "archived" when the key was only resolvable via the archived-key
    #fallback, i.e. it had already been purged from the live
    #: keystore. `None` when no key was resolved at all. Purely diagnostic —
    #: never affects `key_valid`.
    key_source: Optional[str] = None
    expiry_valid: bool = False
    timestamp_valid: bool = False
    transparency_verified: TransparencyVerifiedState = "unavailable"
    transparency_detail: Optional[TransparencyVerificationDetail] = None
    verification_errors: List[str] = field(default_factory=list)
    verification_warnings: List[str] = field(default_factory=list)
    failed_stage: FailedStage = None
    verified_at: int = 0
