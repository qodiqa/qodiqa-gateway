"""QODIQA local artifact verification — remediation.

Performs the complete verification pipeline entirely offline: schema
validation, canonical JSON reconstruction, payload-hash computation,
public-key resolution, Ed25519 signature verification, signed-metadata
validation, and optional transparency-proof verification. None of this
depends on calling the server's ``/verify`` endpoint or trusting its
response — ``resources/verify.py``'s ``POST /verify`` remains available as
an optional remote convenience only and is never used internally here.
"""

from __future__ import annotations

import base64
import binascii
import time
from typing import Any, Dict, Optional, cast

from ..exceptions import ValidationError
from ..models import KeyStatus
from ._canonical_json import CanonicalizationError
from ._domain_hash import envelope_hash
from ._ed25519 import verify_ed25519
from ._key_providers import AsyncKeyProvider, KeyProvider, maybe_await_get_public_key
from ._result_types import ArtifactVerificationResult
from ._transparency_proof import async_verify_transparency_proof, verify_transparency_proof

_ARTIFACT_SCHEMA = frozenset({"expiry", "payload", "publicKeyId", "signature", "timestamp"})
_SIG_BYTE_LEN = 64


def _is_plain_dict(value: Any) -> bool:
    return isinstance(value, dict)


_MAX_SAFE_INTEGER = 2**53 - 1


def _is_safe_positive_int(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and (value != value or not value.is_integer()):
        return False
    return 0 < value <= _MAX_SAFE_INTEGER


def _validate_structure(artifact: Any, result: ArtifactVerificationResult) -> Optional[Dict[str, Any]]:
    """Run stage 1 (structural/schema validation). Returns the artifact dict
    if structurally valid, or ``None`` after populating `result` with the
    failure.
    """
    if not _is_plain_dict(artifact):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact must be a dict/object.")
        return None

    for key in artifact.keys():
        if key not in _ARTIFACT_SCHEMA:
            result.failed_stage = "STRUCTURE"
            result.verification_errors.append(f'Unexpected field "{key}" is not part of the artifact envelope.')
            return None
    for field_name in _ARTIFACT_SCHEMA:
        if field_name not in artifact or artifact[field_name] is None:
            result.failed_stage = "STRUCTURE"
            result.verification_errors.append(f'Missing required field "{field_name}".')
            return None

    payload = artifact["payload"]
    timestamp = artifact["timestamp"]
    expiry = artifact["expiry"]
    signature = artifact["signature"]
    public_key_id = artifact["publicKeyId"]

    if not _is_plain_dict(payload):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact payload must be a dict/object.")
        return None
    # same numeric rule as the gateway: positive safe integers (an integral float such as 1.0 is the same JSON
    # number as 1 in JavaScript, so it is accepted), and timestamp < expiry.
    if not _is_safe_positive_int(timestamp):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact timestamp must be a positive safe integer (Unix ms).")
        return None
    if not _is_safe_positive_int(expiry):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact expiry must be a positive safe integer (Unix ms).")
        return None
    if timestamp >= expiry:
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact expiry must be greater than its timestamp.")
        return None
    if not isinstance(signature, str):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact signature must be a base64 string.")
        return None
    try:
        sig_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact signature is not valid base64.")
        return None
    if len(sig_bytes) != _SIG_BYTE_LEN:
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append(f"Artifact signature must decode to exactly {_SIG_BYTE_LEN} bytes.")
        return None
    if not isinstance(public_key_id, str) or not public_key_id.strip():
        result.failed_stage = "STRUCTURE"
        result.verification_errors.append("Artifact publicKeyId must be a non-empty string.")
        return None

    return cast(Dict[str, Any], artifact)


def _run_structure_and_canonicalization(artifact: Any, now: int) -> tuple[ArtifactVerificationResult, Optional[Dict[str, Any]], Optional[bytes]]:
    result = ArtifactVerificationResult(verified_at=now)

    validated = _validate_structure(artifact, result)
    if validated is None:
        return result, None, None

    try:
        hash_buf = envelope_hash(validated)
        result.canonicalization_valid = True
        result.payload_hash_valid = True
    except CanonicalizationError as exc:
        result.failed_stage = "CANONICALIZATION"
        result.verification_errors.append(f"Envelope canonicalization failed: {exc.message}")
        return result, None, None

    return result, validated, hash_buf


def _finalize_after_key(
    result: ArtifactVerificationResult,
    resolved_status: Optional[KeyStatus],
    public_key_id: str,
    resolution_error: Optional[str],
    resolved_source: Optional[str] = None,
) -> bool:
    """Populate key-resolution fields. Returns True if verification may proceed."""
    if resolution_error is not None:
        result.verification_status = "error"
        result.failed_stage = "KEY_RESOLUTION"
        result.verification_errors.append(f'Key provider failed to resolve "{public_key_id}": {resolution_error}')
        return False
    result.key_id = public_key_id
    if resolved_status is None:
        result.failed_stage = "KEY_RESOLUTION"
        result.verification_errors.append(f'Unknown key id "{public_key_id}".')
        return False
    result.key_status = resolved_status
    result.key_source = resolved_source or "live"
    result.key_valid = resolved_status in ("active", "deprecated")
    if not result.key_valid:
        result.failed_stage = "KEY_RESOLUTION"
        result.verification_errors.append(f'Key "{public_key_id}" has status "{resolved_status}" and cannot verify.')
        return False
    return True


def _check_timestamps(result: ArtifactVerificationResult, timestamp: float, expiry: float, now: int, tolerance_ms: int) -> bool:
    result.timestamp_valid = timestamp <= now + tolerance_ms
    if not result.timestamp_valid:
        result.failed_stage = "FUTURE_TIMESTAMP"
        result.verification_errors.append("Artifact timestamp is in the future.")
        return False
    result.expiry_valid = now - tolerance_ms < expiry
    if not result.expiry_valid:
        result.failed_stage = "EXPIRED"
        result.verification_errors.append("Artifact has expired.")
        return False
    return True


class ArtifactVerifier:
    """Local, offline verifier for QODIQA execution artifacts (sync).

    Example::

        verifier = ArtifactVerifier(
            keys=RemoteKeyProvider(discovery_url="https://api.example.com/.well-known/qodiqa/keys"),
        )
        result = verifier.verify(artifact)
        if result.verification_status != "valid":
            # result.verification_errors / result.failed_stage explain exactly why.
            ...
    """

    def __init__(
        self,
        *,
        keys: KeyProvider,
        transparency_keys: Optional[KeyProvider] = None,
        clock_tolerance_ms: int = 0,
        require_transparency: bool = False,
        _now: Optional[int] = None,
    ) -> None:
        if keys is None:
            raise ValidationError("ArtifactVerifier requires a `keys` KeyProvider.")
        if require_transparency and transparency_keys is None:
            raise ValidationError(
                "ArtifactVerifier: require_transparency=True requires a `transparency_keys` KeyProvider."
            )
        self._keys = keys
        self._transparency_keys = transparency_keys
        self._clock_tolerance_ms = clock_tolerance_ms
        self._require_transparency = require_transparency
        self._now = _now

    def verify(
        self,
        artifact: Any,
        *,
        transparency_proof: Optional[Dict[str, Any]] = None,
    ) -> ArtifactVerificationResult:
        """Run the full local verification pipeline against `artifact`.

        Never raises for content problems (malformed artifact, bad
        signature, unknown key, expired, bad transparency proof, even a
        key-provider network failure) — every such case resolves to a
        structured result instead.
        """
        now = self._now if self._now is not None else int(time.time() * 1000)
        result, validated, hash_buf = _run_structure_and_canonicalization(artifact, now)
        if validated is None or hash_buf is None:
            return result

        public_key_id = validated["publicKeyId"]
        try:
            resolved = self._keys.get_public_key(public_key_id)
            error: Optional[str] = None
        except Exception as exc:  # noqa: BLE001 - surfaced as a structured error field
            resolved = None
            error = str(exc)

        can_proceed = _finalize_after_key(
            result,
            resolved.status if resolved else None,
            public_key_id,
            error,
            resolved.source if resolved else None,
        )
        if not can_proceed:
            return result

        assert resolved is not None
        if not _check_timestamps(result, validated["timestamp"], validated["expiry"], now, self._clock_tolerance_ms):
            return result

        result.signature_valid = verify_ed25519(hash_buf, validated["signature"], resolved.pub_der)
        if not result.signature_valid:
            result.failed_stage = "INVALID_SIGNATURE"
            result.verification_errors.append("Ed25519 signature verification failed.")
            return result

        if transparency_proof:
            if self._transparency_keys is None:
                result.transparency_verified = "unavailable"
                result.verification_warnings.append(
                    "A transparency_proof was supplied but no transparency_keys provider is configured; "
                    "skipping transparency verification."
                )
            else:
                detail = verify_transparency_proof(transparency_proof, self._transparency_keys)
                result.transparency_detail = detail
                result.transparency_verified = "verified" if detail.all_passed() else "failed"
                if result.transparency_verified == "failed":
                    result.failed_stage = "TRANSPARENCY"
                    result.verification_errors.append("Transparency inclusion proof verification failed.")
                    return result
        elif self._require_transparency:
            result.transparency_verified = "unavailable"
            result.failed_stage = "TRANSPARENCY"
            result.verification_errors.append("Transparency verification is required but no transparency_proof was supplied.")
            return result
        else:
            result.transparency_verified = "unavailable"

        result.verification_status = "valid"
        return result


class AsyncArtifactVerifier:
    """Async counterpart of :class:`ArtifactVerifier`."""

    def __init__(
        self,
        *,
        keys: AsyncKeyProvider,
        transparency_keys: Optional[AsyncKeyProvider] = None,
        clock_tolerance_ms: int = 0,
        require_transparency: bool = False,
        _now: Optional[int] = None,
    ) -> None:
        if keys is None:
            raise ValidationError("AsyncArtifactVerifier requires a `keys` KeyProvider.")
        if require_transparency and transparency_keys is None:
            raise ValidationError(
                "AsyncArtifactVerifier: require_transparency=True requires a `transparency_keys` KeyProvider."
            )
        self._keys = keys
        self._transparency_keys = transparency_keys
        self._clock_tolerance_ms = clock_tolerance_ms
        self._require_transparency = require_transparency
        self._now = _now

    async def verify(
        self,
        artifact: Any,
        *,
        transparency_proof: Optional[Dict[str, Any]] = None,
    ) -> ArtifactVerificationResult:
        now = self._now if self._now is not None else int(time.time() * 1000)
        result, validated, hash_buf = _run_structure_and_canonicalization(artifact, now)
        if validated is None or hash_buf is None:
            return result

        public_key_id = validated["publicKeyId"]
        try:
            resolved = await maybe_await_get_public_key(self._keys, public_key_id)
            error: Optional[str] = None
        except Exception as exc:  # noqa: BLE001 - surfaced as a structured error field
            resolved = None
            error = str(exc)

        can_proceed = _finalize_after_key(
            result,
            resolved.status if resolved else None,
            public_key_id,
            error,
            resolved.source if resolved else None,
        )
        if not can_proceed:
            return result

        assert resolved is not None
        if not _check_timestamps(result, validated["timestamp"], validated["expiry"], now, self._clock_tolerance_ms):
            return result

        result.signature_valid = verify_ed25519(hash_buf, validated["signature"], resolved.pub_der)
        if not result.signature_valid:
            result.failed_stage = "INVALID_SIGNATURE"
            result.verification_errors.append("Ed25519 signature verification failed.")
            return result

        if transparency_proof:
            if self._transparency_keys is None:
                result.transparency_verified = "unavailable"
                result.verification_warnings.append(
                    "A transparency_proof was supplied but no transparency_keys provider is configured; "
                    "skipping transparency verification."
                )
            else:
                detail = await async_verify_transparency_proof(transparency_proof, self._transparency_keys)
                result.transparency_detail = detail
                result.transparency_verified = "verified" if detail.all_passed() else "failed"
                if result.transparency_verified == "failed":
                    result.failed_stage = "TRANSPARENCY"
                    result.verification_errors.append("Transparency inclusion proof verification failed.")
                    return result
        elif self._require_transparency:
            result.transparency_verified = "unavailable"
            result.failed_stage = "TRANSPARENCY"
            result.verification_errors.append("Transparency verification is required but no transparency_proof was supplied.")
            return result
        else:
            result.transparency_verified = "unavailable"

        result.verification_status = "valid"
        return result


def verify_artifact(
    artifact: Any,
    *,
    keys: KeyProvider,
    transparency_keys: Optional[KeyProvider] = None,
    clock_tolerance_ms: int = 0,
    require_transparency: bool = False,
    transparency_proof: Optional[Dict[str, Any]] = None,
    _now: Optional[int] = None,
) -> ArtifactVerificationResult:
    """One-shot convenience wrapper around :class:`ArtifactVerifier`.

    Example::

        result = verify_artifact(
            artifact,
            keys=StaticKeyProvider([{"keyId": "dev-local:key_v1", "publicKey": base64_der, "status": "active"}]),
        )
    """
    verifier = ArtifactVerifier(
        keys=keys,
        transparency_keys=transparency_keys,
        clock_tolerance_ms=clock_tolerance_ms,
        require_transparency=require_transparency,
        _now=_now,
    )
    return verifier.verify(artifact, transparency_proof=transparency_proof)
