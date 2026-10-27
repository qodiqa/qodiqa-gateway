"""Tests for qodiqa.ArtifactVerifier / AsyncArtifactVerifier / verify_artifact."""

from __future__ import annotations

import json
import os

import pytest

import base64

from qodiqa import (
    ArtifactVerifier,
    AsyncArtifactVerifier,
    ResolvedKey,
    StaticKeyProvider,
    create_async_key_provider,
    create_key_provider,
    verify_artifact,
)
from qodiqa.exceptions import ValidationError

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "artifact-v1.json")

with open(VECTORS_PATH, "r", encoding="utf-8") as f:
    _VECTOR_FILE = json.load(f)

_VALID_VECTOR = next(v for v in _VECTOR_FILE["artifactVectors"] if v["id"] == "valid-artifact")


class TestConstructorValidation:
    def test_raises_without_keys(self) -> None:
        with pytest.raises(TypeError):
            ArtifactVerifier()  # type: ignore[call-arg]

    def test_raises_when_keys_is_none(self) -> None:
        with pytest.raises(ValidationError):
            ArtifactVerifier(keys=None)  # type: ignore[arg-type]

    def test_raises_when_require_transparency_without_transparency_keys(self) -> None:
        with pytest.raises(ValidationError):
            ArtifactVerifier(keys=StaticKeyProvider([]), require_transparency=True)


class TestValidArtifact:
    def test_reports_every_stage_as_passed(self) -> None:
        verifier = ArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]), _now=_VALID_VECTOR["verifyAt"])
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.verification_status == "valid"
        assert result.signature_valid is True
        assert result.payload_hash_valid is True
        assert result.canonicalization_valid is True
        assert result.key_valid is True
        assert result.key_id == "test-vectors:key_v1"
        assert result.key_status == "active"
        assert result.key_source == "live"
        assert result.timestamp_valid is True
        assert result.expiry_valid is True
        assert result.transparency_verified == "unavailable"
        assert result.failed_stage is None
        assert result.verification_errors == []


class TestKeySource:
    """result.key_source is diagnostic-only and never affects validity."""

    def test_defaults_to_live_when_provider_does_not_set_source(self) -> None:
        verifier = ArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]), _now=_VALID_VECTOR["verifyAt"])
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.key_source == "live"

    def test_reports_archived_when_resolved_with_source_archived(self) -> None:
        entry = _VALID_VECTOR["keySet"][0]

        def lookup(key_id: str):
            if key_id == entry["keyId"]:
                return ResolvedKey(pub_der=base64.b64decode(entry["publicKey"]), status="deprecated", source="archived")
            return None

        verifier = ArtifactVerifier(keys=create_key_provider(lookup), _now=_VALID_VECTOR["verifyAt"])
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.key_source == "archived"
        # Purely diagnostic — never affects the validity outcome.
        assert result.key_valid is True
        assert result.verification_status == "valid"

    def test_none_when_no_key_resolved(self) -> None:
        verifier = ArtifactVerifier(keys=StaticKeyProvider([]), _now=_VALID_VECTOR["verifyAt"])
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.key_source is None
        assert result.failed_stage == "KEY_RESOLUTION"

    async def test_async_reports_archived_when_resolved_with_source_archived(self) -> None:
        entry = _VALID_VECTOR["keySet"][0]

        async def lookup(key_id: str):
            if key_id == entry["keyId"]:
                return ResolvedKey(pub_der=base64.b64decode(entry["publicKey"]), status="deprecated", source="archived")
            return None

        verifier = AsyncArtifactVerifier(keys=create_async_key_provider(lookup), _now=_VALID_VECTOR["verifyAt"])
        result = await verifier.verify(_VALID_VECTOR["artifact"])
        assert result.key_source == "archived"
        assert result.verification_status == "valid"


class TestVerifyArtifactFunction:
    def test_matches_artifact_verifier(self) -> None:
        result = verify_artifact(
            _VALID_VECTOR["artifact"], keys=StaticKeyProvider(_VALID_VECTOR["keySet"]), _now=_VALID_VECTOR["verifyAt"]
        )
        assert result.verification_status == "valid"


class TestNeverRaisesForContentProblems:
    verifier = ArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]))

    @pytest.mark.parametrize(
        "garbage",
        [
            None,
            "a string",
            42,
            [],
            {},
            {"expiry": 1, "payload": {}, "publicKeyId": "k", "signature": "x", "timestamp": 1, "extra": "field"},
            {"payload": {"a": 1}},
        ],
    )
    def test_does_not_raise(self, garbage) -> None:
        result = self.verifier.verify(garbage)
        assert result is not None
        assert result.verification_status in ("invalid", "error")

    def test_key_provider_that_raises_surfaces_as_error_status(self) -> None:
        class ThrowingProvider:
            def get_public_key(self, key_id: str):
                raise RuntimeError("network down")

        verifier = ArtifactVerifier(keys=ThrowingProvider())
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.verification_status == "error"
        assert result.failed_stage == "KEY_RESOLUTION"
        assert any("network down" in e for e in result.verification_errors)


class TestTransparencyWiring:
    def _find_transparency_vector(self, vector_id: str):
        return next(v for v in _VECTOR_FILE["transparencyVectors"] if v["id"] == vector_id)

    def test_unverifiable_proof_fails_overall_result(self) -> None:
        bad = self._find_transparency_vector("wrong-merkle-root")
        verifier = ArtifactVerifier(
            keys=StaticKeyProvider(_VALID_VECTOR["keySet"]),
            transparency_keys=StaticKeyProvider(bad["transparencyKeySet"]),
            _now=_VALID_VECTOR["verifyAt"],
        )
        result = verifier.verify(_VALID_VECTOR["artifact"], transparency_proof=bad["proof"])
        assert result.transparency_verified == "failed"
        assert result.verification_status == "invalid"
        assert result.failed_stage == "TRANSPARENCY"

    def test_require_transparency_fails_when_no_proof_supplied(self) -> None:
        verifier = ArtifactVerifier(
            keys=StaticKeyProvider(_VALID_VECTOR["keySet"]),
            transparency_keys=StaticKeyProvider([]),
            require_transparency=True,
            _now=_VALID_VECTOR["verifyAt"],
        )
        result = verifier.verify(_VALID_VECTOR["artifact"])
        assert result.transparency_verified == "unavailable"
        assert result.verification_status == "invalid"
        assert result.failed_stage == "TRANSPARENCY"

    def test_proof_without_configured_provider_is_unavailable_with_warning(self) -> None:
        good = self._find_transparency_vector("valid-merkle-proof")
        verifier = ArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]), _now=_VALID_VECTOR["verifyAt"])
        result = verifier.verify(_VALID_VECTOR["artifact"], transparency_proof=good["proof"])
        assert result.transparency_verified == "unavailable"
        assert len(result.verification_warnings) > 0
        assert result.verification_status == "valid"


class TestAsyncArtifactVerifier:
    async def test_reports_valid_for_a_genuine_artifact(self) -> None:
        verifier = AsyncArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]), _now=_VALID_VECTOR["verifyAt"])
        result = await verifier.verify(_VALID_VECTOR["artifact"])
        assert result.verification_status == "valid"

    async def test_does_not_raise_for_garbage_input(self) -> None:
        verifier = AsyncArtifactVerifier(keys=StaticKeyProvider(_VALID_VECTOR["keySet"]))
        result = await verifier.verify(None)
        assert result.verification_status in ("invalid", "error")

    async def test_async_key_provider_failure_surfaces_as_error_status(self) -> None:
        class ThrowingAsyncProvider:
            async def get_public_key(self, key_id: str):
                raise RuntimeError("network down")

        verifier = AsyncArtifactVerifier(keys=ThrowingAsyncProvider())
        result = await verifier.verify(_VALID_VECTOR["artifact"])
        assert result.verification_status == "error"
        assert result.failed_stage == "KEY_RESOLUTION"


class TestNumericStrictness:
    """timestamp / expiry follow the gateway's rule: positive safe integers, timestamp < expiry."""


    def test_rules(self) -> None:
        from qodiqa._verification._artifact_verifier import _is_safe_positive_int

        assert _is_safe_positive_int(1_700_000_000_000)
        assert _is_safe_positive_int(1_700_000_000_000.0)      # integral float == the same JSON number in JavaScript
        assert not _is_safe_positive_int(1_700_000_000_000.5)
        assert not _is_safe_positive_int(2**53)
        assert not _is_safe_positive_int(0)
        assert not _is_safe_positive_int(True)
        assert not _is_safe_positive_int(float("nan"))

    @pytest.mark.parametrize("delta", [("ts_plus_half", 0.5), ("equal", None), ("inverted", -1)])
    def test_structure_rejects(self, delta) -> None:
        from qodiqa._verification._artifact_verifier import _validate_structure
        from qodiqa._verification._result_types import ArtifactVerificationResult

        base = {"payload": {}, "publicKeyId": "k", "signature": base64.b64encode(b"\x00" * 64).decode()}
        name, d = delta
        if name == "ts_plus_half":
            art = {**base, "timestamp": 1_700_000_000_000.5, "expiry": 1_700_000_060_000}
        elif name == "equal":
            art = {**base, "timestamp": 1_700_000_000_000, "expiry": 1_700_000_000_000}
        else:
            art = {**base, "timestamp": 1_700_000_060_000, "expiry": 1_700_000_000_000}
        res = ArtifactVerificationResult(verified_at=1_700_000_000_000)
        assert _validate_structure(art, res) is None
        assert res.failed_stage == "STRUCTURE"
