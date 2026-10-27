"""QODIQA Local Artifact & Transparency-Proof Verification —
Python SDK Conformance Test.

Loads the shared, language-neutral vector file
(test-vectors/artifact-v1.json) and verifies every vector with the real,
unmodified Python SDK verifier. Every signature, hash, and Merkle proof in
the vector file was produced by the production server signing/hashing code
(see test-vectors/generate-artifact-vectors.js) — nothing is regenerated
here.

``sdk/javascript``'s ``tests/artifact-conformance.test.ts`` loads this exact
same file and must produce identical outcomes per vector — that is the
cross-language consistency requirement for.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from qodiqa import ArtifactVerifier, StaticKeyProvider
from qodiqa._verification._transparency_proof import verify_transparency_proof

VECTORS_PATH = Path(__file__).resolve().parents[3] / "test-vectors" / "artifact-v1.json"

with open(VECTORS_PATH, "r", encoding="utf-8") as f:
    VECTOR_FILE: Dict[str, Any] = json.load(f)

ARTIFACT_VECTORS = VECTOR_FILE["artifactVectors"]
TRANSPARENCY_VECTORS = VECTOR_FILE["transparencyVectors"]

_ARTIFACT_FIELD_MAP = {
    "verificationStatus": "verification_status",
    "signatureValid": "signature_valid",
    "payloadHashValid": "payload_hash_valid",
    "canonicalizationValid": "canonicalization_valid",
    "keyValid": "key_valid",
    "keyStatus": "key_status",
    "timestampValid": "timestamp_valid",
    "expiryValid": "expiry_valid",
    "failedStage": "failed_stage",
}

_DETAIL_FIELD_MAP = {
    "entryHashValid": "entry_hash_valid",
    "merklePathValid": "merkle_path_valid",
    "entrySignatureValid": "entry_signature_valid",
    "rootSignatureValid": "root_signature_valid",
    "leafIndexValid": "leaf_index_valid",
    "keyValid": "key_valid",
}


class TestSharedVectorFile:
    def test_loads_and_is_non_empty(self) -> None:
        assert isinstance(ARTIFACT_VECTORS, list) and len(ARTIFACT_VECTORS) > 0
        assert isinstance(TRANSPARENCY_VECTORS, list) and len(TRANSPARENCY_VECTORS) > 0

    def test_vector_count_metadata_matches_actual_arrays(self) -> None:
        assert VECTOR_FILE["vectorCount"]["artifact"] == len(ARTIFACT_VECTORS)
        assert VECTOR_FILE["vectorCount"]["transparency"] == len(TRANSPARENCY_VECTORS)


@pytest.mark.parametrize("vector", ARTIFACT_VECTORS, ids=[v["id"] for v in ARTIFACT_VECTORS])
def test_artifact_conformance_vector(vector: Dict[str, Any]) -> None:
    verifier = ArtifactVerifier(
        keys=StaticKeyProvider(vector["keySet"]),
        _now=vector["verifyAt"],
        clock_tolerance_ms=vector["clockToleranceMs"],
    )
    result = verifier.verify(vector["artifact"])
    for key, expected in vector["expected"].items():
        actual = getattr(result, _ARTIFACT_FIELD_MAP[key])
        assert actual == expected, f"{vector['id']}.{key}: expected {expected!r}, got {actual!r}"


@pytest.mark.parametrize("vector", TRANSPARENCY_VECTORS, ids=[v["id"] for v in TRANSPARENCY_VECTORS])
def test_transparency_conformance_vector(vector: Dict[str, Any]) -> None:
    if vector["proof"] is None:
        # The "no proof supplied" case is verified through the full
        # ArtifactVerifier pipeline instead, using an arbitrary valid vector.
        artifact_vector = ARTIFACT_VECTORS[0]
        verifier = ArtifactVerifier(
            keys=StaticKeyProvider(artifact_vector["keySet"]),
            transparency_keys=StaticKeyProvider(vector["transparencyKeySet"]),
            _now=artifact_vector["verifyAt"],
        )
        result = verifier.verify(artifact_vector["artifact"])
        assert result.transparency_verified == vector["expected"]["transparencyVerified"]
        return

    detail = verify_transparency_proof(vector["proof"], StaticKeyProvider(vector["transparencyKeySet"]))
    verified = "verified" if detail.all_passed() else "failed"
    for key, expected in vector["expected"].items():
        actual = verified if key == "transparencyVerified" else getattr(detail, _DETAIL_FIELD_MAP[key])
        assert actual == expected, f"{vector['id']}.{key}: expected {expected!r}, got {actual!r}"
