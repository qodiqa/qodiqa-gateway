"""Tests for qodiqa._verification._transparency_proof, driven by the shared
generated conformance vectors (test-vectors/artifact-v1.json).
"""

from __future__ import annotations

import json
import os

import pytest

from qodiqa import StaticKeyProvider
from qodiqa._verification._transparency_proof import verify_transparency_proof

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "test-vectors", "artifact-v1.json")

with open(VECTORS_PATH, "r", encoding="utf-8") as f:
    _VECTOR_FILE = json.load(f)

_PROOF_VECTORS = [v for v in _VECTOR_FILE["transparencyVectors"] if v["proof"] is not None]


@pytest.mark.parametrize("vector", _PROOF_VECTORS, ids=[v["id"] for v in _PROOF_VECTORS])
def test_conformance_vector(vector) -> None:
    detail = verify_transparency_proof(vector["proof"], StaticKeyProvider(vector["transparencyKeySet"]))
    verified = "verified" if detail.all_passed() else "failed"
    assert verified == vector["expected"]["transparencyVerified"]

    field_map = {
        "entryHashValid": "entry_hash_valid",
        "merklePathValid": "merkle_path_valid",
        "entrySignatureValid": "entry_signature_valid",
        "rootSignatureValid": "root_signature_valid",
        "leafIndexValid": "leaf_index_valid",
        "keyValid": "key_valid",
    }
    for key, expected in vector["expected"].items():
        if key == "transparencyVerified":
            continue
        assert getattr(detail, field_map[key]) == expected


def test_never_raises_on_completely_malformed_proof() -> None:
    keys = StaticKeyProvider([])
    detail = verify_transparency_proof({}, keys)
    assert detail.all_passed() is False
    detail2 = verify_transparency_proof(None, keys)
    assert detail2.all_passed() is False


def test_unknown_transparency_key_resolves_to_key_invalid_not_an_exception() -> None:
    valid = next(v for v in _PROOF_VECTORS if v["id"] == "valid-merkle-proof")
    detail = verify_transparency_proof(valid["proof"], StaticKeyProvider([]))
    assert detail.key_valid is False
    assert detail.entry_signature_valid is False
