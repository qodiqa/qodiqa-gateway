"""Tests for AttestationResource and AsyncAttestationResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import AuthenticationError, ValidationError

BASE_URL = "http://test.local"
VALID_KEY = "ok_" + "c" * 64

MOCK_ARTIFACT = {"expiry": 9999999999, "signature": "sig123"}
ATTESTATION_RECORD = {
    "id": "att-001",
    "decision": "EXECUTE",
    "reason": "OK",
    "timestamp": "2024-01-01T00:00:00Z",
}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestAttestationVerify:
    def test_posts_to_verify_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        make_client().attestation.verify(MOCK_ARTIFACT)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/attestation/verify")

    def test_returns_attestation(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        result = make_client().attestation.verify(MOCK_ARTIFACT)
        assert result["id"] == "att-001"


class TestAttestationVerifyEvidence:
    def test_posts_to_evidence_verify_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        make_client().attestation.verify_evidence(MOCK_ARTIFACT)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/attestation/evidence/verify")


class TestAttestationVerifyChain:
    def test_posts_to_chain_verify_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        make_client(api_key=VALID_KEY).attestation.verify_chain(MOCK_ARTIFACT)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/attestation/chain/verify")
        assert req.headers["authorization"].startswith("Bearer ok_")

    def test_requires_api_key(self) -> None:
        # admin router + MANAGE_ATTESTATIONS server-side — the ops key is required.
        with pytest.raises(AuthenticationError):
            make_client().attestation.verify_chain(evidence_ids=["e1"])


class TestAttestationGet:
    def test_returns_record(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        result = make_client().attestation.get("att-001")
        assert result["id"] == "att-001"

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().attestation.get("")

    def test_gets_from_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        make_client().attestation.get("att-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/attestation/att-001" in str(req.url)


class TestAttestationOpsEndpoints:
    def test_get_evidence_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().attestation.get_evidence("att-001")

    def test_get_evidence_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"evidence": []})
        make_client(api_key=VALID_KEY).attestation.get_evidence("att-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/attestation/att-001/evidence" in str(req.url)

    def test_get_summary_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().attestation.get_summary("att-001")

    def test_list_fetches_history_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [], "total": 0})
        make_client(api_key=VALID_KEY).attestation.list()
        req = httpx_mock.get_requests()[0]
        assert "/v1/attestation/admin/history" in str(req.url)

    def test_stats_fetches_stats_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"total": 42})
        make_client(api_key=VALID_KEY).attestation.stats()
        req = httpx_mock.get_requests()[0]
        assert "/v1/attestation/admin/stats" in str(req.url)


class TestAsyncAttestationResource:
    async def test_verify(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ATTESTATION_RECORD)
        async with make_async_client() as client:
            result = await client.attestation.verify(MOCK_ARTIFACT)
        assert result["id"] == "att-001"

    async def test_get_raises_on_empty_id(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.attestation.get("")

    async def test_stats_fetches_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"total": 10})
        async with make_async_client(api_key=VALID_KEY) as client:
            result = await client.attestation.stats()
        assert result["total"] == 10
