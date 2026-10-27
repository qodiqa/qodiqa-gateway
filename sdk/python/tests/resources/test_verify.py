"""Tests for VerifyResource and AsyncVerifyResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import ValidationError, VerificationError

BASE_URL = "http://test.local"
ARTIFACT_B64 = "dGVzdC1hcnRpZmFjdA=="

VERIFY_RESPONSE = {
    "decision": "EXECUTE",
    "reason": "OK",
    "requestId": "req-verify-001",
}

VERIFY_REQUEST = {
    "artifact": {"expiry": 9999999999, "signature": "sig"},
    "request": {"method": "POST", "path": "/ai/chat"},
}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestVerifyResource:
    def test_returns_decision(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        result = make_client().verify.verify(ARTIFACT_B64, VERIFY_REQUEST)
        assert result["decision"] == "EXECUTE"

    def test_does_not_send_artifact_header(self, httpx_mock: HTTPXMock) -> None:
        # /verify reads the artifact from the body only; the header was never part of its contract
        # (the server ignored it; the JS SDK stopped sending it).
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        make_client().verify.verify(ARTIFACT_B64, VERIFY_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert "x-qodiqa-artifact" not in req.headers

    def test_posts_to_verify_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        make_client().verify.verify(ARTIFACT_B64, VERIFY_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/verify")

    def test_raises_on_empty_artifact(self) -> None:
        with pytest.raises(ValidationError):
            make_client().verify.verify("", VERIFY_REQUEST)

    def test_raises_on_whitespace_artifact(self) -> None:
        with pytest.raises(ValidationError):
            make_client().verify.verify("   ", VERIFY_REQUEST)

    def test_invalid_signature_raises_verification_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=400,
            json={"reason": "INVALID_SIGNATURE", "message": "Bad signature"},
        )
        with pytest.raises(VerificationError):
            make_client().verify.verify(ARTIFACT_B64, VERIFY_REQUEST)

    def test_expired_raises_verification_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=400,
            json={"reason": "EXPIRED", "message": "expired"},
        )
        with pytest.raises(VerificationError):
            make_client().verify.verify(ARTIFACT_B64, VERIFY_REQUEST)


class TestVerifyDryRun:
    def test_dry_run_no_artifact_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        make_client().verify.dry_run(VERIFY_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert "x-qodiqa-artifact" not in req.headers

    def test_dry_run_returns_decision(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"decision": "BLOCK", "reason": "POLICY"})
        result = make_client().verify.dry_run(VERIFY_REQUEST)
        assert result["decision"] == "BLOCK"


class TestAsyncVerifyResource:
    async def test_returns_decision(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        async with make_async_client() as client:
            result = await client.verify.verify(ARTIFACT_B64, VERIFY_REQUEST)
        assert result["decision"] == "EXECUTE"

    async def test_raises_on_empty_artifact(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.verify.verify("", VERIFY_REQUEST)

    async def test_dry_run_no_artifact_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=VERIFY_RESPONSE)
        async with make_async_client() as client:
            await client.verify.dry_run(VERIFY_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert "x-qodiqa-artifact" not in req.headers
