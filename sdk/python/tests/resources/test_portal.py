"""Tests for PortalResource and AsyncPortalResource.

rewritten to match the real, synchronous
``POST /v1/portal/verify`` contract. There is no async submit/poll model on
the server; the old submit()/get_status()/wait_for_result() tests targeted
routes that never existed.
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import ValidationError

BASE_URL = "http://test.local"

MOCK_ARTIFACT = {
    "expiry": 9999999999999,
    "payload": {
        "requestId": "req-portal",
        "requestHash": "h1",
        "policyHash": "h2",
        "tenantId": "t1",
    },
    "publicKeyId": "key-1",
    "timestamp": 1000,
    "signature": "sig-1",
}

PORTAL_VERIFY_RESULT = {
    "verificationId": "ver-001",
    "overallResult": "VERIFIED",
    "failedCheck": None,
    "failureReason": None,
    "warnings": [],
    "checks": [{"check": "SIGNATURE", "result": "PASS"}],
    "metadata": {"publicKeyId": "key-1", "timestampMs": 1000, "expiryMs": 2000, "artifactId": None},
    "durationMs": 12,
    "verifiedAt": "2026-08-14T00:00:00.000Z",
}

PORTAL_VERIFICATION_RECORD = {
    "verification": {
        "id": "1",
        "verification_id": "ver-001",
        "artifact_fingerprint": "f" * 64,
        "artifact_public_key_id": "key-1",
        "artifact_timestamp_ms": "1000",
        "artifact_expiry_ms": "2000",
        "artifact_id": None,
        "overall_result": "VERIFIED",
        "checks_performed": [{"check": "SIGNATURE", "result": "PASS"}],
        "failed_check": None,
        "failure_reason": None,
        "warnings": [],
        "transparency_id": None,
        "submitted_by": "public",
        "duration_ms": 12,
        "verified_at": "2026-08-14T00:00:00.000Z",
    },
}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestPortalVerify:
    def test_returns_a_complete_report_in_one_call(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFY_RESULT)
        result = make_client().portal.verify(MOCK_ARTIFACT)
        assert result["verificationId"] == "ver-001"
        assert result["overallResult"] == "VERIFIED"

    def test_posts_to_verify_url_with_the_raw_artifact(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFY_RESULT)
        make_client().portal.verify(MOCK_ARTIFACT)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/portal/verify")
        import json as _json

        sent_body = _json.loads(req.content)
        assert sent_body["signature"] == "sig-1"
        assert "artifact" not in sent_body

    def test_surfaces_a_failed_report_as_a_normal_return_value(self, httpx_mock: HTTPXMock) -> None:
        failed = {**PORTAL_VERIFY_RESULT, "overallResult": "FAILED", "failedCheck": "SIGNATURE"}
        httpx_mock.add_response(json=failed)
        result = make_client().portal.verify(MOCK_ARTIFACT)
        assert result["overallResult"] == "FAILED"
        assert result["failedCheck"] == "SIGNATURE"


class TestPortalGetResult:
    def test_returns_the_persisted_record(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFICATION_RECORD)
        result = make_client().portal.get_result("ver-001")
        assert result["verification"]["verification_id"] == "ver-001"
        assert result["verification"]["overall_result"] == "VERIFIED"

    def test_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFICATION_RECORD)
        make_client().portal.get_result("ver-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/portal/result/ver-001" in str(req.url)

    def test_raises_on_empty_verification_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().portal.get_result("")


class TestAsyncPortalResource:
    async def test_verify(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFY_RESULT)
        async with make_async_client() as client:
            result = await client.portal.verify(MOCK_ARTIFACT)
        assert result["verificationId"] == "ver-001"
        assert result["overallResult"] == "VERIFIED"

    async def test_get_result(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=PORTAL_VERIFICATION_RECORD)
        async with make_async_client() as client:
            result = await client.portal.get_result("ver-001")
        assert result["verification"]["overall_result"] == "VERIFIED"

    async def test_raises_on_empty_verification_id(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.portal.get_result("")
