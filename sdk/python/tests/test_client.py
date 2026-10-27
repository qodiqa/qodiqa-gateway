"""Tests for QodiqaClient and AsyncQodiqaClient convenience methods."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import ValidationError

BASE_URL = "http://test.local"
VALID_KEY = "ok_" + "c" * 64


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestHealthCheck:
    def test_returns_health_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "ok", "uptime": 12345})
        result = make_client().health_check()
        assert result["status"] == "ok"
        assert result["uptime"] == 12345

    async def test_async_health_check(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "ok", "uptime": 42})
        async with make_async_client() as client:
            result = await client.health_check()
        assert result["status"] == "ok"


class TestReadinessCheck:
    def test_returns_readiness_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={
                "ready": True,
                "components": {
                    "nonceStore": True,
                    "anomalyStore": True,
                    "rateLimitStore": True,
                },
            }
        )
        result = make_client().readiness_check()
        assert result["ready"] is True
        assert result["components"]["nonceStore"] is True


class TestGetPublicKeys:
    def test_returns_keys_list(self, httpx_mock: HTTPXMock) -> None:
        # Real server response is enveloped ({status,timestamp,requestId,data})
        # — confirmed live during's SDK-accuracy sweep. get_public_keys()
        # unwraps ["data"] internally so callers can use keys["keys"] directly.
        httpx_mock.add_response(
            json={
                "status": "success",
                "timestamp": "2024-01-01T00:00:00Z",
                "requestId": "req-keys-1",
                "data": {
                    "keys": [
                        {"keyId": "key-1", "algorithm": "RS256", "publicKey": "MIIBIj...", "status": "active"}
                    ]
                },
            }
        )
        result = make_client().get_public_keys()
        assert len(result["keys"]) == 1
        assert result["keys"][0]["keyId"] == "key-1"


class TestGetPublicKey:
    def test_returns_public_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            json={"keyId": "key-1", "algorithm": "Ed25519", "publicKey": "...", "status": "active"}
        )
        result = make_client().get_public_key("key-1")
        assert result["keyId"] == "key-1"

    def test_raises_on_empty_key_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().get_public_key("")


class TestGetAuditChain:
    def test_returns_audit_chain(self, httpx_mock: HTTPXMock) -> None:
        # /audit/:artifactId is ops-gated server-side (adminStack('READ_AUDIT'))
        # — confirmed live during's SDK-accuracy sweep. Requires api_key.
        httpx_mock.add_response(
            json={
                "artifactId": "art-abc",
                "decision": "EXECUTE",
                "reason": "OK",
                "timestamp": "2024-01-01T00:00:00Z",
                "chain": [],
                "requestId": "req-001",
            }
        )
        result = make_client(api_key=VALID_KEY).get_audit_chain("art-abc")
        assert result["artifactId"] == "art-abc"
        assert result["decision"] == "EXECUTE"

    def test_raises_authentication_error_without_api_key(self) -> None:
        from qodiqa.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError):
            make_client().get_audit_chain("art-abc")

    def test_raises_on_empty_artifact_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).get_audit_chain("")


class TestAsyncClient:
    async def test_all_resources_available(self) -> None:
        async with make_async_client() as client:
            assert client.sign is not None
            assert client.chat is not None
            assert client.verify is not None
            assert client.portal is not None
            assert client.attestation is not None
            assert client.transparency is not None
            assert client.evidence is not None
            assert client.certification is not None
            assert client.webhooks is not None

    async def test_context_manager_closes_cleanly(self) -> None:
        async with make_async_client():
            pass
