"""Tests for the internal HTTP client (sync and async)."""

from __future__ import annotations

import pytest
import httpx
from pytest_httpx import HTTPXMock

from qodiqa._http import HttpClient, AsyncHttpClient
from qodiqa.config import ClientConfig
from qodiqa.exceptions import (
    AuthenticationError,
    AuthorizationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    ServerError,
    TimeoutError,
    ValidationError,
    VerificationError,
)

BASE_URL = "http://test.local"


def make_sync_client(max_retries: int = 0, timeout: float = 5.0) -> HttpClient:
    return HttpClient(ClientConfig(base_url=BASE_URL, max_retries=max_retries, timeout=timeout))


def make_async_client(max_retries: int = 0, timeout: float = 5.0) -> AsyncHttpClient:
    return AsyncHttpClient(ClientConfig(base_url=BASE_URL, max_retries=max_retries, timeout=timeout))


class TestSyncGet:
    def test_parses_json_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"hello": "world"})
        client = make_sync_client()
        result = client.get("/test")
        assert result == {"hello": "world"}

    def test_sends_content_type_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = make_sync_client()
        client.get("/test")
        req = httpx_mock.get_requests()[0]
        assert req.headers["accept"] == "application/json"

    def test_query_params_sent(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = make_sync_client()
        client.get("/items", params={"page": 2, "pageSize": 25})
        req = httpx_mock.get_requests()[0]
        assert "page=2" in str(req.url)
        assert "pageSize=25" in str(req.url)

    def test_none_params_omitted(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = make_sync_client()
        client.get("/items", params={"page": 1, "filter": None})
        req = httpx_mock.get_requests()[0]
        assert "filter" not in str(req.url)


class TestSyncPost:
    def test_serialises_body_as_json(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"ok": True})
        client = make_sync_client()
        client.post("/test", {"name": "qodiqa"})
        req = httpx_mock.get_requests()[0]
        import json
        assert json.loads(req.content) == {"name": "qodiqa"}

    def test_post_without_body(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = make_sync_client()
        client.post("/test")


class TestSyncErrorMapping:
    def test_401_raises_authentication_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"reason": "UNAUTHORIZED", "message": "Bad token", "requestId": "r1"},
        )
        client = make_sync_client()
        with pytest.raises(AuthenticationError):
            client.get("/protected")

    def test_403_raises_authorization_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=403,
            json={"reason": "FORBIDDEN", "message": "No access", "requestId": "r2"},
        )
        client = make_sync_client()
        with pytest.raises(AuthorizationError):
            client.get("/admin")

    def test_404_raises_not_found_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=404,
            json={"reason": "NOT_FOUND", "message": "Gone", "requestId": "r3"},
        )
        client = make_sync_client()
        with pytest.raises(NotFoundError):
            client.get("/missing")

    def test_429_raises_rate_limit_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=429,
            json={"reason": "RATE_LIMITED", "message": "Slow down"},
            headers={"retry-after": "30"},
        )
        client = make_sync_client()
        with pytest.raises(RateLimitError):
            client.get("/slow")

    def test_400_raises_validation_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=400,
            json={"reason": "VALIDATION_ERROR", "message": "Bad input"},
        )
        client = make_sync_client()
        with pytest.raises(ValidationError):
            client.post("/validate", {})

    def test_500_raises_server_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=500,
            json={"reason": "INTERNAL_ERROR", "message": "Boom"},
        )
        client = make_sync_client()
        with pytest.raises(ServerError):
            client.get("/broken")

    def test_request_id_attached_to_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=404,
            json={"reason": "NOT_FOUND", "message": "Gone", "requestId": "my-req-id"},
        )
        client = make_sync_client()
        with pytest.raises(NotFoundError) as exc_info:
            client.get("/err")
        assert exc_info.value.request_id == "my-req-id"

    # D26-7: MANAGEMENT_ERROR envelope ({status:'error', error:{code,message,
    # details}}, used by the management/admin/observability surface — webhooks,
    # attestation, certification, transparency, RBAC, audit) — previously never
    # read at all, silently dropping the real message and falling back to the
    # generic "HTTP {status}" text. Confirmed live during against a real
    # /v1/webhooks 400.
    def test_management_error_envelope_surfaces_error_code_and_message(
        self, httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            status_code=400,
            json={
                "status": "error",
                "timestamp": "2026-08-13T00:00:00.000Z",
                "requestId": "req-mgmt-1",
                "error": {
                    "code": "INVALID_PARAM",
                    "message": "tenantId query parameter is required",
                    "details": {"field": "tenantId"},
                },
            },
        )
        client = make_sync_client()
        with pytest.raises(ValidationError) as exc_info:
            client.post("/v1/webhooks", {})
        # A caller reading exc.message gets the real server text, not a
        # generic "HTTP 400" fallback — this is what "readable by an SDK
        # caller" means, not merely present somewhere on the wire.
        assert exc_info.value.message == "tenantId query parameter is required"
        assert exc_info.value.request_id == "req-mgmt-1"
        assert exc_info.value.details == {"field": "tenantId"}

    def test_management_error_401_still_classifies_authentication_error(
        self, httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={
                "status": "error",
                "requestId": "req-mgmt-2",
                "error": {"code": "UNAUTHORIZED", "message": "Missing authentication credentials"},
            },
        )
        client = make_sync_client()
        with pytest.raises(AuthenticationError) as exc_info:
            client.get("/audit/art-1")
        assert exc_info.value.message == "Missing authentication credentials"

    # (SDK half): create_error() used to check status==403 before checking
    # reason code, so a real REQUEST_MISMATCH (or any of the other 7
    # VerificationError reasons) at HTTP 403 — which is how the server always
    # sends them, per src/errors/catalog.js — was masked as AuthorizationError.
    def test_request_mismatch_at_403_raises_verification_error_not_authorization(
        self, httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            status_code=403,
            json={
                "decision": "BLOCK",
                "reason": "REQUEST_MISMATCH",
                "details": {"issue": "requestHash does not match actual request"},
                "requestId": "req-vf-1",
            },
        )
        client = make_sync_client()
        with pytest.raises(VerificationError):
            client.post("/ai/chat", {})

    @pytest.mark.parametrize(
        "reason",
        [
            "INVALID_SIGNATURE", "INVALID_ARTIFACT", "KEY_NOT_FOUND", "EXPIRED",
            "FUTURE_TIMESTAMP", "TIME_SKEW_EXCEEDED", "REQUEST_MISMATCH", "REPLAY_DETECTED",
        ],
    )
    def test_all_verification_reasons_at_403_classify_correctly(
        self, httpx_mock: HTTPXMock, reason: str,
    ) -> None:
        httpx_mock.add_response(
            status_code=403,
            json={"decision": "BLOCK", "reason": reason, "details": {}, "requestId": "req"},
        )
        client = make_sync_client()
        with pytest.raises(VerificationError):
            client.post("/ai/chat", {})

    # No misclassification introduced: a genuine 403 that is NOT one of the 8
    # VerificationError reasons still correctly raises AuthorizationError.
    def test_genuine_403_forbidden_still_raises_authorization_error(
        self, httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            status_code=403,
            json={"decision": "BLOCK", "reason": "FORBIDDEN", "details": {}, "requestId": "req-authz"},
        )
        client = make_sync_client()
        with pytest.raises(AuthorizationError):
            client.get("/v1/admin/restricted")

    def test_401_unaffected_by_reorder(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"decision": "BLOCK", "reason": "UNAUTHORIZED", "details": {}, "requestId": "req-auth"},
        )
        client = make_sync_client()
        with pytest.raises(AuthenticationError):
            client.get("/v1/admin/x")

    def test_network_error_raised(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        client = make_sync_client()
        with pytest.raises(NetworkError):
            client.get("/unreachable")

    def test_timeout_error_raised(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.TimeoutException("timeout"))
        client = make_sync_client()
        with pytest.raises(TimeoutError):
            client.get("/slow")


class TestSyncRetry:
    def test_retries_on_500_and_succeeds(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=500, json={"reason": "INTERNAL_ERROR", "message": "fail"})
        httpx_mock.add_response(status_code=500, json={"reason": "INTERNAL_ERROR", "message": "fail"})
        httpx_mock.add_response(json={"ok": True})
        client = make_sync_client(max_retries=3)
        result = client.get("/flaky")
        assert result == {"ok": True}

    def test_exhausts_retries_and_raises(self, httpx_mock: HTTPXMock) -> None:
        for _ in range(4):
            httpx_mock.add_response(status_code=500, json={"reason": "INTERNAL_ERROR", "message": "fail"})
        client = make_sync_client(max_retries=3)
        with pytest.raises(ServerError):
            client.get("/always-fails")

    def test_does_not_retry_401(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=401, json={"reason": "UNAUTHORIZED", "message": "bad"})
        client = make_sync_client(max_retries=3)
        with pytest.raises(AuthenticationError):
            client.get("/protected")
        assert len(httpx_mock.get_requests()) == 1

    def test_does_not_retry_404(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=404, json={"reason": "NOT_FOUND", "message": "gone"})
        client = make_sync_client(max_retries=3)
        with pytest.raises(NotFoundError):
            client.get("/gone")
        assert len(httpx_mock.get_requests()) == 1


class TestSyncHeaders:
    def test_default_headers_merged(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = HttpClient(
            ClientConfig(base_url=BASE_URL, default_headers={"x-tenant": "t1"})
        )
        client.get("/h")
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-tenant"] == "t1"

    def test_per_request_headers_override_defaults(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={})
        client = HttpClient(
            ClientConfig(base_url=BASE_URL, default_headers={"x-custom": "default"})
        )
        client.get("/h2", headers={"x-custom": "override"})
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-custom"] == "override"


class TestAsyncGet:
    async def test_parses_json_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"hello": "async"})
        client = make_async_client()
        result = await client.get("/test")
        assert result == {"hello": "async"}

    async def test_401_raises_authentication_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"reason": "UNAUTHORIZED", "message": "bad"},
        )
        client = make_async_client()
        with pytest.raises(AuthenticationError):
            await client.get("/protected")

    async def test_context_manager(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"ok": True})
        async with make_async_client() as client:
            result = await client.get("/test")
        assert result == {"ok": True}

    async def test_retries_on_503(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=503, json={"reason": "SERVICE_UNAVAILABLE", "message": "down"})
        httpx_mock.add_response(json={"ok": True})
        client = make_async_client(max_retries=2)
        result = await client.get("/flaky")
        assert result == {"ok": True}
