"""API/SDK contract fixes.

* API-02 an artifact rejection is a VerificationError from create() AND stream(), in both server BLOCK modes
* API-03 non-idempotent requests are retried only when the server guarantees they were not processed
* API-04 operator MFA step-up: typed errors and the otp_provider resend
"""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa._http import should_retry_request
from qodiqa.exceptions import (
    VERIFICATION_REASONS,
    AuthenticationError,
    BlockedError,
    MfaEnrollmentRequiredError,
    MfaLockedError,
    MfaRequiredError,
    RateLimitError,
    ServerError,
    VerificationError,
)

BASE = "http://test.local"
ART = "dGVzdC1hcnRpZmFjdA=="
KEY = "ok_" + "a" * 64


def _block(reason: str) -> dict:
    return {"decision": "BLOCK", "reason": reason, "details": {}, "requestId": "00000000-0000-4000-8000-000000000000"}


def _mfa(code: str) -> dict:
    return {"status": "error", "timestamp": "t", "requestId": None, "error": {"code": code, "message": code}}


def _client(**kw) -> QodiqaClient:
    return QodiqaClient(api_key=KEY, base_url=BASE, max_retries=kw.pop("max_retries", 2), **kw)


# ── API-02 ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("status", [200, 403])
def test_invalid_signature_both_paths_raise_verification_error(httpx_mock: HTTPXMock, status: int) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=status, json=_block("INVALID_SIGNATURE"))
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=status, json=_block("INVALID_SIGNATURE"))
    c = _client()
    with pytest.raises(VerificationError):
        c.chat.create(ART, {"prompt": "hi"})
    with pytest.raises(VerificationError):
        next(iter(c.chat.stream(ART, {"prompt": "hi"})))


def test_key_revoked_and_replay_are_verification_errors(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=200, json=_block("KEY_REVOKED"))
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=409, json=_block("REPLAY_DETECTED"))
    c = _client()
    with pytest.raises(VerificationError) as e:
        c.chat.create(ART, {"prompt": "hi"})
    assert e.value.reason == "KEY_REVOKED"
    with pytest.raises(VerificationError):
        c.chat.create(ART, {"prompt": "hi"})


def test_policy_block_returned_by_create_raised_by_stream(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=200, json=_block("CONSENT_SUSPENDED"))
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=200, json=_block("CONSENT_SUSPENDED"))
    c = _client()
    r = c.chat.create(ART, {"prompt": "hi"})
    assert (r["decision"], r["reason"]) == ("BLOCK", "CONSENT_SUSPENDED")
    with pytest.raises(BlockedError) as e:
        next(iter(c.chat.stream(ART, {"prompt": "hi"})))
    assert e.value.reason == "CONSENT_SUSPENDED"


@pytest.mark.asyncio
async def test_async_create_raises_verification_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=200, json=_block("EXPIRED"))
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE) as c:
        with pytest.raises(VerificationError):
            await c.chat.create(ART, {"prompt": "hi"})


def test_verification_list_size() -> None:
    assert len(VERIFICATION_REASONS) == 31  # 26 + the four protocol-V2 reasons + ARTIFACT_REVOKED


# ── API-03 ────────────────────────────────────────────────────────────────────


def test_post_ai_chat_502_not_resent(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=502, json=_block("PROVIDER_UNAVAILABLE"))
    with pytest.raises(ServerError):
        _client().chat.create(ART, {"prompt": "hi"})
    assert len(httpx_mock.get_requests()) == 1


def test_post_ai_chat_server_overloaded_resent(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "0"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=200, json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "ok"})
    r = _client().chat.create(ART, {"prompt": "hi"})
    assert r["decision"] == "EXECUTE"
    assert len(httpx_mock.get_requests()) == 2


def test_retry_predicate() -> None:
    e = lambda status, reason=None: ServerError("x", status=status, reason=reason)  # noqa: E731
    assert should_retry_request(e(502), "GET", "/v1/webhooks") is True
    assert should_retry_request(e(502), "POST", "/v1/webhooks") is False
    assert should_retry_request(RateLimitError("x"), "POST", "/sign") is True
    assert should_retry_request(RateLimitError("x"), "POST", "/v1/ai/chat") is False
    assert should_retry_request(MfaLockedError("x", reason="MFA_LOCKED"), "GET", "/x") is False


# ── API-04 ────────────────────────────────────────────────────────────────────


def test_mfa_typed_errors(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=401, json=_mfa("MFA_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=403, json=_mfa("MFA_ENROLLMENT_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=429, json=_mfa("MFA_LOCKED"))
    c = _client()
    with pytest.raises(MfaRequiredError) as a:
        c.webhooks.delete("w1", "tenant-1")
    assert isinstance(a.value, AuthenticationError)
    with pytest.raises(MfaEnrollmentRequiredError):
        c.webhooks.delete("w1", "tenant-1")
    with pytest.raises(MfaLockedError):
        c.webhooks.delete("w1", "tenant-1")
    assert len(httpx_mock.get_requests()) == 3  # MFA_LOCKED never retried


def test_otp_provider_resends_once(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=401, json=_mfa("MFA_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=200, json={"status": "success", "data": {}})
    calls = []
    _client(otp_provider=lambda: calls.append(1) or "123456").webhooks.delete("w1", "tenant-1")
    reqs = httpx_mock.get_requests()
    assert len(reqs) == 2 and len(calls) == 1
    assert "x-qodiqa-otp" not in reqs[0].headers
    assert reqs[1].headers["x-qodiqa-otp"] == "123456"


def test_otp_provider_wrong_code_surfaced(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=401, json=_mfa("MFA_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=f"{BASE}/v1/webhooks/w1?tenantId=tenant-1", status_code=401, json=_mfa("MFA_INVALID"))
    with pytest.raises(MfaRequiredError) as e:
        _client(otp_provider=lambda: "000000").webhooks.delete("w1", "tenant-1")
    assert e.value.reason == "MFA_INVALID"
    assert len(httpx_mock.get_requests()) == 2


# ── 2026-10-06 ─────────────────────────

_W1 = f"{BASE}/v1/webhooks/w1?tenantId=tenant-1"


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
def test_pl01_request_with_otp_is_never_auto_retried(httpx_mock: HTTPXMock) -> None:
    # Before the fix the OTP header per request was [None, '100000', '100000'] and the final error MFA_INVALID.
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=401, json=_mfa("MFA_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=502, json=_block("PROVIDER_UNAVAILABLE"))
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=401, json=_mfa("MFA_INVALID"))
    calls = []
    with pytest.raises(ServerError) as e:
        _client(max_retries=2, otp_provider=lambda: calls.append(1) or "100000").webhooks.delete("w1", "tenant-1")
    assert not isinstance(e.value, MfaRequiredError)
    assert e.value.status == 502
    assert [r.headers.get("x-qodiqa-otp") for r in httpx_mock.get_requests()] == [None, "100000"]
    assert len(calls) == 1


@pytest.mark.httpx_mock(assert_all_responses_were_requested=False)
async def test_pl01_async_request_with_otp_is_never_auto_retried(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=401, json=_mfa("MFA_REQUIRED"))
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=502, json=_block("PROVIDER_UNAVAILABLE"))
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=401, json=_mfa("MFA_INVALID"))
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE, max_retries=2, otp_provider=lambda: "100000") as c:
        with pytest.raises(ServerError) as e:
            await c.webhooks.delete("w1", "tenant-1")
    assert e.value.status == 502
    assert [r.headers.get("x-qodiqa-otp") for r in httpx_mock.get_requests()] == [None, "100000"]


def test_pl01_requests_without_otp_keep_their_retries(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=502, json=_block("X"))
    httpx_mock.add_response(method="DELETE", url=_W1, status_code=200, json={"status": "success", "data": {}})
    _client(max_retries=2).webhooks.delete("w1", "tenant-1")
    assert len(httpx_mock.get_requests()) == 2


def test_pl14_create_sends_idempotency_key_only_when_given(httpx_mock: HTTPXMock) -> None:
    ok = {"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "ok"}
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", json=ok)
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", json=ok)
    c = _client()
    c.chat.create(ART, {"prompt": "hi"}, idempotency_key="idem-123")
    c.chat.create(ART, {"prompt": "hi"})
    reqs = httpx_mock.get_requests()
    assert reqs[0].headers["idempotency-key"] == "idem-123"
    assert "idempotency-key" not in reqs[1].headers
    from qodiqa.exceptions import ValidationError

    with pytest.raises(ValidationError):
        c.chat.create(ART, {"prompt": "hi"}, idempotency_key=" ")


async def test_pl14_async_create_sends_idempotency_key(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", json={"decision": "EXECUTE", "response": "ok"})
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE) as c:
        await c.chat.create(ART, {"prompt": "hi"}, idempotency_key="idem-async")
    assert httpx_mock.get_requests()[0].headers["idempotency-key"] == "idem-async"


def test_pl16_request_id_falls_back_to_x_request_id_header(httpx_mock: HTTPXMock) -> None:
    rid = "11111111-1111-4111-8111-111111111111"
    httpx_mock.add_response(
        method="DELETE", url=_W1, status_code=503,
        json={"success": False, "error": {"code": "SERVICE_SHUTTING_DOWN", "message": "draining"}},
        headers={"x-request-id": rid},
    )
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=502, json=_block("PROVIDER_RESPONSE_INVALID"), headers={"x-request-id": rid})
    c = _client(max_retries=0)
    with pytest.raises(ServerError) as a:
        c.webhooks.delete("w1", "tenant-1")
    assert a.value.request_id == rid
    with pytest.raises(ServerError) as b:
        c.chat.create(ART, {"prompt": "hi"})
    assert b.value.request_id == "00000000-0000-4000-8000-000000000000"  # a body requestId wins


def test_pl19_stream_default_keeps_connect_timeout(httpx_mock: HTTPXMock) -> None:
    sse = {"content-type": "text/event-stream"}
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=sse, content=b"data: [DONE]\n\n")
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=sse, content=b"data: [DONE]\n\n")
    c = QodiqaClient(api_key=KEY, base_url=BASE, timeout=7.0)
    list(c.chat.stream(ART, {"prompt": "hi"}))
    list(c.chat.stream(ART, {"prompt": "hi"}, timeout=3.0))
    t0, t1 = (r.extensions["timeout"] for r in httpx_mock.get_requests())
    assert t0["connect"] == 7.0 and t0["read"] is None and t0["pool"] is None
    assert t1 == {"connect": 3.0, "read": 3.0, "write": 3.0, "pool": 3.0}


async def test_pl19_async_stream_default_keeps_connect_timeout(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers={"content-type": "text/event-stream"}, content=b"data: [DONE]\n\n")
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE, timeout=7.0) as c:
        async for _ in c.chat.stream(ART, {"prompt": "hi"}):
            pass
    t = httpx_mock.get_requests()[0].extensions["timeout"]
    assert t["connect"] == 7.0 and t["read"] is None
