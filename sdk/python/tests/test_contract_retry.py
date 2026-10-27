"""API/SDK contract fixes.

* P15-01 a server-stated Retry-After is honoured on every retryable error (503 SERVER_OVERLOADED included), a wait
  longer than the retry cap surfaces the error, and stream() resends a pre-stream 503 SERVER_OVERLOADED (admission
  refuses before nonce registration) like create() does
* P15-02 Retry-After is parsed as delta-seconds or HTTP-date, for every body shape
* P15-03 a stream body that ends without the terminal [DONE] frame is a NetworkError, not a normal end
* P15-04 the flat protocol-limiter 429 body maps its ``error`` code to ``err.reason``; the window name stays in
  ``details["blockedBy"]``

Evidence:
"""

from __future__ import annotations

import json as _json
from email.utils import formatdate
import time

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa import _http
from qodiqa.exceptions import NetworkError, RateLimitError, ServerError

BASE = "http://test.local"
ART = "dGVzdC1hcnRpZmFjdA=="
KEY = "ok_" + "a" * 64
SSE = {"content-type": "text/event-stream"}
STARTED = {"event": "stream_started", "streamId": "s", "requestId": "r", "artifactId": "r", "provider": "p", "model": "m"}
COMPLETED = {"event": "stream_completed", "streamId": "s", "requestId": "r", "chunksTotal": 0, "bytesTotal": 0, "durationMs": 1}


def _block(reason: str) -> dict:
    return {"decision": "BLOCK", "reason": reason, "details": {}, "requestId": "00000000-0000-4000-8000-000000000000"}


def _sse(*frames: object) -> bytes:
    return b"".join(
        b"data: " + (f if isinstance(f, bytes) else _json.dumps(f).encode()) + b"\n\n" for f in frames
    )


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list:
    recorded: list = []
    monkeypatch.setattr(_http.time, "sleep", lambda s: recorded.append(s))
    return recorded


def test_p15_01_create_waits_server_overloaded_retry_after(httpx_mock: HTTPXMock, sleeps: list) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "1"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "ok"})
    r = QodiqaClient(api_key=KEY, base_url=BASE, max_retries=2).chat.create(ART, {"prompt": "hi"})
    assert r["decision"] == "EXECUTE"
    assert sleeps == [1.0]  # before: one jittered back-off in [0, 0.5) — the server's Retry-After was ignored


async def test_p15_01_async_create_waits_server_overloaded_retry_after(httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    recorded: list = []

    async def fake_sleep(s: float) -> None:
        recorded.append(s)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "2"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "response": "ok"})
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE, max_retries=2) as c:
        r = await c.chat.create(ART, {"prompt": "hi"})
    assert r["decision"] == "EXECUTE"
    assert recorded == [2.0]


def test_p15_01_retry_after_beyond_cap_is_not_retried_early(httpx_mock: HTTPXMock, sleeps: list) -> None:
    httpx_mock.add_response(method="GET", url=f"{BASE}/health", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "3600"})
    with pytest.raises(ServerError) as e:
        QodiqaClient(api_key=KEY, base_url=BASE, max_retries=2).health_check()
    assert e.value.details["retryAfter"] == 3600.0
    assert len(httpx_mock.get_requests()) == 1
    assert sleeps == []


def test_p15_02_retry_after_http_date_and_non_json_body(httpx_mock: HTTPXMock) -> None:
    future = formatdate(time.time() + 5, usegmt=True)
    httpx_mock.add_response(method="GET", url=f"{BASE}/health", status_code=429, json=_block("RATE_LIMITED"), headers={"retry-after": future})
    with pytest.raises(RateLimitError) as e1:
        QodiqaClient(api_key=KEY, base_url=BASE, max_retries=0).health_check()
    assert e1.value.retry_after is not None and e1.value.retry_after >= 3

    httpx_mock.add_response(method="GET", url=f"{BASE}/health", status_code=503, headers={"content-type": "text/html", "retry-after": "7"}, content=b"<html>busy</html>")
    with pytest.raises(ServerError) as e2:
        QodiqaClient(api_key=KEY, base_url=BASE, max_retries=0).health_check()
    assert e2.value.details.get("retryAfter") == 7.0

    assert _http._parse_retry_after("not a date") is None
    assert _http._parse_retry_after("") is None
    assert _http._parse_retry_after(None) is None
    assert _http._parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT") == 0.0


def test_p15_03_stream_without_done_is_network_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=SSE, content=_sse(STARTED, {"event": "chunk_forwarded", "delta": "partial", "index": 0}))
    events = []
    with pytest.raises(NetworkError, match=r"\[DONE\]"):
        for ev in QodiqaClient(api_key=KEY, base_url=BASE).chat.stream(ART, {"prompt": "hi"}):
            events.append(ev)
    assert len(events) == 2


async def test_p15_03_async_stream_without_done_is_network_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=SSE, content=_sse(STARTED))
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE) as c:
        with pytest.raises(NetworkError, match=r"\[DONE\]"):
            async for _ in c.chat.stream(ART, {"prompt": "hi"}):
                pass


def test_p15_03_complete_stream_still_ends_normally(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=SSE, content=_sse(STARTED, COMPLETED, b"[DONE]"))
    events = list(QodiqaClient(api_key=KEY, base_url=BASE).chat.stream(ART, {"prompt": "hi"}))
    assert [e["event"] for e in events] == ["stream_started", "stream_completed"]


def test_p15_01_stream_resends_pre_stream_server_overloaded(httpx_mock: HTTPXMock, sleeps: list) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "1"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=SSE, content=_sse(STARTED, COMPLETED, b"[DONE]"))
    events = list(QodiqaClient(api_key=KEY, base_url=BASE, max_retries=2).chat.stream(ART, {"prompt": "hi"}))
    assert [e["event"] for e in events] == ["stream_started", "stream_completed"]
    assert len(httpx_mock.get_requests()) == 2
    assert sleeps == [1.0]


async def test_p15_01_async_stream_resends_pre_stream_server_overloaded(httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def fake_sleep(s: float) -> None:
        return None

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("SERVER_OVERLOADED"), headers={"retry-after": "0"})
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", headers=SSE, content=_sse(STARTED, COMPLETED, b"[DONE]"))
    async with AsyncQodiqaClient(api_key=KEY, base_url=BASE, max_retries=2) as c:
        events = [e async for e in c.chat.stream(ART, {"prompt": "hi"})]
    assert [e["event"] for e in events] == ["stream_started", "stream_completed"]
    assert len(httpx_mock.get_requests()) == 2


def test_p15_01_stream_never_resends_other_pre_stream_errors(httpx_mock: HTTPXMock, sleeps: list) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/ai/chat", status_code=503, json=_block("PROVIDER_UNAVAILABLE"), headers={"retry-after": "0"})
    with pytest.raises(ServerError):
        list(QodiqaClient(api_key=KEY, base_url=BASE, max_retries=2).chat.stream(ART, {"prompt": "hi"}))
    assert len(httpx_mock.get_requests()) == 1
    assert sleeps == []


def test_p15_04_flat_limiter_body_maps_error_code(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/sign", status_code=429, headers={"retry-after": "3"},
        json={"error": "RATE_LIMIT_EXCEEDED", "surface": "sign", "dimension": "identity", "reason": "BURST", "retryAfterSeconds": 3, "requestId": None},
    )
    c = QodiqaClient(sign_token="sk_x", base_url=BASE, max_retries=0)
    with pytest.raises(RateLimitError) as e:
        c.sign.sign({"request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}}})
    assert e.value.reason == "RATE_LIMIT_EXCEEDED"  # before: "BURST" (the limiter window name)
    assert e.value.details["blockedBy"] == "BURST"
    assert e.value.details["surface"] == "sign" and e.value.details["dimension"] == "identity"
    assert e.value.retry_after == 3.0


def test_p15_05_verify_v2_posts_body_to_verify_v2(httpx_mock: HTTPXMock) -> None:
    """JS/Python parity: the JS SDK has verifyV2() (POST /verify/v2); Python had no equivalent."""
    httpx_mock.add_response(method="POST", url=f"{BASE}/verify/v2", json={"decision": "EXECUTE", "reason": "ALL_CHECKS_PASSED", "details": {}, "requestId": None})
    body = {"artifact": {"payload": {}}, "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}}}
    r = QodiqaClient(base_url=BASE).verify.verify_v2(body)  # type: ignore[arg-type]
    assert r["decision"] == "EXECUTE"
    req = httpx_mock.get_requests()[0]
    assert _json.loads(req.content) == body
    assert "x-qodiqa-artifact" not in req.headers


async def test_p15_05_async_verify_v2(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(method="POST", url=f"{BASE}/verify/v2", json={"decision": "BLOCK", "reason": "EXPIRED", "details": {}, "requestId": None})
    async with AsyncQodiqaClient(base_url=BASE) as c:
        r = await c.verify.verify_v2({"artifact": {}, "request": {"method": "POST", "path": "/x", "body": {}}})  # type: ignore[typeddict-item]
    assert r["reason"] == "EXPIRED"
