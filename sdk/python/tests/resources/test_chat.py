"""Tests for ChatResource and AsyncChatResource."""

from __future__ import annotations

import time
from unittest.mock import patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import (
    AuthenticationError,
    NetworkError,
    QodiqaError,
    ServerError,
    TimeoutError,
    ValidationError,
    VerificationError,
)

from ..conftest import ChunkedAsyncStream, ChunkedSyncStream, chunk_bytes, sse_body

BASE_URL = "http://test.local"
ARTIFACT_B64 = "dGVzdC1hcnRpZmFjdA=="

CHAT_RESPONSE = {
    "decision": "EXECUTE",
    "reason": "OK",
    "aiText": "Hello, world!",
    "requestId": "req-001",
}

STREAM_STARTED = {
    "event": "stream_started",
    "streamId": "s1",
    "requestId": "req-001",
    "artifactId": "art-1",
    "provider": "openai",
    "model": "gpt-4",
}
CHUNK_0 = {"event": "chunk_forwarded", "delta": "Hel", "index": 0}
CHUNK_1 = {"event": "chunk_forwarded", "delta": "lo", "index": 1}
STREAM_COMPLETED = {
    "event": "stream_completed",
    "streamId": "s1",
    "requestId": "req-001",
    "chunksTotal": 2,
    "bytesTotal": 5,
    "durationMs": 12,
}
STREAM_CANCELLED = {
    "event": "stream_cancelled",
    "streamId": "s1",
    "reason": "PROVIDER_UNAVAILABLE",
    "requestId": "req-001",
}
SSE_HEADERS = {"content-type": "text/event-stream"}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestChatResource:
    def test_returns_decision(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CHAT_RESPONSE)
        result = make_client().chat.create(ARTIFACT_B64, {"prompt": "Hello"})
        assert result["decision"] == "EXECUTE"
        assert result["aiText"] == "Hello, world!"

    def test_sends_artifact_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CHAT_RESPONSE)
        make_client().chat.create(ARTIFACT_B64, {"prompt": "Hello"})
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-qodiqa-artifact"] == ARTIFACT_B64

    def test_posts_to_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CHAT_RESPONSE)
        make_client().chat.create(ARTIFACT_B64, {"prompt": "Hi"})
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/ai/chat")

    def test_raises_on_empty_artifact(self) -> None:
        with pytest.raises(ValidationError):
            make_client().chat.create("", {"prompt": "Hello"})

    def test_raises_on_whitespace_artifact(self) -> None:
        with pytest.raises(ValidationError):
            make_client().chat.create("   ", {"prompt": "Hello"})

    def test_raises_on_empty_prompt(self) -> None:
        with pytest.raises(ValidationError):
            make_client().chat.create(ARTIFACT_B64, {"prompt": ""})

    def test_raises_on_whitespace_prompt(self) -> None:
        with pytest.raises(ValidationError):
            make_client().chat.create(ARTIFACT_B64, {"prompt": "   "})

    def test_block_decision_returned(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"decision": "BLOCK", "reason": "POLICY", "requestId": "r2"})
        result = make_client().chat.create(ARTIFACT_B64, {"prompt": "bad prompt"})
        assert result["decision"] == "BLOCK"


class TestAsyncChatResource:
    async def test_returns_decision(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CHAT_RESPONSE)
        async with make_async_client() as client:
            result = await client.chat.create(ARTIFACT_B64, {"prompt": "Hello"})
        assert result["decision"] == "EXECUTE"

    async def test_raises_on_empty_artifact(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.chat.create("", {"prompt": "Hello"})

    async def test_sends_artifact_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=CHAT_RESPONSE)
        async with make_async_client() as client:
            await client.chat.create(ARTIFACT_B64, {"prompt": "Hello"})
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-qodiqa-artifact"] == ARTIFACT_B64


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


class TestChatResourceStream:
    def test_successful_multi_chunk_stream_in_order(self, httpx_mock: HTTPXMock) -> None:
        body = sse_body([STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED])
        httpx_mock.add_response(
            stream=ChunkedSyncStream(chunk_bytes(body, size=17)), headers=SSE_HEADERS
        )
        events = list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))
        assert events == [STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED]

    def test_events_arrive_incrementally_not_only_after_completion(
        self, httpx_mock: HTTPXMock
    ) -> None:
        frames = [sse_body([e], done=False) for e in (STREAM_STARTED, CHUNK_0, CHUNK_1)]
        frames.append(b"data: [DONE]\n\n")
        httpx_mock.add_response(
            stream=ChunkedSyncStream(frames, delay=0.08), headers=SSE_HEADERS
        )
        gen = make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"})
        timestamps = []
        try:
            for _ in range(3):
                next(gen)
                timestamps.append(time.monotonic())
        finally:
            gen.close()
        gaps = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        assert all(gap >= 0.04 for gap in gaps), (
            f"events did not arrive incrementally, gaps were {gaps} — "
            "the whole stream was likely buffered before yielding anything"
        )

    def test_empty_stream_yields_nothing(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            stream=ChunkedSyncStream([b"data: [DONE]\n\n"]), headers=SSE_HEADERS
        )
        events = list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))
        assert events == []

    def test_stream_cancelled_terminal_event_on_provider_error(
        self, httpx_mock: HTTPXMock
    ) -> None:
        body = sse_body([STREAM_STARTED, STREAM_CANCELLED])
        httpx_mock.add_response(stream=ChunkedSyncStream([body]), headers=SSE_HEADERS)
        events = list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))
        assert events[-1]["event"] == "stream_cancelled"

    def test_malformed_frame_raises_server_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            stream=ChunkedSyncStream([b"data: {not-json\n\n"]), headers=SSE_HEADERS
        )
        with pytest.raises(ServerError):
            list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))

    def test_pre_stream_auth_failure_raises_before_any_event(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"reason": "UNAUTHORIZED", "message": "bad artifact", "requestId": "r1"},
        )
        with pytest.raises(AuthenticationError):
            list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))

    def test_pre_stream_block_at_200_raises_verification_error(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """a pre-stream policy/verification BLOCK now
        returns HTTP 200 (not 403) with a JSON body — ``is_success`` alone
        can no longer detect "enforcement failed before the stream opened".
        Confirms stream() checks Content-Type too and still raises the
        correctly-classified error rather than silently yielding zero
        events (the real regression this fix closes — see
)."""
        httpx_mock.add_response(
            status_code=200,
            json={"decision": "BLOCK", "reason": "REQUEST_MISMATCH", "details": {}, "requestId": "r1b"},
        )
        events = []
        with pytest.raises(VerificationError) as exc_info:
            for event in make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                events.append(event)
        assert exc_info.value.status == 200
        assert events == []

    def test_mid_stream_disconnect_raises_network_error(self, httpx_mock: HTTPXMock) -> None:
        frames = [sse_body([STREAM_STARTED], done=False), sse_body([CHUNK_0], done=False)]
        httpx_mock.add_response(
            stream=ChunkedSyncStream(frames, error_after=1), headers=SSE_HEADERS
        )
        with pytest.raises(NetworkError):
            list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))

    def test_timeout_raises_when_overall_budget_exceeded(self, httpx_mock: HTTPXMock) -> None:
        frames = [sse_body([{"event": "chunk_forwarded", "delta": str(i), "index": i}], done=False) for i in range(10)]
        httpx_mock.add_response(
            stream=ChunkedSyncStream(frames, delay=0.05), headers=SSE_HEADERS
        )
        with pytest.raises(TimeoutError):
            list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}, timeout=0.12))

    def test_no_explicit_timeout_does_not_inherit_client_default(self) -> None:
        """Regression guard: `stream()` must not silently apply
        `ClientConfig.timeout` (5.0s in `make_client()`) the way `request()`
        does — passing no `timeout` kwarg must leave read/write/pool
        unbounded. (2026-10-06, deliberate update of this
        pin): the CONNECT phase keeps `ClientConfig.timeout`, so an
        unreachable or half-open server cannot hang the caller forever — it
        was `Timeout(None)` (connect included) before.
        """
        client = make_client()
        captured: dict = {}

        class _Boom(Exception):
            pass

        def fake_stream(method, path, *, json=None, headers=None, params=None, timeout=None):
            captured["timeout"] = timeout
            raise _Boom("short-circuit before any real I/O")

        with patch.object(client._http._client, "stream", side_effect=fake_stream):
            with pytest.raises(NetworkError):
                list(client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}))

        assert captured["timeout"] == httpx.Timeout(None, connect=5.0)
        assert captured["timeout"].read is None and captured["timeout"].pool is None

    def test_explicit_timeout_is_forwarded_to_transport(self) -> None:
        client = make_client()
        captured: dict = {}

        class _Boom(Exception):
            pass

        def fake_stream(method, path, *, json=None, headers=None, params=None, timeout=None):
            captured["timeout"] = timeout
            raise _Boom("short-circuit before any real I/O")

        with patch.object(client._http._client, "stream", side_effect=fake_stream):
            with pytest.raises(NetworkError):
                list(client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}, timeout=2.0))

        assert captured["timeout"] == httpx.Timeout(2.0)

    def test_explicit_close_stops_consumption_cleanly(self, httpx_mock: HTTPXMock) -> None:
        body = sse_body([STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED])
        httpx_mock.add_response(stream=ChunkedSyncStream(chunk_bytes(body, size=999)), headers=SSE_HEADERS)
        gen = make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"})
        first = next(gen)
        assert first == STREAM_STARTED
        gen.close()
        with pytest.raises(StopIteration):
            next(gen)

    def test_breaking_for_loop_early_does_not_raise(self, httpx_mock: HTTPXMock) -> None:
        body = sse_body([STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED])
        httpx_mock.add_response(stream=ChunkedSyncStream(chunk_bytes(body, size=999)), headers=SSE_HEADERS)
        seen = []
        for event in make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
            seen.append(event)
            break
        assert seen == [STREAM_STARTED]

    def test_raises_on_empty_artifact_before_any_http_call(self) -> None:
        # No httpx_mock response registered: if this made an HTTP call, the
        # test would fail with "no response registered" instead. Validation
        # must happen eagerly, not lazily on first iteration.
        with pytest.raises(ValidationError):
            make_client().chat.stream("", {"prompt": "Hello"})

    def test_raises_on_empty_prompt_before_any_http_call(self) -> None:
        with pytest.raises(ValidationError):
            make_client().chat.stream(ARTIFACT_B64, {"prompt": "   "})

    def test_wire_body_includes_stream_true_and_artifact_header(
        self, httpx_mock: HTTPXMock
    ) -> None:
        body = sse_body([STREAM_STARTED, STREAM_COMPLETED])
        httpx_mock.add_response(stream=ChunkedSyncStream([body]), headers=SSE_HEADERS)
        list(make_client().chat.stream(ARTIFACT_B64, {"prompt": "Hello", "model": "gpt-4"}))
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-qodiqa-artifact"] == ARTIFACT_B64
        assert str(req.url).endswith("/ai/chat")
        import json as _json

        sent = _json.loads(req.content)
        assert sent == {"prompt": "Hello", "model": "gpt-4", "stream": True}


class TestAsyncChatResourceStream:
    async def test_successful_multi_chunk_stream_in_order(self, httpx_mock: HTTPXMock) -> None:
        body = sse_body([STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED])
        httpx_mock.add_response(
            stream=ChunkedAsyncStream(chunk_bytes(body, size=17)), headers=SSE_HEADERS
        )
        events = []
        async with make_async_client() as client:
            async for event in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                events.append(event)
        assert events == [STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED]

    async def test_malformed_frame_raises_server_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            stream=ChunkedAsyncStream([b"data: {not-json\n\n"]), headers=SSE_HEADERS
        )
        async with make_async_client() as client:
            with pytest.raises(ServerError):
                async for _ in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                    pass

    async def test_pre_stream_auth_failure_raises_before_any_event(
        self, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"reason": "UNAUTHORIZED", "message": "bad artifact", "requestId": "r1"},
        )
        async with make_async_client() as client:
            with pytest.raises(AuthenticationError):
                async for _ in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                    pass

    async def test_pre_stream_block_at_200_raises_verification_error(
        self, httpx_mock: HTTPXMock
    ) -> None:
        """Async counterpart of the sync regression test above."""
        httpx_mock.add_response(
            status_code=200,
            json={"decision": "BLOCK", "reason": "REQUEST_MISMATCH", "details": {}, "requestId": "r1b"},
        )
        events = []
        async with make_async_client() as client:
            with pytest.raises(VerificationError) as exc_info:
                async for event in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                    events.append(event)
        assert exc_info.value.status == 200
        assert events == []

    async def test_mid_stream_disconnect_raises_network_error(
        self, httpx_mock: HTTPXMock
    ) -> None:
        frames = [sse_body([STREAM_STARTED], done=False), sse_body([CHUNK_0], done=False)]
        httpx_mock.add_response(
            stream=ChunkedAsyncStream(frames, error_after=1), headers=SSE_HEADERS
        )
        async with make_async_client() as client:
            with pytest.raises(NetworkError):
                async for _ in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                    pass

    async def test_timeout_raises_when_overall_budget_exceeded(
        self, httpx_mock: HTTPXMock
    ) -> None:
        frames = [
            sse_body([{"event": "chunk_forwarded", "delta": str(i), "index": i}], done=False)
            for i in range(10)
        ]
        httpx_mock.add_response(
            stream=ChunkedAsyncStream(frames, delay=0.05), headers=SSE_HEADERS
        )
        async with make_async_client() as client:
            with pytest.raises(TimeoutError):
                async for _ in client.chat.stream(
                    ARTIFACT_B64, {"prompt": "Hello"}, timeout=0.12
                ):
                    pass

    async def test_explicit_aclose_stops_consumption_cleanly(
        self, httpx_mock: HTTPXMock
    ) -> None:
        body = sse_body([STREAM_STARTED, CHUNK_0, CHUNK_1, STREAM_COMPLETED])
        httpx_mock.add_response(
            stream=ChunkedAsyncStream(chunk_bytes(body, size=999)), headers=SSE_HEADERS
        )
        async with make_async_client() as client:
            gen = client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"})
            first = await gen.__anext__()
            assert first == STREAM_STARTED
            await gen.aclose()
            with pytest.raises(StopAsyncIteration):
                await gen.__anext__()

    async def test_raises_on_empty_artifact_before_any_http_call(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                client.chat.stream("", {"prompt": "Hello"})

    async def test_wire_body_includes_stream_true_and_artifact_header(
        self, httpx_mock: HTTPXMock
    ) -> None:
        body = sse_body([STREAM_STARTED, STREAM_COMPLETED])
        httpx_mock.add_response(stream=ChunkedAsyncStream([body]), headers=SSE_HEADERS)
        async with make_async_client() as client:
            async for _ in client.chat.stream(ARTIFACT_B64, {"prompt": "Hello"}):
                pass
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-qodiqa-artifact"] == ARTIFACT_B64
        import json as _json

        sent = _json.loads(req.content)
        assert sent == {"prompt": "Hello", "stream": True}


class TestMessagesRequests:
    """F13-SDK-01: a multi-turn request (messages, no prompt) is accepted by the typed chat resource; prompt and messages together are not."""

    def test_messages_only_is_valid(self):
        from qodiqa.resources.chat import _assert_prompt_or_messages

        _assert_prompt_or_messages({"messages": [{"role": "user", "content": "hi"}]})

    def test_prompt_and_messages_together_are_refused(self):
        import pytest

        from qodiqa.exceptions import ValidationError
        from qodiqa.resources.chat import _assert_prompt_or_messages

        with pytest.raises(ValidationError):
            _assert_prompt_or_messages({"prompt": "x", "messages": [{"role": "user", "content": "hi"}]})

    def test_neither_is_refused(self):
        import pytest

        from qodiqa.exceptions import ValidationError
        from qodiqa.resources.chat import _assert_prompt_or_messages

        for bad in ({}, {"prompt": "  "}, {"messages": []}):
            with pytest.raises(ValidationError):
                _assert_prompt_or_messages(bad)
