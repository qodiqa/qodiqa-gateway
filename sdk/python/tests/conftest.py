"""Shared pytest fixtures for the QODIQA Python SDK test suite."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

import pytest
import httpx

VALID_API_KEY = "ok_" + "d" * 64
VALID_BASE_URL = "http://test.qodiqa.local"

MOCK_ARTIFACT: Dict[str, Any] = {
    "expiry": int(time.time() * 1000) + 300_000,
    "payload": {
        "requestId": "req-001",
        "requestHash": "abc123",
        "policyHash": "def456",
        "tenantId": "tenant-1",
    },
    "publicKeyId": "key-1",
    "timestamp": int(time.time() * 1000),
    "signature": "c2lnLWFiYw==",
}

import base64

ARTIFACT_B64 = base64.b64encode(json.dumps(MOCK_ARTIFACT).encode()).decode()


def make_api_response(data: Any) -> Dict[str, Any]:
    return {
        "status": "success",
        "timestamp": "2024-01-01T00:00:00.000Z",
        "requestId": "req-test-001",
        "data": data,
    }


# ---------------------------------------------------------------------------
# SSE streaming test helpers
# ---------------------------------------------------------------------------


def sse_body(events: List[Dict[str, Any]], *, done: bool = True) -> bytes:
    """Builds a native-SSE-framed wire body from event dicts:
    an `event:` line (mirroring each dict's own `event` key) and an `id:`
    line ahead of every `data:` line, matching the real server's current
    output — so tests using this fixture are an honest regression check
    against the actual current wire format, not the pre-API-10 data-only
    shape.
    """
    parts = []
    for i, e in enumerate(events):
        frame = b""
        event_name = e.get("event")
        if isinstance(event_name, str):
            frame += f"event: {event_name}\n".encode("utf-8")
        frame += f"id: mock:{i}\n".encode("utf-8")
        frame += f"data: {json.dumps(e)}\n\n".encode("utf-8")
        parts.append(frame)
    body = b"".join(parts)
    if done:
        body += f"id: mock:{len(events)}\n".encode("utf-8") + b"data: [DONE]\n\n"
    return body


def chunk_bytes(data: bytes, size: int = 24) -> List[bytes]:
    """Splits a byte string into fixed-size chunks, deliberately not aligned
    to SSE frame (``\\n\\n``) boundaries, to exercise the parser's buffering.
    """
    return [data[i : i + size] for i in range(0, len(data), size)] or [b""]


class ChunkedSyncStream(httpx.SyncByteStream):
    """A ``pytest_httpx``-compatible sync response stream for exercising the
    real ``httpx.Client.stream()`` code path (not a mocked SDK method) —
    optionally with per-chunk delay or a simulated mid-stream connection drop.
    """

    def __init__(
        self,
        chunks: List[bytes],
        *,
        delay: float = 0.0,
        error_after: Optional[int] = None,
    ) -> None:
        self._chunks = chunks
        self._delay = delay
        self._error_after = error_after

    def __iter__(self):
        for i, chunk in enumerate(self._chunks):
            if self._error_after is not None and i == self._error_after:
                raise httpx.ReadError("simulated connection drop")
            if self._delay:
                time.sleep(self._delay)
            yield chunk

    def close(self) -> None:
        pass


class ChunkedAsyncStream(httpx.AsyncByteStream):
    """Async counterpart of :class:`ChunkedSyncStream`."""

    def __init__(
        self,
        chunks: List[bytes],
        *,
        delay: float = 0.0,
        error_after: Optional[int] = None,
    ) -> None:
        self._chunks = chunks
        self._delay = delay
        self._error_after = error_after

    async def __aiter__(self):
        for i, chunk in enumerate(self._chunks):
            if self._error_after is not None and i == self._error_after:
                raise httpx.ReadError("simulated connection drop")
            if self._delay:
                await asyncio.sleep(self._delay)
            yield chunk

    async def aclose(self) -> None:
        pass
