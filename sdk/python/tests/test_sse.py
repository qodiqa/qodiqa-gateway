"""Unit tests for the QODIQA SSE frame parser."""

from __future__ import annotations

import pytest

from qodiqa._sse import aiter_sse_events, iter_sse_events
from qodiqa.exceptions import ServerError


def test_parses_multiple_events_across_chunk_boundaries() -> None:
    raw = (
        b'data: {"event": "stream_started", "streamId": "s1"}\n\n'
        b'data: {"event": "chunk_forwarded", "delta": "Hi", "index": 0}\n\n'
        b"data: [DONE]\n\n"
    )
    # Split at an arbitrary offset that does not line up with any frame
    # boundary, to prove the parser buffers correctly rather than assuming
    # one chunk == one frame.
    chunks = [raw[:40], raw[40:90], raw[90:]]
    events = list(iter_sse_events(chunks))
    assert events == [
        {"event": "stream_started", "streamId": "s1"},
        {"event": "chunk_forwarded", "delta": "Hi", "index": 0},
    ]


def test_handles_multibyte_utf8_character_split_across_chunks() -> None:
    raw = (
        b'data: {"event": "chunk_forwarded", "delta": "caf\xc3\xa9", "index": 0}\n\n'
        b"data: [DONE]\n\n"
    )
    split_at = raw.index(b"\xc3") + 1  # splits the two-byte UTF-8 sequence in half
    chunks = [raw[:split_at], raw[split_at:]]
    events = list(iter_sse_events(chunks))
    assert events == [{"event": "chunk_forwarded", "delta": "café", "index": 0}]


def test_empty_stream_yields_nothing() -> None:
    assert list(iter_sse_events([])) == []
    assert list(iter_sse_events([b""])) == []


def test_done_sentinel_stops_iteration_and_is_not_yielded() -> None:
    raw = b"data: [DONE]\n\ndata: {\"event\": \"should_not_appear\"}\n\n"
    events = list(iter_sse_events([raw]))
    assert events == []


def test_blank_frame_between_events_is_ignored() -> None:
    raw = b'\n\ndata: {"event": "stream_started"}\n\n\n\ndata: [DONE]\n\n'
    events = list(iter_sse_events([raw]))
    assert events == [{"event": "stream_started"}]


def test_malformed_json_frame_raises_server_error() -> None:
    with pytest.raises(ServerError, match="malformed SSE event"):
        list(iter_sse_events([b"data: {not-json\n\n"]))


def test_stream_ends_mid_frame_without_done_raises_on_leftover_content() -> None:
    # Connection dropped after a complete frame's `data:` line was sent but
    # before the terminating blank line arrived — this is genuinely malformed
    # (not a clean truncation), so it must surface as ServerError, not be
    # silently swallowed.
    with pytest.raises(ServerError):
        list(iter_sse_events([b'data: {"event": "chunk_forwarded"']))


def test_stream_ends_cleanly_without_done_and_without_trailing_content() -> None:
    # A frame that completed (blank line seen) but the stream just ends
    # without an explicit [DONE] — not itself an error at the parser level.
    raw = b'data: {"event": "stream_started"}\n\n'
    events = list(iter_sse_events([raw]))
    assert events == [{"event": "stream_started"}]


def test_multiline_data_lines_are_joined() -> None:
    raw = b'data: {"event":\ndata: "stream_started"}\n\n'
    events = list(iter_sse_events([raw]))
    assert events == [{"event": "stream_started"}]


def test_native_event_id_retry_lines_are_ignored_transparently() -> None:
    # API-10 remediation: the real server now emits native
    # event:/id:/retry: lines ahead of data: on every frame. This parser
    # only reads data: lines, so those new fields must be ignored without
    # affecting the parsed payload.
    raw = (
        b"retry: 3000\n"
        b"event: stream_started\n"
        b"id: s1:0\n"
        b'data: {"event": "stream_started", "streamId": "s1"}\n\n'
        b"event: chunk_forwarded\n"
        b"id: s1:1\n"
        b'data: {"event": "chunk_forwarded", "delta": "Hi", "index": 0}\n\n'
        b"id: s1:2\n"
        b"data: [DONE]\n\n"
    )
    events = list(iter_sse_events([raw]))
    assert events == [
        {"event": "stream_started", "streamId": "s1"},
        {"event": "chunk_forwarded", "delta": "Hi", "index": 0},
    ]


async def test_async_parses_multiple_events() -> None:
    raw = (
        b'data: {"event": "stream_started", "streamId": "s1"}\n\n'
        b'data: {"event": "chunk_forwarded", "delta": "Hi", "index": 0}\n\n'
        b"data: [DONE]\n\n"
    )

    async def chunks():
        for i in range(0, len(raw), 13):
            yield raw[i : i + 13]

    events = [event async for event in aiter_sse_events(chunks())]
    assert events == [
        {"event": "stream_started", "streamId": "s1"},
        {"event": "chunk_forwarded", "delta": "Hi", "index": 0},
    ]


async def test_async_malformed_json_frame_raises_server_error() -> None:
    async def chunks():
        yield b"data: {not-json\n\n"

    with pytest.raises(ServerError, match="malformed SSE event"):
        [event async for event in aiter_sse_events(chunks())]
