"""SSE frame parsing for QODIQA streaming responses — internal module.

Mirrors ``sdk/javascript/src/utils/sse.ts``. API-10 remediation:
QODIQA's server (``src/streaming/streamEnforcer.js`` ``_writeSSE()``) now
emits native SSE framing — an ``event:`` line (matching the ``data:`` JSON
payload's own ``event`` property) and an ``id:`` line ahead of every
``data:`` line, plus a ``retry:`` hint on the first frame. This is additive:
the JSON payload shape is unchanged from before, kept for one deprecation
cycle so this parser doesn't need to change to keep working.

This parser deliberately keeps reading only the ``data:`` line(s) of each
frame rather than switching to the native ``event:``/``id:`` fields as its
primary source of truth — ``_extract_payload()`` below already filters for
lines starting with ``data:`` specifically (not "the whole frame"), so the
new ``event:``/``id:``/``retry:`` lines are transparently ignored without any
change needed here. ``Last-Event-ID`` reconnection and full multi-line
``data:``/comment-line support remain out of scope: QODIQA's server doesn't
support HTTP-level stream resumption, so implementing that half of the spec
here would be unfaithful to the actual contract, not a robustness
improvement.
"""

from __future__ import annotations

import codecs
import json as _json
from typing import (
    Any,
    AsyncIterable,
    Dict,
    AsyncIterator,
    Iterable,
    Iterator,
    Optional,
)

from .exceptions import ServerError

_DATA_PREFIX = "data:"
_DONE_SENTINEL = "[DONE]"


def _extract_payload(frame: str) -> Optional[str]:
    """Extracts the payload string from a single SSE frame's `data:` line(s)."""
    lines = [
        line[len(_DATA_PREFIX):].lstrip()
        for line in frame.split("\n")
        if line.startswith(_DATA_PREFIX)
    ]
    if not lines:
        return None
    # QODIQA never splits one event across multiple `data:` lines, but join
    # defensively per the SSE spec's own multi-line join rule rather than
    # silently dropping anything past the first line.
    return "\n".join(lines)


def _parse_payload(payload: str) -> Any:
    try:
        return _json.loads(payload)
    except ValueError as exc:
        raise ServerError(
            "Received a malformed SSE event from the server (not valid JSON, "
            f'not "[DONE]"): {payload[:200]}'
        ) from exc


def iter_sse_events(chunks: Iterable[bytes], state: Optional[Dict[str, bool]] = None) -> Iterator[Any]:
    """Reads a byte-chunk iterable of ``data: <json>\\n\\n``-framed SSE output
    and yields each frame's parsed JSON payload.

    Stops (without yielding) when the ``[DONE]`` sentinel is read, or when the
    chunk iterable is exhausted. Raises :class:`~qodiqa.exceptions.ServerError`
    if a ``data:`` frame's payload is not ``[DONE]`` and not valid JSON — a
    protocol violation, not a condition to silently skip.

    Uses an incremental UTF-8 decoder so a multi-byte character split across
    two chunk boundaries is decoded correctly rather than raising or
    corrupting data.

 P15-03: when ``state`` is given, ``state["done"]`` is set to
    ``True`` once the ``[DONE]`` sentinel is read. The HTTP client uses it to
    raise :class:`~qodiqa.exceptions.NetworkError` for a body that ended
    without it — the server always writes ``[DONE]`` last, so such a body was
    truncated in transit. The parser itself still just stops.
    """
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""

    for chunk in chunks:
        if chunk:
            buffer += decoder.decode(chunk)

        while True:
            boundary = buffer.find("\n\n")
            if boundary == -1:
                break
            frame, buffer = buffer[:boundary], buffer[boundary + 2:]

            payload = _extract_payload(frame)
            if payload is None:
                continue  # blank frame between events — ignore
            if payload == _DONE_SENTINEL:
                if state is not None:
                    state["done"] = True
                return

            yield _parse_payload(payload)

    # The chunk iterable ended. A well-behaved stream always ends with
    # `[DONE]` already consumed out of the buffer above; any leftover
    # non-blank content here means the connection closed mid-frame (e.g. a
    # network interruption).
    buffer += decoder.decode(b"", final=True)
    if buffer.strip() != "":
        payload = _extract_payload(buffer)
        if payload == _DONE_SENTINEL:
            if state is not None:
                state["done"] = True
        elif payload is not None:
            yield _parse_payload(payload)


async def aiter_sse_events(
    chunks: AsyncIterable[bytes], state: Optional[Dict[str, bool]] = None
) -> AsyncIterator[Any]:
    """Async counterpart of :func:`iter_sse_events`. See its docstring."""
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""

    async for chunk in chunks:
        if chunk:
            buffer += decoder.decode(chunk)

        while True:
            boundary = buffer.find("\n\n")
            if boundary == -1:
                break
            frame, buffer = buffer[:boundary], buffer[boundary + 2:]

            payload = _extract_payload(frame)
            if payload is None:
                continue
            if payload == _DONE_SENTINEL:
                if state is not None:
                    state["done"] = True
                return

            yield _parse_payload(payload)

    buffer += decoder.decode(b"", final=True)
    if buffer.strip() != "":
        payload = _extract_payload(buffer)
        if payload == _DONE_SENTINEL:
            if state is not None:
                state["done"] = True
        elif payload is not None:
            yield _parse_payload(payload)
