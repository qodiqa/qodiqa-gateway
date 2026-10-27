"""Chat resource — POST /ai/chat."""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Iterator, Optional

from ..exceptions import VERIFICATION_REASONS, ValidationError, create_error
from ..models import ChatRequest, ChatResponse, ChatStreamEvent
from ._base import AsyncBaseResource, BaseResource


class ChatResource(BaseResource):
    """Execute AI prompts through QODIQA enforcement.

    Requires a base64-encoded artifact obtained from ``POST /sign``.
    """

    def create(
        self,
        artifact: str,
        request: ChatRequest,
        *,
        idempotency_key: Optional[str] = None,
    ) -> ChatResponse:
        """Execute an enforced AI chat request.

        Args:
            artifact: Base64-encoded artifact string from ``sign.sign()``.
            request: Chat request containing ``prompt`` and optional ``model``.
            idempotency_key: Optional exactly-once retry token, sent as the
                ``Idempotency-Key`` header (
). Re-sending the same key with the same
                (freshly signed) request after an outcome-unknown failure
                (e.g. a 504) replays the original result. Not accepted by
                :meth:`stream` — the server rejects that combination with
                ``IDEMPOTENCY_STREAMING_UNSUPPORTED``.

        Returns:
            :class:`~qodiqa.models.ChatResponse` with decision and AI text.

        Raises:
            :class:`~qodiqa.exceptions.AuthenticationError`: If the artifact
                is empty or rejected.
            :class:`~qodiqa.exceptions.ValidationError`: If the prompt is empty.

        Example::

            import base64, json
            artifact_b64 = base64.b64encode(
                json.dumps(signed["artifact"]).encode()
            ).decode()
            chat = client.chat.create(artifact_b64, {"prompt": "Hello"})
            if chat["decision"] == "EXECUTE":
                print(chat.get("aiText"))
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')
        _assert_prompt_or_messages(request)

        headers = _create_headers(self._auth.get_artifact_header(artifact), idempotency_key)
        result = self._http.post("/ai/chat", request, headers=headers)
        _raise_if_verification_block(result)
        return _normalize_ai_text(result)  # type: ignore[return-value]

    def stream(
        self,
        artifact: str,
        request: ChatRequest,
        *,
        timeout: Optional[float] = None,
    ) -> Iterator[ChatStreamEvent]:
        """Execute an enforced AI chat request via ``POST /ai/chat`` with
        ``stream: true``, yielding each SSE event as it arrives.

        ``request`` MUST be the same dict (or same field values) passed as
        ``request["body"]`` to ``sign.sign()`` — the server binds the
        artifact to the exact request body via ``requestHash``; this method
        sends ``{**request, "stream": True}`` on the wire, so ``sign.sign()``
        must have been called with ``stream: True`` already present in its
        request body too, or the server rejects the call with
        ``REQUEST_MISMATCH`` before the stream opens (see
        :class:`~qodiqa.exceptions.VerificationError`).

        Ends iteration after the terminal ``stream_completed`` or
        ``stream_cancelled`` event — the raw ``[DONE]`` sentinel that follows
        it on the wire is not itself yielded.

        Unlike JavaScript's async generators, calling this method validates
        ``artifact``/``request["prompt"]`` and builds the request immediately
        — the returned iterator only defers opening the connection, not
        input validation.

        Args:
            artifact: Base64-encoded artifact string from ``sign.sign()``
                (called with ``stream: True`` in its request body).
            request: Chat request containing ``prompt`` and optional ``model``.
            timeout: Overall time budget for the streaming session, in
                seconds. ``None`` by default (no client-side cap) — the
                server itself terminates a session after
                ``STREAM_MAX_DURATION_MS`` (default 5 minutes; see
), so most callers never need
                this.

        Returns:
            An iterator of :data:`~qodiqa.models.ChatStreamEvent`. Breaking
            out of the consuming ``for`` loop early closes the underlying
            connection once the (otherwise unreferenced) generator is
            garbage-collected; call ``.close()`` on the returned iterator
            explicitly for deterministic cleanup instead of relying on that.

        Raises:
            :class:`~qodiqa.exceptions.ValidationError`: If ``artifact`` or
                ``request["prompt"]`` is empty.
            :class:`~qodiqa.exceptions.AuthenticationError`: If the artifact
                is empty or rejected.
            :class:`~qodiqa.exceptions.TimeoutError`: If ``timeout`` was
                given and exceeded.
            :class:`~qodiqa.exceptions.ServerError`: On a malformed SSE
                frame.
            :class:`~qodiqa.exceptions.NetworkError`: On a dropped or
                interrupted connection.

        Example::

            for event in client.chat.stream(artifact_b64, {"prompt": "Hello", "stream": True}):
                if event["event"] == "chunk_forwarded":
                    print(event["delta"], end="", flush=True)
                elif event["event"] == "stream_completed":
                    print("\\ndone:", event["chunksTotal"], "chunks")
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')
        _assert_prompt_or_messages(request)

        headers = self._auth.get_artifact_header(artifact)
        wire_body = {**request, "stream": True}
        return self._http.stream(
            "POST", "/ai/chat", json=wire_body, headers=headers, timeout=timeout
        )


class AsyncChatResource(AsyncBaseResource):
    """Async version of :class:`ChatResource`."""

    async def create(
        self,
        artifact: str,
        request: ChatRequest,
        *,
        idempotency_key: Optional[str] = None,
    ) -> ChatResponse:
        """Execute an enforced AI chat request asynchronously.

        See :meth:`ChatResource.create` for full documentation.
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')
        _assert_prompt_or_messages(request)

        headers = _create_headers(self._auth.get_artifact_header(artifact), idempotency_key)
        result = await self._http.post("/ai/chat", request, headers=headers)
        _raise_if_verification_block(result)
        return _normalize_ai_text(result)  # type: ignore[return-value]

    def stream(
        self,
        artifact: str,
        request: ChatRequest,
        *,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[ChatStreamEvent]:
        """Async version of :meth:`ChatResource.stream`.

        Deliberately not an ``async def`` — it validates and builds the
        request synchronously, then returns an async generator immediately.
        Do not ``await`` this call; only iterating it is asynchronous::

            async for event in client.chat.stream(artifact_b64, {"prompt": "Hello", "stream": True}):
                ...

        For deterministic cleanup if you stop consuming before exhaustion
        (rather than relying on garbage collection to call ``aclose()``),
        keep a reference and close it explicitly::

            stream = client.chat.stream(artifact_b64, request)
            try:
                async for event in stream:
                    ...
                    break
            finally:
                await stream.aclose()

        See :meth:`ChatResource.stream` for the full parameter/exception
        documentation — identical here except every raised exception occurs
        on ``__anext__`` rather than synchronously.
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')
        _assert_prompt_or_messages(request)

        headers = self._auth.get_artifact_header(artifact)
        wire_body = {**request, "stream": True}
        return self._http.stream(
            "POST", "/ai/chat", json=wire_body, headers=headers, timeout=timeout
        )


def _assert_prompt_or_messages(request: ChatRequest) -> None:
    """A chat request needs a non-empty ``prompt`` or a non-empty ``messages`` list, not both (the gateway answers 400 PROMPT_AND_MESSAGES)."""
    prompt = request.get("prompt")
    messages = request.get("messages")
    has_prompt = isinstance(prompt, str) and prompt.strip() != ""
    has_messages = isinstance(messages, list) and len(messages) > 0
    if has_prompt and has_messages:
        raise ValidationError('"request.prompt" and "request.messages" are mutually exclusive.')
    if not has_prompt and not has_messages:
        raise ValidationError('"request.prompt" must be a non-empty string (or "request.messages" a non-empty list).')


def _create_headers(artifact_headers: Dict[str, str], idempotency_key: Optional[str]) -> Dict[str, str]:
    """add the optional ``Idempotency-Key`` header to a ``create()`` call."""
    headers = dict(artifact_headers)
    if idempotency_key is not None:
        if not str(idempotency_key).strip():
            raise ValidationError('"idempotency_key" must be a non-empty string.')
        headers["Idempotency-Key"] = idempotency_key
    return headers


def _raise_if_verification_block(result: Dict[str, Any]) -> None:
    """/ API-02: an artifact rejection is a VerificationError on BOTH paths and in both server modes. In the
    default QODIQA_BLOCK_HTTP_MODE=decision the server answers it with HTTP 200, so it arrives as a result; stream()
    already raised for the same response. Other BLOCKs (policy, consent, semantic, ...) stay a normal result."""
    if isinstance(result, dict) and result.get("decision") == "BLOCK" and result.get("reason") in VERIFICATION_REASONS:
        details = result.get("details") if isinstance(result.get("details"), dict) else {}
        request_id = result.get("requestId") if isinstance(result.get("requestId"), str) else None
        raise create_error(200, result["reason"], f"BLOCK: {result['reason']}", request_id, details)


def _normalize_ai_text(result: Dict[str, Any]) -> Dict[str, Any]:
    """Map the server's wire-format `response` field to the SDK's `aiText`.

    The server (src/api/routes/aiChat.js) returns the AI output text under
    `response`; the SDK's public ChatResponse type exposes it as `aiText`
    (see docs/sdk/python/api.md and README.md "Quick start"). Normalize here
    rather than changing the wire format, which curl callers already
    depend on.
    """
    if result.get("aiText") is None and isinstance(result.get("response"), str):
        result["aiText"] = result["response"]
    return result
