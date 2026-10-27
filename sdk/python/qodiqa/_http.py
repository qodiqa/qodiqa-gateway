"""QODIQA SDK HTTP client — internal module.

Wraps ``httpx`` to provide:

* automatic JSON serialisation / deserialisation
* configurable timeout
* retry with exponential back-off + full jitter
* request-ID extraction from error bodies
* consistent exception mapping via :func:`~qodiqa.exceptions.create_error`
"""

from __future__ import annotations

import math
import random
import re
import time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterator, Optional, AsyncIterator

import httpx

from .config import ClientConfig
from ._sse import aiter_sse_events, iter_sse_events
from .exceptions import (
    MfaRequiredError,
    NetworkError,
    QodiqaError,
    RateLimitError,
    TimeoutError,
    create_error,
)

# Retryable HTTP status codes
_RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
_IDEMPOTENT_METHODS = frozenset({"GET", "PUT", "DELETE"})
_CHAT_PATH = re.compile(r"(^|/)ai/chat(/stream)?/?$")


def _is_retryable(status: int) -> bool:
    return status in _RETRYABLE_STATUSES


def should_retry_request(err: QodiqaError, method: str, path: str) -> bool:
    """Whether a failed request may be sent again.

    * ``SERVER_OVERLOADED`` (503, admission control) refuses a request before it is decoded, verified or
      nonce-registered: always safe to resend, the artifact included.
    * ``MFA_LOCKED`` is never retried.
    * Idempotent methods (GET/PUT/DELETE): 429, 500, 502, 503, 504 as before.
    * POST/PATCH: only a 429, which the request limiters answer before the handler runs — except on ``/ai/chat``,
      where a 429 may come from the per-identity limiter AFTER the artifact nonce was consumed. A 5xx on a POST may
      have been processed; it is surfaced, not resent.
    """
    if err.reason == "MFA_LOCKED":
        return False
    if err.reason == "SERVER_OVERLOADED":
        return True
    if method.upper() in _IDEMPOTENT_METHODS:
        return isinstance(err, RateLimitError) or (err.status is not None and _is_retryable(err.status))
    return err.status == 429 and not _CHAT_PATH.search(path.split("?")[0])


def _needs_otp(err: QodiqaError, config: ClientConfig, headers: Optional[Dict[str, str]]) -> bool:
    return (
        isinstance(err, MfaRequiredError)
        and err.reason == "MFA_REQUIRED"
        and config.otp_provider is not None
        and not any(k.lower() == "x-qodiqa-otp" for k in (headers or {}))
    )


def _carries_otp(headers: Optional[Dict[str, str]], client_headers: Any) -> bool:
    """a request carrying an MFA code is never auto-retried. The server accepts a TOTP code at most
    once per step, so a resend with the same code is refused as ``MFA_INVALID`` (hiding the original error) and counts
    toward the operator's MFA lockout."""
    return any(k.lower() == "x-qodiqa-otp" for k in (headers or {})) or "x-qodiqa-otp" in client_headers


_DELTA_SECONDS = re.compile(r"^\d+(\.\d+)?$")
_MAX_DELAY = 30.0


def _parse_retry_after(value: Optional[str], now: Optional[float] = None) -> Optional[float]:
    """Parses an HTTP ``Retry-After`` value (RFC 9110 §10.2.3): delta-seconds or an HTTP-date. Returns seconds
    (>= 0), or ``None`` when absent or unparseable."""
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    if _DELTA_SECONDS.match(v):
        return float(v)
    try:
        when = parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if when is None:
        return None
    current = time.time() if now is None else now
    return float(max(0, math.ceil(when.timestamp() - current)))


def _retry_after_of(err: QodiqaError) -> Optional[float]:
    """The server-stated wait carried by an error: ``RateLimitError.retry_after``, else the parsed ``Retry-After``
    header stored in ``details["retryAfter"]`` (any status, e.g. 503 ``SERVER_OVERLOADED``)."""
    if isinstance(err, RateLimitError) and isinstance(err.retry_after, (int, float)):
        return float(err.retry_after)
    ra = (err.details or {}).get("retryAfter")
    if isinstance(ra, (int, float)) and not isinstance(ra, bool) and math.isfinite(ra) and ra >= 0:
        return float(ra)
    return None


def _retry_delay(err: QodiqaError, attempt: int, base_delay: float, max_delay: float) -> Optional[float]:
    """P15-01: the wait before the next attempt, or ``None`` when the request must not be retried. A
    server-stated ``Retry-After`` is honoured on ANY retryable error (429, 503 ``SERVER_OVERLOADED``, ...), not only
    :class:`RateLimitError`; a retry before it is refused by construction, so a wait longer than ``max_delay`` surfaces
    the error instead of retrying early."""
    retry_after = _retry_after_of(err)
    if retry_after is not None:
        return retry_after if retry_after <= max_delay else None
    return _compute_delay(attempt, base_delay, max_delay, jitter=True)


def _compute_delay(
    attempt: int,
    base_delay: float,
    max_delay: float,
    jitter: bool,
) -> float:
    """Exponential back-off with optional full jitter."""
    exp = float(min(base_delay * (2**attempt), max_delay))
    if not jitter:
        return exp
    return float(random.uniform(0, exp))


def _build_httpx_client(config: ClientConfig) -> httpx.Client:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
        **config.default_headers,
    }
    kwargs: Dict[str, Any] = {
        "base_url": config.base_url,
        "headers": headers,
        "timeout": config.timeout,
        "verify": config.verify_ssl,
    }
    if config.proxy:
        kwargs["proxy"] = config.proxy
    return httpx.Client(**kwargs)


def _build_async_httpx_client(config: ClientConfig) -> httpx.AsyncClient:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": config.user_agent,
        **config.default_headers,
    }
    kwargs: Dict[str, Any] = {
        "base_url": config.base_url,
        "headers": headers,
        "timeout": config.timeout,
        "verify": config.verify_ssl,
    }
    if config.proxy:
        kwargs["proxy"] = config.proxy
    return httpx.AsyncClient(**kwargs)


def _parse_error_response(response: httpx.Response) -> tuple[str, str, Optional[str], Dict[str, Any]]:
    """Extract (reason, message, request_id, details) from an error response."""
    reason = "UNKNOWN"
    message = f"HTTP {response.status_code}"
    request_id: Optional[str] = None
    details: Dict[str, Any] = {}

    try:
        body = response.json()
        if isinstance(body, dict):
            if isinstance(body.get("reason"), str):
                reason = body["reason"]
            if isinstance(body.get("requestId"), str):
                request_id = body["requestId"]
            if isinstance(body.get("message"), str):
                message = body["message"]
            if isinstance(body.get("details"), dict):
                details = body["details"]
                if isinstance(details.get("message"), str):
                    message = details["message"]

            # MANAGEMENT_ERROR envelope: {status:'error', error:{code,message,details}}
            # — the management/admin/observability API surface (webhooks,
            # attestation, certification, transparency, RBAC, audit, and
            # similar; see src/api/response.js's buildFailureBody()). Distinct
            # from the ENFORCEMENT_DECISION envelope handled above (/ai/chat,
            # /sign, /verify), which has no nested `error` object — the two
            # shapes never collide on the same response, so this check is
            # purely additive. Previously never read at all (D26-7), silently
            # dropping real diagnostic text and falling back to the generic
            # "HTTP {status}" message.
            err_obj = body.get("error")
            if isinstance(err_obj, dict):
                if isinstance(err_obj.get("code"), str):
                    reason = err_obj["code"]
                if isinstance(err_obj.get("message"), str):
                    message = err_obj["message"]
                if isinstance(err_obj.get("details"), dict):
                    details = {**details, **err_obj["details"]}

            # Flat protocol-limiter 429 body (src/core/rateLimit/middleware.js _deny429, used by /sign):
            # {error: "<CODE>", surface, dimension, reason: "BURST"|"SUSTAINED"|..., retryAfterSeconds}.
            # P15-04: the machine code is `error`; that body's `reason` is the limiter's window name, which was
            # surfacing as err.reason. It stays available as details["blockedBy"] (compat path).
            flat_code = body.get("error")
            if isinstance(flat_code, str) and re.match(r"^[A-Z][A-Z0-9_]+$", flat_code):
                if isinstance(body.get("reason"), str):
                    details = {**details, "blockedBy": body["reason"]}
                reason = flat_code
                for key in ("surface", "dimension", "retryAfterSeconds"):
                    if body.get(key) is not None:
                        details = {**details, key: body[key]}
    except Exception:
        pass

    # P15-02: Retry-After is read for every body shape (a proxy's text/HTML 503 included) and parsed as
    # delta-seconds or an HTTP-date.
    retry_after = _parse_retry_after(response.headers.get("retry-after"))
    if retry_after is not None:
        details = {**details, "retryAfter": retry_after}

    # a 2xx status here means a policy/verification BLOCK
    # reached this (streaming-only) path with no more specific message
    # found above — the generic "HTTP 200" fallback would read as "not
    # actually an error", exactly backwards for a raised exception. Prefer
    # the reason code whenever the status can't carry the explanation.
    if response.is_success and message == f"HTTP {response.status_code}":
        message = f"BLOCK: {reason}"

    # bodies without a requestId (ServiceShuttingDown, the flat limiter 429, a proxy 502/504)
    # still carry the server's correlation id in the X-Request-ID response header.
    if request_id is None:
        request_id = response.headers.get("x-request-id")

    return reason, message, request_id, details


def _stream_resend_delay(
    err: QodiqaError,
    attempt: int,
    max_retries: int,
    headers: Optional[Dict[str, str]],
    client_headers: Any,
    deadline: Optional[float],
) -> Optional[float]:
    """P15-01: the one pre-stream refusal ``stream()`` resends is 503 ``SERVER_OVERLOADED`` — admission
    control answers it before the artifact is decoded, verified or nonce-registered (src/api/admission.js), so nothing
    was streamed and the same artifact may be sent again after ``Retry-After`` (``create()`` already did). Any other
    pre-stream error is raised; never for a request carrying an MFA code. ``None`` = raise."""
    if err.reason != "SERVER_OVERLOADED" or attempt >= max_retries or _carries_otp(headers, client_headers):
        return None
    delay = _retry_delay(err, attempt, 0.5, _MAX_DELAY)
    if delay is None or (deadline is not None and time.monotonic() + delay >= deadline):
        return None
    return delay


def _raise_if_truncated(state: Dict[str, bool], method: str, path: str) -> None:
    """P15-03: the server always writes ``[DONE]`` last (src/streaming/streamEnforcer.js). A body that ended
    without it (a proxy idle timeout, a reset that closes cleanly, a server crash between frames) was truncated:
    ending iteration normally would let a caller take a partial answer for a complete one."""
    if not state.get("done"):
        raise NetworkError(
            f"Streaming response ended before the terminal [DONE] frame (truncated stream): {method} {path}"
        )


# ---------------------------------------------------------------------------
# Sync HTTP client
# ---------------------------------------------------------------------------


class HttpClient:
    """Synchronous HTTP client wrapping ``httpx.Client``."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._client = _build_httpx_client(config)

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        binary: bool = False,
    ) -> Any:
        """Execute an HTTP request with retry logic; on 401 ``MFA_REQUIRED`` with an ``otp_provider`` configured,
        resend it once with ``X-QODIQA-OTP``."""
        try:
            return self._request(method, path, json=json, headers=headers, params=params, binary=binary)
        except QodiqaError as err:
            if not _needs_otp(err, self._config, headers):
                raise
            otp_headers = {**(headers or {}), "X-QODIQA-OTP": str(self._config.otp_provider())}  # type: ignore[misc]
            return self._request(method, path, json=json, headers=otp_headers, params=params, binary=binary)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        binary: bool = False,
    ) -> Any:
        """Execute an HTTP request with retry logic.

        Args:
            method: HTTP verb (``GET``, ``POST``, etc.).
            path: URL path relative to ``base_url``.
            json: Request body — serialised automatically.
            headers: Per-request headers merged over defaults.
            params: URL query parameters.

        Returns:
            Deserialised JSON response body.

        Raises:
            :class:`~qodiqa.exceptions.TimeoutError`: On timeout.
            :class:`~qodiqa.exceptions.NetworkError`: On connection failure.
            :class:`~qodiqa.exceptions.QodiqaError`: For HTTP error responses.
        """
        base_delay = 0.5
        max_delay = 30.0
        last_error: Optional[Exception] = None

        for attempt in range(self._config.max_retries + 1):
            try:
                response = self._client.request(
                    method,
                    path,
                    json=json,
                    headers=headers or {},
                    params={k: v for k, v in (params or {}).items() if v is not None},
                )
            except httpx.TimeoutException as exc:
                raise TimeoutError(
                    f"Request timed out after {self._config.timeout}s: {method} {path}"
                ) from exc
            except httpx.RequestError as exc:
                raise NetworkError(
                    f"Network error on {method} {path}: {exc}"
                ) from exc

            if response.is_success:
                return self._parse_response(response, binary)

            # Map error response
            reason, message, request_id, details = _parse_error_response(response)
            err = create_error(response.status_code, reason, message, request_id, details)

            # Don't retry non-retryable errors, nor any request carrying an MFA code
            #
            if _carries_otp(headers, self._client.headers) or not should_retry_request(err, method, path):
                raise err

            last_error = err

            if attempt >= self._config.max_retries:
                break

            # P15-01: honour Retry-After on any retryable error; never retry before it.
            delay = _retry_delay(err, attempt, base_delay, max_delay)
            if delay is None:
                raise err

            time.sleep(delay)

        raise last_error  # type: ignore[misc]

    def get(
        self,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.request("GET", path, headers=headers, params=params)

    def post(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.request("POST", path, json=body, headers=headers, params=params)

    def put(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return self.request("PUT", path, json=body, headers=headers)

    def patch(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.request("PATCH", path, json=body, headers=headers, params=params)

    def delete(
        self,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return self.request("DELETE", path, headers=headers, params=params)

    @staticmethod
    def _parse_response(response: httpx.Response, binary: bool = False) -> Any:
        if binary:
            return response.content
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        text = response.text
        return text if text else None

    # -------------------------------------------------------------------
    # SSE streaming
    # -------------------------------------------------------------------

    def stream(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Iterator[Any]:
        """Sends a request exactly like :meth:`request`, but expects an SSE
        response body and yields each parsed event as it arrives instead of
        waiting for the response to complete.

        Deliberately not wrapped in :meth:`request`'s retry logic — a
        partially-consumed streaming session is not restartable as a single
        idempotent HTTP call the way a JSON request is (mirrors the server's
        own ``IDEMPOTENCY_STREAMING_UNSUPPORTED`` rejection and the identical
        decision made for ``sdk/javascript``'s ``HttpClient.stream()``).

        No overall time budget is enforced unless the caller passes
        ``timeout`` explicitly. Unlike :meth:`request`, ``self._config.timeout``
        (default 30s) is intentionally NOT applied here — the server bounds a
        streaming session at ``STREAM_MAX_DURATION_MS`` (default 5 minutes;
), and defaulting to a 30s client
        timeout would silently truncate almost every real stream.

        Raises:
            :class:`~qodiqa.exceptions.TimeoutError`: If ``timeout`` was given
                and the connection or an individual read exceeded it, or the
                overall stream ran longer than ``timeout`` seconds.
            :class:`~qodiqa.exceptions.NetworkError`: On connection failure or
                an unexpected mid-stream disconnect.
            :class:`~qodiqa.exceptions.QodiqaError`: For a pre-stream HTTP
                error response (enforcement ``BLOCK``, ``401``/``403``, etc.)
                or a malformed SSE frame.
        """
        request_timeout: Any = (
            httpx.Timeout(timeout)
            if timeout is not None
            # no overall/read cap by default, but keep the connect timeout so an unreachable or
            # half-open server cannot hang the caller indefinitely.
            else httpx.Timeout(None, connect=self._config.timeout)
        )
        deadline = (time.monotonic() + timeout) if timeout is not None else None
        query = {k: v for k, v in (params or {}).items() if v is not None}

        try:
            attempt = 0
            while True:
                with self._client.stream(
                    method,
                    path,
                    json=json,
                    headers=headers or {},
                    params=query,
                    timeout=request_timeout,
                ) as response:
                    # a pre-stream policy/verification BLOCK
                    # now returns HTTP 200 (not 403) with a JSON body —
                    # `is_success` alone can no longer detect "enforcement
                    # failed before the stream opened". A real stream response
                    # is always `text/event-stream`; any JSON content-type here
                    # (at ANY status) means the stream never opened. There is no
                    # sensible way to represent that as a yielded SSE event, so
                    # this still raises — same classification as before, just
                    # no longer gated on status.
                    content_type = response.headers.get("content-type", "")
                    if not response.is_success or "application/json" in content_type:
                        response.read()
                        reason, message, request_id, details = _parse_error_response(response)
                        err = create_error(response.status_code, reason, message, request_id, details)
                        delay = _stream_resend_delay(err, attempt, self._config.max_retries, headers, self._client.headers, deadline)
                        if delay is None:
                            raise err
                    else:
                        state: Dict[str, bool] = {}

                        def _bounded_chunks() -> Iterator[bytes]:
                            for chunk in response.iter_bytes():
                                if deadline is not None and time.monotonic() > deadline:
                                    raise TimeoutError(
                                        f"Streaming request timed out after {timeout}s: {method} {path}"
                                    )
                                yield chunk

                        yield from iter_sse_events(_bounded_chunks(), state)
                        _raise_if_truncated(state, method, path)
                        return
                time.sleep(delay)
                attempt += 1
        except QodiqaError:
            raise
        except httpx.TimeoutException as exc:
            budget = timeout if timeout is not None else self._config.timeout
            raise TimeoutError(
                f"Streaming request timed out after {budget}s: {method} {path}"
            ) from exc
        except httpx.RequestError as exc:
            raise NetworkError(
                f"Streaming connection was interrupted: {method} {path} ({exc})"
            ) from exc
        except Exception as exc:
            # Anything else reaching here (e.g. a malformed byte sequence the
            # incremental UTF-8 decoder rejects) is a raw low-level failure,
            # not an already-typed SDK error — normalize it so every error
            # this method can raise is a QodiqaError subclass, same as
            # request().
            raise NetworkError(
                f"Streaming connection was interrupted: {method} {path} ({exc})"
            ) from exc


# ---------------------------------------------------------------------------
# Async HTTP client
# ---------------------------------------------------------------------------


class AsyncHttpClient:
    """Asynchronous HTTP client wrapping ``httpx.AsyncClient``."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._client = _build_async_httpx_client(config)

    async def aclose(self) -> None:
        """Close the underlying connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        binary: bool = False,
    ) -> Any:
        """Async counterpart of :meth:`HttpClient.request` (retry policy + one-shot MFA step-up resend)."""
        try:
            return await self._request(method, path, json=json, headers=headers, params=params, binary=binary)
        except QodiqaError as err:
            if not _needs_otp(err, self._config, headers):
                raise
            otp_headers = {**(headers or {}), "X-QODIQA-OTP": str(self._config.otp_provider())}  # type: ignore[misc]
            return await self._request(method, path, json=json, headers=otp_headers, params=params, binary=binary)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        binary: bool = False,
    ) -> Any:
        """Execute an async HTTP request with retry logic."""
        import asyncio

        base_delay = 0.5
        max_delay = 30.0
        last_error: Optional[Exception] = None

        for attempt in range(self._config.max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json,
                    headers=headers or {},
                    params={k: v for k, v in (params or {}).items() if v is not None},
                )
            except httpx.TimeoutException as exc:
                raise TimeoutError(
                    f"Request timed out after {self._config.timeout}s: {method} {path}"
                ) from exc
            except httpx.RequestError as exc:
                raise NetworkError(
                    f"Network error on {method} {path}: {exc}"
                ) from exc

            if response.is_success:
                return self._parse_response(response, binary)

            reason, message, request_id, details = _parse_error_response(response)
            err = create_error(response.status_code, reason, message, request_id, details)

            if _carries_otp(headers, self._client.headers) or not should_retry_request(err, method, path):
                raise err

            last_error = err

            if attempt >= self._config.max_retries:
                break

            delay = _retry_delay(err, attempt, base_delay, max_delay)
            if delay is None:
                raise err

            await asyncio.sleep(delay)

        raise last_error  # type: ignore[misc]

    async def get(
        self,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return await self.request("GET", path, headers=headers, params=params)

    async def post(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return await self.request("POST", path, json=body, headers=headers, params=params)

    async def put(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return await self.request("PUT", path, json=body, headers=headers)

    async def patch(
        self,
        path: str,
        body: Optional[Any] = None,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return await self.request("PATCH", path, json=body, headers=headers, params=params)

    async def delete(
        self,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return await self.request("DELETE", path, headers=headers, params=params)

    @staticmethod
    def _parse_response(response: httpx.Response, binary: bool = False) -> Any:
        if binary:
            return response.content
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            return response.json()
        text = response.text
        return text if text else None

    # -------------------------------------------------------------------
    # SSE streaming
    # -------------------------------------------------------------------

    async def stream(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[Any]:
        """Async counterpart of :meth:`HttpClient.stream`. See its docstring
        for the full contract (no retry, no default timeout, error mapping).
        """
        request_timeout: Any = (
            httpx.Timeout(timeout)
            if timeout is not None
            # no overall/read cap by default, but keep the connect timeout so an unreachable or
            # half-open server cannot hang the caller indefinitely.
            else httpx.Timeout(None, connect=self._config.timeout)
        )
        deadline = (time.monotonic() + timeout) if timeout is not None else None
        query = {k: v for k, v in (params or {}).items() if v is not None}

        import asyncio

        try:
            attempt = 0
            while True:
                async with self._client.stream(
                    method,
                    path,
                    json=json,
                    headers=headers or {},
                    params=query,
                    timeout=request_timeout,
                ) as response:
                    # see the sync stream()'s identical comment
                    # above — a 2xx pre-stream BLOCK must still raise, detected
                    # via Content-Type rather than is_success alone.
                    content_type = response.headers.get("content-type", "")
                    if not response.is_success or "application/json" in content_type:
                        await response.aread()
                        reason, message, request_id, details = _parse_error_response(response)
                        err = create_error(response.status_code, reason, message, request_id, details)
                        delay = _stream_resend_delay(err, attempt, self._config.max_retries, headers, self._client.headers, deadline)
                        if delay is None:
                            raise err
                    else:
                        state: Dict[str, bool] = {}

                        async def _bounded_chunks() -> AsyncIterator[bytes]:
                            async for chunk in response.aiter_bytes():
                                if deadline is not None and time.monotonic() > deadline:
                                    raise TimeoutError(
                                        f"Streaming request timed out after {timeout}s: {method} {path}"
                                    )
                                yield chunk

                        async for event in aiter_sse_events(_bounded_chunks(), state):
                            yield event
                        _raise_if_truncated(state, method, path)
                        return
                await asyncio.sleep(delay)
                attempt += 1
        except QodiqaError:
            raise
        except httpx.TimeoutException as exc:
            budget = timeout if timeout is not None else self._config.timeout
            raise TimeoutError(
                f"Streaming request timed out after {budget}s: {method} {path}"
            ) from exc
        except httpx.RequestError as exc:
            raise NetworkError(
                f"Streaming connection was interrupted: {method} {path} ({exc})"
            ) from exc
        except Exception as exc:
            raise NetworkError(
                f"Streaming connection was interrupted: {method} {path} ({exc})"
            ) from exc
