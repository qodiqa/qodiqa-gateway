"""QODIQA SDK exception hierarchy.

All SDK exceptions derive from :class:`QodiqaError`.  HTTP-level errors carry
a ``status`` code, a ``request_id`` for server correlation, and a ``details``
dict from the response body.

Example::

    from qodiqa.exceptions import (
        QodiqaError,
        AuthenticationError,
        RateLimitError,
    )

    try:
        client.chat.create(artifact, request)
    except AuthenticationError as exc:
        print("Auth failed:", exc.message)
    except RateLimitError as exc:
        if exc.retry_after is not None:
            time.sleep(exc.retry_after)
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class QodiqaError(Exception):
    """Base class for all QODIQA SDK errors.

    Attributes:
        message: Human-readable error description.
        status: HTTP status code, or ``None`` for network-level errors.
        request_id: Server-assigned request ID for tracing, when available.
        details: Additional structured detail from the server response.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.request_id = request_id
        self.details: Dict[str, Any] = details or {}
        #: Machine-readable server reason / error code (e.g. ``INVALID_SIGNATURE``, ``MFA_REQUIRED``), when known.
        self.reason = reason

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"message={self.message!r}, "
            f"status={self.status!r}, "
            f"request_id={self.request_id!r})"
        )


class AuthenticationError(QodiqaError):
    """HTTP 401 — missing or invalid credentials.

    Raised when the API key, sign token, or artifact header is absent or invalid.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 401)
        super().__init__(message, **kwargs)


class AuthorizationError(QodiqaError):
    """HTTP 403 — authenticated but not authorized for this operation.

    The credentials are valid but the caller lacks permission to perform
    the requested action (e.g. missing ops API key scope).
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 403)
        super().__init__(message, **kwargs)


class ValidationError(QodiqaError):
    """HTTP 400 / 422 — request payload or parameter is invalid."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 400)
        super().__init__(message, **kwargs)


class VerificationError(QodiqaError):
    """Artifact verification failed at the cryptographic level.

    Raised when the server signals that an artifact's signature is invalid,
    the artifact has expired or been tampered with, or its structure is
    malformed.  This is distinct from a policy ``BLOCK`` decision, which is
    a successful response where enforcement logic denies the request.

    Common ``reason`` values carried in ``details``:

    * ``INVALID_SIGNATURE``
    * ``INVALID_ARTIFACT``
    * ``KEY_NOT_FOUND``
    * ``EXPIRED``
    * ``FUTURE_TIMESTAMP``
    * ``TIME_SKEW_EXCEEDED``
    * ``REQUEST_MISMATCH``
    * ``REPLAY_DETECTED``
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 400)
        super().__init__(message, **kwargs)


class NotFoundError(QodiqaError):
    """HTTP 404 — the requested resource does not exist."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 404)
        super().__init__(message, **kwargs)


class RateLimitError(QodiqaError):
    """HTTP 429 — the caller has exceeded the rate limit.

    Attributes:
        retry_after: Seconds to wait before retrying, when provided by the
            server in the ``Retry-After`` response header.
    """

    def __init__(
        self,
        message: str,
        *,
        retry_after: Optional[float] = None,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("status", 429)
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ServerError(QodiqaError):
    """HTTP 5xx — an unexpected server-side error occurred."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 500)
        super().__init__(message, **kwargs)


class KillSwitchError(ServerError):
    """The gateway's global kill switch is active (``KILL_SWITCH_ACTIVE``), or this replica cannot confirm its state (``KILL_SWITCH_STATE_UNAVAILABLE``).

    Every /sign and /ai/chat request is refused with HTTP 503 until an operator releases it. Nothing was signed, no nonce was consumed and no provider was
    called, so retrying later is safe — but the SDK never retries it automatically (it can last hours). ``retry_after`` (seconds) is the server's hint.
    """

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kwargs: Any) -> None:
        kwargs.setdefault("status", 503)
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class BlockedError(QodiqaError):
    """An enforcement ``BLOCK`` decision surfaced as an exception.

    ``chat.create()`` RETURNS a non-verification BLOCK (policy, consent, semantic, ...) as its normal result — read
    ``decision``. ``chat.stream()`` cannot return a decision from an iterator, so a BLOCK decided before the stream
    opened is raised as this error (or as :class:`VerificationError` for an artifact failure, on both paths alike).
    """

    decision = "BLOCK"


class MfaRequiredError(AuthenticationError):
    """HTTP 401 ``MFA_REQUIRED`` / ``MFA_INVALID`` — this operator mutation needs an MFA step-up code in
    ``X-QODIQA-OTP``. Pass ``otp_provider`` to the client to supply one automatically.
    Subclass of :class:`AuthenticationError`, so existing handlers still match.
    """


class MfaEnrollmentRequiredError(AuthorizationError):
    """HTTP 403 ``MFA_ENROLLMENT_REQUIRED`` — enroll MFA first (POST /rbac/me/mfa/enroll, then /confirm)."""


class MfaLockedError(QodiqaError):
    """HTTP 429 ``MFA_LOCKED`` — too many failed MFA codes. Never retried automatically."""

    def __init__(self, message: str, *, retry_after: Optional[float] = None, **kwargs: Any) -> None:
        kwargs.setdefault("status", 429)
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class NetworkError(QodiqaError):
    """A network-level failure prevented the request from completing.

    Examples: DNS resolution failure, connection refused, TLS error.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)


class TimeoutError(QodiqaError):
    """The request exceeded the configured timeout budget."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)


class UnknownError(QodiqaError):
    """Catch-all for HTTP status codes not mapped to a specific subclass."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)


# ---------------------------------------------------------------------------
# Crypto / local errors (preserved from prior SDK version)
# ---------------------------------------------------------------------------


class SigningError(QodiqaError):
    """Raised when local artifact signing fails."""


class SerializationError(QodiqaError):
    """Raised when canonical serialization encounters an unexpected value."""


class CryptoKeyError(QodiqaError):
    """Raised when key material is invalid, missing, or unsupported."""


# ---------------------------------------------------------------------------
# Webhook verification errors
# ---------------------------------------------------------------------------


class InvalidSignatureError(QodiqaError):
    """Webhook HMAC does not match any active secret.

    Raised when the computed HMAC-SHA256 does not match any of the
    ``sha256=`` values in the ``X-QODIQA-Signature`` header for any
    configured secret.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 401)
        super().__init__(message, **kwargs)


class ExpiredSignatureError(QodiqaError):
    """Webhook timestamp is outside the accepted tolerance window.

    Raised when the ``X-QODIQA-Timestamp`` header value is more than
    :data:`~qodiqa.webhook_verifier.DEFAULT_TOLERANCE_SECONDS` seconds away
    from the current clock, protecting against replay attacks.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 401)
        super().__init__(message, **kwargs)


class MalformedSignatureError(QodiqaError):
    """The ``X-QODIQA-Signature`` header cannot be parsed.

    Raised when the header is missing, empty, or does not contain a
    well-formed ``sha256=<hex>`` component.
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 400)
        super().__init__(message, **kwargs)


class InvalidTimestampError(QodiqaError):
    """The ``X-QODIQA-Timestamp`` header is missing or malformed.

    Raised when the header is absent or does not contain a valid ISO-8601
    UTC timestamp (e.g. ``"2026-01-01T00:00:00.000Z"``).
    """

    def __init__(self, message: str, **kwargs: Any) -> None:
        kwargs.setdefault("status", 400)
        super().__init__(message, **kwargs)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

# Enforcement BLOCK reasons that mean "the artifact itself was rejected" — the server's artifact_malformed,
# artifact_invalid, request_mismatch and replay classes (src/api/blockHttpStatus.js). Mapped to VerificationError at
# any HTTP status by both chat.create() and chat.stream(). Held equal to the server table by
# src/api/__tests__/ind14SdkContractDrift.test.js in the gateway repository.
VERIFICATION_REASONS = frozenset(
    {
        # artifact_malformed
        "MISSING_ARTIFACT", "ARTIFACT_DECODE_FAILED", "ARTIFACT_INVALID_TYPE", "INVALID_JSON", "NOT_OBJECT",
        "MISSING_SIGNATURE", "MALFORMED_REQUEST_ID", "VERSION_MISMATCH", "UNSUPPORTED_PROTOCOL_VERSION",
        "UNSUPPORTED_CRITICAL_CLAIM",
        # artifact_invalid
        "PROTOCOL_VERSION_TOO_LOW", "WRONG_ARTIFACT_KIND", "ARTIFACT_REVOKED",
        "INVALID_ARTIFACT", "INVALID_SIGNATURE", "SIGNATURE_UNVERIFIABLE", "KEY_NOT_FOUND", "KEY_REVOKED",
        "KEY_ARCHIVED", "KEY_DEPRECATED", "KEY_NOT_YET_ACTIVE", "KEY_NOT_ACTIVE_AT_SIGNING_TIME",
        "KEY_STATUS_UNKNOWN", "SIGNING_TIME_UNKNOWN", "EXPIRED", "FUTURE_TIMESTAMP", "TIME_SKEW_EXCEEDED",
        "INVALID_EXPIRY", "MISSING_TIMESTAMP",
        # request_mismatch, replay
        "REQUEST_MISMATCH", "REPLAY_DETECTED",
    }
)
_VERIFICATION_REASONS = VERIFICATION_REASONS  # backward-compatible private alias


def create_error(
    status: int,
    reason: str,
    message: str,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> QodiqaError:
    """Map an HTTP status code and QODIQA reason string to the right error class.

    Args:
        status: HTTP response status code.
        reason: Machine-readable reason string from the response body.
        message: Human-readable error message.
        request_id: Server-assigned request correlation ID.
        details: Structured detail dict from the response body.

    Returns:
        An appropriate :class:`QodiqaError` subclass instance.
    """
    opts: Dict[str, Any] = {
        "status": status,
        "request_id": request_id,
        "details": details or {},
        "reason": reason,
    }

    # / API-04: operator MFA step-up (src/middleware/mfaStepUp.js) — before the generic 401/403/429 branches.
    if reason in ("MFA_REQUIRED", "MFA_INVALID"):
        return MfaRequiredError(message, **opts)
    if reason == "MFA_ENROLLMENT_REQUIRED":
        return MfaEnrollmentRequiredError(message, **opts)
    if reason == "MFA_LOCKED":
        locked_after: Optional[float] = None
        if details and isinstance(details.get("retryAfter"), (int, float)):
            locked_after = float(details["retryAfter"])
        return MfaLockedError(message, retry_after=locked_after, **opts)

    if status == 401 or reason in ("UNAUTHORIZED", "UNAUTHENTICATED"):
        return AuthenticationError(message, **opts)

    # (SDK half): checked BEFORE the blanket status==403 branch below —
    # every reason in _VERIFICATION_REASONS maps to HTTP 403 server-side
    # (src/errors/catalog.js), so checking status first always masked this
    # branch as AuthorizationError instead. None of these reasons is ever
    # paired with a genuine authorization failure (catalog.js confirms all
    # 8 are in the 'validation'/'replay' categories, never 'auth'), so this
    # reorder cannot misclassify a real 401/403 authentication/authorization
    # error — it only recovers the cases that were always meant to be
    # VerificationError.
    if reason in VERIFICATION_REASONS:
        return VerificationError(message, **opts)

    if status == 403 or reason == "FORBIDDEN":
        return AuthorizationError(message, **opts)

    if status == 404 or reason == "NOT_FOUND":
        return NotFoundError(message, **opts)

    if status == 429 or reason in ("RATE_LIMITED", "RATE_LIMIT_EXCEEDED"):
        retry_after: Optional[float] = None
        if details and isinstance(details.get("retryAfter"), (int, float)):
            retry_after = float(details["retryAfter"])
        return RateLimitError(message, retry_after=retry_after, **opts)

    if status in (400, 422) or reason in ("VALIDATION_ERROR", "INVALID_REQUEST"):
        return ValidationError(message, **opts)

    # the global kill switch (HTTP 503 BLOCK) — a distinct class so callers can tell "stopped by an operator" from an outage.
    if reason in ("KILL_SWITCH_ACTIVE", "KILL_SWITCH_STATE_UNAVAILABLE"):
        ks_after: Optional[float] = None
        if details and isinstance(details.get("retryAfter"), (int, float)):
            ks_after = float(details["retryAfter"])
        return KillSwitchError(message, retry_after=ks_after, **opts)

    if 500 <= status < 600:
        return ServerError(message, **opts)

    # A 2xx enforcement BLOCK that reached an error path (only chat.stream(): the stream never opened).
    if 200 <= status < 300:
        return BlockedError(message, **opts)

    return UnknownError(message, **opts)
