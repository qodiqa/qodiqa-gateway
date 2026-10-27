"""QODIQA Webhook Signature Verification.

Verifies that incoming webhook requests were genuinely sent by QODIQA and
were not modified in transit.

Signature format
----------------
QODIQA signs each webhook delivery with HMAC-SHA256 and sends the result in
the ``X-QODIQA-Signature`` request header, with the delivery timestamp sent
*separately* in its own ``X-QODIQA-Timestamp`` header::

    X-QODIQA-Timestamp: 2026-01-01T00:00:00.000Z
    X-QODIQA-Signature: sha256=<hex_hmac>

If an intermediary proxy folds duplicate ``X-QODIQA-Signature`` headers into
one comma-separated value, each ``sha256=`` component is checked in turn.

Canonical message
------------------
The HMAC is computed over::

    <raw_X-QODIQA-Timestamp_header_value> + "." + <raw_request_body>

The timestamp must be passed through exactly as received in the
``X-QODIQA-Timestamp`` header — never reformatted or re-serialised — and the
body must be the **raw bytes** as received, never a re-serialised JSON string.

Example::

    from qodiqa import verify_webhook_signature, WebhookVerifier
    from qodiqa.exceptions import InvalidSignatureError, ExpiredSignatureError

    # Convenience function
    verify_webhook_signature(
        body=request.body,
        signature=request.headers["X-QODIQA-Signature"],
        timestamp=request.headers["X-QODIQA-Timestamp"],
        secret=WEBHOOK_SECRET,
    )

    # Reusable verifier (preferred for multiple endpoints)
    verifier = WebhookVerifier(WEBHOOK_SECRET)
    verifier.verify(
        body=request.body,
        signature=request.headers["X-QODIQA-Signature"],
        timestamp=request.headers["X-QODIQA-Timestamp"],
    )
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from typing import List, Optional, Union

from .exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTimestampError,
    MalformedSignatureError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Default timestamp tolerance in seconds (5 minutes).
DEFAULT_TOLERANCE_SECONDS: int = 300

_SIGNATURE_SCHEME = "sha256"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Matches the ISO-8601 UTC format produced by JavaScript's Date.toISOString(),
# e.g. "2026-01-01T00:00:00.000Z". Fractional seconds are optional.
_ISO8601_UTC_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_signature_header(header: str) -> list[str]:
    """Parse the ``X-QODIQA-Signature`` header value.

    Accepts one or more comma-separated ``sha256=<hex>`` components (an
    intermediary may fold duplicate headers of the same name into a single
    comma-joined value). Components using an unrecognised scheme prefix are
    ignored for forward compatibility, as long as at least one ``sha256=``
    component is present.

    Returns:
        The list of lowercase hex digest strings found.

    Raises:
        :class:`~qodiqa.exceptions.MalformedSignatureError`: Header cannot be parsed.
    """
    if not header or not header.strip():
        raise MalformedSignatureError(
            "The X-QODIQA-Signature header is empty or missing."
        )

    digests: list[str] = []
    saw_unrecognized_scheme = False

    for part in header.split(","):
        value = part.strip()
        if not value:
            continue

        eq_idx = value.find("=")
        if eq_idx == -1:
            raise MalformedSignatureError(
                f"Malformed component in X-QODIQA-Signature: {value!r}"
            )

        scheme = value[:eq_idx].strip().lower()
        digest = value[eq_idx + 1:].strip()

        if scheme != _SIGNATURE_SCHEME:
            # Forward-compatible: unrecognised schemes (e.g. a future sha512=)
            # are silently ignored.
            saw_unrecognized_scheme = True
            continue

        if not digest:
            raise MalformedSignatureError(
                "Found an empty sha256 signature value in X-QODIQA-Signature."
            )
        if not _HEX_RE.match(digest):
            raise MalformedSignatureError(
                f"Non-hex sha256 signature value in X-QODIQA-Signature: {digest!r}"
            )
        digests.append(digest.lower())

    if not digests:
        if saw_unrecognized_scheme:
            raise MalformedSignatureError(
                "X-QODIQA-Signature contains no supported signature scheme; "
                'expected a "sha256=" component.'
            )
        raise MalformedSignatureError(
            'No "sha256=" signature found in X-QODIQA-Signature header.'
        )

    return digests


def _parse_timestamp_header(value: str) -> float:
    """Parse the ``X-QODIQA-Timestamp`` header value into Unix epoch seconds.

    The header carries an ISO-8601 UTC timestamp exactly as produced by
    JavaScript's ``Date.prototype.toISOString()``
    (e.g. ``"2026-01-01T00:00:00.000Z"``).

    Raises:
        :class:`~qodiqa.exceptions.InvalidTimestampError`: Header is missing
            or not a valid ISO-8601 UTC timestamp.
    """
    if not value or not value.strip():
        raise InvalidTimestampError(
            "The X-QODIQA-Timestamp header is empty or missing."
        )

    match = _ISO8601_UTC_RE.match(value.strip())
    if not match:
        raise InvalidTimestampError(
            f"Invalid timestamp in X-QODIQA-Timestamp: {value!r}. "
            'Expected ISO-8601 UTC format, e.g. "2026-01-01T00:00:00.000Z".'
        )

    year, month, day, hour, minute, second, frac = match.groups()
    microsecond = int(frac.ljust(6, "0")[:6]) if frac else 0

    try:
        dt = datetime(
            int(year), int(month), int(day),
            int(hour), int(minute), int(second),
            microsecond,
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise InvalidTimestampError(
            f"Invalid timestamp in X-QODIQA-Timestamp: {value!r} ({exc})"
        ) from exc

    return dt.timestamp()


def _compute_expected_digest(
    timestamp: str,
    body: Union[str, bytes],
    secret: str,
) -> bytes:
    """Compute the HMAC-SHA256 digest for the canonical payload.

    ``timestamp`` must be the raw ``X-QODIQA-Timestamp`` header value —
    never reparsed or reformatted — since the server signs the literal
    header string.

    Returns raw digest bytes (not hex) so we can use :func:`hmac.compare_digest`.
    """
    prefix = f"{timestamp}.".encode("utf-8")
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    payload = prefix + body_bytes
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Public API — function
# ---------------------------------------------------------------------------

def verify_webhook_signature(
    *,
    body: Union[str, bytes],
    signature: str,
    timestamp: str,
    secret: Union[str, List[str]],
    tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    _now: Optional[float] = None,
) -> None:
    """Verify a QODIQA webhook signature.

    Call this at the top of every webhook handler before trusting the payload.

    Args:
        body: Raw request body exactly as received — a UTF-8 ``str`` or ``bytes``.
            Never pass a re-serialised JSON string.
        signature: Value of the ``X-QODIQA-Signature`` request header
            (``sha256=<hex>``).
        timestamp: Value of the ``X-QODIQA-Timestamp`` request header, passed
            through exactly as received — never reformatted.
        secret: Your webhook signing secret, or a list of secrets to support
            rotation (verification succeeds if any secret matches).
        tolerance: Maximum age of the webhook timestamp in seconds.  Requests
            outside this window are rejected to prevent replay attacks.
            Defaults to :data:`DEFAULT_TOLERANCE_SECONDS` (300 s).
        _now: Override the current Unix time (seconds).  For testing only.

    Raises:
        :class:`~qodiqa.exceptions.MalformedSignatureError`: Header cannot be parsed.
        :class:`~qodiqa.exceptions.InvalidTimestampError`: Timestamp is not a valid
            ISO-8601 UTC value.
        :class:`~qodiqa.exceptions.ExpiredSignatureError`: Timestamp is outside tolerance.
        :class:`~qodiqa.exceptions.InvalidSignatureError`: HMAC does not match any secret.

    Example::

        from qodiqa import verify_webhook_signature

        @app.post("/webhooks/qodiqa")
        async def webhook(request: Request):
            verify_webhook_signature(
                body=await request.body(),
                signature=request.headers["x-qodiqa-signature"],
                timestamp=request.headers["x-qodiqa-timestamp"],
                secret=WEBHOOK_SECRET,
            )
            event = await request.json()
            # process event ...
    """
    secrets: list[str] = [secret] if isinstance(secret, str) else list(secret)
    now = _now if _now is not None else time.time()

    if not secrets:
        raise InvalidSignatureError("At least one webhook secret must be provided.")

    digests = _parse_signature_header(signature)
    ts_epoch = _parse_timestamp_header(timestamp)

    # Timestamp tolerance — prevents replay attacks.
    age = abs(now - ts_epoch)
    if age > tolerance:
        raise ExpiredSignatureError(
            f"Webhook timestamp is {age:.3f}s away from current time "
            f"(tolerance: {tolerance}s). "
            "This may indicate a replay attack or a clock skew issue."
        )

    # Try every (secret x digest) pair using constant-time comparison.
    for sec in secrets:
        expected = _compute_expected_digest(timestamp, body, sec)
        for digest_hex in digests:
            try:
                actual = bytes.fromhex(digest_hex)
            except ValueError:
                continue
            if hmac.compare_digest(expected, actual):
                return  # Valid

    raise InvalidSignatureError(
        "Webhook signature verification failed: no active secret produces a matching HMAC. "
        "Ensure you are using the correct webhook secret and that the request body "
        "has not been modified."
    )


# ---------------------------------------------------------------------------
# Public API — class
# ---------------------------------------------------------------------------

class WebhookVerifier:
    """Reusable webhook signature verifier.

    Configure your secret(s) and tolerance once; call :meth:`verify` for each
    incoming request.  Prefer this class when handling multiple endpoints or
    when you want to encapsulate the verifier in middleware.

    Args:
        secret: Your webhook signing secret, or a list of secrets to support
            rotation.
        tolerance: Maximum timestamp age in seconds.  Defaults to
            :data:`DEFAULT_TOLERANCE_SECONDS` (300 s).

    Example::

        verifier = WebhookVerifier(WEBHOOK_SECRET)

        @app.post("/webhooks/qodiqa")
        async def webhook(request: Request):
            verifier.verify(
                body=await request.body(),
                signature=request.headers["x-qodiqa-signature"],
                timestamp=request.headers["x-qodiqa-timestamp"],
            )

    Example — secret rotation::

        verifier = WebhookVerifier([
            NEW_WEBHOOK_SECRET,
            OLD_WEBHOOK_SECRET,
        ])
    """

    def __init__(
        self,
        secret: Union[str, List[str]],
        *,
        tolerance: int = DEFAULT_TOLERANCE_SECONDS,
    ) -> None:
        secrets = [secret] if isinstance(secret, str) else list(secret)
        if not secrets:
            raise InvalidSignatureError(
                "At least one webhook secret must be provided."
            )
        self._secrets: list[str] = secrets
        self._tolerance: int = tolerance

    def verify(
        self,
        *,
        body: Union[str, bytes],
        signature: str,
        timestamp: str,
        _now: Optional[float] = None,
    ) -> None:
        """Verify the signature on a single webhook delivery.

        Args:
            body: Raw request body (``str`` or ``bytes``).
            signature: Value of the ``X-QODIQA-Signature`` header.
            timestamp: Value of the ``X-QODIQA-Timestamp`` header.
            _now: Override current time (seconds).  For testing only.

        Raises:
            :class:`~qodiqa.exceptions.MalformedSignatureError`
            :class:`~qodiqa.exceptions.InvalidTimestampError`
            :class:`~qodiqa.exceptions.ExpiredSignatureError`
            :class:`~qodiqa.exceptions.InvalidSignatureError`
        """
        verify_webhook_signature(
            body=body,
            signature=signature,
            timestamp=timestamp,
            secret=self._secrets,
            tolerance=self._tolerance,
            _now=_now,
        )
