"""QODIQA SDK client configuration.

Configuration is validated once at construction time and then frozen — the
:class:`ClientConfig` dataclass is immutable so callers cannot accidentally
modify shared state after the client is created.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional
from urllib.parse import urlparse

from .exceptions import ValidationError
from ._version import __version__

_API_KEY_RE = re.compile(r"^ok_[0-9a-f]{64}$")

DEFAULT_BASE_URL = "http://localhost:3000"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_USER_AGENT = f"qodiqa-python/{__version__} python/{sys.version.split()[0]}"


@dataclass(frozen=True)
class ClientConfig:
    """Immutable configuration for :class:`~qodiqa.QodiqaClient`.

    All fields are validated at construction time.

    Args:
        api_key: Ops API key — must match ``ok_[0-9a-f]{64}`` when provided.
            Required for admin-protected endpoints (webhooks, stats, batch).
        sign_token: Per-identity signing API key (prefix ``sk_``), sent as
            ``Authorization: Bearer <sign_token>`` for ``POST /sign``.
            Issued via ``POST /signing-identities/:id/api-key`` or
            ``scripts/provision-signing-identity.js`` — never a shared secret.
        base_url: Base URL of the QODIQA server.  Default: ``http://localhost:3000``.
        timeout: Request timeout in seconds.  Default: ``30.0``.
        max_retries: Maximum retry attempts for retryable errors.  Default: ``2``.
        default_headers: Extra HTTP headers merged into every request.
        user_agent: Override the ``User-Agent`` header.
        verify_ssl: Whether to verify TLS certificates.  Default: ``True``.
        proxy: Optional HTTP/HTTPS proxy URL.

    Raises:
        :class:`~qodiqa.exceptions.ValidationError`: If any field fails
            validation.
    """

    api_key: Optional[str] = None
    sign_token: Optional[str] = None
    base_url: str = DEFAULT_BASE_URL
    timeout: float = DEFAULT_TIMEOUT
    max_retries: int = DEFAULT_MAX_RETRIES
    default_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = DEFAULT_USER_AGENT
    verify_ssl: bool = True
    proxy: Optional[str] = None
    #Operator MFA step-up: called only when the server answers 401 ``MFA_REQUIRED`` to a mutation
    #: (refused before the handler runs); the request is then resent ONCE with ``X-QODIQA-OTP``. Return a fresh code —
    #: the server accepts a TOTP code at most once per 30-second step.
    otp_provider: Optional[Callable[[], str]] = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValidationError(
                f'Invalid base_url: "{self.base_url}" — must be a valid http or https URL.'
            )

        if self.api_key is not None and not _API_KEY_RE.match(self.api_key):
            raise ValidationError(
                'Invalid api_key: must start with "ok_" followed by exactly '
                "64 hexadecimal characters (total 67 chars)."
            )

        if self.timeout <= 0:
            raise ValidationError("timeout must be a positive number (seconds).")

        if not isinstance(self.max_retries, int) or self.max_retries < 0:
            raise ValidationError("max_retries must be a non-negative integer.")
