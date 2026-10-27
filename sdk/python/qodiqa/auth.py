"""QODIQA SDK authentication provider.

Internal module — not part of the public API.
"""

from __future__ import annotations

from typing import Dict

from .config import ClientConfig
from .exceptions import AuthenticationError


class AuthProvider:
    """Builds authentication headers for QODIQA API requests.

    This class is internal to the SDK.  Users never interact with it directly.
    """

    def __init__(self, config: ClientConfig) -> None:
        self._config = config

    def get_auth_header(self) -> Dict[str, str]:
        """Return the ``Authorization: Bearer ok_…`` header for ops endpoints.

        Raises:
            AuthenticationError: If no ``api_key`` was configured.
        """
        if not self._config.api_key:
            raise AuthenticationError(
                "An ops API key (api_key) is required for this endpoint. "
                'Provide it when constructing QodiqaClient: QodiqaClient(api_key="ok_...").'
            )
        return {"Authorization": f"Bearer {self._config.api_key}"}

    def get_artifact_header(self, artifact_b64: str) -> Dict[str, str]:
        """Return the ``x-qodiqa-artifact`` header from a base64 artifact string.

        Raises:
            AuthenticationError: If ``artifact_b64`` is empty.
        """
        if not artifact_b64 or not artifact_b64.strip():
            raise AuthenticationError(
                "A base64-encoded artifact string is required for this endpoint."
            )
        return {"x-qodiqa-artifact": artifact_b64}

    def get_sign_token_header(self) -> Dict[str, str]:
        """Return the ``Authorization: Bearer <token>`` header for ``POST /sign``.

        As of the TRUST-1 remediation, ``POST /sign`` no longer accepts a
        single shared secret via ``x-qodiqa-sign-token`` — every caller
        authenticates with its own individually-issued, individually-
        revocable signing API key (prefix ``sk_``), provisioned via
        ``POST /signing-identities`` or
        ``scripts/provision-signing-identity.js``. The ``sign_token``
        config field name is unchanged for backward compatibility; its
        value is now a per-identity signing key rather than a shared token.

 remediation (follow-on to TRUST-1): the server now embeds
        this key's authenticated identity (``callerContext`` — see
        ``ArtifactPayload`` in models.py) directly into every artifact it
        signs, so the returned artifact durably proves not just which
        shared tenant key signed it, but which specific ``sk_...``
        credential requested the signature. Nothing to change on the
        client side — this happens automatically server-side from the
        credential presented here.

        Raises:
            AuthenticationError: If no ``sign_token`` was configured.
        """
        if not self._config.sign_token:
            raise AuthenticationError(
                "A signing API key (sign_token) is required to call POST /sign. "
                "Provide it when constructing QodiqaClient: "
                'QodiqaClient(sign_token="sk_...").'
            )
        return {"Authorization": f"Bearer {self._config.sign_token}"}
