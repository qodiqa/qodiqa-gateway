"""QODIQA SDK main client classes.

Two client classes are provided:

* :class:`QodiqaClient` — synchronous (default)
* :class:`AsyncQodiqaClient` — async/await for use with ``asyncio``

Both support the context-manager protocol for automatic connection cleanup.

Example (sync)::

    from qodiqa import QodiqaClient

    with QodiqaClient(sign_token="...", base_url="http://localhost:3000") as client:
        health = client.health_check()

Example (async)::

    from qodiqa import AsyncQodiqaClient

    async with AsyncQodiqaClient(sign_token="...") as client:
        health = await client.health_check()
"""

from __future__ import annotations

from typing import Any, Callable, cast, Dict, Optional
from ._paths import seg as _seg

from .auth import AuthProvider
from .config import ClientConfig
from .exceptions import ValidationError
from ._operations import AsyncOperationsResource, OperationsResource
from ._http import AsyncHttpClient, HttpClient
from .models import ApiResponse, AuditResponse, HealthResponse, KeysResponse, PublicKey, ReadyResponse
from .resources.attestation import AsyncAttestationResource, AttestationResource
from .resources.certification import AsyncCertificationResource, CertificationResource
from .resources.chat import AsyncChatResource, ChatResource
from .resources.evidence import AsyncEvidenceResource, EvidenceResource
from .resources.portal import AsyncPortalResource, PortalResource
from .resources.sign import AsyncSignResource, SignResource
from .resources.transparency import AsyncTransparencyResource, TransparencyResource
from .resources.verify import AsyncVerifyResource, VerifyResource
from .resources.webhooks import AsyncWebhooksResource, WebhooksResource
from .resources.simulation import AsyncSimulationResource, SimulationResource
from .resources import agents_actions as _fa

class QodiqaClient:
    """Synchronous QODIQA API client.

    All configuration is validated once at construction time and then frozen.
    The client owns an ``httpx.Client`` connection pool; call :meth:`close` (or
    use the context-manager form) to release it when you are done.

    Args:
        api_key: Ops API key (``ok_<64hex>``).  Required for admin endpoints.
        sign_token: Sign token for ``POST /sign``.
        base_url: QODIQA server URL.  Default: ``http://localhost:3000``.
        timeout: Request timeout in seconds.  Default: ``30.0``.
        max_retries: Max retry attempts for transient errors.  Default: ``2``.
        default_headers: Extra headers sent on every request.
        user_agent: Override the ``User-Agent`` header.
        verify_ssl: Verify TLS certificates.  Default: ``True``.
        proxy: HTTP/HTTPS proxy URL.

    Raises:
        :class:`~qodiqa.exceptions.ValidationError`: If the configuration is
            invalid (bad ``base_url``, malformed ``api_key``, etc.).

    Example::

        client = QodiqaClient(
            sign_token="my-sign-token",
            api_key="ok_" + "a" * 64,
            base_url="https://gateway.example.com",
            timeout=15.0,
        )
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        sign_token: Optional[str] = None,
        base_url: str = "http://localhost:3000",
        timeout: float = 30.0,
        max_retries: int = 2,
        default_headers: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        otp_provider: Optional[Callable[[], str]] = None,
    ) -> None:
        from .config import DEFAULT_USER_AGENT

        cfg_kwargs: Dict[str, Any] = {
            "api_key": api_key,
            "sign_token": sign_token,
            "base_url": base_url,
            "timeout": timeout,
            "max_retries": max_retries,
            "default_headers": default_headers or {},
            "verify_ssl": verify_ssl,
        }
        if user_agent is not None:
            cfg_kwargs["user_agent"] = user_agent
        if proxy is not None:
            cfg_kwargs["proxy"] = proxy
        if otp_provider is not None:
            cfg_kwargs["otp_provider"] = otp_provider

        self._config = ClientConfig(**cfg_kwargs)
        self._http = HttpClient(self._config)
        self._auth = AuthProvider(self._config)

        self.sign = SignResource(self._http, self._auth)
        self.chat = ChatResource(self._http, self._auth)
        self.verify = VerifyResource(self._http, self._auth)
        self.portal = PortalResource(self._http, self._auth)
        self.attestation = AttestationResource(self._http, self._auth)
        self.transparency = TransparencyResource(self._http, self._auth)
        self.evidence = EvidenceResource(self._http, self._auth)
        self.certification = CertificationResource(self._http, self._auth)
        self.webhooks = WebhooksResource(self._http, self._auth)
        self.simulation = SimulationResource(self._http, self._auth)
        self.agents = _fa.AgentsResource(self._http, self._auth)
        self.sessions = _fa.SessionsResource(self._http, self._auth)
        self.actions = _fa.ActionsResource(self._http, self._auth)
        self.tools = _fa.ToolsResource(self._http, self._auth)
        self.delegations = _fa.DelegationsResource(self._http, self._auth)
        self.tool_registry = _fa.ToolRegistryResource(self._http, self._auth)
        self.mcp_servers = _fa.McpServersResource(self._http, self._auth)
        self.approvals = _fa.ApprovalsResource(self._http, self._auth)
        self.operations = OperationsResource(self._http, self._auth)   # every documented operation, generated

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> QodiqaClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    def health_check(self) -> HealthResponse:
        """Liveness probe.

        ``GET /health``

        Returns:
            :class:`~qodiqa.models.HealthResponse` with ``status`` and ``uptime``.
        """
        return cast('HealthResponse', self._http.get("/health"))

    def readiness_check(self) -> ReadyResponse:
        """Readiness probe.

        ``GET /ready``

        Returns:
            :class:`~qodiqa.models.ReadyResponse` indicating component status.
        """
        return cast('ReadyResponse', self._http.get("/ready"))

    def get_public_keys(self) -> KeysResponse:
        """Get all active public signing keys.

        ``GET /public-keys``

        Returns:
            :class:`~qodiqa.models.KeysResponse` with a list of
            :class:`~qodiqa.models.PublicKey` objects.
        """
        # Server wraps this in the standard {status,timestamp,requestId,data}
        # envelope — unwrapped here so callers can use keys["keys"] directly.
        res = self._http.get("/public-keys")
        return cast("KeysResponse", res["data"])

    def get_public_key(self, key_id: str) -> PublicKey:
        """Get a single public key by ID.

        ``GET /.well-known/qodiqa/keys/:key_id``

        Args:
            key_id: The key identifier.

        Returns:
            :class:`~qodiqa.models.PublicKey`.

        Raises:
            :class:`~qodiqa.exceptions.ValidationError`: If ``key_id`` is empty.
        """
        if not key_id or not key_id.strip():
            raise ValidationError('"key_id" must be a non-empty string.')
        return cast('PublicKey', self._http.get(f"/.well-known/qodiqa/keys/{_seg(key_id)}"))

    def get_audit_chain(self, artifact_id: str) -> ApiResponse[AuditResponse]:
        """Retrieve the full audit chain for an artifact.

        ``GET /audit/:artifactId``

        Requires an ops API key — this route is mounted behind
        ``adminStack('READ_AUDIT')`` server-side (``src/app.js``).

        Args:
            artifact_id: Artifact identifier.

        Returns:
            :class:`~qodiqa.models.ApiResponse` whose ``data`` is the
            :class:`~qodiqa.models.AuditResponse` (the route replies with the standard
            success envelope).

        Raises:
            :class:`~qodiqa.exceptions.ValidationError`: If ``artifact_id`` is empty.
        """
        if not artifact_id or not artifact_id.strip():
            raise ValidationError('"artifact_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[AuditResponse]', self._http.get(f"/audit/{_seg(artifact_id)}", headers=headers))


class AsyncQodiqaClient:
    """Asynchronous QODIQA API client.

    Drop-in async replacement for :class:`QodiqaClient`.  All methods are
    coroutines and must be awaited.  Use ``async with`` for automatic cleanup.

    Args:
        Same as :class:`QodiqaClient`.

    Example::

        async with AsyncQodiqaClient(sign_token="...") as client:
            health = await client.health_check()
            signed = await client.sign.sign({...})
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        sign_token: Optional[str] = None,
        base_url: str = "http://localhost:3000",
        timeout: float = 30.0,
        max_retries: int = 2,
        default_headers: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        proxy: Optional[str] = None,
        otp_provider: Optional[Callable[[], str]] = None,
    ) -> None:
        from .config import DEFAULT_USER_AGENT

        cfg_kwargs: Dict[str, Any] = {
            "api_key": api_key,
            "sign_token": sign_token,
            "base_url": base_url,
            "timeout": timeout,
            "max_retries": max_retries,
            "default_headers": default_headers or {},
            "verify_ssl": verify_ssl,
        }
        if user_agent is not None:
            cfg_kwargs["user_agent"] = user_agent
        if proxy is not None:
            cfg_kwargs["proxy"] = proxy
        if otp_provider is not None:
            cfg_kwargs["otp_provider"] = otp_provider

        self._config = ClientConfig(**cfg_kwargs)
        self._http = AsyncHttpClient(self._config)
        self._auth = AuthProvider(self._config)

        self.sign = AsyncSignResource(self._http, self._auth)
        self.chat = AsyncChatResource(self._http, self._auth)
        self.verify = AsyncVerifyResource(self._http, self._auth)
        self.portal = AsyncPortalResource(self._http, self._auth)
        self.attestation = AsyncAttestationResource(self._http, self._auth)
        self.transparency = AsyncTransparencyResource(self._http, self._auth)
        self.evidence = AsyncEvidenceResource(self._http, self._auth)
        self.certification = AsyncCertificationResource(self._http, self._auth)
        self.webhooks = AsyncWebhooksResource(self._http, self._auth)
        self.simulation = AsyncSimulationResource(self._http, self._auth)
        self.agents = _fa.AsyncAgentsResource(self._http, self._auth)
        self.sessions = _fa.AsyncSessionsResource(self._http, self._auth)
        self.actions = _fa.AsyncActionsResource(self._http, self._auth)
        self.tools = _fa.AsyncToolsResource(self._http, self._auth)
        self.delegations = _fa.AsyncDelegationsResource(self._http, self._auth)
        self.tool_registry = _fa.AsyncToolRegistryResource(self._http, self._auth)
        self.mcp_servers = _fa.AsyncMcpServersResource(self._http, self._auth)
        self.approvals = _fa.AsyncApprovalsResource(self._http, self._auth)
        self.operations = AsyncOperationsResource(self._http, self._auth)   #

    async def aclose(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> AsyncQodiqaClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def health_check(self) -> HealthResponse:
        """Liveness probe. ``GET /health``"""
        return cast('HealthResponse', await self._http.get("/health"))

    async def readiness_check(self) -> ReadyResponse:
        """Readiness probe. ``GET /ready``"""
        return cast('ReadyResponse', await self._http.get("/ready"))

    async def get_public_keys(self) -> KeysResponse:
        """Get all active public signing keys. ``GET /public-keys``"""
        # Server wraps this in the standard {status,timestamp,requestId,data}
        # envelope — unwrapped here so callers can use keys["keys"] directly.
        res = await self._http.get("/public-keys")
        return cast("KeysResponse", res["data"])

    async def get_public_key(self, key_id: str) -> PublicKey:
        """Get a single public key by ID. ``GET /.well-known/qodiqa/keys/:key_id``"""
        if not key_id or not key_id.strip():
            raise ValidationError('"key_id" must be a non-empty string.')
        return cast('PublicKey', await self._http.get(f"/.well-known/qodiqa/keys/{_seg(key_id)}"))

    async def get_audit_chain(self, artifact_id: str) -> ApiResponse[AuditResponse]:
        """Retrieve the full audit chain for an artifact. ``GET /audit/:artifactId``

        Requires an ops API key — this route is mounted behind
        ``adminStack('READ_AUDIT')`` server-side (``src/app.js``).
        """
        if not artifact_id or not artifact_id.strip():
            raise ValidationError('"artifact_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[AuditResponse]', await self._http.get(f"/audit/{_seg(artifact_id)}", headers=headers))
