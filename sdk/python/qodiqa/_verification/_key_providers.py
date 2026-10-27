"""Public-key resolution for local artifact/transparency verification.

Three supported approaches: an embedded/supplied static trust bundle, a remote
endpoint with TTL caching, or a fully custom provider. Unknown key IDs
always resolve to ``None`` — the verifier fails closed.
"""

from __future__ import annotations

import base64
import inspect
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional, Protocol, TypedDict, Union, cast

import httpx

from ..models import KeyStatus


@dataclass(frozen=True)
class ResolvedKey:
    pub_der: bytes
    status: KeyStatus
    #: Which discovery tier resolved this key: "live" (the ordinary case) or
    #: "archived" when it was only resolvable via the archived-key fallback
    #:, i.e. it had already been purged from the live keystore.
    #: Purely diagnostic — never affects whether ``status`` is treated as
    #: valid for verification. Providers that don't distinguish tiers (e.g.
    #: :class:`StaticKeyProvider`) leave this at the default "live".
    source: str = "live"


class KeyProvider(Protocol):
    """A source of truth for `key_id -> public key` resolution (sync)."""

    def get_public_key(self, key_id: str) -> Optional[ResolvedKey]: ...


class AsyncKeyProvider(Protocol):
    """A source of truth for `key_id -> public key` resolution (async)."""

    async def get_public_key(self, key_id: str) -> Optional[ResolvedKey]: ...


async def maybe_await_get_public_key(
    provider: Union[KeyProvider, AsyncKeyProvider], key_id: str
) -> Optional[ResolvedKey]:
    """Call `provider.get_public_key(key_id)` and await the result only if it
    is actually awaitable.

    This is what lets a no-I/O provider like :class:`StaticKeyProvider` —
    whose `get_public_key` is a plain synchronous method — be used
    interchangeably with :class:`AsyncArtifactVerifier` and
    :func:`async_verify_transparency_proof`, without every provider having to
    declare an `async def` method regardless of whether it does any I/O.
    Genuinely I/O-bound async providers (:class:`AsyncRemoteKeyProvider`)
    still run non-blocking as normal, since their `get_public_key` really is
    a coroutine function. Do not pass a blocking sync :class:`RemoteKeyProvider`
    to an async verifier — its `get_public_key` performs real (blocking)
    network I/O and would stall the event loop; use
    :class:`AsyncRemoteKeyProvider` there instead.
    """
    result = provider.get_public_key(key_id)
    if inspect.isawaitable(result):
        return await result
    return result


class StaticKeyEntry(TypedDict):
    keyId: str
    publicKey: str  # base64-encoded SPKI DER
    status: KeyStatus


class StaticKeyProvider:
    """Trust bundle supplied directly by the caller — either embedded at
    build time or fetched/pinned out-of-band. No network access. Usable
    from both sync and async verifiers, since it performs no I/O.
    """

    def __init__(self, entries: List[StaticKeyEntry]) -> None:
        self._keys: Dict[str, ResolvedKey] = {
            entry["keyId"]: ResolvedKey(pub_der=base64.b64decode(entry["publicKey"]), status=entry["status"])
            for entry in entries
        }

    def get_public_key(self, key_id: str) -> Optional[ResolvedKey]:
        return self._keys.get(key_id)


class _DiscoveryKeyEntry(TypedDict):
    keyId: str
    algorithm: str
    publicKey: str
    # The live endpoint always sends a real KeyStatus ("active" | "deprecated").
    # The archived endpoint sends the literal string "archived",
    # which is not itself a KeyStatus — the fetch helpers below normalize it
    # to "deprecated" (the status it actually held immediately before being
    # purged) rather than propagating the wire-only "archived" marker into
    # ResolvedKey.status, so `str` is used here rather than `KeyStatus`.
    status: str


def _derive_archived_url(discovery_url: str) -> Optional[str]:
    """Default archived-tier discovery URL for a given live discovery URL.

    Only the artifact-signing key discovery endpoint has an archived tier
    (see ``src/api/routes/well-known.js``) — never derive one for
    ``/qodiqa/transparency-keys`` or a custom URL shape we can't be sure of.
    """
    return f"{discovery_url}/archived" if discovery_url.endswith("/qodiqa/keys") else None


def _parse_key_list(body: Dict[str, Any], *, source: str) -> Dict[str, ResolvedKey]:
    keys: Dict[str, ResolvedKey] = {}
    for entry in body.get("keys", []):
        # Archived entries carry the wire-only status "archived" — normalize
        # to "deprecated", the real status they held immediately before
        # being purged (see _DiscoveryKeyEntry.status above).
        status = "deprecated" if source == "archived" else entry["status"]
        keys[entry["keyId"]] = ResolvedKey(pub_der=base64.b64decode(entry["publicKey"]), status=cast(Literal["active", "deprecated", "revoked"], status), source=source)
    return keys


class RemoteKeyProvider:
    """Sync resolver for a ``/.well-known/qodiqa/keys``-shaped discovery
    endpoint (or the transparency-key sibling,
    ``/.well-known/qodiqa/transparency-keys``), with an in-memory TTL cache
    so repeated verifications don't refetch on every call.

    A network failure never raises out of :meth:`get_public_key` — it is
    surfaced as a resolution failure (``None``, same as "unknown key"; if a
    caller needs to distinguish the two, call :meth:`refresh` directly).

    when a key_id isn't found in the primary list (but the primary
    fetch itself succeeded), and an archived-tier URL is configured/derived,
    this transparently retries against ``GET
    /.well-known/qodiqa/keys/archived`` before giving up — extending
    verification to keys that have since been purged from the live keystore.
    The archived list is cached independently (same TTL) and is only ever
    fetched after a primary-list miss, so primary lookup latency and cache
    behavior are completely unchanged.
    """

    def __init__(
        self,
        *,
        discovery_url: str,
        archived_discovery_url: Optional[str] = None,
        cache_ttl_ms: int = 300_000,
        client: Optional[httpx.Client] = None,
        timeout: float = 10.0,
    ) -> None:
        self._discovery_url = discovery_url
        self._archived_discovery_url = (
            archived_discovery_url if archived_discovery_url is not None else _derive_archived_url(discovery_url)
        )
        self._cache_ttl_ms = cache_ttl_ms
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._cache: Optional[Dict[str, ResolvedKey]] = None
        self._cached_at_ms = 0.0
        self._archived_cache: Optional[Dict[str, ResolvedKey]] = None
        self._archived_cached_at_ms = 0.0

    def refresh(self) -> None:
        """Force a re-fetch of the key list (both the live and, if configured, archived tiers), bypassing the cache."""
        self._cache = None
        self._archived_cache = None
        self._load_keys()

    def get_public_key(self, key_id: str) -> Optional[ResolvedKey]:
        try:
            keys = self._load_keys()
        except Exception:
            return None
        hit = keys.get(key_id)
        if hit is not None:
            return hit

        if not self._archived_discovery_url:
            return None
        try:
            archived_keys = self._load_archived_keys()
        except Exception:
            return None
        return archived_keys.get(key_id)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _load_keys(self) -> Dict[str, ResolvedKey]:
        now = time.time() * 1000
        if self._cache is not None and now - self._cached_at_ms < self._cache_ttl_ms:
            return self._cache
        keys = self._fetch_key_list(self._discovery_url, source="live")
        self._cache = keys
        self._cached_at_ms = now
        return keys

    def _load_archived_keys(self) -> Dict[str, ResolvedKey]:
        now = time.time() * 1000
        if self._archived_cache is not None and now - self._archived_cached_at_ms < self._cache_ttl_ms:
            return self._archived_cache
        assert self._archived_discovery_url is not None
        keys = self._fetch_key_list(self._archived_discovery_url, source="archived")
        self._archived_cache = keys
        self._archived_cached_at_ms = now
        return keys

    def _fetch_key_list(self, url: str, *, source: str) -> Dict[str, ResolvedKey]:
        response = self._client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        return _parse_key_list(response.json(), source=source)


class AsyncRemoteKeyProvider:
    """Async counterpart of :class:`RemoteKeyProvider`, backed by
    ``httpx.AsyncClient``. See:class:`RemoteKeyProvider` for the
    archived-tier fallback behavior, identical here in async form.
    """

    def __init__(
        self,
        *,
        discovery_url: str,
        archived_discovery_url: Optional[str] = None,
        cache_ttl_ms: int = 300_000,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 10.0,
    ) -> None:
        self._discovery_url = discovery_url
        self._archived_discovery_url = (
            archived_discovery_url if archived_discovery_url is not None else _derive_archived_url(discovery_url)
        )
        self._cache_ttl_ms = cache_ttl_ms
        self._client = client or httpx.AsyncClient(timeout=timeout)
        self._owns_client = client is None
        self._cache: Optional[Dict[str, ResolvedKey]] = None
        self._cached_at_ms = 0.0
        self._archived_cache: Optional[Dict[str, ResolvedKey]] = None
        self._archived_cached_at_ms = 0.0

    async def refresh(self) -> None:
        self._cache = None
        self._archived_cache = None
        await self._load_keys()

    async def get_public_key(self, key_id: str) -> Optional[ResolvedKey]:
        try:
            keys = await self._load_keys()
        except Exception:
            return None
        hit = keys.get(key_id)
        if hit is not None:
            return hit

        if not self._archived_discovery_url:
            return None
        try:
            archived_keys = await self._load_archived_keys()
        except Exception:
            return None
        return archived_keys.get(key_id)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _load_keys(self) -> Dict[str, ResolvedKey]:
        now = time.time() * 1000
        if self._cache is not None and now - self._cached_at_ms < self._cache_ttl_ms:
            return self._cache
        keys = await self._fetch_key_list(self._discovery_url, source="live")
        self._cache = keys
        self._cached_at_ms = now
        return keys

    async def _load_archived_keys(self) -> Dict[str, ResolvedKey]:
        now = time.time() * 1000
        if self._archived_cache is not None and now - self._archived_cached_at_ms < self._cache_ttl_ms:
            return self._archived_cache
        assert self._archived_discovery_url is not None
        keys = await self._fetch_key_list(self._archived_discovery_url, source="archived")
        self._archived_cache = keys
        self._archived_cached_at_ms = now
        return keys

    async def _fetch_key_list(self, url: str, *, source: str) -> Dict[str, ResolvedKey]:
        response = await self._client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        return _parse_key_list(response.json(), source=source)


def create_key_provider(fn: Callable[[str], Optional[ResolvedKey]]) -> KeyProvider:
    """Adapt an arbitrary sync lookup function into a :class:`KeyProvider`."""

    class _Adapter:
        def get_public_key(self, key_id: str) -> Optional[ResolvedKey]:
            return fn(key_id)

    return _Adapter()


def create_async_key_provider(fn: Callable[[str], Awaitable[Optional[ResolvedKey]]]) -> AsyncKeyProvider:
    """Adapt an arbitrary async lookup function into an :class:`AsyncKeyProvider`."""

    class _Adapter:
        async def get_public_key(self, key_id: str) -> Optional[ResolvedKey]:
            return await fn(key_id)

    return _Adapter()
