"""Tests for qodiqa._verification._key_providers."""

from __future__ import annotations

import base64

import httpx
import pytest
from pytest_httpx import HTTPXMock

from qodiqa import (
    AsyncRemoteKeyProvider,
    RemoteKeyProvider,
    StaticKeyProvider,
    create_async_key_provider,
    create_key_provider,
)

PUB_B64 = "MCowBQYDK2VwAyEArI9wKSGHg7Ig9ZtbOg+7d/QSddFvQ9xHSQxJ7ErydFs="
DISCOVERY_URL = "http://test.local/.well-known/qodiqa/keys"


class TestStaticKeyProvider:
    def test_resolves_a_configured_key(self) -> None:
        provider = StaticKeyProvider([{"keyId": "k1", "publicKey": PUB_B64, "status": "active"}])
        resolved = provider.get_public_key("k1")
        assert resolved is not None
        assert resolved.status == "active"
        assert base64.b64encode(resolved.pub_der).decode() == PUB_B64

    def test_returns_none_for_unknown_key(self) -> None:
        provider = StaticKeyProvider([{"keyId": "k1", "publicKey": PUB_B64, "status": "active"}])
        assert provider.get_public_key("unknown") is None

    def test_preserves_revoked_status(self) -> None:
        provider = StaticKeyProvider([{"keyId": "k1", "publicKey": PUB_B64, "status": "revoked"}])
        assert provider.get_public_key("k1").status == "revoked"


class TestCreateKeyProvider:
    def test_adapts_a_plain_function(self) -> None:
        def lookup(key_id: str):
            from qodiqa import ResolvedKey

            if key_id == "k1":
                return ResolvedKey(pub_der=base64.b64decode(PUB_B64), status="active")
            return None

        provider = create_key_provider(lookup)
        assert provider.get_public_key("k1").status == "active"
        assert provider.get_public_key("other") is None


class TestRemoteKeyProvider:
    def test_fetches_and_resolves_a_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "dev-local:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = provider.get_public_key("dev-local:key_v1")
        assert resolved.status == "active"
        assert base64.b64encode(resolved.pub_der).decode() == PUB_B64
        provider.close()

    def test_returns_none_for_key_absent_from_response(self, httpx_mock: HTTPXMock) -> None:
        # a key absent from the live list now falls back to the
        # archived tier before giving up — mock it empty too, so this test
        # still exercises "absent everywhere" rather than an unmocked call.
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(url=f"{DISCOVERY_URL}/archived", json={"keys": []})
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert provider.get_public_key("unknown:key_v1") is None
        provider.close()

    def test_caches_within_ttl(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL, cache_ttl_ms=60_000)
        provider.get_public_key("k1")
        provider.get_public_key("k1")
        provider.get_public_key("k1")
        assert len(httpx_mock.get_requests()) == 1
        provider.close()

    def test_refresh_bypasses_cache(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL, cache_ttl_ms=60_000)
        provider.get_public_key("k1")
        provider.refresh()
        assert len(httpx_mock.get_requests()) == 2
        provider.close()

    def test_network_failure_is_caught_not_raised(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert provider.get_public_key("k1") is None
        provider.close()

    def test_http_error_status_is_caught_not_raised(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, status_code=500)
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert provider.get_public_key("k1") is None
        provider.close()


class TestRemoteKeyProviderArchivedFallback:
    """archived-tier fallback, sync provider."""

    ARCHIVED_URL = f"{DISCOVERY_URL}/archived"

    def test_falls_back_to_archived_when_absent_from_live_list(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(
            url=self.ARCHIVED_URL,
            json={"keys": [{"keyId": "purged:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "archived", "source": "archived"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = provider.get_public_key("purged:key_v1")
        assert resolved is not None
        assert resolved.status == "deprecated"  # normalized from the wire-only "archived" marker
        assert resolved.source == "archived"
        assert base64.b64encode(resolved.pub_der).decode() == PUB_B64
        provider.close()

    def test_live_key_never_triggers_an_archived_lookup(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        # No mock registered for ARCHIVED_URL — an attempted call would raise
        # inside pytest_httpx's teardown assertion, failing this test.
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = provider.get_public_key("k1")
        assert resolved.source == "live"
        provider.close()

    def test_unknown_everywhere_resolves_to_none(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(url=self.ARCHIVED_URL, json={"keys": []})
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert provider.get_public_key("nowhere:key_v1") is None
        provider.close()

    def test_archived_tier_cached_independently_within_ttl(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(
            url=self.ARCHIVED_URL,
            json={"keys": [{"keyId": "purged:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "archived"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL, cache_ttl_ms=60_000)
        provider.get_public_key("purged:key_v1")
        provider.get_public_key("purged:key_v1")
        provider.get_public_key("purged:key_v1")
        archived_calls = [r for r in httpx_mock.get_requests() if str(r.url) == self.ARCHIVED_URL]
        assert len(archived_calls) == 1
        provider.close()

    def test_no_archived_tier_derived_for_transparency_keys_url(self, httpx_mock: HTTPXMock) -> None:
        transparency_url = "http://test.local/.well-known/qodiqa/transparency-keys"
        httpx_mock.add_response(url=transparency_url, json={"keys": []})
        provider = RemoteKeyProvider(discovery_url=transparency_url)
        assert provider.get_public_key("unknown:key_v1") is None
        provider.close()

    def test_explicit_archived_discovery_url_override(self, httpx_mock: HTTPXMock) -> None:
        custom_archived_url = "http://test.local/custom/archived-keys"
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(
            url=custom_archived_url,
            json={"keys": [{"keyId": "purged:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "archived"}]},
        )
        provider = RemoteKeyProvider(discovery_url=DISCOVERY_URL, archived_discovery_url=custom_archived_url)
        resolved = provider.get_public_key("purged:key_v1")
        assert resolved is not None
        assert resolved.source == "archived"
        provider.close()


class TestAsyncRemoteKeyProvider:
    async def test_fetches_and_resolves_a_key(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "dev-local:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = await provider.get_public_key("dev-local:key_v1")
        assert resolved.status == "active"
        await provider.aclose()

    async def test_network_failure_is_caught_not_raised(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("connection refused"))
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert await provider.get_public_key("k1") is None
        await provider.aclose()

    async def test_create_async_key_provider_adapts_a_coroutine_function(self) -> None:
        from qodiqa import ResolvedKey

        async def lookup(key_id: str):
            if key_id == "k1":
                return ResolvedKey(pub_der=base64.b64decode(PUB_B64), status="active")
            return None

        provider = create_async_key_provider(lookup)
        resolved = await provider.get_public_key("k1")
        assert resolved.status == "active"
        assert await provider.get_public_key("other") is None


class TestAsyncRemoteKeyProviderArchivedFallback:
    """archived-tier fallback, async provider (mirrors the sync suite above)."""

    ARCHIVED_URL = f"{DISCOVERY_URL}/archived"

    async def test_falls_back_to_archived_when_absent_from_live_list(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(
            url=self.ARCHIVED_URL,
            json={"keys": [{"keyId": "purged:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "archived", "source": "archived"}]},
        )
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = await provider.get_public_key("purged:key_v1")
        assert resolved is not None
        assert resolved.status == "deprecated"
        assert resolved.source == "archived"
        await provider.aclose()

    async def test_live_key_never_triggers_an_archived_lookup(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=DISCOVERY_URL,
            json={"keys": [{"keyId": "k1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "active"}]},
        )
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL)
        resolved = await provider.get_public_key("k1")
        assert resolved.source == "live"
        await provider.aclose()

    async def test_unknown_everywhere_resolves_to_none(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(url=self.ARCHIVED_URL, json={"keys": []})
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL)
        assert await provider.get_public_key("nowhere:key_v1") is None
        await provider.aclose()

    async def test_archived_tier_cached_independently_within_ttl(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=DISCOVERY_URL, json={"keys": []})
        httpx_mock.add_response(
            url=self.ARCHIVED_URL,
            json={"keys": [{"keyId": "purged:key_v1", "algorithm": "ed25519", "publicKey": PUB_B64, "status": "archived"}]},
        )
        provider = AsyncRemoteKeyProvider(discovery_url=DISCOVERY_URL, cache_ttl_ms=60_000)
        await provider.get_public_key("purged:key_v1")
        await provider.get_public_key("purged:key_v1")
        await provider.get_public_key("purged:key_v1")
        archived_calls = [r for r in httpx_mock.get_requests() if str(r.url) == self.ARCHIVED_URL]
        assert len(archived_calls) == 1
        await provider.aclose()
