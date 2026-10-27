"""Tests for TransparencyResource and AsyncTransparencyResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import AuthenticationError, ValidationError

BASE_URL = "http://test.local"
VALID_KEY = "ok_" + "c" * 64

ENTRY = {
    "id": "entry-001",
    "artifactId": "art-001",
    "timestamp": "2024-01-01T00:00:00Z",
    "hash": "abc123",
}

ROOT = {"treeSize": 100, "rootHash": "rootabc", "timestamp": "2024-01-01T00:00:00Z"}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestGetEntry:
    def test_returns_entry(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ENTRY)
        result = make_client().transparency.get_entry("entry-001")
        assert result["id"] == "entry-001"

    def test_fetches_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ENTRY)
        make_client().transparency.get_entry("entry-001")
        req = httpx_mock.get_requests()[0]
        assert "/v1/transparency/entry/entry-001" in str(req.url)

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().transparency.get_entry("")


class TestListEntries:
    def test_returns_entries(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [ENTRY], "total": 1})
        result = make_client().transparency.list_entries()
        assert result["total"] == 1

    def test_sends_pagination_params(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [], "total": 0})
        make_client().transparency.list_entries({"page": 3, "pageSize": 5})
        req = httpx_mock.get_requests()[0]
        assert "page=3" in str(req.url)


class TestGetRoot:
    def test_returns_root(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ROOT)
        result = make_client().transparency.get_root()
        assert result["treeSize"] == 100


class TestVerifyEntry:
    def test_verifies_entry(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"valid": True})
        result = make_client().transparency.verify_entry("entry-001")
        assert result["valid"] is True

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().transparency.verify_entry("")


class TestGetProof:
    def test_returns_proof(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"proof": ["hash1", "hash2"]})
        result = make_client().transparency.get_proof("entry-001")
        assert "proof" in result

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client().transparency.get_proof("")


class TestTransparencyOpsEndpoints:
    def test_register_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().transparency.register({"hash": "abc"})

    def test_register_posts_to_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"id": "entry-new"})
        make_client(api_key=VALID_KEY).transparency.register({"hash": "abc"})
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/v1/transparency/register")

    def test_stats_requires_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().transparency.stats()

    def test_validate_chain_calls_transparency_validator(self, httpx_mock: HTTPXMock) -> None:
        # the TRANSPARENCY chain validator, not the audit-chain endpoint (/audit/chain/integrity).
        httpx_mock.add_response(json={"status": "success", "data": {"chainValidation": {"valid": True, "checkedCount": 2}}})
        make_client(api_key=VALID_KEY).transparency.validate_chain()
        req = httpx_mock.get_requests()[0]
        assert req.url.path == "/v1/transparency/admin/chain/validate"

    def test_validate_chain_forwards_range(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "success", "data": {}})
        make_client(api_key=VALID_KEY).transparency.validate_chain(start_id="1", end_id="9", limit=50)
        q = httpx_mock.get_requests()[0].url.params
        assert (q["startId"], q["endId"], q["limit"]) == ("1", "9", "50")


class TestTransparencyRootsW12:
    """list_roots calls /v1/transparency/roots; get_root accepts root_id."""

    ROW = {"id": "1", "root_id": "49d25ba4-5f5f-4f63-85cf-b2c5c851ac76", "seq_from": "1", "seq_to": "2", "entry_count": 2,
           "root_hash": "9c48368c91610b89c176fe494001d9e9c6b1df676d56c621e03eda20ba28590f", "previous_root_hash": None,
           "signer_key_id": "tr-dev-local:key_v1", "generated_by": "admin", "generated_at": "2026-10-02T07:11:13.340Z"}

    def test_list_roots_calls_roots_endpoint(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "success", "data": {"roots": [self.ROW], "total": 1, "page": 1, "pageSize": 5}})
        res = make_client().transparency.list_roots({"page": 1, "page_size": 5})
        req = httpx_mock.get_requests()[0]
        assert req.url.path == "/v1/transparency/roots"
        assert (req.url.params["page"], req.url.params["pageSize"]) == ("1", "5")
        assert res["data"]["roots"][0]["root_hash"] == self.ROW["root_hash"]

    def test_get_root_latest_and_by_id(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"status": "success", "data": {"root": self.ROW}})
        httpx_mock.add_response(json={"status": "success", "data": {"root": self.ROW}})
        c = make_client()
        c.transparency.get_root()
        c.transparency.get_root(self.ROW["root_id"])
        r0, r1 = httpx_mock.get_requests()
        assert r0.url.path == "/v1/transparency/root" and "rootId" not in r0.url.params
        assert r1.url.params["rootId"] == self.ROW["root_id"]

    def test_path_ids_are_encoded_as_one_segment(self, httpx_mock: HTTPXMock) -> None:
        # an id can never address a different route
        httpx_mock.add_response(json={"status": "success", "data": {"entry": {}}})
        make_client().transparency.get_entry("a/b?c")
        assert str(httpx_mock.get_requests()[0].url).endswith("/v1/transparency/entry/a%2Fb%3Fc")


class TestAsyncTransparencyResource:
    async def test_get_entry(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ENTRY)
        async with make_async_client() as client:
            result = await client.transparency.get_entry("entry-001")
        assert result["id"] == "entry-001"

    async def test_get_root(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=ROOT)
        async with make_async_client() as client:
            result = await client.transparency.get_root()
        assert result["treeSize"] == 100

    async def test_raises_on_empty_id(self) -> None:
        async with make_async_client() as client:
            with pytest.raises(ValidationError):
                await client.transparency.get_entry("")
