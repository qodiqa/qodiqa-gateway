"""Tests for SignResource and AsyncSignResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import QodiqaClient, AsyncQodiqaClient
from qodiqa.exceptions import AuthenticationError, ValidationError

BASE_URL = "http://test.local"
SIGN_TOKEN = "my-sign-token"
VALID_KEY = "ok_" + "c" * 64


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


SIGN_RESPONSE = {
    "artifactId": "art-001",
    "artifact": {"expiry": 9999999999, "signature": "sig123"},
    "expiresAt": "2099-01-01T00:00:00Z",
}

SIGN_REQUEST = {
    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hello"}},
    "payload": {"userId": "u_1"},
    "ttl": 300_000,
}


class TestSignResource:
    def test_sends_sign_token_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert req.headers["Authorization"] == f"Bearer {SIGN_TOKEN}"

    def test_returns_sign_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        result = make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST)
        assert result["artifactId"] == "art-001"

    def test_raises_when_no_sign_token(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().sign.sign(SIGN_REQUEST)

    def test_raises_on_empty_method(self) -> None:
        with pytest.raises(ValidationError):
            make_client(sign_token=SIGN_TOKEN).sign.sign(
                {"request": {"method": "", "path": "/ai/chat"}}
            )

    def test_raises_on_empty_path(self) -> None:
        with pytest.raises(ValidationError):
            make_client(sign_token=SIGN_TOKEN).sign.sign(
                {"request": {"method": "POST", "path": ""}}
            )

    def test_sends_artifact_chain_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST, artifact_header="existing-b64")
        req = httpx_mock.get_requests()[0]
        assert req.headers["x-qodiqa-artifact"] == "existing-b64"

    def test_no_artifact_header_without_chain(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert "x-qodiqa-artifact" not in req.headers

    def test_posts_to_correct_url(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert str(req.url).endswith("/sign")

    def test_401_from_server_raises_auth_error(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            status_code=401,
            json={"reason": "UNAUTHORIZED", "message": "bad token"},
        )
        with pytest.raises(AuthenticationError):
            make_client(sign_token=SIGN_TOKEN).sign.sign(SIGN_REQUEST)


class TestAsyncSignResource:
    async def test_returns_sign_response(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        async with make_async_client(sign_token=SIGN_TOKEN) as client:
            result = await client.sign.sign(SIGN_REQUEST)
        assert result["artifactId"] == "art-001"

    async def test_raises_on_empty_method(self) -> None:
        async with make_async_client(sign_token=SIGN_TOKEN) as client:
            with pytest.raises(ValidationError):
                await client.sign.sign({"request": {"method": "", "path": "/ai/chat"}})

    async def test_sends_sign_token_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=SIGN_RESPONSE)
        async with make_async_client(sign_token=SIGN_TOKEN) as client:
            await client.sign.sign(SIGN_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert req.headers["Authorization"] == f"Bearer {SIGN_TOKEN}"
