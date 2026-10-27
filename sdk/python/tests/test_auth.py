"""Tests for the AuthProvider."""

from __future__ import annotations

import pytest

from qodiqa.auth import AuthProvider
from qodiqa.config import ClientConfig
from qodiqa.exceptions import AuthenticationError

VALID_KEY = "ok_" + "b" * 64


def make_auth(api_key=None, sign_token=None):
    return AuthProvider(ClientConfig(api_key=api_key, sign_token=sign_token))


class TestGetAuthHeader:
    def test_returns_bearer_header(self) -> None:
        auth = make_auth(api_key=VALID_KEY)
        headers = auth.get_auth_header()
        assert headers["Authorization"] == f"Bearer {VALID_KEY}"

    def test_raises_when_no_api_key(self) -> None:
        auth = make_auth()
        with pytest.raises(AuthenticationError, match="api_key"):
            auth.get_auth_header()


class TestGetArtifactHeader:
    def test_returns_artifact_header(self) -> None:
        auth = make_auth()
        headers = auth.get_artifact_header("my-base64-artifact")
        assert headers["x-qodiqa-artifact"] == "my-base64-artifact"

    def test_raises_on_empty_artifact(self) -> None:
        auth = make_auth()
        with pytest.raises(AuthenticationError):
            auth.get_artifact_header("")

    def test_raises_on_whitespace_artifact(self) -> None:
        auth = make_auth()
        with pytest.raises(AuthenticationError):
            auth.get_artifact_header("   ")


class TestGetSignTokenHeader:
    def test_returns_sign_token_header(self) -> None:
        auth = make_auth(sign_token="my-sign-token")
        headers = auth.get_sign_token_header()
        assert headers["Authorization"] == "Bearer my-sign-token"

    def test_raises_when_no_sign_token(self) -> None:
        auth = make_auth()
        with pytest.raises(AuthenticationError, match="sign_token"):
            auth.get_sign_token_header()
