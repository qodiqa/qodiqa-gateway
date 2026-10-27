"""Tests for ClientConfig validation."""

from __future__ import annotations

import pytest

from qodiqa import QodiqaClient
from qodiqa.config import ClientConfig
from qodiqa.exceptions import ValidationError

VALID_KEY = "ok_" + "a" * 64


class TestClientConfig:
    def test_default_config_is_valid(self) -> None:
        cfg = ClientConfig()
        assert cfg.base_url == "http://localhost:3000"
        assert cfg.timeout == 30.0
        assert cfg.max_retries == 2

    def test_full_config(self) -> None:
        cfg = ClientConfig(
            api_key=VALID_KEY,
            sign_token="tok",
            base_url="https://gateway.example.com",
            timeout=15.0,
            max_retries=3,
        )
        assert cfg.api_key == VALID_KEY
        assert cfg.timeout == 15.0

    def test_invalid_base_url_raises(self) -> None:
        with pytest.raises(ValidationError, match="base_url"):
            ClientConfig(base_url="not-a-url")

    def test_invalid_api_key_raises(self) -> None:
        with pytest.raises(ValidationError, match="api_key"):
            ClientConfig(api_key="bad-key")

    def test_api_key_wrong_prefix_raises(self) -> None:
        with pytest.raises(ValidationError):
            ClientConfig(api_key="sk_" + "f" * 64)

    def test_api_key_too_short_raises(self) -> None:
        with pytest.raises(ValidationError):
            ClientConfig(api_key="ok_" + "a" * 63)

    def test_api_key_none_is_allowed(self) -> None:
        cfg = ClientConfig(api_key=None)
        assert cfg.api_key is None

    def test_zero_timeout_raises(self) -> None:
        with pytest.raises(ValidationError, match="timeout"):
            ClientConfig(timeout=0)

    def test_negative_timeout_raises(self) -> None:
        with pytest.raises(ValidationError):
            ClientConfig(timeout=-1.0)

    def test_negative_max_retries_raises(self) -> None:
        with pytest.raises(ValidationError, match="max_retries"):
            ClientConfig(max_retries=-1)

    def test_config_is_immutable(self) -> None:
        cfg = ClientConfig()
        with pytest.raises((AttributeError, TypeError)):
            cfg.timeout = 99.0  # type: ignore[misc]

    def test_user_agent_contains_version(self) -> None:
        cfg = ClientConfig()
        assert "qodiqa-python" in cfg.user_agent


class TestQodiqaClientInstantiation:
    def test_creates_with_defaults(self) -> None:
        client = QodiqaClient()
        assert client is not None
        client.close()

    def test_creates_with_full_config(self) -> None:
        client = QodiqaClient(
            api_key=VALID_KEY,
            sign_token="tok",
            base_url="http://localhost:3000",
            timeout=10.0,
            max_retries=3,
        )
        assert client is not None
        client.close()

    def test_exposes_all_resources(self) -> None:
        client = QodiqaClient()
        assert client.sign is not None
        assert client.chat is not None
        assert client.verify is not None
        assert client.portal is not None
        assert client.attestation is not None
        assert client.transparency is not None
        assert client.evidence is not None
        assert client.certification is not None
        assert client.webhooks is not None
        client.close()

    def test_context_manager(self) -> None:
        with QodiqaClient() as client:
            assert client is not None

    def test_invalid_base_url_raises_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            QodiqaClient(base_url="not-a-url")

    def test_invalid_api_key_raises_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            QodiqaClient(api_key="bad-key")

    def test_zero_timeout_raises_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            QodiqaClient(timeout=0)

    def test_negative_max_retries_raises_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            QodiqaClient(max_retries=-1)
