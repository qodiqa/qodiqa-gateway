"""Tests for WebhooksResource and AsyncWebhooksResource."""

from __future__ import annotations

import pytest
from pytest_httpx import HTTPXMock

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import AuthenticationError, ValidationError

BASE_URL = "http://test.local"
VALID_KEY = "ok_" + "c" * 64

WEBHOOK_RECORD = {
    "id": "wh-001",
    "tenantId": "tenant-1",
    "url": "https://example.com/hook",
    "eventTypes": ["sign.created"],
    "active": True,
}

CREATE_REQUEST = {
    "tenantId": "tenant-1",
    "url": "https://example.com/hook",
    "eventTypes": ["sign.created"],
}


def make_client(**kwargs) -> QodiqaClient:
    return QodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


def make_async_client(**kwargs) -> AsyncQodiqaClient:
    return AsyncQodiqaClient(base_url=BASE_URL, timeout=5.0, max_retries=0, **kwargs)


class TestWebhooksCreate:
    def test_creates_webhook(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=WEBHOOK_RECORD)
        result = make_client(api_key=VALID_KEY).webhooks.create(CREATE_REQUEST)
        assert result["id"] == "wh-001"

    def test_sends_auth_header(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=WEBHOOK_RECORD)
        make_client(api_key=VALID_KEY).webhooks.create(CREATE_REQUEST)
        req = httpx_mock.get_requests()[0]
        assert req.headers["authorization"] == f"Bearer {VALID_KEY}"

    def test_raises_when_no_api_key(self) -> None:
        with pytest.raises(AuthenticationError):
            make_client().webhooks.create(CREATE_REQUEST)

    def test_raises_on_missing_tenant_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.create(
                {"tenantId": "", "url": "https://example.com/hook", "eventTypes": ["x"]}
            )

    def test_raises_on_missing_url(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.create(
                {"tenantId": "t1", "url": "", "eventTypes": ["x"]}
            )

    def test_raises_on_empty_event_types(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.create(
                {"tenantId": "t1", "url": "https://example.com/hook", "eventTypes": []}
            )


class TestWebhooksList:
    def test_lists_webhooks(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [WEBHOOK_RECORD], "total": 1})
        result = make_client(api_key=VALID_KEY).webhooks.list("tenant-1")
        assert result["total"] == 1

    def test_sends_pagination_params(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [], "total": 0})
        make_client(api_key=VALID_KEY).webhooks.list("tenant-1", {"page": 2, "pageSize": 10})
        req = httpx_mock.get_requests()[0]
        assert "page=2" in str(req.url)

    def test_sends_tenant_id_as_query_param(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [], "total": 0})
        make_client(api_key=VALID_KEY).webhooks.list("tenant-1")
        req = httpx_mock.get_requests()[0]
        assert "tenantId=tenant-1" in str(req.url)

    def test_raises_on_empty_tenant_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.list("")


class TestWebhooksGet:
    def test_gets_webhook(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=WEBHOOK_RECORD)
        result = make_client(api_key=VALID_KEY).webhooks.get("wh-001", "tenant-1")
        assert result["id"] == "wh-001"

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.get("", "tenant-1")


class TestWebhooksUpdate:
    def test_updates_webhook(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={**WEBHOOK_RECORD, "active": False})
        result = make_client(api_key=VALID_KEY).webhooks.update("wh-001", {"active": False}, "tenant-1")
        assert result["active"] is False

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.update("", {"active": False}, "tenant-1")


class TestWebhooksDelete:
    def test_deletes_webhook(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"deleted": True})
        result = make_client(api_key=VALID_KEY).webhooks.delete("wh-001", "tenant-1")
        assert result["deleted"] is True

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.delete("", "tenant-1")


class TestWebhooksTest:
    def test_sends_test_event(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"sent": True})
        result = make_client(api_key=VALID_KEY).webhooks.test("wh-001", "tenant-1")
        assert result["sent"] is True
        req = httpx_mock.get_requests()[0]
        assert req.url.path.endswith("/wh-001/test")
        assert req.url.params["tenantId"] == "tenant-1"  # / API-15

    def test_raises_on_empty_id(self) -> None:
        with pytest.raises(ValidationError):
            make_client(api_key=VALID_KEY).webhooks.test("", "tenant-1")


class TestWebhooksDeliveries:
    def test_gets_deliveries(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [], "total": 0})
        result = make_client(api_key=VALID_KEY).webhooks.get_deliveries("wh-001", "tenant-1")
        assert result["total"] == 0


class TestWebhooksMetrics:
    def test_gets_metrics(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"successRate": 0.99, "totalDeliveries": 1000})
        result = make_client(api_key=VALID_KEY).webhooks.metrics()
        assert result["successRate"] == 0.99


class TestAsyncWebhooksResource:
    async def test_creates_webhook(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json=WEBHOOK_RECORD)
        async with make_async_client(api_key=VALID_KEY) as client:
            result = await client.webhooks.create(CREATE_REQUEST)
        assert result["id"] == "wh-001"

    async def test_raises_on_missing_tenant_id(self) -> None:
        async with make_async_client(api_key=VALID_KEY) as client:
            with pytest.raises(ValidationError):
                await client.webhooks.create(
                    {"tenantId": "", "url": "https://example.com/hook", "eventTypes": ["x"]}
                )

    async def test_lists_webhooks(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(json={"items": [WEBHOOK_RECORD], "total": 1})
        async with make_async_client(api_key=VALID_KEY) as client:
            result = await client.webhooks.list("tenant-1")
        assert result["total"] == 1
