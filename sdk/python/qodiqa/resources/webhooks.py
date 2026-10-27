"""Webhooks resource — /v1/webhooks/*."""

from __future__ import annotations

from typing import Any, cast, List, Optional
from .._paths import seg as _seg

from ..exceptions import ValidationError
from ..models import ApiResponse, PaginationParams, WebhookCreateRequest, WebhookUpdateRequest
from ._base import AsyncBaseResource, BaseResource


class WebhooksResource(BaseResource):
    """Webhook management — /v1/webhooks/*.

    All methods require an ops API key.
    """

    def create(self, request: WebhookCreateRequest) -> ApiResponse[Any]:
        """Create a new webhook.

        ``POST /v1/webhooks``

        Args:
            request: Webhook creation request with ``tenant_id``, ``url``,
                ``event_types``, and optional ``description``.

        Returns:
            :class:`~qodiqa.models.ApiResponse` wrapping a
            :class:`~qodiqa.models.WebhookRecord`.

        Raises:
            :class:`~qodiqa.exceptions.AuthenticationError`: If no ops API key.
            :class:`~qodiqa.exceptions.ValidationError`: If required fields are
                missing.
        """
        if not request.get("tenantId", "").strip():
            raise ValidationError('"tenantId" must be a non-empty string.')
        if not request.get("url", "").strip():
            raise ValidationError('"url" must be a non-empty string.')
        event_types = request.get("eventTypes", [])
        if not isinstance(event_types, list) or len(event_types) == 0:
            raise ValidationError('"eventTypes" must be a non-empty list of strings.')

        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post("/v1/webhooks", request, headers=headers))

    def list(
        self, tenant_id: str, params: Optional[PaginationParams] = None
    ) -> ApiResponse[Any]:
        """List webhooks.

        ``GET /v1/webhooks``

        Requires ops API key. ``tenant_id`` is required server-side
        (``src/api/routes/webhooks.js``) — there is no cross-tenant list.
        """
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        query["tenantId"] = tenant_id
        return cast('ApiResponse[Any]', self._http.get("/v1/webhooks", headers=headers, params=query))

    def get(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        """Retrieve a single webhook by ID.

        ``GET /v1/webhooks/:id?tenantId=``

        Requires ops API key. ``tenant_id`` is required server-side (400 without it — / API-15: before
        this argument existed, the call could never succeed against a real gateway).
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/webhooks/{_seg(id)}", headers=headers, params={"tenantId": tenant_id}))

    def update(self, id: str, request: WebhookUpdateRequest, tenant_id: str) -> ApiResponse[Any]:
        """Update a webhook.

        ``PATCH /v1/webhooks/:id?tenantId=``

        Requires ops API key. ``tenant_id`` is required server-side (400 without it — / API-15: before
        this argument existed, the call could never succeed against a real gateway).
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast(ApiResponse[Any], self._http.patch(f"/v1/webhooks/{_seg(id)}", request, headers=headers, params={"tenantId": tenant_id}))

    def delete(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        """Delete a webhook.

        ``DELETE /v1/webhooks/:id?tenantId=``

        Requires ops API key. ``tenant_id`` is required server-side (400 without it — / API-15: before
        this argument existed, the call could never succeed against a real gateway).
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.delete(f"/v1/webhooks/{_seg(id)}", headers=headers, params={"tenantId": tenant_id}))

    def test(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        """Send a test event to a webhook.

        ``POST /v1/webhooks/:id/test?tenantId=``

        Requires ops API key. ``tenant_id`` is required server-side (400 without it — / API-15: before
        this argument existed, the call could never succeed against a real gateway).
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post(f"/v1/webhooks/{_seg(id)}/test", {}, headers=headers, params={"tenantId": tenant_id}))

    def get_deliveries(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        """Get delivery log for a webhook.

        ``GET /v1/webhooks/:id/deliveries?tenantId=``

        Requires ops API key. ``tenant_id`` is required server-side (400 without it — / API-15: before
        this argument existed, the call could never succeed against a real gateway).
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/webhooks/{_seg(id)}/deliveries", headers=headers, params={"tenantId": tenant_id}))

    def metrics(self) -> ApiResponse[Any]:
        """Get webhook delivery metrics.

        ``GET /v1/webhooks/metrics``

        Requires ops API key.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get("/v1/webhooks/metrics", headers=headers))


class AsyncWebhooksResource(AsyncBaseResource):
    """Async version of :class:`WebhooksResource`."""

    async def create(self, request: WebhookCreateRequest) -> ApiResponse[Any]:
        if not request.get("tenantId", "").strip():
            raise ValidationError('"tenantId" must be a non-empty string.')
        if not request.get("url", "").strip():
            raise ValidationError('"url" must be a non-empty string.')
        event_types = request.get("eventTypes", [])
        if not isinstance(event_types, list) or len(event_types) == 0:
            raise ValidationError('"eventTypes" must be a non-empty list of strings.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post("/v1/webhooks", request, headers=headers))

    async def list(
        self, tenant_id: str, params: Optional[PaginationParams] = None
    ) -> ApiResponse[Any]:
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        query["tenantId"] = tenant_id
        return cast('ApiResponse[Any]', await self._http.get("/v1/webhooks", headers=headers, params=query))

    async def get(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/webhooks/{_seg(id)}", headers=headers, params={"tenantId": tenant_id}))

    async def update(self, id: str, request: WebhookUpdateRequest, tenant_id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast(ApiResponse[Any], await self._http.patch(f"/v1/webhooks/{_seg(id)}", request, headers=headers, params={"tenantId": tenant_id}))

    async def delete(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.delete(f"/v1/webhooks/{_seg(id)}", headers=headers, params={"tenantId": tenant_id}))

    async def test(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post(f"/v1/webhooks/{_seg(id)}/test", {}, headers=headers, params={"tenantId": tenant_id}))

    async def get_deliveries(self, id: str, tenant_id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        if not tenant_id or not tenant_id.strip():
            raise ValidationError('"tenant_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/webhooks/{_seg(id)}/deliveries", headers=headers, params={"tenantId": tenant_id}))

    async def metrics(self) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get("/v1/webhooks/metrics", headers=headers))
