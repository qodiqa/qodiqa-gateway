"""Transparency resource — /v1/transparency/*."""

from __future__ import annotations

from typing import Any, cast, Dict, Optional
from .._paths import seg as _seg

from ..exceptions import ValidationError
from ..models import ApiResponse, PaginationParams
from ._base import AsyncBaseResource, BaseResource


class TransparencyResource(BaseResource):
    """Transparency log — /v1/transparency/*."""

    def get_entry(self, id: str) -> ApiResponse[Any]:
        """Fetch a single transparency log entry.

        ``GET /v1/transparency/entry/:id``
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/transparency/entry/{_seg(id)}"))

    def list_entries(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        """List transparency log entries.

        ``GET /v1/transparency/entries``
        """
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', self._http.get("/v1/transparency/entries", params=query))

    def get_root(self, root_id: Optional[str] = None) -> ApiResponse[Any]:
        """Get the latest signed root, or the root named by ``root_id``.

        ``GET /v1/transparency/root[?rootId=]`` — ``data["root"]`` is ``None`` (with
        ``data["message"]``) before the first root exists.
        """
        params = {"rootId": root_id} if root_id is not None else None
        return cast('ApiResponse[Any]', self._http.get("/v1/transparency/root", params=params))

    def list_roots(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        """List signed roots, newest first.

        ``GET /v1/transparency/roots`` — ``data["roots"]`` plus flat pagination metadata.
        previously called the latest-root endpoint, which ignores pagination.
        """
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', self._http.get("/v1/transparency/roots", params=query))

    def verify_entry(self, id: str) -> ApiResponse[Any]:
        """Verify a single transparency entry by ID.

        ``GET /v1/transparency/verify/:id``
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/transparency/verify/{_seg(id)}"))

    def get_proof(self, id: str) -> ApiResponse[Any]:
        """Get an inclusion proof for a transparency entry.

        ``GET /v1/transparency/proof/:id``
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/transparency/proof/{_seg(id)}"))

    def get_receipt(self, request_id: str) -> ApiResponse[Any]:
        """The signed receipt of a request's decision (V2-FREEZE section 6).

        ``GET /v1/transparency/receipt/:requestId`` — no credentials: knowing the ``requestId`` (the artifact's ``payload.requestId``) is the authorization.
        Receipts are kept for a bounded window (default one hour); after it the server answers 404 (:class:`~qodiqa.exceptions.NotFoundError`).
        Verify the result with :func:`qodiqa.verify_receipt`.
        """
        if not request_id or not request_id.strip():
            raise ValidationError('"request_id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/transparency/receipt/{_seg(request_id)}"))

    # Ops-protected

    def register(self, data: Dict[str, Any]) -> ApiResponse[Any]:
        """Register a new transparency log entry.

        ``POST /v1/transparency/register``

        Requires ops API key. Real (server-strict-validated) body shape:
        ``{entryType: 'ARTIFACT'|'EVIDENCE'|'VERIFICATION'|'POLICY'|'AUDIT'|'SYSTEM',
        artifactId?, evidenceChainId?, verificationId?, payload?, tenantId?}``
        — NOT ``{type, ref}``.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post("/v1/transparency/register", data, headers=headers))

    def generate_root(self) -> ApiResponse[Any]:
        """Generate a new transparency root covering all entries not yet
        included in a prior root.

        ``POST /v1/transparency/admin/roots/generate``

        Requires ops API key. Required before ``get_proof()`` can return a
        populated ``proof`` array for entries registered since the last root.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post("/v1/transparency/admin/roots/generate", {}, headers=headers))

    def stats(self) -> ApiResponse[Any]:
        """Get transparency log admin statistics.

        ``GET /v1/transparency/admin/stats``

        Requires ops API key.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get("/v1/transparency/admin/stats", headers=headers))

    def validate_chain(
        self, start_id: Optional[str] = None, end_id: Optional[str] = None, limit: Optional[int] = None
    ) -> ApiResponse[Any]:
        """Validate the transparency log hash chain.

        ``GET /v1/transparency/admin/chain/validate`` (previously called
        ``/audit/chain/integrity``, which is the audit chain, not the transparency log).

        Requires ops API key (READ_TRANSPARENCY_LOG).
        """
        headers = self._auth.get_auth_header()
        params: Dict[str, Any] = {}
        if start_id is not None:
            params["startId"] = start_id
        if end_id is not None:
            params["endId"] = end_id
        if limit is not None:
            params["limit"] = limit
        return cast('ApiResponse[Any]', self._http.get("/v1/transparency/admin/chain/validate", headers=headers, params=params))


class AsyncTransparencyResource(AsyncBaseResource):
    """Async version of :class:`TransparencyResource`."""

    async def get_entry(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/transparency/entry/{_seg(id)}"))

    async def list_entries(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', await self._http.get("/v1/transparency/entries", params=query))

    async def get_root(self, root_id: Optional[str] = None) -> ApiResponse[Any]:
        params = {"rootId": root_id} if root_id is not None else None
        return cast('ApiResponse[Any]', await self._http.get("/v1/transparency/root", params=params))

    async def list_roots(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', await self._http.get("/v1/transparency/roots", params=query))

    async def verify_entry(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/transparency/verify/{_seg(id)}"))

    async def get_proof(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/transparency/proof/{_seg(id)}"))

    async def get_receipt(self, request_id: str) -> ApiResponse[Any]:
        if not request_id or not request_id.strip():
            raise ValidationError('"request_id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/transparency/receipt/{_seg(request_id)}"))

    async def register(self, data: Dict[str, Any]) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post("/v1/transparency/register", data, headers=headers))

    async def generate_root(self) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post("/v1/transparency/admin/roots/generate", {}, headers=headers))

    async def stats(self) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get("/v1/transparency/admin/stats", headers=headers))

    async def validate_chain(
        self, start_id: Optional[str] = None, end_id: Optional[str] = None, limit: Optional[int] = None
    ) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        params: Dict[str, Any] = {}
        if start_id is not None:
            params["startId"] = start_id
        if end_id is not None:
            params["endId"] = end_id
        if limit is not None:
            params["limit"] = limit
        return cast('ApiResponse[Any]', await self._http.get("/v1/transparency/admin/chain/validate", headers=headers, params=params))
