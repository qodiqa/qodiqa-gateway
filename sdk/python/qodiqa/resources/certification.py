"""Certification resource — /v1/certification/*."""

from __future__ import annotations

from typing import Any, cast, Dict, List, Optional
from .._paths import seg as _seg

from ..exceptions import ValidationError
from ..models import ApiResponse, Artifact, PaginationParams
from ._base import AsyncBaseResource, BaseResource


class CertificationResource(BaseResource):
    """Certification evaluation — /v1/certification/*."""

    def evaluate(self, artifacts: List[Artifact], **extra: Any) -> ApiResponse[Any]:
        """Run a certification evaluation.

        ``POST /v1/certification/evaluate``

        Real (server-`.strict()`-validated) body shape is
        ``{artifacts: [...] (array, plural), evidencePackages?, chain?, options?}``
        — NOT a single ``artifact`` plus an ``evaluationLevel`` field.

        Args:
            artifacts: Signed artifacts to evaluate (max 50 per request).
            **extra: Additional fields (``evidencePackages``, ``chain``, ``options``)
                forwarded in the request body.
        """
        # admin router + SUBMIT_BATCH_CERTIFICATION server-side — requires the ops API key.
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post("/v1/certification/evaluate", {"artifacts": artifacts, **extra}, headers=headers))

    def get(self, id: str) -> ApiResponse[Any]:
        """Retrieve a certification record by ID.

        ``GET /v1/certification/:id``
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/certification/{_seg(id)}"))

    def get_summary(self, id: str) -> ApiResponse[Any]:
        """Retrieve a summary for a certification record.

        ``GET /v1/certification/:id/summary``
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/certification/{_seg(id)}/summary"))

    # Ops-protected

    def submit_batch(self, framework_id: str, items: List[Dict[str, Any]]) -> ApiResponse[Any]:
        """Submit a batch of certification requests.

        ``POST /v1/certifications/batch``

        Requires ops API key. Real (server-validated) body shape is
        ``{frameworkId: string (required), items: [{subjectId: string (required),
        artifacts?, evidencePackages?, controls?}]}`` — NOT bare
        ``{items: [{artifact}]}``.

        Args:
            framework_id: The certification framework this batch is evaluated against.
            items: List of dicts, each with a required ``subjectId`` and optional
                ``artifacts``/``evidencePackages``/``controls``.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post(
            "/v1/certifications/batch",
            {"frameworkId": framework_id, "items": items},
            headers=headers,
        ))

    def get_batch(self, batch_id: str) -> ApiResponse[Any]:
        """Get the status of a certification batch.

        ``GET /v1/certifications/batch/:batchId``

        Requires ops API key.
        """
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/certifications/batch/{_seg(batch_id)}", headers=headers))

    def get_batch_results(self, batch_id: str) -> ApiResponse[Any]:
        """Get the results for a completed certification batch.

        ``GET /v1/certifications/batch/:batchId/results``

        Requires ops API key.
        """
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/certifications/batch/{_seg(batch_id)}/results", headers=headers))

    def cancel_batch(self, batch_id: str) -> ApiResponse[Any]:
        """Cancel a pending certification batch.

        ``POST /v1/certifications/batch/:batchId/cancel``

        Requires ops API key.
        """
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post(f"/v1/certifications/batch/{_seg(batch_id)}/cancel", {}, headers=headers))

    def list(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        """List certification history (admin).

        ``GET /v1/certification/admin/history``

        Requires ops API key. Note the singular ``/v1/certification`` mount —
        distinct from the plural ``/v1/certifications/batch/*`` routes above.
        """
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', self._http.get("/v1/certification/admin/history", headers=headers, params=query))

    def stats(self) -> ApiResponse[Any]:
        """Retrieve certification admin statistics.

        ``GET /v1/certification/admin/stats``

        Requires ops API key. Note the singular ``/v1/certification`` mount.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get("/v1/certification/admin/stats", headers=headers))


class AsyncCertificationResource(AsyncBaseResource):
    """Async version of :class:`CertificationResource`."""

    async def evaluate(self, artifacts: List[Artifact], **extra: Any) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post("/v1/certification/evaluate", {"artifacts": artifacts, **extra}, headers=headers))

    async def get(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/certification/{_seg(id)}"))

    async def get_summary(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/certification/{_seg(id)}/summary"))

    async def submit_batch(self, framework_id: str, items: List[Dict[str, Any]]) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post(
            "/v1/certifications/batch",
            {"frameworkId": framework_id, "items": items},
            headers=headers,
        ))

    async def get_batch(self, batch_id: str) -> ApiResponse[Any]:
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/certifications/batch/{_seg(batch_id)}", headers=headers))

    async def get_batch_results(self, batch_id: str) -> ApiResponse[Any]:
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/certifications/batch/{_seg(batch_id)}/results", headers=headers))

    async def cancel_batch(self, batch_id: str) -> ApiResponse[Any]:
        if not batch_id or not batch_id.strip():
            raise ValidationError('"batch_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post(f"/v1/certifications/batch/{_seg(batch_id)}/cancel", {}, headers=headers))

    async def list(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', await self._http.get("/v1/certification/admin/history", headers=headers, params=query))

    async def stats(self) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get("/v1/certification/admin/stats", headers=headers))
