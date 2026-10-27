"""Attestation resource — /v1/attestation/*."""

from __future__ import annotations

from typing import Any, cast, Dict, List, Optional
from .._paths import seg as _seg

from ..exceptions import ValidationError
from ..models import ApiResponse, AttestationRecord, Artifact, PaginatedResponse, PaginationParams
from ._base import AsyncBaseResource, BaseResource


class AttestationResource(BaseResource):
    """Attestation verification — /v1/attestation/*."""

    def verify(self, artifact: Artifact) -> ApiResponse[Any]:
        """Generate an attestation from an artifact.

        ``POST /v1/attestation/verify``

        Args:
            artifact: Signed artifact dict.

        Returns:
            :class:`~qodiqa.models.ApiResponse` wrapping an
            :class:`~qodiqa.models.AttestationRecord`.
        """
        return cast('ApiResponse[Any]', self._http.post("/v1/attestation/verify", {"artifact": artifact}))

    def verify_evidence(self, evidence_package: Dict[str, Any]) -> ApiResponse[Any]:
        """Verify an evidence package (e.g. one previously obtained from
        ``get_evidence()``/``evidence.get_package()``).

        ``POST /v1/attestation/evidence/verify``

        Takes an evidence package, NOT a signed artifact — the server checks
        ``evidencePackage.packageType == 'QODIQA::PORTAL_EVIDENCE::V1'`` and
        rejects anything else (including a raw artifact) with
        ``valid: False, failureReason: "Unsupported package type: undefined"``.
        """
        return cast('ApiResponse[Any]', self._http.post("/v1/attestation/evidence/verify", {"evidencePackage": evidence_package}))

    def verify_chain(
        self,
        evidence_ids: Optional[List[str]] = None,
        range: Optional[Dict[str, Any]] = None,
    ) -> ApiResponse[Any]:
        """Verify a full attestation chain by evidence ID range.

        ``POST /v1/attestation/chain/verify``

        Takes ``evidenceIds`` and/or a ``range``, NOT a signed artifact — the
        server's schema is strict and rejects any other key (including
        ``artifact``) with a 400.
        """
        body: Dict[str, Any] = {}
        if evidence_ids is not None:
            body["evidenceIds"] = evidence_ids
        if range is not None:
            body["range"] = range
        # admin router + MANAGE_ATTESTATIONS server-side — requires the ops API key.
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.post("/v1/attestation/chain/verify", body, headers=headers))

    def get(self, id: str) -> ApiResponse[Any]:
        """Fetch a single attestation record by ID.

        ``GET /v1/attestation/:id``

        Args:
            id: Attestation ID.
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', self._http.get(f"/v1/attestation/{_seg(id)}"))

    # Ops-protected

    def get_evidence(self, id: str) -> ApiResponse[Any]:
        """Retrieve the evidence package for an attestation.

        ``GET /v1/attestation/:id/evidence``

        Requires ops API key.
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/attestation/{_seg(id)}/evidence", headers=headers))

    def get_summary(self, id: str) -> ApiResponse[Any]:
        """Retrieve a summary for an attestation record.

        ``GET /v1/attestation/:id/summary``

        Requires ops API key.
        """
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/attestation/{_seg(id)}/summary", headers=headers))

    def list(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        """List attestation history (admin).

        ``GET /v1/attestation/admin/history``

        Requires ops API key.
        """
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', self._http.get("/v1/attestation/admin/history", headers=headers, params=query))

    def stats(self) -> ApiResponse[Any]:
        """Retrieve attestation admin statistics.

        ``GET /v1/attestation/admin/stats``

        Requires ops API key.
        """
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get("/v1/attestation/admin/stats", headers=headers))


class AsyncAttestationResource(AsyncBaseResource):
    """Async version of :class:`AttestationResource`."""

    async def verify(self, artifact: Artifact) -> ApiResponse[Any]:
        return cast('ApiResponse[Any]', await self._http.post("/v1/attestation/verify", {"artifact": artifact}))

    async def verify_evidence(self, evidence_package: Dict[str, Any]) -> ApiResponse[Any]:
        return cast('ApiResponse[Any]', await self._http.post("/v1/attestation/evidence/verify", {"evidencePackage": evidence_package}))

    async def verify_chain(
        self,
        evidence_ids: Optional[List[str]] = None,
        range: Optional[Dict[str, Any]] = None,
    ) -> ApiResponse[Any]:
        body: Dict[str, Any] = {}
        if evidence_ids is not None:
            body["evidenceIds"] = evidence_ids
        if range is not None:
            body["range"] = range
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.post("/v1/attestation/chain/verify", body, headers=headers))

    async def get(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/attestation/{_seg(id)}"))

    async def get_evidence(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/attestation/{_seg(id)}/evidence", headers=headers))

    async def get_summary(self, id: str) -> ApiResponse[Any]:
        if not id or not id.strip():
            raise ValidationError('"id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/attestation/{_seg(id)}/summary", headers=headers))

    async def list(self, params: Optional[PaginationParams] = None) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        query = self._pagination_params(params)
        return cast('ApiResponse[Any]', await self._http.get("/v1/attestation/admin/history", headers=headers, params=query))

    async def stats(self) -> ApiResponse[Any]:
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get("/v1/attestation/admin/stats", headers=headers))
