"""Evidence resource — /v1/attestation/:id/evidence."""

from __future__ import annotations

from typing import Any, cast

from ..exceptions import ValidationError
from ..models import ApiResponse
from ._base import AsyncBaseResource, BaseResource
from .._paths import seg as _seg


class EvidenceResource(BaseResource):
    """Evidence package retrieval — /v1/attestation/:artifactId/evidence.

    Requires ops API key.
    """

    def get_package(self, artifact_id: str) -> ApiResponse[Any]:
        """Retrieve the evidence package for an artifact.

        ``GET /v1/attestation/:attestationId/evidence``

        Args:
            artifact_id: The ATTESTATION id (a UUID returned by ``attestation.verify``). the
                route is keyed by attestation id, not by an artifact id; the parameter name is kept for
                backward compatibility.

        Returns:
            :class:`~qodiqa.models.ApiResponse` with the evidence package.

        Raises:
            :class:`~qodiqa.exceptions.AuthenticationError`: If no ops API key.
            :class:`~qodiqa.exceptions.ValidationError`: If ``artifact_id`` is
                empty.
        """
        if not artifact_id or not artifact_id.strip():
            raise ValidationError('"artifact_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', self._http.get(f"/v1/attestation/{_seg(artifact_id)}/evidence", headers=headers))


class AsyncEvidenceResource(AsyncBaseResource):
    """Async version of :class:`EvidenceResource`."""

    async def get_package(self, artifact_id: str) -> ApiResponse[Any]:
        """Retrieve the evidence package for an artifact asynchronously."""
        if not artifact_id or not artifact_id.strip():
            raise ValidationError('"artifact_id" must be a non-empty string.')
        headers = self._auth.get_auth_header()
        return cast('ApiResponse[Any]', await self._http.get(f"/v1/attestation/{_seg(artifact_id)}/evidence", headers=headers))
