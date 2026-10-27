"""Portal resource — /v1/portal/*.

rewritten to match the real, synchronous
``POST /v1/portal/verify`` contract. There is no async submit/poll model on
the server; this replaces an earlier ``submit()``/``get_status()``/
``wait_for_result()`` shape that targeted routes which never existed.
"""

from __future__ import annotations

from typing import Any, cast, TypedDict
from .._paths import seg as _seg

from ..exceptions import ValidationError
from ..models import ApiResponse, Artifact, PortalVerificationRecord, PortalVerifyResult
from ._base import AsyncBaseResource, BaseResource


class _ResultEnvelope(TypedDict):
    verification: PortalVerificationRecord


class PortalResource(BaseResource):
    """Verification portal — /v1/portal/*."""

    def verify(self, artifact: Artifact) -> ApiResponse[PortalVerifyResult]:
        """Submit an artifact for immediate verification.

        ``POST /v1/portal/verify`` — no authentication required
        (rate-limited only), and synchronous: no pending/in-progress state,
        the full check suite runs and a complete report is returned in this
        one call.

        Args:
            artifact: The raw QODIQA artifact dict (the request body IS the
                artifact — not wrapped in ``{"artifact": ..., "request": ...}``).

        Returns:
            :class:`~qodiqa.models.ApiResponse` wrapping a
            :class:`~qodiqa.models.PortalVerifyResult`.
        """
        return cast('ApiResponse[PortalVerifyResult]', self._http.post("/v1/portal/verify", artifact))

    def get_result(self, verification_id: str) -> ApiResponse[_ResultEnvelope]:
        """Retrieve a previously-run verification by its ``verificationId``.

        ``GET /v1/portal/result/:id`` — requires PostgreSQL to be enabled
        server-side (the verification portal's history store is
        Postgres-only). 404s if PostgreSQL was disabled at :meth:`verify`
        time (nothing was ever persisted) or is disabled now, even for a
        ``verificationId`` :meth:`verify` itself just returned.

        Args:
            verification_id: The ``verificationId`` a prior :meth:`verify`
                call returned.

        Returns:
            :class:`~qodiqa.models.ApiResponse` wrapping
            ``{"verification": PortalVerificationRecord}``.
        """
        if not verification_id or not verification_id.strip():
            raise ValidationError('"verification_id" must be a non-empty string.')
        return cast('ApiResponse[_ResultEnvelope]', self._http.get(f"/v1/portal/result/{_seg(verification_id)}"))


class AsyncPortalResource(AsyncBaseResource):
    """Async version of :class:`PortalResource`."""

    async def verify(self, artifact: Artifact) -> ApiResponse[PortalVerifyResult]:
        """Submit an artifact for immediate verification. See
        :meth:`PortalResource.verify`."""
        return cast('ApiResponse[PortalVerifyResult]', await self._http.post("/v1/portal/verify", artifact))

    async def get_result(self, verification_id: str) -> ApiResponse[_ResultEnvelope]:
        """Retrieve a previously-run verification by its ``verificationId``.
        See :meth:`PortalResource.get_result`."""
        if not verification_id or not verification_id.strip():
            raise ValidationError('"verification_id" must be a non-empty string.')
        return cast('ApiResponse[_ResultEnvelope]', await self._http.get(f"/v1/portal/result/{_seg(verification_id)}"))
