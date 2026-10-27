"""Verify resource — POST /verify, POST /verify/v2."""

from __future__ import annotations

from typing import Any, cast

from ..exceptions import ValidationError
from ..models import VerifyRequest, VerifyResponse
from ._base import AsyncBaseResource, BaseResource


class VerifyResource(BaseResource):
    """Verify signed artifacts via ``POST /verify``."""

    def verify(self, artifact: str, request: VerifyRequest) -> VerifyResponse:
        """Live enforcement verification.

        Args:
            artifact: Base64-encoded artifact string.
            request: Verify request with the artifact object and request descriptor.

        Returns:
            :class:`~qodiqa.models.VerifyResponse` with ``decision`` and ``reason``.

        Raises:
            :class:`~qodiqa.exceptions.ValidationError`: If ``artifact`` is empty.

        Example::

            result = client.verify.verify(artifact_b64, {
                "artifact": signed["artifact"],
                "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hi"}},
            })
            print(result["decision"])  # "EXECUTE" or "BLOCK"
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')

        # the artifact travels only in request["artifact"]; /verify reads no header.
        return cast('VerifyResponse', self._http.post("/verify", request))

    def dry_run(self, request: VerifyRequest) -> VerifyResponse:
        """Dry-run verification — artifact supplied in request body only.

        No ``x-qodiqa-artifact`` header is sent (neither does :meth:`verify` —
        the ``/verify`` route reads the artifact only from the body), so this
        sends the same wire request as :meth:`verify`.

        Args:
            request: Verify request with a populated ``artifact`` field.

        Returns:
            :class:`~qodiqa.models.VerifyResponse`.
        """
        return cast('VerifyResponse', self._http.post("/verify", request))

    def verify_v2(self, request: VerifyRequest) -> VerifyResponse:
        """Verification under the higher ``verify_v2`` rate-limit bucket.

        ``POST /verify/v2`` — the identical server-side handler as ``/verify``
        (``src/api/routes/verify.js``); only the endpoint's rate-limit
        configuration differs. added for parity with the JS SDK's
        ``verifyV2()``.

        Args:
            request: Verify request with a populated ``artifact`` field.

        Returns:
            :class:`~qodiqa.models.VerifyResponse`.
        """
        return cast('VerifyResponse', self._http.post("/verify/v2", request))


class AsyncVerifyResource(AsyncBaseResource):
    """Async version of :class:`VerifyResource`."""

    async def verify(self, artifact: str, request: VerifyRequest) -> VerifyResponse:
        """Live enforcement verification asynchronously.

        See :meth:`VerifyResource.verify` for full documentation.
        """
        if not artifact or not artifact.strip():
            raise ValidationError('"artifact" must be a non-empty string.')
        return cast('VerifyResponse', await self._http.post("/verify", request))

    async def verify_v2(self, request: VerifyRequest) -> VerifyResponse:
        """``POST /verify/v2`` asynchronously. See :meth:`VerifyResource.verify_v2`."""
        return cast('VerifyResponse', await self._http.post("/verify/v2", request))

    async def dry_run(self, request: VerifyRequest) -> VerifyResponse:
        """Dry-run verification asynchronously.

        See :meth:`VerifyResource.dry_run` for full documentation.
        """
        return cast('VerifyResponse', await self._http.post("/verify", request))
