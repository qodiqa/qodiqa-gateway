"""Sign resource — POST /sign."""

from __future__ import annotations

from typing import Any, cast, Optional

from ..exceptions import ValidationError
from ..models import SignRequest, SignResponse
from ._base import AsyncBaseResource, BaseResource


class SignResource(BaseResource):
    """Issue signed artifacts via ``POST /sign``.

    Requires ``sign_token`` to be configured on the client.
    """

    def sign(
        self,
        request: SignRequest,
        artifact_header: Optional[str] = None,
    ) -> SignResponse:
        """Issue a signed artifact.

        Args:
            request: Signing request containing the HTTP request descriptor
                (``method``, ``path``, ``body``), optional ``payload`` metadata,
                and optional ``ttl`` in milliseconds.
            artifact_header: Optional existing base64 artifact to chain.
                When provided, the artifact is sent in ``x-qodiqa-artifact``.

        Returns:
            :class:`~qodiqa.models.SignResponse` with the artifact and metadata.

        Raises:
            :class:`~qodiqa.exceptions.AuthenticationError`: If no ``sign_token``
                is configured or the server rejects it.
            :class:`~qodiqa.exceptions.ValidationError`: If required request
                fields are missing.

        Example::

            signed = client.sign.sign(
                {
                    "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "hello"}},
                    "payload": {"user_id": "u_123"},
                    "ttl": 300_000,
                }
            )
            print(signed["artifactId"])
        """
        req_desc = request.get("request", {})
        method = req_desc.get("method", "")
        path = req_desc.get("path", "")

        if not method or not method.strip():
            raise ValidationError('"request.method" must be a non-empty string.')
        if not path or not path.strip():
            raise ValidationError('"request.path" must be a non-empty string.')

        headers = {**self._auth.get_sign_token_header()}
        if artifact_header is not None:
            headers.update(self._auth.get_artifact_header(artifact_header))

        return cast('SignResponse', self._http.post("/sign", request, headers=headers))


class AsyncSignResource(AsyncBaseResource):
    """Async version of :class:`SignResource`."""

    async def sign(
        self,
        request: SignRequest,
        artifact_header: Optional[str] = None,
    ) -> SignResponse:
        """Issue a signed artifact asynchronously.

        See :meth:`SignResource.sign` for full documentation.
        """
        req_desc = request.get("request", {})
        method = req_desc.get("method", "")
        path = req_desc.get("path", "")

        if not method or not method.strip():
            raise ValidationError('"request.method" must be a non-empty string.')
        if not path or not path.strip():
            raise ValidationError('"request.path" must be a non-empty string.')

        headers = {**self._auth.get_sign_token_header()}
        if artifact_header is not None:
            headers.update(self._auth.get_artifact_header(artifact_header))

        return cast('SignResponse', await self._http.post("/sign", request, headers=headers))
