"""Middleware for existing applications: the artifact guard.

* :class:`ArtifactGuard` - the framework-neutral decision (``check(method, path, body, header)``).
* :mod:`qodiqa.middleware.fastapi` - ASGI middleware for FastAPI / Starlette.
* :mod:`qodiqa.middleware.django` - Django middleware.

A request passes only with a QODIQA artifact that verifies offline and is bound to that very request (V1 request hash). See ``_core`` for the exact contract.
"""

from ._core import ArtifactGuard, GuardResult

__all__ = ["ArtifactGuard", "GuardResult"]
