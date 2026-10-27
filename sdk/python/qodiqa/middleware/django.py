"""Django middleware: the artifact guard of :mod:`qodiqa.middleware`.

settings.py::

    MIDDLEWARE = [..., "qodiqa.middleware.django.QodiqaArtifactMiddleware", ...]
    QODIQA_GUARD = {
        "KEYS": StaticKeyProvider(trust_bundle),     # or RemoteKeyProvider(...)
        "PROTECT": ["/protected/"],                    # path prefixes; default: everything
        # optional: "EXCLUDE", "HEADER", "CLOCK_TOLERANCE_MS", "BIND_REQUEST", "REPLAY_GUARD", "MAX_BODY_BYTES"
    }

The verified artifact is ``request.qodiqa`` (a dict with ``artifact``, ``payload``, ``key_id``). Django's own ``request.body`` stays readable by the view.
"""

from __future__ import annotations

from typing import Any, Callable

from ._core import ArtifactGuard


class QodiqaArtifactMiddleware:
    def __init__(self, get_response: Callable[[Any], Any]) -> None:
        from django.conf import settings
        from django.core.exceptions import ImproperlyConfigured

        cfg = getattr(settings, "QODIQA_GUARD", None)
        if not cfg or cfg.get("KEYS") is None:
            raise ImproperlyConfigured("QODIQA_GUARD['KEYS'] (a KeyProvider) is required by QodiqaArtifactMiddleware")
        self.get_response = get_response
        self.guard = ArtifactGuard(
            cfg["KEYS"],
            header=cfg.get("HEADER", "x-qodiqa-artifact"),
            clock_tolerance_ms=cfg.get("CLOCK_TOLERANCE_MS", 0),
            bind_request=cfg.get("BIND_REQUEST", True),
            replay_guard=cfg.get("REPLAY_GUARD"),
        )
        self.protect = tuple(cfg.get("PROTECT") or ())
        self.exclude = tuple(cfg.get("EXCLUDE") or ())
        self.max_body = int(cfg.get("MAX_BODY_BYTES", 1_048_576))

    def _guarded(self, path: str) -> bool:
        if any(path == e or path.startswith(e.rstrip("/") + "/") for e in self.exclude):
            return False
        if not self.protect:
            return True
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.protect)

    def __call__(self, request: Any) -> Any:
        if not self._guarded(request.path):
            return self.get_response(request)
        from django.http import JsonResponse

        try:
            length = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > self.max_body:
            return JsonResponse({"status": "error", "error": {"code": "QODIQA_BODY_TOO_LARGE", "message": "The request body is too large for the artifact guard."}}, status=413)
        result = self.guard.check(request.method, request.path, request.body, request.headers.get(self.guard.header))
        if not result.ok:
            response = JsonResponse(result.body(), status=result.status)
            response["Cache-Control"] = "no-store"
            return response
        request.qodiqa = {k: v for k, v in (result.info or {}).items() if k != "result"}
        return self.get_response(request)
