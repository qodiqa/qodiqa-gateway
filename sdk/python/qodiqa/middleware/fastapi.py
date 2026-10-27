"""ASGI middleware for FastAPI / Starlette (and any ASGI app): the artifact guard of :mod:`qodiqa.middleware`.

    from qodiqa.middleware.fastapi import QodiqaArtifactMiddleware
    app.add_middleware(QodiqaArtifactMiddleware, keys=StaticKeyProvider(trust_bundle), protect=("/protected",))

The request body is read once (at most ``max_body_bytes``), checked against the artifact and replayed to the application. The verified artifact is available as
``request.scope["qodiqa"]`` (a dict with ``artifact``, ``payload``, ``key_id``). Only paths under one of the ``protect`` prefixes are guarded (default: everything).
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional

from ._core import ArtifactGuard

Scope = Dict[str, Any]
Receive = Callable[[], Awaitable[Dict[str, Any]]]
Send = Callable[[Dict[str, Any]], Awaitable[None]]


class QodiqaArtifactMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        *,
        keys: Any,
        protect: Optional[Iterable[str]] = None,
        exclude: Iterable[str] = (),
        header: str = "x-qodiqa-artifact",
        clock_tolerance_ms: int = 0,
        bind_request: bool = True,
        replay_guard: Optional[Callable[[Dict[str, Any]], bool]] = None,
        max_body_bytes: int = 1_048_576,
    ) -> None:
        self.app = app
        self.guard = ArtifactGuard(keys, header=header, clock_tolerance_ms=clock_tolerance_ms, bind_request=bind_request, replay_guard=replay_guard)
        self.protect = tuple(protect) if protect else None
        self.exclude = tuple(exclude)
        self.max_body_bytes = max_body_bytes

    def _guarded(self, path: str) -> bool:
        if any(path == e or path.startswith(e.rstrip("/") + "/") for e in self.exclude):
            return False
        if self.protect is None:
            return True
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.protect)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._guarded(scope["path"]):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        chunks = []
        size = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            part = message.get("body", b"")
            size += len(part)
            if size > self.max_body_bytes:
                await self._refuse(send, 413, "QODIQA_BODY_TOO_LARGE", "The request body is too large for the artifact guard.")
                return
            chunks.append(part)
            more = message.get("more_body", False)
        body = b"".join(chunks)
        result = self.guard.check(scope["method"], scope["path"], body, headers.get(self.guard.header))
        if not result.ok:
            await self._refuse(send, result.status, result.code, result.message)
            return
        scope["qodiqa"] = {k: v for k, v in (result.info or {}).items() if k != "result"}
        sent = False

        async def replay() -> Dict[str, Any]:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    @staticmethod
    async def _refuse(send: Send, status: int, code: str, message: str) -> None:
        payload = json.dumps({"status": "error", "error": {"code": code, "message": message}}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store"), (b"content-length", str(len(payload)).encode())]})
        await send({"type": "http.response.body", "body": payload})
