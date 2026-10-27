"""the artifact guard for existing applications: framework-neutral core, ASGI (FastAPI/Starlette) and Django middleware.

Artifacts are signed here with a real Ed25519 key and the SDK's own envelope hash; the trust bundle is the matching public key. No network, no gateway.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, Optional

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qodiqa import StaticKeyProvider, request_hash
from qodiqa._verification._domain_hash import envelope_hash
from qodiqa.middleware import ArtifactGuard
from qodiqa.middleware.fastapi import QodiqaArtifactMiddleware

NOW_MS = 1_790_000_000_000
KEY_ID = "tenant-a:key_v1"
_priv = Ed25519PrivateKey.generate()
_spki = _priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
KEYS = StaticKeyProvider([{"keyId": KEY_ID, "algorithm": "ed25519", "publicKey": base64.b64encode(_spki).decode(), "status": "active"}])


def make_artifact(method: str = "POST", path: str = "/protected/echo", body: Any = None, *, request_hash_override: Optional[str] = None, ts: int = NOW_MS - 1000, exp: int = NOW_MS + 60_000) -> str:
    bound = request_hash(method, path, {} if body is None else body)
    art: Dict[str, Any] = {"expiry": exp, "payload": {"requestId": "r1", "requestHash": request_hash_override or bound, "tenantId": "tenant-a"}, "publicKeyId": KEY_ID, "timestamp": ts}
    art["signature"] = base64.b64encode(_priv.sign(envelope_hash(art))).decode()
    return base64.b64encode(json.dumps(art).encode()).decode()


def body_bytes(body: Any) -> bytes:
    return b"" if body is None else json.dumps(body).encode()


class TestCore:
    def guard(self, **kw: Any) -> ArtifactGuard:
        return ArtifactGuard(KEYS, _now=NOW_MS, **kw)

    def test_a_bound_artifact_passes_and_exposes_the_payload(self) -> None:
        body = {"prompt": "hi"}
        r = self.guard().check("POST", "/protected/echo", body_bytes(body), make_artifact(body=body))
        assert r.ok and r.info["payload"]["tenantId"] == "tenant-a" and r.info["key_id"] == KEY_ID

    def test_an_empty_body_is_bound_as_an_empty_object(self) -> None:
        assert self.guard().check("GET", "/protected/x", b"", make_artifact("GET", "/protected/x")).ok

    def test_missing_malformed_oversized_and_invalid_artifacts_are_401(self) -> None:
        g = self.guard()
        assert g.check("GET", "/p", b"", None).code == "QODIQA_ARTIFACT_REQUIRED"
        for bad in ("%%%not-base64", base64.b64encode(b"not json").decode(), base64.b64encode(b"[]").decode(), "A" * 20000):
            r = g.check("GET", "/p", b"", bad)
            assert (r.ok, r.status, r.code) == (False, 401, "QODIQA_ARTIFACT_INVALID"), bad[:20]

    def test_a_tampered_expired_or_future_artifact_is_401(self) -> None:
        g = self.guard()
        art = json.loads(base64.b64decode(make_artifact("GET", "/p")))
        art["payload"]["tenantId"] = "tenant-b"
        assert g.check("GET", "/p", b"", base64.b64encode(json.dumps(art).encode()).decode()).status == 401
        assert g.check("GET", "/p", b"", make_artifact("GET", "/p", ts=NOW_MS - 120_000, exp=NOW_MS - 60_000)).status == 401
        assert g.check("GET", "/p", b"", make_artifact("GET", "/p", ts=NOW_MS + 60_000, exp=NOW_MS + 120_000)).status == 401

    def test_an_artifact_for_another_request_is_403(self) -> None:
        g = self.guard()
        art = make_artifact("POST", "/protected/echo", {"prompt": "hi"})
        assert g.check("POST", "/protected/echo", body_bytes({"prompt": "other"}), art).code == "QODIQA_REQUEST_MISMATCH"
        assert g.check("POST", "/protected/other", body_bytes({"prompt": "hi"}), art).status == 403
        assert g.check("DELETE", "/protected/echo", body_bytes({"prompt": "hi"}), art).status == 403
        assert g.check("POST", "/protected/echo", b"{not json", art).status == 403

    def test_a_body_the_sdk_cannot_hash_is_refused_not_raised(self) -> None:
        # finding: non-integer numbers and excessive nesting raised CanonicalizationError out of check() (a 500 in the middleware).
        g = self.guard()
        art = make_artifact("POST", "/protected/echo", {"prompt": "hi"})
        for raw in (b'{"temperature":0.7}', b"[" * 5000 + b"]" * 5000):
            r = g.check("POST", "/protected/echo", raw, art)
            assert (r.ok, r.status, r.code) == (False, 403, "QODIQA_REQUEST_MISMATCH")

    def test_without_binding_any_genuine_artifact_passes(self) -> None:
        assert self.guard(bind_request=False).check("PUT", "/anything", b"{}", make_artifact("GET", "/p")).ok

    def test_the_replay_guard_can_refuse(self) -> None:
        seen = set()

        def once(info: Dict[str, Any]) -> bool:
            rid = info["payload"]["requestId"]
            if rid in seen:
                return False
            seen.add(rid)
            return True

        g = self.guard(replay_guard=once)
        art = make_artifact("GET", "/p")
        assert g.check("GET", "/p", b"", art).ok
        assert g.check("GET", "/p", b"", art).code == "QODIQA_REPLAY_OR_POLICY"


async def _echo_app(scope: Dict[str, Any], receive: Any, send: Any) -> None:
    body = b""
    more = True
    while more:
        m = await receive()
        body += m.get("body", b"")
        more = m.get("more_body", False)
    payload = json.dumps({"path": scope["path"], "body": body.decode(), "qodiqa": scope.get("qodiqa", {}).get("payload", {}).get("tenantId")}).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": payload})


@pytest.mark.asyncio
class TestAsgi:
    def client(self, **kw: Any) -> httpx.AsyncClient:
        app = QodiqaArtifactMiddleware(_echo_app, keys=KEYS, protect=["/protected"], **kw)
        # the guard is built with a fixed clock through its private hook: rebuild it
        app.guard._now = NOW_MS
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")

    async def test_a_bound_request_reaches_the_app_with_its_body_intact(self) -> None:
        body = {"prompt": "hi"}
        async with self.client() as c:
            r = await c.post("/protected/echo", content=json.dumps(body), headers={"x-qodiqa-artifact": make_artifact(body=body)})
        assert r.status_code == 200 and json.loads(r.json()["body"]) == body and r.json()["qodiqa"] == "tenant-a"

    async def test_refusals_are_json_and_never_reach_the_app(self) -> None:
        async with self.client() as c:
            none = await c.post("/protected/echo", content="{}")
            wrong = await c.post("/protected/echo", content='{"a":1}', headers={"x-qodiqa-artifact": make_artifact(body={"a": 2})})
        assert none.status_code == 401 and none.json()["error"]["code"] == "QODIQA_ARTIFACT_REQUIRED"
        assert wrong.status_code == 403 and wrong.json()["error"]["code"] == "QODIQA_REQUEST_MISMATCH" and wrong.headers["cache-control"] == "no-store"

    async def test_paths_outside_protect_and_in_exclude_are_untouched(self) -> None:
        async with self.client() as c:
            assert (await c.get("/public/health")).status_code == 200
            assert (await c.get("/protectedx")).status_code == 200      # a different path, not under the prefix
            assert (await c.get("/protected")).status_code == 401          # the prefix itself is guarded

    async def test_an_oversized_body_is_413_before_any_check(self) -> None:
        async with self.client(max_body_bytes=16) as c:
            r = await c.post("/protected/echo", content="x" * 100, headers={"x-qodiqa-artifact": make_artifact(body={})})
        assert r.status_code == 413


def test_django_middleware() -> None:
    django = pytest.importorskip("django")
    from django.conf import settings

    if not settings.configured:
        settings.configure(DEBUG=True, SECRET_KEY="x" * 40, ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__, QODIQA_GUARD={"KEYS": KEYS, "PROTECT": ["/protected/"]})
        django.setup()
    from django.http import JsonResponse
    from django.test import RequestFactory

    from qodiqa.middleware.django import QodiqaArtifactMiddleware as DjangoMiddleware

    mw = DjangoMiddleware(lambda request: JsonResponse({"tenant": request.qodiqa["payload"]["tenantId"], "body": request.body.decode()}))
    mw.guard._now = NOW_MS
    rf = RequestFactory()
    body = {"prompt": "hi"}
    ok = mw(rf.post("/protected/echo", data=json.dumps(body), content_type="application/json", HTTP_X_QODIQA_ARTIFACT=make_artifact(body=body)))
    assert ok.status_code == 200 and json.loads(ok.content)["tenant"] == "tenant-a" and json.loads(json.loads(ok.content)["body"]) == body
    refused = mw(rf.post("/protected/echo", data=json.dumps(body), content_type="application/json", HTTP_X_QODIQA_ARTIFACT=make_artifact(body={"x": 1})))
    assert refused.status_code == 403 and json.loads(refused.content)["error"]["code"] == "QODIQA_REQUEST_MISMATCH"
    assert mw(rf.post("/protected/echo", data="{}", content_type="application/json")).status_code == 401
    outside = DjangoMiddleware(lambda request: JsonResponse({"ok": True}))
    assert outside(rf.get("/open/page")).status_code == 200
