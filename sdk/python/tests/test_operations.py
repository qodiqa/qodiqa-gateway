"""the generated, operation-complete layer of the Python SDK: every operation of docs/api/openapi.json is callable, with the right verb, URL, credential and checked parameters.

The contract file is read from the repository (this test belongs to the repo gate, not to the published package).
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa._operations_data import OPERATIONS
from qodiqa.exceptions import AuthenticationError, ValidationError

SPEC_PATH = Path(__file__).resolve().parents[3] / "docs" / "api" / "openapi.json"
METHODS = ("get", "post", "put", "patch", "delete")
OPS_KEY = "ok_" + "a" * 64
SIGN_KEY = "sk_" + "b" * 64

pytestmark = pytest.mark.skipif(not SPEC_PATH.exists(), reason="repository checkout required (docs/api/openapi.json)")


class _Handler(BaseHTTPRequestHandler):
    seen: List[Dict[str, Any]] = []
    mode = "json"

    def _answer(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf8") if length else ""
        type(self).seen.append({"method": self.command, "url": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
        mode = type(self).mode
        if mode == "binary":
            payload, ctype = bytes([0x25, 0x50, 0x44, 0x46, 0xFF, 0xFE]), "application/pdf"
        elif mode == "sse":
            payload, ctype = b'data: {"n":1}\n\ndata: [DONE]\n\n', "text/event-stream"
        elif mode == "text":
            payload, ctype = b"a,b\n1,2\n", "text/csv"
        else:
            payload, ctype = b'{"ok":true}', "application/json"
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _answer  # noqa: N815

    def log_message(self, *args: Any) -> None:  # noqa: D401
        return


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def client(server):
    _Handler.seen.clear()
    _Handler.mode = "json"
    c = QodiqaClient(base_url=server, api_key=OPS_KEY, sign_token=SIGN_KEY, max_retries=0, timeout=5)
    yield c
    c.close()


def _contract_ops() -> List[str]:
    spec = json.loads(SPEC_PATH.read_text(encoding="utf8"))
    return sorted(f"{item[m]['operationId']} {m.upper()} {p}" for p, item in spec["paths"].items() for m in METHODS if m in item)


def _args_for(d: Dict[str, Any]) -> Dict[str, Any]:
    a: Dict[str, Any] = {}
    if d["path_params"]:
        a["path"] = {n: f"v/{n} 1" for n in d["path_params"]}
    if d["required_query"]:
        a["query"] = {n: "x" for n in d["required_query"]}
    if d["body"] == "json":
        a["body"] = {"probe": True}
    return a


def test_op_01_covers_exactly_the_contract():
    sdk = sorted(f"{d['id']} {d['method']} {d['path']}" for d in OPERATIONS.values())
    contract = _contract_ops()
    assert len(contract) > 300
    assert sdk == contract


def test_op_02_every_operation_is_a_method(client):
    assert len(client.operations.list()) == len(OPERATIONS)
    for name in OPERATIONS:
        assert callable(getattr(client.operations, name))
    assert "get_health" in dir(client.operations) or len(dir(client.operations)) > len(OPERATIONS)


def test_op_03_every_non_streaming_operation_reaches_the_server_correctly(client):
    for name, d in OPERATIONS.items():
        if d["response"] == "sse" or d["body"] in ("form", "raw"):
            continue
        _Handler.seen.clear()
        _Handler.mode = "binary" if d["response"] == "binary" else "json"
        getattr(client.operations, name)(**_args_for(d))
        assert len(_Handler.seen) == 1, name
        s = _Handler.seen[0]
        assert s["method"] == d["method"], name
        expected = "".join(
            quote(f"v/{part[1:-1]} 1", safe="") if part.startswith("{") else part
            for part in __import__("re").split(r"(\{[^}]+\})", d["path"])
        )
        assert urlsplit(s["url"]).path == expected, name
        auth = s["headers"].get("authorization")
        if d["auth"] == "none":
            assert auth is None, name
        elif d["auth"] == "sign":
            assert auth == f"Bearer {SIGN_KEY}", name
        else:
            assert auth == f"Bearer {OPS_KEY}", name


def test_op_04_body_query_and_header(client):
    d = next(x for x in OPERATIONS.values() if x["body"] == "json" and x["query"] and x["headers"] and x["response"] == "json")
    a = _args_for(d)
    a["query"] = {**a.get("query", {}), d["query"][0]: "a b&c"}
    a["headers"] = {d["headers"][0]: "123456"}
    client.operations.call(d["id"], **a)
    s = _Handler.seen[0]
    assert json.loads(s["body"]) == {"probe": True}
    assert parse_qs(urlsplit(s["url"]).query)[d["query"][0]] == ["a b&c"]
    assert s["headers"][d["headers"][0].lower()] == "123456"


def test_op_05_argument_mistakes_fail_locally(client):
    one = next(x for x in OPERATIONS.values() if len(x["path_params"]) == 1 and x["method"] == "GET")
    name = next(k for k, v in OPERATIONS.items() if v is one)
    p = one["path_params"][0]
    with pytest.raises(ValidationError):
        getattr(client.operations, name)()
    with pytest.raises(ValidationError):
        getattr(client.operations, name)(path={p: ""})
    with pytest.raises(ValidationError, match="unknown path parameter"):
        getattr(client.operations, name)(path={p: "x", "extra": "y"})
    with pytest.raises(ValidationError, match="unknown query parameter"):
        getattr(client.operations, name)(path={p: "x"}, query={"nope": 1})
    nobody = next(k for k, v in OPERATIONS.items() if v["body"] == "none" and not v["path_params"] and v["method"] == "GET")
    with pytest.raises(ValidationError, match="no request body"):
        getattr(client.operations, nobody)(body={})
    with pytest.raises(ValidationError, match="unknown header"):
        getattr(client.operations, nobody)(headers={"X-Nope": "1"})
    needs = next(k for k, v in OPERATIONS.items() if v["body_required"] and not v["path_params"])
    with pytest.raises(ValidationError, match="body is required"):
        getattr(client.operations, needs)()
    with pytest.raises(ValidationError, match="Unknown operation"):
        client.operations.call("noSuchOperation")
    with pytest.raises(AttributeError):
        client.operations.no_such_operation  # noqa: B018
    assert _Handler.seen == []


def test_op_06_missing_credentials_are_local_authentication_errors(server):
    c = QodiqaClient(base_url=server, max_retries=0)
    try:
        ops = next(k for k, v in OPERATIONS.items() if v["auth"] == "ops" and not v["path_params"] and v["body"] == "none")
        sign = next(k for k, v in OPERATIONS.items() if v["auth"] == "sign" and not v["path_params"])
        with pytest.raises(AuthenticationError):
            getattr(c.operations, ops)()
        with pytest.raises(AuthenticationError):
            getattr(c.operations, sign)(**_args_for(OPERATIONS[sign]))
        none = next(k for k, v in OPERATIONS.items() if v["auth"] == "none" and not v["path_params"] and v["body"] == "none" and v["response"] == "json")
        getattr(c.operations, none)()
        optional = next(k for k, v in OPERATIONS.items() if v["auth"] == "optional" and not v["path_params"] and v["body"] == "none")
        getattr(c.operations, optional)(**_args_for(OPERATIONS[optional]))
    finally:
        c.close()


def test_op_07_binary_text_and_sse(client):
    binary = next(k for k, v in OPERATIONS.items() if v["response"] == "binary")
    _Handler.mode = "binary"
    assert client.operations.call(binary, **_args_for(OPERATIONS[binary])) == bytes([0x25, 0x50, 0x44, 0x46, 0xFF, 0xFE])
    text = next(k for k, v in OPERATIONS.items() if v["response"] == "text" and not v["path_params"])
    _Handler.mode = "text"
    assert client.operations.call(text, **_args_for(OPERATIONS[text])) == "a,b\n1,2\n"
    sse = next(k for k, v in OPERATIONS.items() if v["response"] == "sse")
    _Handler.mode = "sse"
    assert list(client.operations.call(sse, **_args_for(OPERATIONS[sse]))) == [{"n": 1}]


def test_op_08_async_client(server):
    async def run() -> None:
        _Handler.seen.clear()
        _Handler.mode = "json"
        c = AsyncQodiqaClient(base_url=server, api_key=OPS_KEY, sign_token=SIGN_KEY, max_retries=0, timeout=5)
        try:
            name = next(k for k, v in OPERATIONS.items() if v["auth"] == "ops" and not v["path_params"] and v["body"] == "none" and v["method"] == "GET" and not v["required_query"] and v["response"] == "json")
            assert await getattr(c.operations, name)() == {"ok": True}
            sse = next(k for k, v in OPERATIONS.items() if v["response"] == "sse")
            _Handler.mode = "sse"
            got = [e async for e in c.operations.call(sse, **_args_for(OPERATIONS[sse]))]
            assert got == [{"n": 1}]
            binary = next(k for k, v in OPERATIONS.items() if v["response"] == "binary")
            _Handler.mode = "binary"
            assert await c.operations.call(binary, **_args_for(OPERATIONS[binary])) == bytes([0x25, 0x50, 0x44, 0x46, 0xFF, 0xFE])
        finally:
            await c.aclose()

    asyncio.run(run())
