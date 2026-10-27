"""Operation-complete access to the HTTP contract.

``client.operations.<operation_id>(path=..., query=..., body=..., headers=...)`` for every documented operation, generated from ``docs/api/openapi.json`` by
``scripts/sdk/generate-operations.js`` (``npm run sdk:check`` fails on drift). The hand-written resources (``client.sign``, ``client.chat`` ...) stay the typed, documented
path for the main flows; this layer is for everything else, with correct URLs, verbs and credentials and checked parameters; request and response bodies are plain JSON values.

    client.operations.get_policy_version(path={"policyId": "p1", "v": 3})
    client.operations.list_alerts()
    for event in client.operations.stream_alerts(): ...      # SSE operations are iterators

Names are the snake_case form of the OpenAPI ``operationId`` (``getPolicyVersion`` -> ``get_policy_version``); the camelCase id is accepted by :meth:`call` too.
Credentials: ``ops`` operations use ``api_key``, ``sign`` operations use ``sign_token``, ``none`` send no credential, ``optional`` send ``api_key`` when configured.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import quote

from ._operations_data import OPERATIONS
from .exceptions import AuthenticationError, ValidationError

_PLACEHOLDER = re.compile(r"\{([^}]+)\}")
_BY_ID: Dict[str, str] = {d["id"]: name for name, d in OPERATIONS.items()}


def _prepare(
    auth: Any,
    desc: Mapping[str, Any],
    path: Optional[Mapping[str, Any]],
    query: Optional[Mapping[str, Any]],
    headers: Optional[Mapping[str, str]],
    body: Any,
) -> Dict[str, Any]:
    op = desc["id"]
    given = dict(path or {})
    for k in given:
        if k not in desc["path_params"]:
            raise ValidationError(f"{op}: unknown path parameter {k!r}")

    def fill(m: "re.Match[str]") -> str:
        v = given.get(m.group(1))
        if v is None or str(v) == "":
            raise ValidationError(f"{op}: path parameter {m.group(1)!r} is required")
        return quote(str(v), safe="")

    url = _PLACEHOLDER.sub(fill, desc["path"])
    q: Dict[str, Any] = {}
    for k, v in (query or {}).items():
        if k not in desc["query"]:
            raise ValidationError(f"{op}: unknown query parameter {k!r}")
        if v is not None:
            q[k] = v
    for k in desc["required_query"]:
        if k not in q:
            raise ValidationError(f"{op}: query parameter {k!r} is required")
    if desc["body"] == "none" and body is not None:
        raise ValidationError(f"{op}: this operation takes no request body")
    if desc["body_required"] and body is None:
        raise ValidationError(f"{op}: a request body is required")
    if desc["body"] in ("form", "raw"):
        raise ValidationError(f"{op}: {desc['body']} request bodies are not supported by the generic client")
    hdrs: Dict[str, str] = {}
    allowed = {h.lower() for h in desc["headers"]}
    for k, v in (headers or {}).items():
        if k.lower() not in allowed:
            raise ValidationError(f"{op}: unknown header {k!r}")
        hdrs[k] = v
    hdrs.update(_credential(auth, desc["auth"]))
    return {"path": url, "params": q or None, "headers": hdrs, "json": body}


def _credential(auth: Any, kind: str) -> Dict[str, str]:
    if kind == "none":
        return {}
    if kind == "sign":
        return dict(auth.get_sign_token_header())
    if kind == "optional":
        try:
            return dict(auth.get_auth_header())
        except AuthenticationError:
            return {}
    return dict(auth.get_auth_header())


class _OperationsBase:
    def __init__(self, http: Any, auth: Any) -> None:
        self._http = http
        self._auth = auth

    def list(self) -> List[Dict[str, Any]]:
        """Descriptors of every operation this SDK version can call."""
        return [dict(d) for d in OPERATIONS.values()]

    def describe(self, name: str) -> Dict[str, Any]:
        return dict(self._descriptor(name))

    @staticmethod
    def _descriptor(name: str) -> Mapping[str, Any]:
        key = name if name in OPERATIONS else _BY_ID.get(name)
        if key is None:
            raise ValidationError(f"Unknown operation {name!r}")
        return OPERATIONS[key]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name not in OPERATIONS:
            raise AttributeError(name)

        def method(*, path: Optional[Mapping[str, Any]] = None, query: Optional[Mapping[str, Any]] = None, body: Any = None, headers: Optional[Mapping[str, str]] = None) -> Any:
            return self.call(name, path=path, query=query, body=body, headers=headers)

        method.__name__ = name
        method.__doc__ = f"{OPERATIONS[name]['method']} {OPERATIONS[name]['path']} - {OPERATIONS[name]['summary']}"
        return method

    def __dir__(self) -> List[str]:
        return sorted(set(super().__dir__()) | set(OPERATIONS))


class OperationsResource(_OperationsBase):
    """Synchronous operations."""

    def call(self, name: str, *, path: Optional[Mapping[str, Any]] = None, query: Optional[Mapping[str, Any]] = None, body: Any = None, headers: Optional[Mapping[str, str]] = None) -> Any:
        desc = self._descriptor(name)
        req = _prepare(self._auth, desc, path, query, headers, body)
        if desc["response"] == "sse":
            return self._http.stream(desc["method"], req["path"], json=req["json"], headers=req["headers"], params=req["params"])
        return self._http.request(desc["method"], req["path"], json=req["json"], headers=req["headers"], params=req["params"], binary=desc["response"] == "binary")


class AsyncOperationsResource(_OperationsBase):
    """Asynchronous operations: ``await client.operations.x(...)``; SSE operations are used with ``async for``."""

    def call(self, name: str, *, path: Optional[Mapping[str, Any]] = None, query: Optional[Mapping[str, Any]] = None, body: Any = None, headers: Optional[Mapping[str, str]] = None) -> Any:
        desc = self._descriptor(name)
        req = _prepare(self._auth, desc, path, query, headers, body)
        if desc["response"] == "sse":
            return self._http.stream(desc["method"], req["path"], json=req["json"], headers=req["headers"], params=req["params"])
        return self._http.request(desc["method"], req["path"], json=req["json"], headers=req["headers"], params=req["params"], binary=desc["response"] == "binary")


__all__ = ["OperationsResource", "AsyncOperationsResource", "OPERATIONS"]
