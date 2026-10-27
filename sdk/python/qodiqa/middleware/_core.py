"""Framework-neutral core of the artifact guard: decides whether a request may pass.

A request passes only when it carries a QODIQA artifact that

1. verifies offline against the trust bundle (genuine signature, known active key, not expired, not from the future), and
2. is bound to THIS request: ``payload.requestHash`` equals the V1 request hash of (method, path without query, parsed JSON body).

The artifact travels base64-encoded (JSON) in the ``x-qodiqa-artifact`` header, the way the gateway's own routes read it. Nothing is sent to the gateway. The guard does NOT consume the
artifact's nonce (replay protection is the gateway's job, via POST /verify): pass ``replay_guard`` to add your own. Protocol V1 binding only.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .._verification._artifact_verifier import ArtifactVerifier
from .._verification._canonical_json import CanonicalizationError
from .._verification._domain_hash import request_hash

DEFAULT_HEADER = "x-qodiqa-artifact"


@dataclass
class GuardResult:
    """The decision. ``ok`` requests carry ``info`` (artifact, payload, key_id); refusals carry the HTTP status and a stable code."""

    ok: bool
    status: int = 200
    code: str = ""
    message: str = ""
    info: Optional[Dict[str, Any]] = field(default=None, repr=False)

    def body(self) -> Dict[str, Any]:
        return {"status": "error", "error": {"code": self.code, "message": self.message}}


class ArtifactGuard:
    def __init__(
        self,
        keys: Any,
        *,
        header: str = DEFAULT_HEADER,
        clock_tolerance_ms: int = 0,
        bind_request: bool = True,
        replay_guard: Optional[Callable[[Dict[str, Any]], bool]] = None,
        max_header_bytes: int = 16384,
        _now: Optional[int] = None,
    ) -> None:
        if keys is None:
            raise ValueError("ArtifactGuard requires a `keys` KeyProvider")
        self.header = header.lower()
        self._keys = keys
        self._tolerance = clock_tolerance_ms
        self._bind = bind_request
        self._replay = replay_guard
        self._max = max_header_bytes
        self._now = _now

    def _verifier(self) -> ArtifactVerifier:
        return ArtifactVerifier(keys=self._keys, clock_tolerance_ms=self._tolerance, _now=self._now)

    def check(self, method: str, path: str, body: Optional[bytes], header_value: Optional[str]) -> GuardResult:
        """``body``: the raw request body (``b""`` or ``None`` when there is none); an empty body is bound as ``{}``."""
        if not header_value:
            return GuardResult(False, 401, "QODIQA_ARTIFACT_REQUIRED", f"The {self.header} header is required.")
        if len(header_value) > self._max:
            return GuardResult(False, 401, "QODIQA_ARTIFACT_INVALID", "The artifact is too large.")
        try:
            artifact = json.loads(base64.b64decode(header_value, validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return GuardResult(False, 401, "QODIQA_ARTIFACT_INVALID", "The artifact is not base64-encoded JSON.")
        result = self._verifier().verify(artifact)
        if result.verification_status != "valid":
            return GuardResult(False, 401, "QODIQA_ARTIFACT_INVALID", f"The artifact was refused ({result.failed_stage or 'invalid'}).")
        payload = artifact["payload"]
        if self._bind:
            try:
                parsed: Any = json.loads(body.decode("utf-8")) if body else {}
                expected = request_hash(method, path, parsed)
            except (UnicodeDecodeError, ValueError, TypeError, RecursionError, CanonicalizationError):
                # CanonicalizationError: a body this SDK cannot hash with cross-language parity (non-integer numbers, excessive depth): refuse, never 500.
                return GuardResult(False, 403, "QODIQA_REQUEST_MISMATCH", "The request cannot be bound to the artifact.")
            claimed = payload.get("requestHash")
            if not isinstance(claimed, str) or not hmac.compare_digest(claimed.encode(), expected.encode()):
                return GuardResult(False, 403, "QODIQA_REQUEST_MISMATCH", "The artifact was issued for a different request.")
        info = {"artifact": artifact, "payload": payload, "key_id": result.key_id, "result": result}
        if self._replay is not None and not self._replay(info):
            return GuardResult(False, 403, "QODIQA_REPLAY_OR_POLICY", "The artifact was refused by the replay guard.")
        return GuardResult(True, info=info)
