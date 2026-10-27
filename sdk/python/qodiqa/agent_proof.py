"""The agent's proof of possession.

An agent registered with a public key must attach a ``proof`` to every authorisation request: an Ed25519 signature over
``SHA-256("QODIQA::AGENT_REQUEST::V1" || {"agentId":..,"requestId":..,"sessionId":..,"tenantId":..,"v":1})``. The proof is bound to
ONE request id, so it cannot be replayed for another action.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Dict, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .exceptions import ValidationError

AGENT_PROOF_DOMAIN = "QODIQA::AGENT_REQUEST::V1"

AgentProofContext = Dict[str, str]


def agent_proof_digest(ctx: AgentProofContext) -> bytes:
    """SHA-256 over the domain tag and the canonical proof statement. ``ctx`` needs tenantId, agentId, sessionId, requestId."""
    for key in ("tenantId", "agentId", "sessionId", "requestId"):
        value = ctx.get(key)
        if not isinstance(value, str) or value == "":
            raise ValidationError(f'"{key}" is required to sign an agent proof.')
    canonical = json.dumps(
        {"agentId": ctx["agentId"], "requestId": ctx["requestId"], "sessionId": ctx["sessionId"], "tenantId": ctx["tenantId"], "v": 1},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(AGENT_PROOF_DOMAIN.encode("utf-8") + canonical.encode("utf-8")).digest()


def sign_agent_proof(ctx: AgentProofContext, private_key: Union[Ed25519PrivateKey, bytes, str]) -> str:
    """Sign the proof; ``private_key`` is an ``Ed25519PrivateKey``, a PEM (str/bytes) or a PKCS#8 DER blob. Returns base64."""
    if isinstance(private_key, Ed25519PrivateKey):
        key = private_key
    else:
        raw = private_key.encode("utf-8") if isinstance(private_key, str) else private_key
        loaded = (
            serialization.load_pem_private_key(raw, password=None)
            if raw.lstrip().startswith(b"-----BEGIN")
            else serialization.load_der_private_key(raw, password=None)
        )
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValidationError("The agent key must be an Ed25519 private key.")
        key = loaded
    return base64.b64encode(key.sign(agent_proof_digest(ctx))).decode("ascii")


def generate_agent_key_pair() -> Tuple[str, Ed25519PrivateKey]:
    """A fresh Ed25519 key pair: ``(public_key_b64_spki, private_key)``. Register the public key with ``agents.create()``."""
    private = Ed25519PrivateKey.generate()
    spki = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(spki).decode("ascii"), private
