"""QODIQA domain-separated hashing — Python SDK-side port of
``src/infra/crypto/hashing.js`` and ``src/validation/canonicalize.js``.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from ._canonical_json import stable_stringify

#: Full-envelope artifact-signing domain — covers payload+timestamp+expiry+publicKeyId.
ARTIFACT_DOMAIN = "QODIQA::ARTIFACT::V1"
#: Transparency-log entry-signing domain.
TRANSPARENCY_ENTRY_DOMAIN = "QODIQA::TRANSPARENCY::V1"
#: Transparency-log root-signing domain.
TRANSPARENCY_ROOT_DOMAIN = "QODIQA::TRANSPARENCY_ROOT::V1"
#: V1 request-binding domain.
REQUEST_DOMAIN = "QODIQA::REQUEST::V1"


def domain_separated_hash(domain: str, canonical: str) -> bytes:
    """SHA-256(domain || canonical). Prevents cross-protocol signature reuse
    between artifact classes. Returns the raw 32-byte digest.
    """
    h = hashlib.sha256()
    h.update(domain.encode("utf-8"))
    h.update(canonical.encode("utf-8"))
    return h.digest()


_SIGNED_ENVELOPE_KEYS = ("expiry", "payload", "publicKeyId", "timestamp")


def envelope_hash(artifact: Dict[str, Any]) -> bytes:
    """Compute the 32-byte domain-separated hash over the full artifact
    envelope — the exact Ed25519 message the server signs/verifies.

    SHA-256("QODIQA::ARTIFACT::V1" || stableStringify({expiry, payload, publicKeyId, timestamp}))
    """
    envelope = {k: artifact[k] for k in _SIGNED_ENVELOPE_KEYS}
    canonical = stable_stringify(envelope)
    return domain_separated_hash(ARTIFACT_DOMAIN, canonical)


def request_hash(method: str, path: str, body: Any) -> str:
    """The V1 request hash an artifact's ``payload.requestHash`` binds:
    hex(SHA-256("QODIQA::REQUEST::V1" || canonical({body, method: UPPER(method), path}))). ``path`` has no query string.
    (The V2 binding, which also covers the query and chosen headers, is not implemented in this SDK yet.)
    """
    canonical = stable_stringify({"body": body, "method": method.upper(), "path": path})
    return domain_separated_hash(REQUEST_DOMAIN, canonical).hex()
