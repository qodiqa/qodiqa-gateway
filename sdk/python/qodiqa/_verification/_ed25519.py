"""Ed25519 verification — Python SDK-side port of
``src/infra/crypto/ed25519.js``'s ``verify()``. Signing is intentionally not
ported: only the server signs artifacts, the SDK only ever verifies.

Key format: public keys are SPKI DER (not raw 32 bytes, not PEM, not JWK) —
exactly what ``/.well-known/qodiqa/keys`` and
``/.well-known/qodiqa/transparency-keys`` serve, base64-encoded.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key


def verify_ed25519(hash_bytes: bytes, signature_b64: str, pub_der: bytes) -> bool:
    """Verify an Ed25519 signature over `hash_bytes`.

    Never raises — returns ``False`` for any structurally invalid input
    (wrong-length hash/signature, unparseable key, mismatched signature),
    matching the server implementation's fail-closed, non-throwing contract.
    """
    try:
        if not isinstance(hash_bytes, (bytes, bytearray)) or len(hash_bytes) != 32:
            return False
        if not isinstance(signature_b64, str):
            return False
        if not isinstance(pub_der, (bytes, bytearray)) or len(pub_der) == 0:
            return False

        try:
            sig_buf = base64.b64decode(signature_b64, validate=True)
        except Exception:
            return False
        if len(sig_buf) != 64:
            return False

        public_key = load_der_public_key(bytes(pub_der))
        if not isinstance(public_key, Ed25519PublicKey):
            return False

        public_key.verify(sig_buf, bytes(hash_bytes))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
