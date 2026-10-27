"""Offline verification of a signed receipt.

A receipt ``{v, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature}`` proves that the gateway RECORDED a decision (the audit DECISION entry
named by ``entryHash`` and the transparency leaf named by ``leafHash``) — not that the decision was correct. ``signature`` is
``base64(Ed25519.sign(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature))))`` by a TRANSPARENCY key. The receipt carries only strings and one
integer, so its JCS-P1 form is the sorted-key compact JSON this SDK's canonicalizer produces.

Fully offline. A receipt signed by a key that is now revoked verifies only in the timed mode (``trusted_at`` from an independent authority, before the
key's ``revokedAt``).
"""

from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from ._canonical_json import stable_stringify
from ._domain_hash import domain_separated_hash
from ._ed25519 import verify_ed25519

#: Domain separation tag of the receipt signature.
RECEIPT_DOMAIN = "QODIQA::RECEIPT::V1"
_FIELDS = ("v", "requestId", "decision", "issuedAt", "entryHash", "leafHash", "keyId", "signature")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: ``(ok, reason)``; ``reason`` is ``None`` when ``ok``, else one of NOT_AN_OBJECT, FIELD_SET, UNSUPPORTED_VERSION, INVALID_FIELD, UNKNOWN_KEY,
#: BAD_SIGNATURE, REVOKED_KEY.
ReceiptVerifyResult = Tuple[bool, Optional[str]]


def receipt_digest(receipt: Mapping[str, Any]) -> bytes:
    """The 32-byte digest that is signed (the receipt without its ``signature``)."""
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    return domain_separated_hash(RECEIPT_DOMAIN, stable_stringify(unsigned))


def _key_list(keys: Union[Sequence[Mapping[str, Any]], Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    if isinstance(keys, Mapping):
        inner = keys.get("keys")
        return list(inner) if isinstance(inner, (list, tuple)) else []
    return list(keys)


def _epoch_ms(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000
        except ValueError:
            return None
    return None


def verify_receipt(
    receipt: Any,
    keys: Union[Sequence[Mapping[str, Any]], Mapping[str, Any]],
    *,
    trusted_at: Optional[float] = None,
) -> ReceiptVerifyResult:
    """Verify a receipt against transparency keys. Never raises; fails closed.

    Args:
        receipt: the receipt object (``response["receipt"]`` or ``getReceipt()["data"]["receipt"]``).
        keys: ``[{"keyId", "publicKey" (base64 SPKI DER), "status", "revokedAt"?}]`` or the whole body of
            ``GET /.well-known/qodiqa/transparency-keys``.
        trusted_at: timed mode for a receipt signed by a since-revoked key — a time (ms since epoch) attested by an independent authority;
            accepted only before the key's ``revokedAt``.

    Returns:
        ``(True, None)`` when the receipt is genuine, else ``(False, reason)``.
    """
    if not isinstance(receipt, dict):
        return False, "NOT_AN_OBJECT"
    if sorted(receipt.keys()) != sorted(_FIELDS):
        return False, "FIELD_SET"
    if receipt["v"] != 1 or isinstance(receipt["v"], bool):
        return False, "UNSUPPORTED_VERSION"
    issued_at = receipt["issuedAt"]
    invalid = (
        not isinstance(receipt["requestId"], str) or receipt["requestId"] == ""
        or receipt["decision"] not in ("ALLOW", "BLOCK")
        or isinstance(issued_at, bool) or not isinstance(issued_at, int) or issued_at < 0 or issued_at > 9007199254740991
        or not isinstance(receipt["entryHash"], str) or not _HEX64.match(receipt["entryHash"])
        or not isinstance(receipt["leafHash"], str) or not _HEX64.match(receipt["leafHash"])
        or not isinstance(receipt["keyId"], str) or receipt["keyId"] == ""
        or not isinstance(receipt["signature"], str) or receipt["signature"] == ""
    )
    if invalid:
        return False, "INVALID_FIELD"

    key = next((k for k in _key_list(keys) if isinstance(k, Mapping) and k.get("keyId") == receipt["keyId"]), None)
    if key is None:
        return False, "UNKNOWN_KEY"
    try:
        pub_der = base64.b64decode(str(key.get("publicKey", "")), validate=True)
        sig_text = receipt["signature"]
        # one spelling per signature: only the canonical base64 encoding of the signature bytes is accepted
        canonical = base64.b64encode(base64.b64decode(sig_text, validate=True)).decode("ascii") == sig_text
        good = canonical and verify_ed25519(receipt_digest(receipt), sig_text, pub_der)
    except Exception:
        good = False
    if not good:
        return False, "BAD_SIGNATURE"

    if str(key.get("status") or "").lower() == "revoked":
        revoked_at = _epoch_ms(key.get("revokedAt"))
        if trusted_at is None or revoked_at is None or not (float(trusted_at) < revoked_at):
            return False, "REVOKED_KEY"
    return True, None


def receipt_binds_to(
    receipt: Mapping[str, Any],
    *,
    entry_hash: Optional[str] = None,
    leaf_hash: Optional[str] = None,
    request_id: Optional[str] = None,
    decision: Optional[str] = None,
) -> Tuple[bool, List[str]]:
    """Does the receipt name exactly the audit entry / leaf / request / decision the caller already holds? Returns ``(ok, mismatching fields)``."""
    wanted: Dict[str, Optional[str]] = {"entryHash": entry_hash, "leafHash": leaf_hash, "requestId": request_id, "decision": decision}
    mismatches = [f for f, v in wanted.items() if v is not None and receipt.get(f) != v]
    return (not mismatches), mismatches
