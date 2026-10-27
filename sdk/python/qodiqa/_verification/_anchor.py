"""Offline check of one line of an anchors repository.

A line is ``{digest, statement}``; ``statement`` is ``{v: 1, checkpointId, payloadHash, chainLength, headHash, createdAt}`` and ``digest`` is
``hex(SHA-256("QODIQA::EXTERNAL_ANCHOR::V1" || canonical(statement)))``. The statement pins one signed audit checkpoint (its payload hash, chain
position and head) outside the gateway's trust domain; the digest is what an OpenTimestamps stamp or an RFC 3161 token is taken over.

Fully offline. This checks the LINE; whether the checkpoint is the one a proof relies on is the proof verifier's job
(``scripts/audit-repro/verify/qodiqa_proof_verify.py --anchors-repo``).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Mapping, Optional, Tuple

from ._canonical_json import stable_stringify
from ._domain_hash import domain_separated_hash

#: Domain separation tag of the anchor statement digest.
ANCHOR_DOMAIN = "QODIQA::EXTERNAL_ANCHOR::V1"
_STATEMENT_KEYS = sorted(["v", "checkpointId", "payloadHash", "chainLength", "headHash", "createdAt"])
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SAFE = 9007199254740991
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z\Z")

AnchorLineResult = Tuple[Optional[str], Optional[Dict[str, Any]]]


def _no_constant(name: str) -> Any:
    raise ValueError("non-finite JSON constant " + name)


def anchor_statement_digest(statement: Mapping[str, Any]) -> str:
    """The digest (lowercase hex) of an anchor statement."""
    return domain_separated_hash(ANCHOR_DOMAIN, stable_stringify(dict(statement))).hex()


def check_anchor_line(line: str) -> AnchorLineResult:
    """Check one raw line. Returns ``(None, {"digest", "statement"})`` when it is valid, else ``(code, None)`` with ``code`` one of
    ``ANCHOR_LINE_MALFORMED`` / ``ANCHOR_DIGEST_MISMATCH``."""
    if line.endswith("\r"):
        return "ANCHOR_LINE_MALFORMED", None
    try:
        rec = json.loads(line, parse_constant=_no_constant)
    except ValueError:
        return "ANCHOR_LINE_MALFORMED", None
    st = rec.get("statement") if isinstance(rec, dict) else None
    if not isinstance(st, dict) or sorted(st.keys()) != _STATEMENT_KEYS:
        return "ANCHOR_LINE_MALFORMED", None
    n = st.get("chainLength")
    if isinstance(n, float) and n == int(n) and abs(n) <= _MAX_SAFE:
        n = int(n)          # JSON has one number type: 50.0 is the integer 50
        st = dict(st, chainLength=n)
    if (st.get("v") != 1 or not isinstance(st.get("checkpointId"), str) or not re.fullmatch(r"[\x21-\x7e]{1,256}", st["checkpointId"]) or not _HEX64.match(str(st.get("payloadHash")))
            or not _HEX64.match(str(st.get("headHash"))) or not isinstance(n, int) or isinstance(n, bool) or n < 1 or n > _MAX_SAFE
            or not isinstance(st.get("createdAt"), str) or not _ISO_UTC.match(st["createdAt"])):
        return "ANCHOR_LINE_MALFORMED", None
    digest = anchor_statement_digest(st)
    if rec.get("digest") != digest:
        return "ANCHOR_DIGEST_MISMATCH", None
    return None, {"digest": digest, "statement": st}
