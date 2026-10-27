#!/usr/bin/env python3
"""
INDEPENDENT Python verifier for the approval-statement vectors (docs/protocol/vectors/approval.json, APPROVAL-nnn).

Standard library only. JCS-P1 and Ed25519 are the independent implementations of verify_v2_vectors.py (no QODIQA code). The rules of
src/core/approvals/approvalToken.js are re-implemented here from the specification text (its header).

    python verify_approval_vectors.py [file.json]       exit 1 on any mismatch
"""

import base64
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_v2_vectors import ed25519_verify, parse_jcs_p1  # noqa: E402

DOMAIN = "QODIQA::APPROVAL::V1"
UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SIG_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
TENANT = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENVELOPE_KEYS = sorted("expiry,payload,publicKeyId,signature,timestamp".split(","))
PAYLOAD_KEYS = sorted("actionHash,agentId,approvalId,approverId,decision,expiresAt,kind,mfa,notBefore,policyRuleId,requesterId,seq,sessionId,tenantId,v".split(","))
MAX_SKEW = 5 * 60_000
SAFE = 9007199254740991
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def is_int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def is_str(v, rx):
    return isinstance(v, str) and rx.match(v) is not None


def id_str(v):
    return isinstance(v, str) and 1 <= len(v) <= 256 and all(ord(c) >= 32 and ord(c) != 127 for c in v)


def shape_ok(p):
    if not isinstance(p, dict) or sorted(p.keys()) != PAYLOAD_KEYS:
        return False
    if p["v"] != 1 or isinstance(p["v"], bool) or p["kind"] != "approval":
        return False
    if not is_str(p["approvalId"], UUID_V4) or not is_str(p["tenantId"], TENANT) or not is_str(p["actionHash"], HEX64):
        return False
    if not is_str(p["agentId"], UUID_V4) or not is_str(p["sessionId"], UUID_V4):
        return False
    if not is_int(p["seq"], 1, SAFE):
        return False
    if not (id_str(p["requesterId"]) and id_str(p["approverId"]) and id_str(p["policyRuleId"])):
        return False
    if p["decision"] not in ("APPROVED", "DENIED"):
        return False
    if not is_int(p["notBefore"], 1, SAFE) or not is_int(p["expiresAt"], 1, SAFE) or p["expiresAt"] <= p["notBefore"]:
        return False
    return p["mfa"] == "step-up"


def digest_of(e):
    text = json.dumps({"expiry": e["expiry"], "payload": e["payload"], "publicKeyId": e["publicKeyId"], "timestamp": e["timestamp"]}, ensure_ascii=False, separators=(",", ":"))
    _, canonical = parse_jcs_p1(text.encode("utf-8"))
    return hashlib.sha256(DOMAIN.encode("utf-8") + canonical.encode("utf-8")).digest()


def no(reason, detail=None):
    r = {"ok": False, "reason": reason}
    if detail:
        r["detail"] = detail
    return r


def verdict(inp, keys):
    e, now, expect = inp["envelope"], inp["now"], inp.get("expect", {})
    if not isinstance(e, dict) or sorted(e.keys()) != ENVELOPE_KEYS:
        return no("APPROVAL_INVALID", "shape")
    p = e["payload"]
    if not shape_ok(p):
        return no("APPROVAL_INVALID", "shape")
    sig = e["signature"]
    if not is_str(sig, SIG_RE) or base64.b64encode(base64.b64decode(sig)).decode("ascii") != sig:
        return no("APPROVAL_INVALID", "shape")
    ts, ex, kid = e["timestamp"], e["expiry"], e["publicKeyId"]
    if not is_int(ts, 1, SAFE) or ex != p["expiresAt"] or not isinstance(ex, int) or ex <= ts or not isinstance(kid, str) or not kid.strip():
        return no("APPROVAL_INVALID", "shape")
    try:
        digest = digest_of(e)
    except Exception:
        return no("APPROVAL_INVALID", "shape")
    key = next((k for k in keys if k["publicKeyId"] == kid), None)
    if key is None:
        return no("APPROVAL_INVALID", "signature")
    spki = base64.b64decode(key["publicKeySpkiB64"])
    if not spki.startswith(SPKI_PREFIX) or not ed25519_verify(spki[len(SPKI_PREFIX):], digest, base64.b64decode(sig)):
        return no("APPROVAL_INVALID", "signature")
    if p["tenantId"] != key["clientId"]:
        return no("APPROVAL_INVALID", "tenant")
    for k in ("actionHash", "tenantId", "agentId", "sessionId", "seq", "approvalId"):
        if k in expect and expect[k] != p[k]:
            return no("APPROVAL_INVALID", "not for this " + k)
    if p["approverId"] == p["requesterId"]:
        return no("APPROVAL_INVALID", "the approver is the requester")
    if p["decision"] != "APPROVED":
        return no("APPROVAL_INVALID", "denied")
    if ts > now + MAX_SKEW:
        return no("APPROVAL_INVALID", "decided in the future")
    if now < p["notBefore"]:
        return no("APPROVAL_INVALID", "not yet valid")
    if now >= p["expiresAt"]:
        return no("APPROVAL_EXPIRED")
    return {"ok": True, "digest": digest.hex()}


def verify_file(path):
    with open(path, "r", encoding="utf-8") as f:
        v = json.load(f)
    failures = []
    for c in v["cases"]:
        got = verdict(c["input"], v["keys"])
        if got != c["expected"]:
            failures.append({"id": c["id"], "description": c["description"], "got": got, "expected": c["expected"]})
    return {"file": os.path.basename(path), "family": v["family"], "cases": len(v["cases"]), "failed": len(failures), "failures": failures}


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    path = argv[1] if len(argv) > 1 else os.path.join(here, "..", "..", "docs", "protocol", "vectors", "approval.json")
    r = verify_file(path)
    print(json.dumps({"implementation": "verify_approval_vectors.py (independent, python %s)" % sys.version.split()[0], "checks": r["cases"], "failed": r["failed"], "reports": [r]}, indent=2))
    return 1 if r["failed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
