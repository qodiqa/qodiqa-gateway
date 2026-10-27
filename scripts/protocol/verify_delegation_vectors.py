#!/usr/bin/env python3
"""
INDEPENDENT Python verifier for the delegation-chain vectors (docs/protocol/vectors/delegation.json, DELEG-nnn).

Standard library only. JCS-P1 and Ed25519 are the independent implementations of verify_v2_vectors.py (no QODIQA code). The chain rules of
docs/protocol/DELEGATION.md are re-implemented here from the specification text alone.

    python verify_delegation_vectors.py [file.json]       exit 1 on any mismatch
"""

import base64
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_v2_vectors import ed25519_verify, parse_jcs_p1  # noqa: E402

DOMAIN = "QODIQA::DELEGATION::V1"
CLASSES = ["read", "write", "file", "database", "external_api", "command", "communication", "financial", "delegate"]
UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SIG_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
TENANT = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SERVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
PAYLOAD_KEYS = sorted("classes,delegationId,depth,issuerAgentId,kind,maxActions,maxDepth,parentDigest,parentId,rootAgentId,subjectAgentId,tenantId,tools,v".split(","))
ENVELOPE_KEYS = sorted("expiry,payload,publicKeyId,signature,timestamp".split(","))
MAX_DEPTH = 8
MAX_SKEW = 5 * 60_000
SAFE = 9007199254740991
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def is_int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def is_str(v, rx):
    return isinstance(v, str) and rx.match(v) is not None


def tool_key(t):
    return t["server"] + "\u0000" + t["name"]


def shape_ok(p):
    if not isinstance(p, dict) or sorted(p.keys()) != PAYLOAD_KEYS:
        return False
    if p["v"] != 1 or isinstance(p["v"], bool) or p["kind"] != "delegation":
        return False
    if not is_str(p["delegationId"], UUID_V4) or not is_str(p["tenantId"], TENANT):
        return False
    if p["parentId"] is not None and not is_str(p["parentId"], UUID_V4):
        return False
    if p["parentDigest"] is not None and not is_str(p["parentDigest"], HEX64):
        return False
    if (p["parentId"] is None) != (p["parentDigest"] is None):
        return False
    for k in ("rootAgentId", "issuerAgentId", "subjectAgentId"):
        if not is_str(p[k], UUID_V4):
            return False
    if not is_int(p["depth"], 1, MAX_DEPTH) or not is_int(p["maxDepth"], 1, MAX_DEPTH):
        return False
    cl = p["classes"]
    if not isinstance(cl, list) or not cl or not all(isinstance(c, str) and c in CLASSES for c in cl):
        return False
    if any(not (cl[i - 1] < cl[i]) for i in range(1, len(cl))):
        return False
    tools = p["tools"]
    if tools is not None:
        if not isinstance(tools, list) or not tools or len(tools) > 100:
            return False
        for t in tools:
            if not isinstance(t, dict) or sorted(t.keys()) != ["name", "server"] or not is_str(t["server"], SERVER) or not is_str(t["name"], TOOL):
                return False
        if any(not (tool_key(tools[i - 1]) < tool_key(tools[i])) for i in range(1, len(tools))):
            return False
    if p["maxActions"] is not None and not is_int(p["maxActions"], 1, 100000):
        return False
    return True


def digest_of(e):
    text = json.dumps({"expiry": e["expiry"], "payload": e["payload"], "publicKeyId": e["publicKeyId"], "timestamp": e["timestamp"]}, ensure_ascii=False, separators=(",", ":"))
    _, canonical = parse_jcs_p1(text.encode("utf-8"))
    return hashlib.sha256(DOMAIN.encode("utf-8") + canonical.encode("utf-8")).digest()


def widens(parent, child, parent_expiry, child_expiry):
    if not all(c in parent["classes"] for c in child["classes"]):
        return True
    if parent["tools"] is not None:
        if child["tools"] is None:
            return True
        allowed = {tool_key(t) for t in parent["tools"]}
        if not all(tool_key(t) in allowed for t in child["tools"]):
            return True
    if parent["maxActions"] is not None and (child["maxActions"] is None or child["maxActions"] > parent["maxActions"]):
        return True
    return child_expiry > parent_expiry


def no(reason, index=None):
    r = {"ok": False, "reason": reason}
    if index is not None:
        r["index"] = index
    return r


def verdict(inp, keys):
    chain, now = inp["chain"], inp["now"]
    if not isinstance(chain, list) or len(chain) < 1 or len(chain) > MAX_DEPTH:
        return no("DELEGATION_INVALID")
    agents, prev, prev_digest, root = [], None, None, None
    for i, e in enumerate(chain):
        if not isinstance(e, dict) or sorted(e.keys()) != ENVELOPE_KEYS:
            return no("DELEGATION_INVALID", i)
        p = e["payload"]
        if not shape_ok(p):
            return no("DELEGATION_INVALID", i)
        sig = e["signature"]
        if not is_str(sig, SIG_RE) or base64.b64encode(base64.b64decode(sig)).decode("ascii") != sig:
            return no("DELEGATION_INVALID", i)
        ts, ex, kid = e["timestamp"], e["expiry"], e["publicKeyId"]
        if not is_int(ts, 1, SAFE) or not is_int(ex, 1, SAFE) or ex <= ts or not isinstance(kid, str) or not kid.strip():
            return no("DELEGATION_INVALID", i)
        try:
            digest = digest_of(e)
        except Exception:
            return no("DELEGATION_INVALID", i)
        key = next((k for k in keys if k["publicKeyId"] == kid), None)
        if key is None:
            return no("DELEGATION_INVALID", i)
        spki = base64.b64decode(key["publicKeySpkiB64"])
        if not spki.startswith(SPKI_PREFIX) or not ed25519_verify(spki[len(SPKI_PREFIX):], digest, base64.b64decode(sig)):
            return no("DELEGATION_INVALID", i)
        if p["tenantId"] != key["clientId"] or (root is not None and p["tenantId"] != root["payload"]["tenantId"]):
            return no("DELEGATION_INVALID", i)
        if i == 0:
            if p["parentId"] is not None or p["depth"] != 1 or p["rootAgentId"] != p["issuerAgentId"]:
                return no("DELEGATION_INVALID", i)
            root = e
            agents.append(p["issuerAgentId"])
        elif (p["parentId"] != prev["payload"]["delegationId"] or p["parentDigest"] != prev_digest or p["issuerAgentId"] != prev["payload"]["subjectAgentId"]
              or p["depth"] != prev["payload"]["depth"] + 1 or p["maxDepth"] != root["payload"]["maxDepth"] or p["rootAgentId"] != root["payload"]["rootAgentId"]):
            return no("DELEGATION_INVALID", i)
        if p["depth"] > p["maxDepth"]:
            return no("DELEGATION_DEPTH_EXCEEDED", i)
        if p["subjectAgentId"] == p["issuerAgentId"] or p["subjectAgentId"] in agents:
            return no("DELEGATION_CYCLE", i)
        agents.append(p["subjectAgentId"])
        if prev is not None:
            if widens(prev["payload"], p, prev["expiry"], ex):
                return no("DELEGATION_ATTENUATION_VIOLATION", i)
            if ts < prev["timestamp"]:
                return no("DELEGATION_INVALID", i)
        if ts > now + MAX_SKEW or ex <= now:
            return no("DELEGATION_INVALID", i)
        prev, prev_digest = e, digest.hex()
    leaf = chain[-1]
    lp = leaf["payload"]
    return {"ok": True, "depth": lp["depth"], "maxDepth": lp["maxDepth"], "chainHash": prev_digest, "rootAgentId": lp["rootAgentId"], "issuerAgentId": lp["issuerAgentId"],
            "subjectAgentId": lp["subjectAgentId"], "tenantId": lp["tenantId"], "delegationId": lp["delegationId"], "classes": lp["classes"], "tools": lp["tools"],
            "maxActions": lp["maxActions"], "expiry": leaf["expiry"]}


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
    path = argv[1] if len(argv) > 1 else os.path.join(here, "..", "..", "docs", "protocol", "vectors", "delegation.json")
    r = verify_file(path)
    print(json.dumps({"implementation": "verify_delegation_vectors.py (independent, python %s)" % sys.version.split()[0], "checks": r["cases"], "failed": r["failed"], "reports": [r]}, indent=2))
    return 1 if r["failed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
