#!/usr/bin/env python3
"""
INDEPENDENT Python verifier for the action-binding vectors (docs/protocol/vectors/action.json, ACTION-nnn).

Standard library only. The JCS-P1 canonicaliser is the one of verify_v2_vectors.py (its own parser and ECMAScript number formatting, no QODIQA code). The
document is rebuilt from the vector's input as TEXT and canonicalised here, so the canonical form of every argument is re-derived by a third implementation.

    python verify_action_vectors.py [file.json]       exit 1 on any mismatch
"""

import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_v2_vectors import Refusal, parse_jcs_p1  # noqa: E402

ACTION_DOMAIN = "QODIQA::ACTION::V2"
SCHEMA_DOMAIN = "QODIQA::TOOL_SCHEMA::V1"
UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TENANT = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SERVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TOOL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def sha(domain, canonical):
    return hashlib.sha256(domain.encode("utf-8") + canonical.encode("utf-8")).hexdigest()


def js(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def is_str(v, rx):
    return isinstance(v, str) and rx.match(v) is not None


def no(code, jcs=None):
    e = {"code": code}
    if jcs:
        e["jcs"] = jcs
    return {"error": e}


def action_verdict(i):
    if not is_str(i["tenantId"], TENANT):
        return no("ACTION_INVALID_TENANT")
    if not is_str(i["agentId"], UUID_V4):
        return no("ACTION_INVALID_AGENT")
    if not is_str(i["sessionId"], UUID_V4):
        return no("ACTION_INVALID_SESSION")
    seq = i["seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 or seq > 9007199254740991:
        return no("ACTION_INVALID_SEQ")
    t = i["tool"]
    if not isinstance(t, dict) or sorted(t.keys()) != ["name", "schemaHash", "server"]:
        return no("ACTION_INVALID_TOOL")
    if not (is_str(t["server"], SERVER) and is_str(t["name"], TOOL) and is_str(t["schemaHash"], HEX64)):
        return no("ACTION_INVALID_TOOL")
    if not i["argsText"].lstrip().startswith("{"):
        return no("ACTION_INVALID_ARGS")
    parent, prev = i["parentRequestHash"], i["prevActionHash"]
    if parent is not None and not is_str(parent, HEX64):
        return no("ACTION_INVALID_PARENT")
    if prev is not None and not is_str(prev, HEX64):
        return no("ACTION_INVALID_PREV")
    if (seq == 1) != (prev is None):
        return no("ACTION_INVALID_PREV")
    text = '{"v":2,"tenantId":%s,"agentId":%s,"sessionId":%s,"seq":%s,"tool":%s,"args":%s,"parentRequestHash":%s,"prevActionHash":%s}' % (
        js(i["tenantId"]), js(i["agentId"]), js(i["sessionId"]), js(seq), js(t), i["argsText"], js(parent), js(prev))
    try:
        _, canonical = parse_jcs_p1(text.encode("utf-8"))
    except Refusal as e:
        return no("ACTION_ARGS_NOT_CANONICALIZABLE", e.code)
    return {"ok": {"canonical": canonical, "actionHash": sha(ACTION_DOMAIN, canonical)}}


def schema_verdict(i):
    if not i["schemaText"].lstrip().startswith("{"):
        return no("SCHEMA_INVALID")
    try:
        _, canonical = parse_jcs_p1(i["schemaText"].encode("utf-8"))
    except Refusal as e:
        return no("SCHEMA_NOT_CANONICALIZABLE", e.code)
    return {"ok": {"schemaHash": sha(SCHEMA_DOMAIN, canonical)}}


def verify_case(c):
    v = schema_verdict(c["input"]) if c["kind"] == "schema" else action_verdict(c["input"])
    if "expectedError" in c:
        if "error" not in v:
            return False, "expected a refusal, derived a hash"
        want = c["expectedError"]
        got = v["error"]
        return (got["code"] == want["code"] and got.get("jcs") == want.get("jcs")), "refusal %s != %s" % (got, want)
    if "ok" not in v:
        return False, "expected a hash, refused %s" % v["error"]
    if c["kind"] == "schema":
        return v["ok"]["schemaHash"] == c["expected"]["schemaHash"], "schemaHash differs"
    if v["ok"]["actionHash"] != c["expected"]["actionHash"]:
        return False, "actionHash differs"
    if hashlib.sha256(v["ok"]["canonical"].encode("utf-8")).hexdigest() != c["expected"]["canonicalSha256"]:
        return False, "canonical form differs"
    if "canonical" in c["expected"] and c["expected"]["canonical"] != v["ok"]["canonical"]:
        return False, "canonical text differs"
    return True, None


def verify_file(path):
    with open(path, "r", encoding="utf-8") as f:
        v = json.load(f)
    failures = []
    for c in v["cases"]:
        ok, why = verify_case(c)
        if not ok:
            failures.append({"id": c["id"], "description": c["description"], "why": why})
    return {"file": os.path.basename(path), "family": v["family"], "cases": len(v["cases"]), "failed": len(failures), "failures": failures}


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    path = argv[1] if len(argv) > 1 else os.path.join(here, "..", "..", "docs", "protocol", "vectors", "action.json")
    r = verify_file(path)
    print(json.dumps({"implementation": "verify_action_vectors.py (independent, python %s)" % sys.version.split()[0], "checks": r["cases"], "failed": r["failed"], "reports": [r]}, indent=2))
    return 1 if r["failed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
