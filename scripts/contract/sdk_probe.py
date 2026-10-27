"""Python SDK live contract probe.

Run by scripts/contract/live-contract.js against a real server it booted: the installed (editable) Python SDK
exercises the SDK-facing flows and asserts the parsed shapes. Env: QODIQA_CONTRACT_BASE, QODIQA_CONTRACT_SIGN_KEY,
QODIQA_CONTRACT_OPS_KEY. Prints one JSON line; exit 1 on any failed check.
"""

import base64
import json
import os
import re
import sys
import time

from qodiqa import QodiqaClient
from qodiqa.exceptions import AuthenticationError

BASE = os.environ["QODIQA_CONTRACT_BASE"]
checks = []


def check(name, fn):
    time.sleep(0.4)  # paced: the transparency public bucket allows a burst of 15 per 5 s (real limiter, not relaxed)
    try:
        detail = fn()
        checks.append({"name": name, "ok": True, **({"detail": detail} if detail is not None else {})})
    except Exception as e:  # noqa: BLE001 - every failure is reported, none swallowed
        checks.append({"name": name, "ok": False, "error": repr(e)[:400]})


def need(cond, msg):
    if not cond:
        raise AssertionError(msg)


HEX64 = re.compile(r"^[0-9a-f]{64}$")
client = QodiqaClient(base_url=BASE, sign_token=os.environ["QODIQA_CONTRACT_SIGN_KEY"], api_key=os.environ["QODIQA_CONTRACT_OPS_KEY"], max_retries=0, timeout=20.0)
anon = QodiqaClient(base_url=BASE, max_retries=0, timeout=20.0)
body = {"prompt": "What is the capital of Spain?", "provider": "llama", "model": "stub-model"}
state = {}


def sign_and_chat():
    s = client.sign.sign({"request": {"method": "POST", "path": "/ai/chat", "body": body}, "payload": {"provider": "llama"}})
    need(len(s["artifact"]["signature"]) == 88, "canonical 88-char signature")
    need(isinstance(s["meta"]["effectiveTtlMs"], int), "meta.effectiveTtlMs")
    r = client.chat.create(base64.b64encode(json.dumps(s["artifact"]).encode()).decode(), body)
    need(r["decision"] == "EXECUTE", f"EXECUTE, got {r.get('decision')} {r.get('reason')}")
    state["artifact_id"] = r["artifactId"]
    return {"decision": r["decision"]}


check("health_check", lambda: need(client.health_check()["status"] == "ok", "status ok"))
check("sign.sign + chat.create EXECUTE", sign_and_chat)
time.sleep(1.5)


def entries():
    r = client.transparency.list_entries({"page": 1, "page_size": 5})
    need(len(r["data"]["entries"]) > 0, "entries")
    state["tid"] = r["data"]["entries"][0]["transparency_id"]


check("transparency.list_entries", entries)
check("transparency.get_entry", lambda: need(client.transparency.get_entry(state["tid"])["data"]["entry"]["transparency_id"] == state["tid"], "entry id"))


def gen_root():
    state["gen"] = client.transparency.generate_root()["data"]
    need(HEX64.match(state["gen"]["rootHash"]), "rootHash")


check("transparency.generate_root", gen_root)


def list_roots():
    r = client.transparency.list_roots({"page": 1, "page_size": 10})
    roots = r["data"]["roots"]
    need(len(roots) > 0 and any(x["root_hash"] == state["gen"]["rootHash"] for x in roots), "generated root listed under data.roots")
    need(isinstance(r["data"]["total"], int), "pagination meta")
    return {"roots": len(roots)}


check("transparency.list_roots", list_roots)
check("transparency.get_root (latest)", lambda: need(HEX64.match(client.transparency.get_root()["data"]["root"]["root_hash"]), "root row"))
check("transparency.get_root(root_id)", lambda: need(client.transparency.get_root(state["gen"]["rootId"])["data"]["root"]["root_id"] == state["gen"]["rootId"], "root by id"))


def proof():
    p = client.transparency.get_proof(state["tid"])["data"]["proof"]
    need(p is None or (isinstance(p["proof"]["merklePath"], list) and HEX64.match(p["proof"]["merkleRoot"])), "proof document")
    return {"proof": "present" if p else "null"}


check("transparency.get_proof", proof)
check("transparency.verify_entry", lambda: need(client.transparency.verify_entry(state["tid"])["data"]["result"] in ("VALID", "INVALID", "PARTIAL", "ERROR"), "verification doc"))
check("transparency.validate_chain (transparency validator)", lambda: need(client.transparency.validate_chain()["data"]["chainValidation"]["valid"] is True, "chainValidation.valid"))
check("get_audit_chain (success envelope)", lambda: need(client.get_audit_chain(state["artifact_id"])["status"] == "success", "envelope"))


def not_auth(fn):
    try:
        fn()
    except AuthenticationError:
        raise
    except Exception as e:  # noqa: BLE001 - a non-auth refusal (e.g. 400 on an empty body) is the expected outcome
        return {"nonAuthError": type(e).__name__}
    return {"ok": True}


check("certification.evaluate sends ops credential (not 401)", lambda: not_auth(lambda: client.certification.evaluate([])))
check("attestation.verify_chain sends ops credential (not 401)", lambda: not_auth(lambda: client.attestation.verify_chain(evidence_ids=[])))


def anon_ops():
    try:
        anon.transparency.stats()
    except AuthenticationError:
        return None
    raise AssertionError("expected AuthenticationError")


check("ops-only call without credentials -> AuthenticationError", anon_ops)

failed = [c for c in checks if not c["ok"]]
print(json.dumps({"sdk": "python", "checks": checks, "failed": len(failed)}))
sys.exit(1 if failed else 0)
