"""SDK smoke test against a RUNNING gateway: the Python SDK (sdk/python) end to end.

Env: QODIQA_BASE_URL, QODIQA_SIGN_TOKEN (sk_...), QODIQA_API_KEY (ok_...). Prints one line per check; exits 1 if any failed.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[5] / "sdk" / "python"))

import qodiqa  # noqa: E402
from qodiqa.exceptions import AuthenticationError  # noqa: E402

base = os.environ["QODIQA_BASE_URL"]
results = []


def check(name, fn):
    try:
        results.append(("PASS", name, fn() or ""))
    except Exception as e:  # noqa: BLE001
        results.append(("FAIL", name, repr(e)[:200]))


c = qodiqa.QodiqaClient(base_url=base, api_key=os.environ["QODIQA_API_KEY"], sign_token=os.environ["QODIQA_SIGN_TOKEN"], max_retries=1, timeout=20)
state = {}


def health():
    c.health_check()
    r = c.readiness_check()
    assert (r.get("ready") if isinstance(r, dict) else getattr(r, "ready", False)), "not ready"


def keys():
    state["keys"] = c.get_public_keys()
    ks = state["keys"]["keys"] if isinstance(state["keys"], dict) else state["keys"].keys
    assert ks, "no keys"
    return f"{len(ks)} keys"


def sign():
    s = c.sign.sign({"request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "py sdk"}}, "payload": {"userId": "smoke-py"}, "ttl": 60000})
    state["artifact"] = s["artifact"]
    state["b64"] = base64.b64encode(json.dumps(state["artifact"], separators=(",", ":")).encode()).decode()
    return s["artifactId"]


def verify():
    ks = state["keys"]["keys"] if isinstance(state["keys"], dict) else state["keys"].keys
    provider = qodiqa.StaticKeyProvider([{"keyId": k["keyId"], "algorithm": k["algorithm"], "publicKey": k["publicKey"], "status": k["status"]} for k in ks])
    v = qodiqa.verify_artifact(state["artifact"], keys=provider, clock_tolerance_ms=5000)
    assert v.verification_status == "valid", f"{v.verification_status} {v.failed_stage}"
    return "valid"


def binding():
    assert state["artifact"]["payload"]["requestHash"] == qodiqa.request_hash("POST", "/ai/chat", {"prompt": "py sdk"}), "requestHash differs"


def chat():
    r = c.chat.create(state["b64"], {"prompt": "py sdk"})
    text = r.get("aiText") or r.get("response")
    assert r["decision"] == "EXECUTE" and str(text).startswith("[sandbox] py sdk"), str(r)[:200]
    return text


def replay():
    try:
        r = c.chat.create(state["b64"], {"prompt": "py sdk"})
        assert r.get("decision") == "BLOCK", "replay accepted"
        return r.get("reason")
    except qodiqa.QodiqaError as e:
        return getattr(e, "reason", str(e))


def generic():
    assert c.operations.list_alerts() is not None
    return "ok"


def autherr():
    bad = qodiqa.QodiqaClient(base_url=base, sign_token="sk_" + "0" * 64, max_retries=0)
    try:
        bad.sign.sign({"request": {"method": "POST", "path": "/ai/chat", "body": {}}})
    except AuthenticationError:
        return "AuthenticationError"
    raise AssertionError("no AuthenticationError")


for name, fn in [("health + ready", health), ("public keys", keys), ("sign", sign), ("offline verification of the artifact against /public-keys", verify), ("request hash binding (artifact guard input)", binding),
                 ("chat through the sandbox provider", chat), ("replay of the same artifact is refused", replay), ("generic operation: client.operations.list_alerts (operator key)", generic),
                 ("error mapping: a wrong signing key is an AuthenticationError", autherr)]:
    check(name, fn)
for s, n, d in results:
    print(f"{s}  py: {n}" + (f"  ({str(d)[:80]})" if d else ""))
sys.exit(1 if any(s == "FAIL" for s, _, _ in results) else 0)
