"""independent CROSS-LANGUAGE verifier for docs/protocol/vectors/qodiqa-protocol-vectors.json.

Runs in Python with no QODIQA server code: canonicalization comes from the canonical Python SDK's own
implementation (qodiqa._verification._canonical_json — a separate implementation from the server's JavaScript
stableStringify), hashing from hashlib and Ed25519 from `cryptography`. It re-derives every canonical form, domain hash,
envelope hash, signature verification, request hash and policy hash in the vector file, and re-implements the artifact
verification procedure (docs/protocol/QODIQA-PROTOCOL.md §4). Agreement shows the protocol is reproducible from the
specification in another language — and that the Python SDK canonicalizes exactly like the server.

    sdk/python/.venv/Scripts/python.exe scripts/protocol/verify_vectors.py [vectors.json]     exit 1 on any mismatch
"""

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

HERE = os.path.dirname(os.path.abspath(__file__))
# always verify against THIS repository's SDK canonicalizer, never whatever `qodiqa` package happens to be
# installed (an unrelated or older install made the verifier fail, or silently check a different implementation).
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "sdk", "python")))

from qodiqa._verification._canonical_json import stable_stringify as canonicalize  # noqa: E402
import qodiqa._verification._canonical_json as _canon_module  # noqa: E402

if not os.path.normcase(os.path.abspath(_canon_module.__file__)).startswith(
        os.path.normcase(os.path.normpath(os.path.join(HERE, "..", "..", "sdk", "python")))):
    sys.exit("verify_vectors: imported a qodiqa canonicalizer outside this repository: " + _canon_module.__file__)

FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "docs", "protocol", "vectors", "qodiqa-protocol-vectors.json")
with open(FILE, "r", encoding="utf-8") as fh:
    V = json.load(fh)

results, failures = [], []


def rec(section, name, ok, detail=None):
    results.append((section, name, ok))
    if not ok:
        failures.append({"section": section, "name": name, "detail": detail})


def domain_hash(tag, canonical):
    return hashlib.sha256(tag.encode("utf-8") + canonical.encode("utf-8")).hexdigest()


def pub(spki_b64):
    return load_der_public_key(base64.b64decode(spki_b64))


def verify_sig(key, digest_hex, sig_b64):
    try:
        key.verify(base64.b64decode(sig_b64), bytes.fromhex(digest_hex))
        return True
    except InvalidSignature:
        return False


# §1 canonicalization (valid inputs; the error constructs are language-specific values, verified by the Node verifier).
# The Python SDK REFUSES non-integer floats by design (cross-language parity policy, qodiqa/_verification/_canonical_json.py);
# protocol §1.3: artifacts and request bodies carry no non-integer numbers. A vector containing one must be refused with
# CanonicalizationError (counted separately); any other error, or acceptance, is a failure.
from qodiqa._verification._canonical_json import CanonicalizationError  # noqa: E402


def has_float(x):
    if isinstance(x, bool):
        return False
    if isinstance(x, float):
        return not x.is_integer()
    if isinstance(x, list):
        return any(has_float(i) for i in x)
    if isinstance(x, dict):
        return any(has_float(i) for i in x.values())
    return False


for v in V["canonicalization"]["valid"]:
    if has_float(v["input"]):
        try:
            canonicalize(v["input"])
            rec("canonicalization.sdkFloatPolicy", v["name"], False, "a non-integer float was accepted")
        except CanonicalizationError:
            rec("canonicalization.sdkFloatPolicy", v["name"], True)
        continue
    c = canonicalize(v["input"])
    rec("canonicalization", v["name"], c == v["canonical"], {"python": c, "production": v["canonical"]})

# §3 domain tags
for t in V["domainTags"]["tags"]:
    rec("domainTags", t["tag"], domain_hash(t["tag"], V["domainTags"]["sampleCanonical"]) == t["digestHex"])

# §2 artifacts
ARTIFACT_TAG = "QODIQA::ARTIFACT::V1"
SIGNER = pub(V["testKeys"]["signerPublicKeySpkiB64"])


def envelope_canonical(a):
    return canonicalize({"expiry": a["expiry"], "payload": a["payload"], "publicKeyId": a["publicKeyId"], "timestamp": a["timestamp"]})


for a in V["artifacts"]:
    c = envelope_canonical(a["artifact"])
    h = domain_hash(ARTIFACT_TAG, c)
    rec("artifacts", a["name"], c == a["envelopeCanonical"] and h == a["envelopeHashHex"] and verify_sig(SIGNER, h, a["artifact"]["signature"]))

# §4 verification — independent decision procedure
KEYS = {k["publicKeyId"]: (pub(k["publicKeySpkiB64"]), k["timeline"]) for k in V["verification"]["keys"]}
L = V["verification"]["limits"]
FIELDS = {"expiry", "payload", "publicKeyId", "signature", "timestamp"}
SIG_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")


def iso_ms(s):
    return None if not s else int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def decide(a, now):
    def block(r):
        return ("BLOCK", r)
    if not isinstance(a, dict) or set(a.keys()) != FIELDS or not isinstance(a["payload"], dict):
        return block("INVALID_ARTIFACT")
    for f in ("timestamp", "expiry"):
        # positive safe integers (an integral float is the same JSON number as the integer in JavaScript)
        if isinstance(a[f], bool) or not isinstance(a[f], (int, float)) or a[f] <= 0 or a[f] != int(a[f]) or a[f] > 2**53 - 1:
            return block("INVALID_ARTIFACT")
    if not isinstance(a["signature"], str):
        return block("INVALID_ARTIFACT")
    if not SIG_RE.match(a["signature"]) or base64.b64encode(base64.b64decode(a["signature"])).decode() != a["signature"]:
        return block("INVALID_SIGNATURE")
    if not isinstance(a["publicKeyId"], str) or not a["publicKeyId"].strip():
        return block("INVALID_ARTIFACT")
    key = KEYS.get(a["publicKeyId"])
    if key is None or not verify_sig(key[0], domain_hash(ARTIFACT_TAG, envelope_canonical(a)), a["signature"]):
        return block("INVALID_SIGNATURE")
    if a["timestamp"] >= a["expiry"]:  # timestamp < expiry, after the signature
        return block("INVALID_ARTIFACT")
    if a["timestamp"] > now + L["futureSkewMs"]:
        return block("FUTURE_TIMESTAMP")
    if now >= a["expiry"]:
        return block("EXPIRED")
    if now - a["timestamp"] > L["maxArtifactAgeMs"]:
        return block("TIME_SKEW_EXCEEDED")
    t = key[1] or {}
    st = t.get("status")
    if st == "revoked":
        return block("KEY_REVOKED")
    if st == "archived":
        return block("KEY_ARCHIVED")
    if st == "deprecated":
        dep = iso_ms(t.get("deprecatedAt"))
        if dep is None or a["timestamp"] >= dep or now >= dep + L["deprecatedWindowMs"]:
            return block("KEY_DEPRECATED")
        return ("EXECUTE", "ALL_CHECKS_PASSED")
    if st == "active":
        act = iso_ms(t.get("activatedAt"))
        if act is not None and a["timestamp"] < act - L["futureSkewMs"]:
            return block("KEY_NOT_YET_ACTIVE")
        return ("EXECUTE", "ALL_CHECKS_PASSED")
    return block("KEY_STATUS_UNKNOWN")


for c in V["verification"]["cases"]:
    d = decide(c["artifact"], V["verification"]["nowMs"])
    rec("verification", c["name"], d == (c["expected"]["decision"], c["expected"]["reason"]), {"python": d, "production": c["expected"]})

# §5 request binding
REQUEST_TAG = "QODIQA::REQUEST::V1"
UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)


def req_canonical(r):
    return canonicalize({"body": r["body"], "method": r["method"].upper(), "path": r["path"]})


for r in V["requestBinding"]["hashes"]:
    c = req_canonical(r["request"])
    rec("requestBinding.hash", r["name"], c == r["canonical"] and domain_hash(REQUEST_TAG, c) == r["requestHashHex"])
for b in V["requestBinding"]["binding"]:
    p = b["artifactPayload"]
    bound = bool(UUID_V4.match(p.get("requestId") or "")) and bool(re.fullmatch(r"[0-9a-f]{64}", p.get("requestHash") or "")) \
        and domain_hash(REQUEST_TAG, req_canonical(b["request"])) == p["requestHash"]
    rec("requestBinding.binding", b["name"], bound == b["expected"]["bound"])


# §6 policy hash
def strip(v):
    if isinstance(v, list):
        return [strip(x) for x in v]
    if isinstance(v, dict):
        return {k: strip(x) for k, x in v.items() if not k.startswith("_") or k == "__proto__"}
    return v


for c in V["policyHash"]["cases"]:
    rec("policyHash", c["name"], domain_hash("QODIQA::POLICY::V1", canonicalize(strip(c["policies"]))) == c["policyHashHex"])

by_section = {}
for s, _, _ in results:
    by_section[s] = by_section.get(s, 0) + 1
print(json.dumps({"verifier": "python", "checks": len(results), "failed": len(failures), "bySection": by_section, "failures": failures}, indent=2, ensure_ascii=False))
sys.exit(1 if failures else 0)
