#!/usr/bin/env python3
"""INDEPENDENT Python verifier for the downloadable proof `qodiqa-proof/1` (docs/protocol/VECTORS-FORMAT.md section 3) and for single audit entries
canonical form (with the ECMAScript Number::toString rule, since Python's repr
differs from it), entry hash and shape (schema versions 1-8), the artifact signature over its envelope hash, the RFC 6962 transparency leaf and
root, the signed checkpoint, the signed receipt, the lifecycle of the request and the contiguous chain path to a checkpoint head.

Standard library only; Ed25519 verification is pure Python (RFC 8032). Nothing is imported from the gateway or from the Node verifier: this is a
third implementation next to them, and a disagreement is a defect in the specification text or in one implementation, never settled by editing
a vector. The helper blocks between the markers below (canonical form, Ed25519, receipt) are shared verbatim with scripts/protocol/verify_v2_vectors.py.

    python scripts/audit-repro/verify/qodiqa_proof_verify.py --proof proof.json [--artifact artifact.json] [--anchors-repo DIR [--require-signed]]
    python scripts/audit-repro/verify/qodiqa_proof_verify.py --vectors docs/protocol/vectors/audit-v8.json docs/protocol/vectors/audit-proof.json
    exit 0 VALID, 3 VALID_PARTIAL, 1 INVALID, 2 usage / input error
"""

import base64
import calendar
import hashlib
import json
import os
import re
import subprocess
import sys

MAX_SAFE = 9007199254740991


# ══ shared helper blocks (verbatim from scripts/protocol/verify_v2_vectors.py) ══

def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")




def es_number(v):
    """ECMAScript Number::toString for a finite double (RFC 8785 section 3.2.2.3)."""
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:e([+-]\d+))?", repr(abs(v)))
    int_part, frac, exp = m.group(1), m.group(2) or "", int(m.group(3) or 0)
    combined = int_part + frac
    stripped = len(combined) - len(combined.lstrip("0"))
    digits = combined.lstrip("0").rstrip("0")
    n = len(int_part) + exp - stripped          # the value is 0.DIGITS x 10^n
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        body = digits + "e" + es if k == 1 else digits[0] + "." + digits[1:] + "e" + es
    return sign + body


def quote(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c == 8:
            out.append("\\b")
        elif c == 12:
            out.append("\\f")
        elif c == 10:
            out.append("\\n")
        elif c == 13:
            out.append("\\r")
        elif c == 9:
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def emit(node):
    kind = node[0]
    if kind == "lit":
        return "null" if node[1] is None else ("true" if node[1] else "false")
    if kind == "num":
        return es_number(node[1])
    if kind == "str":
        return quote(node[1])
    if kind == "arr":
        return "[" + ",".join(emit(x) for x in node[1]) + "]"
    members = sorted(node[1], key=lambda kv: utf16_key(kv[0]))
    return "{" + ",".join(quote(k) + ":" + emit(v) for k, v in members) + "}"




_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, (x * y) % _P)


def _add(P, Q):
    A = ((P[1] - P[0]) * (Q[1] - Q[0])) % _P
    B = ((P[1] + P[0]) * (Q[1] + Q[0])) % _P
    C = (2 * P[3] * Q[3] * _D) % _P
    D = (2 * P[2] * Q[2]) % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return ((E * F) % _P, (G * H) % _P, (F * G) % _P, (E * H) % _P)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _P == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


_GY = (4 * pow(5, _P - 2, _P)) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, (_GX * _GY) % _P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _Q
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))




_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")



RECEIPT_FIELDS = ("v", "requestId", "decision", "issuedAt", "entryHash", "leafHash", "keyId", "signature")


def from_value(v):
    """A parsed JSON value -> a tree for emit(). bool is checked before int (True is an int in Python)."""
    if v is None or isinstance(v, bool):
        return ("lit", v)
    if isinstance(v, (int, float)):
        return ("num", float(v))
    if isinstance(v, str):
        return ("str", v)
    if isinstance(v, list):
        return ("arr", [from_value(x) for x in v])
    return ("obj", [(k, from_value(x)) for k, x in v.items()])


def receipt_verdict(receipt, keys, trusted_at):
    if not isinstance(receipt, dict):
        return "NOT_AN_OBJECT"
    if sorted(receipt.keys()) != sorted(RECEIPT_FIELDS):
        return "FIELD_SET"
    v = receipt["v"]
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != 1:      # JSON 1 and 1.0 are the same number
        return "UNSUPPORTED_VERSION"

    def hex64(x):
        return isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) is not None

    ia = receipt["issuedAt"]
    if (not isinstance(receipt["requestId"], str) or receipt["requestId"] == "" or receipt["decision"] not in ("ALLOW", "BLOCK")
            or isinstance(ia, bool) or not isinstance(ia, (int, float)) or ia != int(ia) or ia < 0 or ia > MAX_SAFE
            or not hex64(receipt["entryHash"]) or not hex64(receipt["leafHash"])
            or not isinstance(receipt["keyId"], str) or receipt["keyId"] == "" or not isinstance(receipt["signature"], str) or receipt["signature"] == ""):
        return "INVALID_FIELD"
    key = next((k for k in keys if k["keyId"] == receipt["keyId"]), None)
    if key is None:
        return "UNKNOWN_KEY"
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    digest = hashlib.sha256(b"QODIQA::RECEIPT::V1" + emit(from_value(unsigned)).encode("utf-8")).digest()
    good = False
    try:
        sig = base64.b64decode(receipt["signature"], validate=True)
        spki = base64.b64decode(key["publicKeySpkiB64"], validate=True)
        if len(sig) == 64 and base64.b64encode(sig).decode() == receipt["signature"] and spki[:12] == _SPKI_PREFIX:
            good = ed25519_verify(spki[12:], digest, sig)
    except Exception:
        good = False
    if not good:
        return "BAD_SIGNATURE"
    if key.get("status") == "revoked" and not (isinstance(trusted_at, (int, float)) and isinstance(key.get("revokedAt"), (int, float)) and trusted_at < key["revokedAt"]):
        return "REVOKED_KEY"
    return None


# ══ the audit contract, from docs/protocol/AUDIT-SCHEMA-V8.md and (restated; nothing imported from the gateway) ══
AUDIT_DOMAIN = "QODIQA::AUDIT::V1"
V1 = ["artifactId", "decision", "inputHash", "policyHash", "prevHash", "publicKeyId", "requestHash", "schemaVersion", "signature", "timestamp", "verificationResult"]
# the hashed field lists are DATA of the contract; they are listed per version exactly as the contract states them
V2 = V1 + []
V3 = V2 + ["consentProvenance", "policyDecision"]
V4 = V3 + ["callerContext"]
V5 = V4 + ["provider", "model"]
V6 = V5 + ["stage", "reason", "semantic", "tokenUsage", "responseId"]
V7 = V6 + ["entryType", "outputHash", "tenantId", "requestId", "organizationId", "executionContext", "executingProvider"]
V8_NEW = ["issuedAt", "protocolVersion", "agentId", "sessionId", "actionSeq", "actionHash", "approvalRef", "dlp", "bytesDelivered", "completionStatus"]
V8 = V7 + V8_NEW
HASHED = {1: V1, 2: V2, 3: V3, 4: V4, 5: V5, 6: V6, 7: V7, 8: V8}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def none(v):
    return v is None


def emit_value(v):
    return emit(from_value(v))


def declared_version(entry):
    v = entry.get("schemaVersion")
    if v is None:
        return 1
    return v if isinstance(v, int) and not isinstance(v, bool) and v in HASHED else None


def expected_canonical(entry, version):
    core = {f: entry.get(f) for f in HASHED[version]}
    return emit_value(core)


def audit_hash(canonical):
    return hashlib.sha256(AUDIT_DOMAIN.encode("utf-8") + canonical.encode("utf-8")).hexdigest()


def is_int(v, minimum):
    return isinstance(v, int) and not isinstance(v, bool) and v >= minimum and v <= MAX_SAFE


def non_empty(v):
    return isinstance(v, str) and len(v) > 0


def hex64(v):
    return isinstance(v, str) and HEX64.match(v) is not None


COMPLETION = ["COMPLETE", "CANCELLED", "ERROR", "TIMEOUT", "CLIENT_DISCONNECTED", "OUTCOME_UNKNOWN"]
V7_LIFECYCLE_FIXED = {"INTENT": ("ALLOW", "PROVIDER_DISPATCH"), "STREAM_OPENED": ("ALLOW", "STREAM_OPENED")}
V8_OLD_MAY = {"DECISION": ["issuedAt", "protocolVersion", "completionStatus"], "INTENT": ["issuedAt", "protocolVersion"], "STREAM_OPENED": ["issuedAt", "protocolVersion"]}
# per NEW type: stage, {decision: reasons}, id suffix (or regex), outputHash carried, system entry, may, must, executionContext key
V8_NEW_TYPES = {
    "COMMIT": ("COMMIT", {"ALLOW": ["RESPONSE_DELIVERED", "RESPONSE_FAILED"]}, ":commit", True, False, ["issuedAt", "protocolVersion", "bytesDelivered", "completionStatus"], ["bytesDelivered", "completionStatus"], None),
    "ACTION_INTENT": ("ACTION_DISPATCH", {"ALLOW": ["ACTION_AUTHORIZED"]}, ":action_intent", False, False, ["issuedAt", "protocolVersion", "agentId", "sessionId", "actionSeq", "actionHash", "approvalRef"], ["agentId", "sessionId", "actionSeq", "actionHash"], "action"),
    "ACTION_COMMIT": ("ACTION_COMMIT", {"ALLOW": ["ACTION_COMPLETED", "ACTION_FAILED"]}, ":action_commit", True, False, ["issuedAt", "protocolVersion", "agentId", "sessionId", "actionSeq", "actionHash", "approvalRef", "completionStatus"], ["agentId", "sessionId", "actionSeq", "actionHash", "completionStatus"], "action"),
    "APPROVAL_REQUESTED": ("APPROVAL", {"BLOCK": ["APPROVAL_REQUIRED"]}, ":approval_requested", False, True, ["approvalRef", "actionHash"], ["approvalRef", "actionHash"], "approval"),
    "APPROVAL_DECIDED": ("APPROVAL", {"ALLOW": ["APPROVED"], "BLOCK": ["DENIED"]}, ":approval_decided", False, True, ["approvalRef", "actionHash"], ["approvalRef", "actionHash"], "approval"),
    "APPROVAL_EXPIRED": ("APPROVAL", {"BLOCK": ["APPROVAL_EXPIRED"]}, ":approval_expired", False, True, ["approvalRef", "actionHash"], ["approvalRef", "actionHash"], "approval"),
    "KILL_SWITCH": ("KILL_SWITCH", {"BLOCK": ["KILL_SWITCH_ON"], "ALLOW": ["KILL_SWITCH_OFF"]}, ":kill_switch", False, True, [], [], "killSwitch"),
    "DLP_TRANSFORM": ("DLP", {"ALLOW": ["DLP_DETECT", "DLP_REDACT", "DLP_MASK"], "BLOCK": ["DLP_BLOCK"]}, re.compile(r":dlp_(in|out)_[0-9]+$"), False, True, ["dlp"], ["dlp"], None),
    "DELEGATION_ISSUED": ("DELEGATION", {"ALLOW": ["DELEGATION_ISSUED"]}, ":delegation_issued", False, True, [], [], "delegation"),
    "DELEGATION_REVOKED": ("DELEGATION", {"ALLOW": ["DELEGATION_REVOKED"]}, ":delegation_revoked", False, True, [], [], "delegation"),
}


def is_obj(v):
    return isinstance(v, dict)


def v8_field_valid(f, v):
    if f == "issuedAt":
        return is_int(v, 0)
    if f == "protocolVersion":
        return is_int(v, 1)
    if f in ("agentId", "sessionId", "approvalRef"):
        return non_empty(v)
    if f == "actionSeq":
        return is_int(v, 1)
    if f == "actionHash":
        return hex64(v)
    if f == "bytesDelivered":
        return is_int(v, 0)
    if f == "completionStatus":
        return v in COMPLETION
    if f == "dlp":
        return (is_obj(v) and isinstance(v.get("rules"), list) and all(non_empty(x) for x in v["rules"])
                and v.get("action") in ("DETECT", "REDACT", "BLOCK", "MASK") and hex64(v.get("inputHashBefore")) and hex64(v.get("inputHashAfter")))
    return False


def v7_shape(entry):
    if entry.get("schemaVersion") != 7:
        return None
    t = entry.get("entryType")
    if t not in ("DECISION", "INTENT", "STREAM_OPENED"):
        return "INVALID_ENTRY_TYPE"
    if t == "DECISION":
        return None if hex64(entry.get("outputHash")) else "INVALID_OUTPUT_HASH"
    if not none(entry.get("outputHash")):
        return "INVALID_ENTRY_SHAPE"
    return None if (entry.get("decision"), entry.get("stage")) == V7_LIFECYCLE_FIXED[t] else "INVALID_ENTRY_SHAPE"


def v8_shape(entry):
    if entry.get("schemaVersion") != 8:
        return None
    t = entry.get("entryType")
    old = V8_OLD_MAY.get(t)
    nu = V8_NEW_TYPES.get(t)
    if old is None and nu is None:
        return "INVALID_ENTRY_TYPE"
    may = old if old is not None else nu[5]
    for f in V8_NEW:
        v = entry.get(f)
        if none(v):
            continue
        if f not in may:
            return "INVALID_ENTRY_SHAPE"
        if not v8_field_valid(f, v):
            return "INVALID_V8_FIELD"
    if old is not None:
        if t == "DECISION":
            return None if hex64(entry.get("outputHash")) else "INVALID_OUTPUT_HASH"
        if not none(entry.get("outputHash")):
            return "INVALID_ENTRY_SHAPE"
        return None if (entry.get("decision"), entry.get("stage")) == V7_LIFECYCLE_FIXED[t] else "INVALID_ENTRY_SHAPE"
    stage, reasons_by, suffix, has_out, system, _may, must, ctx_key = nu
    if any(none(entry.get(f)) for f in must):
        return "INVALID_V8_FIELD"
    reasons = reasons_by.get(entry.get("decision"))
    if reasons is None or entry.get("reason") not in reasons or entry.get("stage") != stage:
        return "INVALID_ENTRY_SHAPE"
    if t == "DLP_TRANSFORM" and entry.get("reason") != "DLP_" + entry["dlp"]["action"]:
        return "INVALID_ENTRY_SHAPE"
    ident = entry.get("artifactId")
    if not isinstance(ident, str):
        return "INVALID_ENTRY_SHAPE"
    if hasattr(suffix, "search"):
        id_ok = suffix.search(ident) is not None
    else:
        id_ok = ident.endswith(suffix) and len(ident) > len(suffix)
    if not id_ok:
        return "INVALID_ENTRY_SHAPE"
    if (not hex64(entry.get("outputHash"))) if has_out else (not none(entry.get("outputHash"))):
        return "INVALID_OUTPUT_HASH"
    if entry.get("verificationResult") is not (not system):
        return "INVALID_ENTRY_SHAPE"
    if system and entry.get("signature") != "SYSTEM":
        return "INVALID_ENTRY_SHAPE"
    if entry.get("inputHash") != "UNAVAILABLE" or entry.get("requestHash") != "UNAVAILABLE" or entry.get("policyHash") != "UNAVAILABLE":
        return "INVALID_ENTRY_SHAPE"
    for f in ("publicKeyId", "provider", "model", "executingProvider", "semantic", "tokenUsage", "responseId", "consentProvenance", "policyDecision", "callerContext"):
        if not none(entry.get(f)):
            return "INVALID_ENTRY_SHAPE"
    ctx = entry.get("executionContext")
    if ctx_key is None:
        return None if none(ctx) else "INVALID_ENTRY_SHAPE"
    return None if (is_obj(ctx) and is_obj(ctx.get(ctx_key))) else "INVALID_ENTRY_SHAPE"


def check_entry_hash(entry):
    """-> None when the entry is sound, else the failure code (the first failing rule)."""
    version = declared_version(entry)
    if version is None:
        return "UNSUPPORTED_SCHEMA_VERSION"
    canonical = entry.get("canonical")
    if not isinstance(canonical, str):
        return "CANONICAL_MISSING"
    if audit_hash(canonical) != entry.get("hash"):
        return "HASH_MISMATCH"
    if expected_canonical(entry, version) != canonical:
        return "CANONICAL_FIELD_MISMATCH"
    return v7_shape(entry) or v8_shape(entry)


# ══ the artifact, the transparency log, the checkpoint (QODIQA-PROTOCOL.md 3.2; transparency / checkpoint contracts) ══
def b64_canonical(text):
    """The 64-byte signature of a canonical standard base64 text (88 characters, round-trip exact) or None."""
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        return None
    return raw if len(raw) == 64 and len(text) == 88 and base64.b64encode(raw).decode() == text else None


def spki_key(b64):
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    return raw[12:] if len(raw) == 44 and raw[:12] == _SPKI_PREFIX else None


def verify_sig(digest, sig_text, spki_b64):
    """-> (ok, canonical_encoding)"""
    if not isinstance(sig_text, str) or not isinstance(spki_b64, str):
        return False, False
    raw = b64_canonical(sig_text)
    canonical = raw is not None
    if raw is None:
        try:
            raw = base64.b64decode(sig_text, validate=True)
        except Exception:
            return False, False
        if len(raw) != 64:
            return False, False
    key = spki_key(spki_b64)
    if key is None:
        return False, canonical
    return ed25519_verify(key, digest, raw), canonical


def envelope_hash(a):
    env = {"expiry": a.get("expiry"), "payload": a.get("payload"), "publicKeyId": a.get("publicKeyId"), "timestamp": a.get("timestamp")}
    return hashlib.sha256(b"QODIQA::ARTIFACT::V1" + emit_value(env).encode("utf-8")).digest()


T_ENTRY_FIELDS = ["transparencyId", "entryType", "artifactId", "evidenceChainId", "verificationId", "payloadHash", "previousEntryHash", "signerKeyId"]
T_ROOT_FIELDS = ["rootId", "seqFrom", "seqTo", "entryCount", "rootHash", "previousRootHash"]


def t_entry_hash(rec):
    return hashlib.sha256(b"QODIQA::TRANSPARENCY::V1" + emit_value({f: rec.get(f) for f in T_ENTRY_FIELDS}).encode("utf-8")).hexdigest()


def t_root_digest(rec):
    return hashlib.sha256(b"QODIQA::TRANSPARENCY_ROOT::V1" + emit_value({f: rec.get(f) for f in T_ROOT_FIELDS}).encode("utf-8")).digest()


def t_payload_hash(payload):
    return hashlib.sha256(emit_value(payload if payload is not None else {}).encode("utf-8")).hexdigest()


def m_leaf(hex_text):
    return hashlib.sha256(b"\x00" + bytes.fromhex(hex_text)).digest()


def m_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def expected_path_sides(index, size):
    if not (isinstance(index, int) and isinstance(size, int)) or isinstance(index, bool) or isinstance(size, bool) or index < 0 or index >= size:
        return None
    sides = []
    while size > 1:
        k = 1
        while k * 2 < size:
            k *= 2
        if index < k:
            sides.append("right")
            size = k
        else:
            sides.append("left")
            index -= k
            size -= k
    sides.reverse()
    return sides


def verify_inclusion(entry_hash, path, root_hex, index, size):
    if not isinstance(path, list):
        return False
    sides = expected_path_sides(index, size)
    if sides is None or len(path) != len(sides) or any((not isinstance(s, dict)) or s.get("side") != sides[i] for i, s in enumerate(path)):
        return False
    try:
        cur = m_leaf(entry_hash)
        for step in path:
            sib = bytes.fromhex(step["hash"])
            cur = m_node(cur, sib) if step["side"] == "right" else m_node(sib, cur)
    except Exception:
        return False
    return cur.hex() == root_hex


def merkle_root(hashes):
    leaves = [m_leaf(h) for h in hashes]

    def sub(items):
        if len(items) == 1:
            return items[0]
        k = 1
        while k * 2 < len(items):
            k *= 2
        return m_node(sub(items[:k]), sub(items[k:]))
    return sub(leaves).hex()


CP_FIELDS = ["v", "checkpointId", "createdAt", "chainLength", "headHash", "pgSeq", "evidenceHead", "transparencyAnchor", "previousCheckpointHash", "keyId", "keyVersion"]


def checkpoint_reason(signed, key_by_id):
    """-> None when the signed checkpoint verifies, else the reason (the first failing rule)"""
    if not is_obj(signed) or not is_obj(signed.get("payload")) or not isinstance(signed.get("signature"), str):
        return "CHECKPOINT_MALFORMED"
    p = signed["payload"]
    if p.get("v") != 1:
        return "CHECKPOINT_UNSUPPORTED_VERSION"
    for f in CP_FIELDS:
        if f not in p:
            return "CHECKPOINT_FIELD_MISSING:" + f
    if any(k not in CP_FIELDS for k in p):
        return "CHECKPOINT_UNKNOWN_FIELD"
    chain_length = p.get("chainLength")
    if isinstance(chain_length, float) and chain_length == int(chain_length) and abs(chain_length) <= MAX_SAFE:
        chain_length = int(chain_length)          # JSON has one number type: 50.0 is the integer 50 (as in JavaScript)
    if not (isinstance(chain_length, int) and not isinstance(chain_length, bool) and chain_length >= 1) or not hex64(p.get("headHash")):
        return "CHECKPOINT_POSITION_INVALID"
    digest = hashlib.sha256(b"QODIQA::AUDIT_CHECKPOINT::V1" + emit_value({f: p.get(f) for f in CP_FIELDS}).encode("utf-8")).digest()
    if signed.get("payloadHash") != digest.hex():
        return "CHECKPOINT_PAYLOAD_HASH_MISMATCH"
    key_id = p.get("keyId")
    k = key_by_id.get(key_id)
    if k is None:
        return "CHECKPOINT_KEY_UNKNOWN:%s" % key_id
    if str(k.get("status") or "").lower() == "revoked":
        return "CHECKPOINT_KEY_REVOKED:%s" % key_id
    ok, _canon = verify_sig(digest, signed["signature"], k.get("publicKeySpkiB64"))
    return None if ok else "CHECKPOINT_SIGNATURE_INVALID"


# ══ "trust from the anchor": keys and checkpoints from the ANCHORS REPOSITORY (see scripts/audit-repro/verify/anchorTrust.js for the format) ══
ANCHOR_DOMAIN = b"QODIQA::EXTERNAL_ANCHOR::V1"
STATEMENT_KEYS = sorted(["v", "checkpointId", "payloadHash", "chainLength", "headHash", "createdAt"])


def _no_constant(name):
    raise ValueError("non-finite JSON constant " + name)


def _loads(text):
    return json.loads(text, parse_constant=_no_constant)


def _git(d, args):
    r = subprocess.run(["git", "-C", d] + args, capture_output=True)   # bytes: universal-newline translation would hide a CRLF
    return (r.returncode == 0), r.stdout.decode("utf-8", errors="replace")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _iso_ms(text):
    """milliseconds of an ISO-8601 UTC timestamp as written by the gateway (YYYY-MM-DDTHH:MM:SS(.mmm)Z); unparseable sorts as 0"""
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z", text or "")
    if not m:
        return 0

    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    return (calendar.timegm((y, mo, d, h, mi, se)) * 1000) + int((m.group(7) or "0").ljust(3, "0"))


def check_anchor_line(line):
    """one line of anchors/<date>.jsonl -> (None, record) or (code, None); code is ANCHOR_LINE_MALFORMED or ANCHOR_DIGEST_MISMATCH"""
    if line.endswith("\r"):
        return "ANCHOR_LINE_MALFORMED", None
    try:
        rec = _loads(line)
    except Exception:
        return "ANCHOR_LINE_MALFORMED", None
    st = rec.get("statement") if is_obj(rec) else None
    if is_obj(st) and isinstance(st.get("chainLength"), float) and st["chainLength"] == int(st["chainLength"]) and abs(st["chainLength"]) <= MAX_SAFE:
        st = dict(st, chainLength=int(st["chainLength"]))      # JSON has one number type: 50.0 is the integer 50 (as in JavaScript)
    if (not is_obj(st) or sorted(st.keys()) != STATEMENT_KEYS or st.get("v") != 1 or not isinstance(st.get("checkpointId"), str) or not re.fullmatch(r"[\x21-\x7e]{1,256}", st["checkpointId"])
            or not hex64(st.get("payloadHash")) or not hex64(st.get("headHash")) or not _is_int(st.get("chainLength")) or st["chainLength"] < 1
            or st["chainLength"] > MAX_SAFE or not isinstance(st.get("createdAt"), str)
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z", st["createdAt"])):
        return "ANCHOR_LINE_MALFORMED", None
    if rec.get("digest") != hashlib.sha256(ANCHOR_DOMAIN + emit_value(st).encode("utf-8")).hexdigest():
        return "ANCHOR_DIGEST_MISMATCH", None
    return None, dict(rec, statement=st)


def load_anchor_repo(d, require_signed=False):
    """-> {statements, keys:{checkpoint,transparency}, findings:[{code,detail}], commits}"""
    out = {"statements": [], "keys": {"checkpoint": [], "transparency": []}, "findings": [], "commits": 0}

    def f(code, detail):
        out["findings"].append({"code": code, "detail": detail})

    if not d or not os.path.exists(d):
        f("ANCHOR_REPO_UNREADABLE", "%s does not exist" % d)
        return out
    ok, _ = _git(d, ["rev-parse", "--git-dir"])
    if not ok:
        f("ANCHOR_REPO_NOT_GIT", "%s is not a git working tree" % d)
        return out
    ok, head = _git(d, ["rev-parse", "HEAD"])
    if not ok or not head.strip():
        f("ANCHOR_REPO_UNREADABLE", "the repository has no commits")
        return out
    ok, dirty = _git(d, ["status", "--porcelain", "--", "anchors", "keys"])
    if ok and dirty.strip():
        f("ANCHOR_REPO_DIRTY", "; ".join(dirty.strip().split("\n")[:5]))

    def listing(sub, ext):
        ok2, out2 = _git(d, ["ls-tree", "-r", "--name-only", "HEAD", "--", sub])
        return sorted(x for x in out2.split("\n") if ok2 and x.startswith(sub + "/") and x.endswith(ext))

    def head_file(rel):
        ok2, out2 = _git(d, ["show", "HEAD:" + rel])
        return out2 if ok2 else None

    anchor_files, key_files, touched = listing("anchors", ".jsonl"), listing("keys", ".json"), set()
    ok, merges = _git(d, ["rev-list", "--merges", "HEAD"])
    if ok and merges.strip():
        f("ANCHOR_HISTORY_REWRITTEN", "the history contains merge commit(s): an anchors repository must be linear")
    ok, ever = _git(d, ["log", "--full-history", "--name-only", "--format=", "--", "anchors", "keys"])
    if ok:
        for p in sorted(set(x for x in ever.split("\n") if x)):
            if re.fullmatch(r"anchors/[^/]+\.jsonl|keys/[^/]+\.json", p) and p not in anchor_files and p not in key_files:
                f("ANCHOR_HISTORY_REWRITTEN", "%s existed in the history and is gone at HEAD (deleted or renamed)" % p)
    for rel in anchor_files + key_files:
        ok, log = _git(d, ["log", "--reverse", "--full-history", "--format=%H", "--", rel])
        commits = [c for c in log.split("\n") if c] if ok else []
        prev = None
        for c in commits:
            touched.add(c)
            ok, shown = _git(d, ["show", "%s:%s" % (c, rel)])
            if not ok:
                continue
            if prev is not None:
                if rel.endswith(".jsonl"):
                    a = [x for x in prev.split("\n") if x]
                    b = [x for x in shown.split("\n") if x]
                    if len(a) > len(b) or any(x != b[i] for i, x in enumerate(a)):
                        f("ANCHOR_HISTORY_REWRITTEN", "%s at %s is not an extension of the previous version" % (rel, c[:12]))
                else:
                    try:
                        pa = dict((k["keyId"], k) for k in _loads(prev)["keys"])
                        nb = dict((k["keyId"], k) for k in _loads(shown)["keys"])
                        for kid, k in pa.items():
                            n = nb.get(kid)
                            if n is None or n["publicKey"] != k["publicKey"]:
                                f("ANCHOR_HISTORY_REWRITTEN", "%s at %s: key %s was removed or changed" % (rel, c[:12], kid))
                            elif str(k.get("status")).lower() == "revoked" and str(n.get("status")).lower() != "revoked":
                                f("ANCHOR_HISTORY_REWRITTEN", "%s at %s: key %s was revoked and is no longer" % (rel, c[:12], kid))
                    except Exception:
                        f("KEYS_MALFORMED", "%s at %s is not valid JSON" % (rel, c[:12]))
            prev = shown
    out["commits"] = len(touched)
    if require_signed:
        for c in touched:
            if not _git(d, ["verify-commit", c])[0]:
                f("ANCHOR_COMMIT_UNSIGNED", "commit %s has no valid signature" % c[:12])
    for rel in anchor_files:
        lines = (head_file(rel) or "").split("\n")
        for i, line in enumerate(lines):
            if not line.strip():
                continue
            code, rec = check_anchor_line(line)
            if code is not None:
                f(code, "%s:%d" % (rel, i + 1))
                continue
            st = rec["statement"]
            out["statements"].append({"digest": rec["digest"], "statement": st, "file": rel, "line": i + 1})
    by_pos, prev = {}, None
    for a in out["statements"]:
        st = a["statement"]
        seen = by_pos.get(st["chainLength"])
        if seen is not None and seen["headHash"] != st["headHash"]:
            f("ANCHOR_FORK", "position %d is anchored with two heads" % st["chainLength"])
        by_pos[st["chainLength"]] = st
        if prev is not None and (st["chainLength"] < prev["chainLength"] or _iso_ms(st["createdAt"]) < _iso_ms(prev["createdAt"])):
            f("ANCHORS_NOT_MONOTONIC", "%s (%d) after %s (%d)" % (st["checkpointId"], st["chainLength"], prev["checkpointId"], prev["chainLength"]))
        prev = st
    for name, slot in (("checkpoint-keys.json", "checkpoint"), ("transparency-keys.json", "transparency")):
        text = head_file("keys/" + name)
        if text is None:
            continue
        try:
            doc = _loads(text)
            if not is_obj(doc) or doc.get("v") != 1 or not isinstance(doc.get("keys"), list) or not all(
                    is_obj(k) and isinstance(k.get("keyId"), str) and isinstance(k.get("publicKey"), str) and isinstance(k.get("status"), str) for k in doc["keys"]):
                raise ValueError("shape")
            out["keys"][slot] = doc["keys"]
        except Exception:
            f("KEYS_MALFORMED", "keys/%s is not of this format" % name)
    return out


def anchor_trust_checks(doc, repo, ok_, bad, partial):
    """evaluation of the proof against the anchors repository. -> True when the proof's entries are anchored"""
    if repo["findings"]:
        for x in repo["findings"]:
            bad("ANCHOR_REPO", x["code"])
        return False
    if not repo["statements"]:
        partial.append("ANCHORS_EMPTY")
        return False
    ok_("ANCHOR_REPO")
    cp = doc.get("checkpoint") if is_obj(doc.get("checkpoint")) else None
    if cp is None:
        partial.append("CHECKPOINT_ABSENT")
        return False
    anchored_keys = dict((k["keyId"], k) for k in repo["keys"]["checkpoint"] + repo["keys"]["transparency"])
    proof_keys = doc.get("keys") if isinstance(doc.get("keys"), list) else []
    differs = [k.get("keyId") for k in proof_keys if is_obj(k) and k.get("keyId") in anchored_keys and anchored_keys[k["keyId"]]["publicKey"] != k.get("publicKeySpkiB64")]
    if differs:
        bad("ANCHOR_KEYS", "PROOF_KEY_DIFFERS_FROM_ANCHORED")
    else:
        ok_("ANCHOR_KEYS")
    by_id = dict((k["keyId"], {"publicKeySpkiB64": k["publicKey"], "status": k["status"]}) for k in repo["keys"]["checkpoint"])
    reason = checkpoint_reason(cp, by_id)
    if reason is not None:
        bad("ANCHOR_CHECKPOINT_SIGNATURE", reason)
        return False
    ok_("ANCHOR_CHECKPOINT_SIGNATURE")
    p = cp["payload"]
    direct = next((a for a in repo["statements"] if a["statement"]["payloadHash"] == cp.get("payloadHash")), None)
    same_pos = next((a for a in repo["statements"] if a["statement"]["chainLength"] == p.get("chainLength")), None)
    path = doc.get("chainPath") if isinstance(doc.get("chainPath"), list) else []
    idx = dict((e.get("hash"), i) for i, e in enumerate(path) if is_obj(e))
    if direct is not None:
        st = direct["statement"]
        if (st["checkpointId"] != p.get("checkpointId") or st["chainLength"] != p.get("chainLength") or st["headHash"] != p.get("headHash")
                or st["createdAt"] != p.get("createdAt")):
            bad("CHECKPOINT_ANCHORED", "ANCHOR_STATEMENT_MISMATCH")
            return False
        ok_("CHECKPOINT_ANCHORED")
        return True
    if same_pos is not None and same_pos["statement"]["headHash"] != p.get("headHash"):
        bad("CHECKPOINT_ANCHORED", "CHECKPOINT_FORKS_ANCHOR")
        return False
    entries = doc.get("auditEntries") if isinstance(doc.get("auditEntries"), list) else []
    entry_idx = [idx.get(e.get("hash")) for e in entries if is_obj(e)]
    last = max(entry_idx) if entry_idx and all(i is not None for i in entry_idx) else None
    cover = None
    if last is not None:
        cover = next((a for a in repo["statements"] if a["statement"]["headHash"] in idx and idx[a["statement"]["headHash"]] >= last), None)
    if cover is not None:
        ok_("CHECKPOINT_ANCHORED")
        return True
    partial.append("CHECKPOINT_NOT_COVERED_BY_ANCHOR")
    return False


# ══ the proof (docs/protocol/VECTORS-FORMAT.md section 3) ══
ARTIFACT_KEYS = sorted(["expiry", "payload", "publicKeyId", "signature", "timestamp"])
NOT_A_SIGNATURE = ("UNAVAILABLE", "SYSTEM")
RANK = {"INTENT": 0, "STREAM_OPENED": 1, "DECISION": 2, "COMMIT": 3}


def entry_type_of(e):
    return e.get("entryType") if isinstance(e.get("schemaVersion"), int) and e.get("schemaVersion") >= 7 else "DECISION"


def verify_proof(doc, anchor_repo=None):
    checks, failed, partial = [], [], []

    def ok_(i):
        checks.append({"id": i, "ok": True})

    def bad(i, code):
        checks.append({"id": i, "ok": False})
        failed.append({"id": i, "code": code})

    def done():
        return {"verdict": "INVALID" if failed else ("VALID_PARTIAL" if partial else "VALID"), "checks": checks, "failed": failed, "partial": partial}

    if not is_obj(doc):
        bad("FORMAT", "NOT_AN_OBJECT")
        return done()
    if doc.get("format") != "qodiqa-proof/1":
        bad("FORMAT", "UNKNOWN_FORMAT")
        return done()
    ok_("FORMAT")
    subject = doc.get("subject")
    request_id = subject.get("requestId") if is_obj(subject) else None
    if not (isinstance(request_id, str) and request_id):
        bad("SUBJECT", "SUBJECT_MISSING")
        return done()
    ok_("SUBJECT")
    keys = doc.get("keys")
    if not (isinstance(keys, list) and all(is_obj(k) and isinstance(k.get("keyId"), str) and isinstance(k.get("publicKeySpkiB64"), str) for k in keys)):
        bad("KEYS", "KEYS_MALFORMED")
        return done()
    ok_("KEYS")
    key_by_id = {k["keyId"]: k for k in keys}

    artifact = None
    a = doc.get("artifact")
    if a is None:
        partial.append("ARTIFACT_ABSENT")
    elif not is_obj(a) or sorted(a.keys()) != ARTIFACT_KEYS:
        bad("ARTIFACT_SHAPE", "ARTIFACT_SHAPE")
    else:
        ok_("ARTIFACT_SHAPE")
        key = key_by_id.get(a.get("publicKeyId"))
        if key is None:
            bad("ARTIFACT_SIGNATURE", "UNKNOWN_KEY")
        else:
            digest = None
            try:
                digest = envelope_hash(a)
            except Exception:
                bad("ARTIFACT_SIGNATURE", "ARTIFACT_NOT_CANONICALIZABLE")
            if digest is not None:
                good, canonical = verify_sig(digest, a.get("signature"), key.get("publicKeySpkiB64"))
                if not canonical:
                    bad("ARTIFACT_SIGNATURE", "SIGNATURE_NOT_CANONICAL")
                elif not good:
                    bad("ARTIFACT_SIGNATURE", "BAD_SIGNATURE")
                else:
                    ok_("ARTIFACT_SIGNATURE")
                    artifact = a
            t = a.get("timestamp")
            revoked, activated = key.get("revokedAt"), key.get("activatedAt")
            if isinstance(revoked, (int, float)) and not isinstance(revoked, bool) and t >= revoked:
                bad("ARTIFACT_KEY_WINDOW", "KEY_REVOKED_AT_ISSUE")
            elif isinstance(activated, (int, float)) and not isinstance(activated, bool) and t < activated:
                bad("ARTIFACT_KEY_WINDOW", "KEY_NOT_YET_ACTIVE")
            else:
                ok_("ARTIFACT_KEY_WINDOW")

    entries = doc.get("auditEntries")
    if not (isinstance(entries, list) and len(entries) > 0 and all(is_obj(e) for e in entries)):
        bad("ENTRY_HASH:0", "AUDIT_ENTRIES_MISSING")
        return done()
    entries_ok = True
    for i, e in enumerate(entries):
        r = check_entry_hash(e)
        if r is None:
            ok_("ENTRY_HASH:%d" % i)
        else:
            bad("ENTRY_HASH:%d" % i, r)
            entries_ok = False

    def owns(e):
        aid = e.get("artifactId")
        return e.get("requestId") == request_id or (isinstance(aid, str) and (aid == request_id or aid.startswith(request_id + ":")))

    if all(owns(e) for e in entries):
        ok_("ENTRY_REQUEST")
    else:
        bad("ENTRY_REQUEST", "ENTRY_REQUEST_MISMATCH")
        entries_ok = False

    if artifact is not None:
        real = [e for e in entries if isinstance(e.get("signature"), str) and e["signature"] not in NOT_A_SIGNATURE]
        if all(e["signature"] == artifact.get("signature") for e in real):
            ok_("ENTRY_SIGNATURE_BINDING")
        else:
            bad("ENTRY_SIGNATURE_BINDING", "ENTRY_SIGNATURE_MISMATCH")
        payload = artifact.get("payload")
        want = payload.get("requestHash") if is_obj(payload) else None
        hashed = [e for e in entries if isinstance(e.get("requestHash"), str) and e["requestHash"] != "UNAVAILABLE"]
        if all(e["requestHash"] == want for e in hashed):
            ok_("ENTRY_REQUEST_HASH")
        else:
            bad("ENTRY_REQUEST_HASH", "REQUEST_HASH_MISMATCH")
        mismatched = [e for e in entries if e.get("schemaVersion") == 8 and e.get("issuedAt") is not None and e.get("issuedAt") != artifact.get("timestamp")]
        if mismatched:
            bad("ISSUED_AT_MISMATCH", "ISSUED_AT_MISMATCH")
        else:
            ok_("ISSUED_AT_MISMATCH")

    types = [entry_type_of(e) for e in entries]
    ordered = all(t in RANK and (i == 0 or RANK[t] >= RANK[types[i - 1]]) for i, t in enumerate(types))
    decisions = types.count("DECISION")
    if not ordered:
        bad("LIFECYCLE", "LIFECYCLE_ORDER")
    elif decisions != 1:
        bad("LIFECYCLE", "NO_DECISION" if decisions == 0 else "TWO_DECISIONS")
    elif "COMMIT" in types and (len(types) - 1 - types[::-1].index("COMMIT")) < types.index("DECISION"):
        bad("LIFECYCLE", "COMMIT_WITHOUT_DECISION")
    else:
        ok_("LIFECYCLE")
    decision = next((e for e, t in zip(entries, types) if t == "DECISION"), None)

    t = doc.get("transparency")
    if not is_obj(t):
        partial.append("TRANSPARENCY_ABSENT")
    else:
        leaf, root, ip = t.get("leaf"), t.get("root"), t.get("inclusionProof")
        valid = False
        try:
            valid = (is_obj(leaf) and is_obj(root) and is_obj(ip)
                     and 0 <= int(ip["leafIndex"]) < int(ip["treeSize"])
                     and int(ip["treeSize"]) == int(root["entryCount"])
                     and t_entry_hash(leaf) == leaf.get("entryHash")
                     and verify_inclusion(leaf["entryHash"], ip.get("merklePath"), root.get("rootHash"), ip["leafIndex"], ip["treeSize"])
                     and _tx_sig(key_by_id, leaf.get("signerKeyId"), bytes.fromhex(leaf["entryHash"]), leaf.get("signature"))
                     and _tx_sig(key_by_id, root.get("signerKeyId"), t_root_digest(root), root.get("signature")))
        except Exception:
            valid = False
        if valid:
            ok_("TRANSPARENCY")
        else:
            bad("TRANSPARENCY", "TRANSPARENCY_INVALID")
        lp = leaf.get("payload") if is_obj(leaf) else None
        target = next((e for e in entries if is_obj(lp) and e.get("hash") == lp.get("auditEntryHash")), None)
        if (target is not None and lp.get("requestId") == request_id
                and (decision is None or target.get("hash") == decision.get("hash") or entry_type_of(target) != "DECISION")
                and lp.get("decision") == target.get("decision")):
            ok_("TRANSPARENCY_BINDING")
        else:
            bad("TRANSPARENCY_BINDING", "LEAF_DOES_NOT_DOCUMENT_ENTRY")

    cp = doc.get("checkpoint")
    if not is_obj(cp):
        partial.append("CHECKPOINT_ABSENT")
    else:
        cp_keys = key_by_id
        if anchor_repo is not None:
            cp_keys = dict((k["keyId"], {"publicKeySpkiB64": k["publicKey"], "status": k["status"]}) for k in anchor_repo["keys"]["checkpoint"])
        reason = checkpoint_reason(cp, cp_keys)
        if reason is None:
            ok_("CHECKPOINT")
        else:
            bad("CHECKPOINT", reason)
        path = doc.get("chainPath")
        if not isinstance(path, list):
            partial.append("CHAIN_NOT_ANCHORED")
        elif reason is not None:
            bad("CHAIN_PATH", "CHECKPOINT_NOT_VERIFIED")
        else:
            good, code = len(path) > 0 and all(is_obj(e) for e in path), None
            if not good:
                code = "CHAIN_PATH_EMPTY"
            for i in range(len(path)):
                if not good:
                    break
                r = check_entry_hash(path[i])
                if r is not None:
                    good, code = False, "PATH_ENTRY_" + r
                elif i > 0 and path[i].get("prevHash") != path[i - 1].get("hash"):
                    good, code = False, "PATH_BROKEN_LINK"
            if good and path[-1].get("hash") != cp["payload"].get("headHash"):
                good, code = False, "PATH_DOES_NOT_REACH_HEAD"
            if good:
                in_path = set(e.get("hash") for e in path)
                if any(e.get("hash") not in in_path for e in entries):
                    good, code = False, "ENTRY_NOT_IN_PATH"
            if good:
                ok_("CHAIN_PATH")
            else:
                bad("CHAIN_PATH", code)

    r = doc.get("receipt")
    if r is None:
        partial.append("RECEIPT_ABSENT")
    else:
        rlist = [{"keyId": k["keyId"], "publicKeySpkiB64": k["publicKeySpkiB64"], "status": k.get("status"), "revokedAt": k.get("revokedAt")} for k in keys]
        verdict = receipt_verdict(r, rlist, None)
        if verdict is None:
            ok_("RECEIPT")
        else:
            bad("RECEIPT", verdict)
        mism = []
        rr = r if is_obj(r) else {}
        if rr.get("requestId") != request_id:
            mism.append("requestId")
        if decision is not None and rr.get("decision") != decision.get("decision"):
            mism.append("decision")
        if decision is not None and rr.get("entryHash") != decision.get("hash"):
            mism.append("entryHash")
        order = ["entryHash", "leafHash", "requestId", "decision"]
        mism.sort(key=lambda x: order.index(x))
        if not mism:
            ok_("RECEIPT_BINDING")
        else:
            bad("RECEIPT_BINDING", "RECEIPT_MISMATCH:" + ",".join(mism))

    anchors = doc.get("anchors")
    if anchor_repo is not None:
        n_failed = len(failed)
        covered = anchor_trust_checks(doc, anchor_repo, ok_, bad, partial)
        if covered and len(failed) == n_failed:
            ok_("ANCHORS")
            for kind in sorted(set(x.get("kind") for x in (anchors if isinstance(anchors, list) else []) if is_obj(x) and x.get("kind") in ("ots", "rfc3161"))):
                partial.append("ANCHOR_RECEIPT_NOT_EVALUATED:" + kind)
    elif not isinstance(anchors, list) or len(anchors) == 0:
        partial.append("ANCHORS_ABSENT")
    elif not all(is_obj(x) and x.get("kind") in ("git", "ots", "rfc3161") and isinstance(x.get("receipt"), str) for x in anchors):
        bad("ANCHORS", "ANCHOR_MALFORMED")
    else:
        ok_("ANCHORS")
        partial.append("ANCHORS_NOT_EVALUATED")

    if not entries_ok and not failed:
        bad("ENTRY_HASH:0", "ENTRIES_INVALID")
    return done()


def _tx_sig(key_by_id, key_id, digest, sig):
    k = key_by_id.get(key_id)
    if k is None or str(k.get("status") or "").lower() == "revoked":
        return False
    ok, _canon = verify_sig(digest, sig, k.get("publicKeySpkiB64"))
    return ok


def verify_vector_file(path):
    """Re-derive every case of an audit vector file (family audit-v8: entries; audit-proof: proofs). -> {file, family, cases, failed, failures}"""
    with open(path, "r", encoding="utf-8") as fh:
        data = _loads(fh.read())
    failures = []
    for c in data["cases"]:
        if data["family"] == "audit-v8":
            code = check_entry_hash(c["input"]["entry"])
            want = c["expectedError"]["code"] if "expectedError" in c else None
            if code != want:
                failures.append({"id": c["id"], "why": "expected %s, got %s" % (want, code)})
        elif data["family"] == "audit-anchor":
            code, rec = check_anchor_line(c["input"]["line"])
            want = c["expectedError"]["code"] if "expectedError" in c else None
            if code != want or (code is None and rec["digest"] != c["expected"]["digest"]):
                failures.append({"id": c["id"], "why": "expected %s, got %s" % (want or c["expected"]["digest"], code or rec["digest"])})
        elif data["family"] == "audit-proof":
            r = verify_proof(c["input"]["proof"])
            got = {"verdict": r["verdict"], "failed": r["failed"], "partial": sorted(r["partial"])}
            if got != c["expected"]:
                failures.append({"id": c["id"], "why": "expected %s, got %s" % (json.dumps(c["expected"]), json.dumps(got))})
        else:
            failures.append({"id": c["id"], "why": "unknown family " + str(data["family"])})
    return {"file": path.replace("\\", "/").split("/")[-1], "family": data["family"], "cases": len(data["cases"]), "failed": len(failures), "failures": failures}


def main(argv):
    """python qodiqa_proof_verify.py --proof proof.json [--artifact artifact.json]   exit 0 VALID, 3 VALID_PARTIAL, 1 INVALID, 2 usage"""
    if argv and argv[0] == "--vectors":
        reports = [verify_vector_file(p) for p in argv[1:]]
        failed = sum(r["failed"] for r in reports)
        sys.stdout.write(json.dumps({"implementation": "qodiqa_proof_verify.py (independent, python %s)" % sys.version.split()[0], "checks": sum(r["cases"] for r in reports), "failed": failed, "reports": reports}) + chr(10))
        return 1 if failed else 0
    args = {}
    i = 0
    while i < len(argv):
        if argv[i].startswith("--"):
            args[argv[i][2:]] = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("--") else True
            i += 1 if args[argv[i][2:]] is True else 2
        else:
            i += 1
    if not isinstance(args.get("proof"), str):
        sys.stderr.write("usage: qodiqa_proof_verify.py --proof <file> [--artifact <file>] [--anchors-repo <dir> [--require-signed]]\n")
        return 2
    try:
        with open(args["proof"], "r", encoding="utf-8") as fh:
            doc = _loads(fh.read())
        # the response of GET /v1/proofs/{requestId} is the usual envelope {status, data}: the proof is `data`
        if is_obj(doc) and doc.get("status") == "success" and is_obj(doc.get("data")) and doc["data"].get("format") == "qodiqa-proof/1":
            doc = doc["data"]
        if isinstance(args.get("artifact"), str):
            with open(args["artifact"], "r", encoding="utf-8") as fh:
                doc["artifact"] = _loads(fh.read())
    except Exception as e:
        sys.stderr.write("cannot read input: %s\n" % e)
        return 2
    repo = load_anchor_repo(args["anchors-repo"], args.get("require-signed") is True) if isinstance(args.get("anchors-repo"), str) else None
    report = verify_proof(doc, repo)
    sys.stdout.write(json.dumps({"verdict": report["verdict"], "failed": report["failed"], "partial": report["partial"]}) + "\n")
    return {"VALID": 0, "VALID_PARTIAL": 3}.get(report["verdict"], 1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
