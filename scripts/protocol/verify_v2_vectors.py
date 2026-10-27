#!/usr/bin/env python3
"""INDEPENDENT Python verifier for the protocol-V2 vector families (docs/protocol/vectors/v2-canon.json, v2-request.json, receipt.json).

Standard library only (json is used to read the vector FILE; the JSON under test is parsed by the parser below, never by json.loads). JCS-P1
(docs/protocol/PROTOCOL-V2.md section 2) and the V2 request binding (section 3) are re-implemented here from the specification text alone —
including the ECMAScript Number::toString rule, since Python's repr differs from it, and a pure-Python Ed25519 verification (RFC 8032) for the receipts — so this file is a third implementation next to the
gateway's and the Node verifier's. A disagreement is a defect in the specification text or in one implementation, never settled by editing a vector.

    python scripts/protocol/verify_v2_vectors.py [file.json ...]        exit 1 on any mismatch
"""

import base64
import hashlib
import json
import os
import re
import sys
import unicodedata

MAX_SAFE = 9007199254740991
MAX_DEPTH = 64
MAX_DOC_BYTES = 1048576
NEST_STOP = 5000
# V2-FREEZE 2.7: the first of this list is the one reported when several rules are broken
ORDER = ["INVALID_UTF8", "INVALID_JSON", "DUPLICATE_KEY", "NON_FINITE_NUMBER", "NUMBER_OUT_OF_RANGE", "FORBIDDEN_KEY",
         "UNSUPPORTED_TYPE", "STRING_NOT_NFC", "LONE_SURROGATE", "MAX_DEPTH_EXCEEDED", "MAX_SIZE_EXCEEDED"]
FORBIDDEN = ("__proto__", "constructor", "prototype")
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
NEVER_BOUND = ("x-qodiqa-artifact", "authorization", "proxy-authorization", "cookie", "set-cookie", "host", "content-length",
               "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "via", "forwarded", "x-forwarded-for")

sys.setrecursionlimit(20000)


class Refusal(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Mismatch(Exception):
    def __init__(self, detail=None):
        super().__init__("REQUEST_MISMATCH")
        self.code = "REQUEST_MISMATCH"
        self.detail = detail


def first_of(found):
    for c in ORDER:
        if c in found:
            return c
    return None


# ── decoding ─────────────────────────────────────────────────────────────────────────────────────────────────────
def utf8(data):
    if data[:3] == b"\xef\xbb\xbf":
        raise Refusal("INVALID_UTF8")          # a BOM is never stripped
    try:
        return data.decode("utf-8")            # strict: rejects overlong forms, surrogates and stray bytes
    except UnicodeDecodeError:
        raise Refusal("INVALID_UTF8")


def units_to_str(units):
    """A list of UTF-16 code units -> str: valid pairs combine into one code point, a lone surrogate stays a surrogate code point."""
    raw = b"".join(u.to_bytes(2, "big") for u in units)
    return raw.decode("utf-16-be", "surrogatepass")


def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


# ── a strict JSON parser that keeps duplicate keys visible ───────────────────────────────────────────────────────
# nodes: ("obj", [(key, node)]) | ("arr", [node]) | ("str", s) | ("num", float) | ("lit", True/False/None)
NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


def parse_tree(text):
    n = len(text)
    pos = [0]

    def bad():
        raise Refusal("INVALID_JSON")

    def skip():
        i = pos[0]
        while i < n and text[i] in " \t\n\r":
            i += 1
        pos[0] = i

    def read_string():
        i = pos[0] + 1
        units = []
        while True:
            if i >= n:
                bad()
            ch = text[i]
            if ch == '"':
                pos[0] = i + 1
                return units_to_str(units)
            if ord(ch) < 0x20:
                bad()
            if ch != "\\":
                cp = ord(ch)
                if cp > 0xFFFF:
                    cp -= 0x10000
                    units.append(0xD800 + (cp >> 10))
                    units.append(0xDC00 + (cp & 0x3FF))
                else:
                    units.append(cp)
                i += 1
                continue
            e = text[i + 1] if i + 1 < n else ""
            if e == "":
                bad()                                       # text ends in a backslash ("" is `in` every string)
            i += 2
            if e in '"\\/':
                units.append(ord(e))
            elif e == "b":
                units.append(8)
            elif e == "f":
                units.append(12)
            elif e == "n":
                units.append(10)
            elif e == "r":
                units.append(13)
            elif e == "t":
                units.append(9)
            elif e == "u":
                h = text[i:i + 4]
                if not re.fullmatch(r"[0-9a-fA-F]{4}", h):
                    bad()
                units.append(int(h, 16))
                i += 4
            else:
                bad()

    def read_value(depth):
        if depth > NEST_STOP:
            raise Refusal("MAX_DEPTH_EXCEEDED")
        skip()
        i = pos[0]
        if i >= n:
            bad()
        c = text[i]
        if c == "{":
            pos[0] += 1
            members = []
            skip()
            if pos[0] < n and text[pos[0]] == "}":
                pos[0] += 1
                return ("obj", members)
            while True:
                skip()
                if pos[0] >= n or text[pos[0]] != '"':
                    bad()
                key = read_string()
                skip()
                if pos[0] >= n or text[pos[0]] != ":":
                    bad()
                pos[0] += 1
                members.append((key, read_value(depth + 1)))
                skip()
                if pos[0] < n and text[pos[0]] == ",":
                    pos[0] += 1
                    continue
                if pos[0] < n and text[pos[0]] == "}":
                    pos[0] += 1
                    return ("obj", members)
                bad()
        if c == "[":
            pos[0] += 1
            items = []
            skip()
            if pos[0] < n and text[pos[0]] == "]":
                pos[0] += 1
                return ("arr", items)
            while True:
                items.append(read_value(depth + 1))
                skip()
                if pos[0] < n and text[pos[0]] == ",":
                    pos[0] += 1
                    continue
                if pos[0] < n and text[pos[0]] == "]":
                    pos[0] += 1
                    return ("arr", items)
                bad()
        if c == '"':
            return ("str", read_string())
        for word, value in (("true", True), ("false", False), ("null", None)):
            if text.startswith(word, i):
                pos[0] += len(word)
                return ("lit", value)
        m = NUM_RE.match(text, i, min(n, i + 500))
        if not m:
            bad()
        pos[0] = m.end()
        return ("num", float(m.group(0)))       # every number is an IEEE-754 double (float() semantics for integer literals too)

    root = read_value(0)
    skip()
    if pos[0] != n:
        bad()
    return root


def lone_surrogate(s):
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def violations(root):
    found = set()

    def check_string(s):
        if unicodedata.normalize("NFC", s) != s:
            found.add("STRING_NOT_NFC")
        if lone_surrogate(s):
            found.add("LONE_SURROGATE")

    max_depth = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        kind = node[0]
        if kind == "num":
            v = node[1]
            if v in (float("inf"), float("-inf")) or v != v:
                found.add("NON_FINITE_NUMBER")
            elif abs(v) > MAX_SAFE:
                found.add("NUMBER_OUT_OF_RANGE")
        elif kind == "str":
            check_string(node[1])
        elif kind == "arr":
            max_depth = max(max_depth, depth)
            for item in node[1]:
                stack.append((item, depth + 1))
        elif kind == "obj":
            max_depth = max(max_depth, depth)
            seen = set()
            for key, val in node[1]:
                if key in seen:
                    found.add("DUPLICATE_KEY")
                seen.add(key)
                if key in FORBIDDEN:
                    found.add("FORBIDDEN_KEY")
                check_string(key)
                stack.append((val, depth + 1))
    if max_depth > MAX_DEPTH:
        found.add("MAX_DEPTH_EXCEEDED")
    return found


# ── canonical form (RFC 8785) ────────────────────────────────────────────────────────────────────────────────────
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


def parse_jcs_p1(data):
    tree = parse_tree(utf8(data))
    found = violations(tree)
    if found:
        raise Refusal(first_of(found))
    canonical = emit(tree)
    if len(canonical.encode("utf-8")) > MAX_DOC_BYTES:
        raise Refusal("MAX_SIZE_EXCEEDED")
    return tree, canonical


# ── V2 request binding (V2-FREEZE section 3) ─────────────────────────────────────────────────────────────────────
def mismatch(detail=None):
    raise Mismatch(detail)


def strict_utf8(data):
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return None


def nfc_or_refuse(s):
    if unicodedata.normalize("NFC", s) != s:
        mismatch("STRING_NOT_NFC")
    return s


def decode_percent(raw):
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x25:
            h = raw[i + 1:i + 3]
            if len(h) != 2 or not re.fullmatch(rb"[0-9a-fA-F]{2}", h):
                mismatch()
            out.append(int(h, 16))
            i += 3
        else:
            out.append(b)
            i += 1
    s = strict_utf8(out)
    if s is None:
        mismatch()
    return nfc_or_refuse(s)


def request_binding(inp):
    method, target, headers, bind, body = inp["method"], inp["target"], inp["headers"], inp["bind"], inp["body"]
    if len(bind) > 16:
        mismatch()
    seen = set()
    for name in bind:
        if not re.fullmatch(r"[a-z0-9-]{1,64}", name) or name in NEVER_BOUND or name in seen:
            mismatch()
        seen.add(name)
    if not method or any(not (0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A) for b in method):
        mismatch()
    m = method.decode("ascii").upper()
    if m not in METHODS:
        mismatch()
    if not target or target[0] != 0x2F:
        mismatch()
    if any(b <= 0x20 or b >= 0x7F or b == 0x23 for b in target):
        mismatch()
    q = target.find(b"?")
    path = (target if q < 0 else target[:q]).decode("latin-1")
    query_bytes = b"" if q < 0 else target[q + 1:]
    query = []
    if query_bytes:
        if b"+" in query_bytes or b";" in query_bytes:
            mismatch()
        pairs = []
        for seg in query_bytes.split(b"&"):
            if not seg:
                continue                                  # empty segments are ignored
            eq = seg.find(b"=")
            name = decode_percent(seg if eq < 0 else seg[:eq])
            value = decode_percent(b"" if eq < 0 else seg[eq + 1:])
            pairs.append((name, value))
        query = sorted(pairs, key=lambda p: utf16_key(p[0]))      # stable, by name only
    for hn, hv in headers:
        if hn.decode("latin-1").lower() == "content-encoding" and hv.decode("latin-1").strip(" 	").lower() != "identity":
            mismatch()                                    # a content-coded body is refused
    header_values = {}
    for name in bind:
        lines = []
        for hn, hv in headers:
            if hn.decode("latin-1").lower() != name:
                continue
            s = strict_utf8(hv)
            if s is None:
                mismatch()
            lines.append(nfc_or_refuse(s.strip(" \t")))
        header_values[name] = ", ".join(lines) if lines else None
    if body is None or len(body) == 0:
        body_node = ("obj", [])
    else:
        try:
            tree, _ = parse_jcs_p1(body)
        except Refusal as e:
            mismatch(e.code)
        if tree[0] != "obj":
            mismatch()
        body_node = tree
    doc = ("obj", [
        ("v", ("num", 2.0)), ("method", ("str", m)), ("path", ("str", path)),
        ("query", ("arr", [("arr", [("str", a), ("str", b)]) for a, b in query])),
        ("headers", ("obj", [(n, ("lit", None) if header_values[n] is None else ("str", header_values[n])) for n in bind])),
        ("body", body_node),
    ])
    found = violations(doc)
    if found:
        mismatch(first_of(found))
    document = emit(doc)
    if len(document.encode("utf-8")) > MAX_DOC_BYTES:
        mismatch("MAX_SIZE_EXCEEDED")
    digest = hashlib.sha256(b"QODIQA::REQUEST::V2" + document.encode("utf-8")).hexdigest()
    return digest, document


# ── Ed25519 verification (RFC 8032 section 5.1.7), pure standard library ─────────────────────────────────────────────
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


# ── signed receipt (V2-FREEZE section 6) ─────────────────────────────────────────────────────────────────────────
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


# ── vectors ──────────────────────────────────────────────────────────────────────────────────────────────────────
def expand(b):
    if isinstance(b, str):
        return bytes.fromhex(b)
    r = b["repeat"]
    return (r["prefix"] + r["unit"] * r["count"] + r["suffix"]).encode("utf-8")


def verify_case(family, c, file=None):
    if family == "v2-receipt":
        got = receipt_verdict(c["input"]["receipt"], (file or {}).get("keys", []), c["input"].get("trustedAt"))
        if "expectedError" in c:
            want = c["expectedError"]["code"]
            return (True, None) if got == want else (False, "expected %s, got %s" % (want, got))
        return (True, None) if got is None else (False, "expected ok, got %s" % got)
    if family == "v2-canon":
        try:
            _, canonical = parse_jcs_p1(expand(c["input"]["bytes"]))
            got = ("ok", canonical.encode("utf-8"))
        except Refusal as e:
            got = ("err", e.code)
        if "expectedError" in c:
            want = c["expectedError"]["code"]
            if got[0] == "ok":
                return False, "expected %s, got a canonical form" % want
            return (True, None) if got[1] == want else (False, "expected %s, got %s" % (want, got[1]))
        if got[0] == "err":
            return False, "expected a canonical form, got %s" % got[1]
        e = c["expected"]
        if "value" in e:
            return (True, None) if got[1].hex() == e["value"] else (False, "canonical bytes differ")
        ok = len(got[1]) == e["length"] and hashlib.sha256(got[1]).hexdigest() == e["sha256"]
        return (True, None) if ok else (False, "canonical length or sha256 differs")
    if family == "v2-request":
        i = c["input"]
        inp = {"method": expand(i["method"]), "target": expand(i["target"]),
               "headers": [(expand(a), expand(b)) for a, b in i["headers"]], "bind": i["bind"],
               "body": None if i["body"] is None else expand(i["body"])}
        try:
            digest, document = request_binding(inp)
            got = ("ok", digest, document)
        except Mismatch as e:
            got = ("err", e.code, e.detail)
        if "expectedError" in c:
            want = c["expectedError"]
            if got[0] == "ok":
                return False, "expected %s, got a hash" % want["code"]
            if got[1] != want["code"]:
                return False, "expected %s, got %s" % (want["code"], got[1])
            return (True, None) if (got[2] or None) == want.get("detail") else (False, "detail: expected %s, got %s" % (want.get("detail"), got[2]))
        if got[0] == "err":
            return False, "expected a hash, got %s%s" % (got[1], ":" + got[2] if got[2] else "")
        if got[1] != c["expected"]["value"]:
            return False, "requestHash differs"
        if "document" in c["expected"] and got[2] != c["expected"]["document"]:
            return False, "hashed document differs"
        return True, None
    raise SystemExit("unknown family %s" % family)


def verify_file(path):
    with open(path, "r", encoding="utf-8") as f:
        v = json.load(f)
    failures = []
    for c in v["cases"]:
        ok, why = verify_case(v["family"], c, v)
        if not ok:
            failures.append({"id": c["id"], "description": c["description"], "why": why})
    return {"file": os.path.basename(path), "family": v["family"], "cases": len(v["cases"]), "failed": len(failures), "failures": failures}


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    d = os.path.join(here, "..", "..", "docs", "protocol", "vectors")
    files = argv[1:] or [os.path.join(d, "v2-canon.json"), os.path.join(d, "v2-request.json"), os.path.join(d, "receipt.json")]
    reports = [verify_file(f) for f in files]
    failed = sum(r["failed"] for r in reports)
    print(json.dumps({"implementation": "verify_v2_vectors.py (independent, python %s)" % sys.version.split()[0],
                      "checks": sum(r["cases"] for r in reports), "failed": failed, "reports": reports}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
