"""QODIQA Canonical JSON Serialization — Python SDK-side port.

A from-scratch, carefully-corrected port of the server's own
``src/utils/stableStringify.js`` (which itself delegates to the
``fast-json-stable-stringify`` npm package). No shared package exists across
languages, so this module hand-implements the exact algorithm rather than
reusing code from elsewhere.

Contract (identical to the server):

* Object keys sorted lexicographically at every depth, in **UTF-16 code unit
  order** — matching JavaScript's ``<`` string comparison exactly. This is
  *not* the same as Python's default codepoint ordering for strings
  containing astral (non-BMP) characters, which are represented in UTF-16 as
  a surrogate pair; see :func:`_utf16_key`.
* Array element order preserved.
* Zero whitespace.
* ``None`` serializes as ``null`` (Python has no undefined/null distinction).
* ``NaN`` / ``Infinity`` / ``-Infinity`` are a protocol violation — raises.
* A ``float`` that represents a whole number (e.g. ``5.0``) is formatted as
  an integer, matching JS (all JS numbers are float64 and ``JSON.stringify``
  never emits a trailing ``.0``). A **non-integer** float is rejected
  outright rather than attempting a lossy, best-effort match of ECMA-262's
  Number-to-string algorithm (shortest round-trip decimal + exponential
  notation thresholds) — real QODIQA artifact payloads only ever carry
  strings, integers, and booleans, so this is a safe, explicit restriction
  rather than a silent gap. See docs for details.
* Object keys ``__proto__``, ``constructor``, ``prototype`` are a protocol
  violation — raises (rather than silently admitting/stripping them, which
  would let a tampered payload hash-identical to the original).
* Any type other than ``dict``, ``list``/``tuple``, ``str``, ``int``,
  ``float``, ``bool``, ``None`` has no defined canonical representation —
  raises.
* Circular references are detected and rejected.
* Nesting beyond ``MAX_DEPTH`` is rejected.
"""

from __future__ import annotations

import math
from typing import Any, List

from ..exceptions import SerializationError

MAX_DEPTH = 1000

_FORBIDDEN_KEYS = frozenset({"__proto__", "constructor", "prototype"})

# JSON string escapes with a named short form (matches JSON.stringify).
_SHORT_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(SerializationError):
    """Raised when a value cannot be canonicalized — mirrors the JS SDK's
    ``CanonicalizationError``, including a machine-readable ``code``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message, details={"code": code})
        self.code = code


def _utf16_key(s: str) -> List[int]:
    """Return `s` as a list of UTF-16 code units, for JS-compatible sorting.

    JavaScript's string `<` operator compares UTF-16 code units. Python's
    default string comparison compares Unicode code points, which agrees
    with UTF-16 code unit order for the Basic Multilingual Plane but
    diverges for astral characters (code point >= 0x10000): those are a
    single Python code point but a *surrogate pair* (two code units, each
    in the 0xD800-0xDFFF range, which sorts below 0xE000) in UTF-16.
    Encoding to UTF-16BE and reading back 16-bit units reproduces JS
    ordering exactly.
    """
    encoded = s.encode("utf-16-be", "surrogatepass")
    return [
        (encoded[i] << 8) | encoded[i + 1] for i in range(0, len(encoded), 2)
    ]


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(n: Any) -> str:
    if isinstance(n, bool):  # guarded by caller, defensive only
        raise CanonicalizationError("UNSUPPORTED_TYPE", "internal: bool reached _encode_number")
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        if not math.isfinite(n):
            raise CanonicalizationError(
                "NON_FINITE_NUMBER",
                "stableStringify: NaN/Infinity is not a valid canonical number (QODIQA-PROTOCOL-SPEC.md §6.1)",
            )
        if n.is_integer():
            return str(int(n))
        raise CanonicalizationError(
            "NON_INTEGER_FLOAT",
            "stableStringify: non-integer floating point numbers cannot be canonicalized "
            "with guaranteed cross-language (Python/JS) parity — reject rather than risk a "
            "silent hash mismatch with the server. Real QODIQA payloads only carry strings, "
            "integers, and booleans.",
        )
    raise CanonicalizationError("UNSUPPORTED_TYPE", f"stableStringify: not a number: {n!r}")


def _encode_leaf(value: Any) -> str:
    """Encode a non-container value. Callers must have already excluded
    dict/list/tuple.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (int, float)):
        return _encode_number(value)
    raise CanonicalizationError(
        "UNSUPPORTED_TYPE",
        f"stableStringify: cannot serialize a non-plain-object value ({type(value).__name__}) — only dicts, "
        "lists, strings, finite numbers, booleans, and None are supported",
    )


def stable_stringify(value: Any) -> str:
    """Produce the canonical JSON string for `value`, matching the server's
    ``stableStringify`` byte-for-byte for all inputs realistic QODIQA
    artifacts contain.

    Deliberately iterative (an explicit work stack, not Python recursion) —
    ``MAX_DEPTH`` (1000) exceeds Python's default recursion limit once the
    caller's own stack depth is accounted for, so a naive recursive
    descent would raise an uncontrolled ``RecursionError`` for legitimately
    deep-but-valid input well before ``MAX_DEPTH`` itself is reached. This
    mirrors the server's own iterative, "no recursion, no stack overflow
    risk" design philosophy (see ``src/core/transparency/merkle.js``).

    Raises:
        CanonicalizationError: if `value` cannot be canonicalized.
    """
    # `work` is a stack of pending tasks, processed depth-first:
    #   ("value", value, depth)         — encode this value, push its result
    #                                      string onto `results`.
    #   ("close_array", count, vid)      — pop `count` strings off `results`
    #                                      (in reverse), join as "[...]".
    #   ("close_object", keys, vid)      — same, joined as "{...}" with keys.
    # Cycle detection: a container's id enters `seen` when its close-marker
    # is pushed (i.e. when we start descending into it) and leaves `seen`
    # when that marker is popped and resolved (i.e. we've finished with it)
    # — equivalent to the add-before/delete-after-recursion pattern, just
    # made explicit instead of implicit in the Python call stack.
    work: List[Any] = [("value", value, 0)]
    results: List[str] = []
    seen: set[int] = set()

    while work:
        task = work.pop()
        tag = task[0]

        if tag == "close_array":
            _, count, vid = task
            parts = results[len(results) - count :]
            del results[len(results) - count :]
            results.append("[" + ",".join(parts) + "]")
            seen.discard(vid)
            continue

        if tag == "close_object":
            _, keys, vid = task
            count = len(keys)
            parts = results[len(results) - count :]
            del results[len(results) - count :]
            body = ",".join(f"{_encode_string(k)}:{v}" for k, v in zip(keys, parts))
            results.append("{" + body + "}")
            seen.discard(vid)
            continue

        _, current, depth = task

        if isinstance(current, (list, tuple)):
            if depth > MAX_DEPTH:
                raise CanonicalizationError(
                    "MAX_DEPTH_EXCEEDED", f"stableStringify: nesting exceeds maximum depth of {MAX_DEPTH}"
                )
            vid = id(current)
            if vid in seen:
                raise CanonicalizationError("CIRCULAR_REFERENCE", "stableStringify: circular reference detected")
            seen.add(vid)
            work.append(("close_array", len(current), vid))
            for item in reversed(current):
                work.append(("value", item, depth + 1))
            continue

        if isinstance(current, dict):
            if depth > MAX_DEPTH:
                raise CanonicalizationError(
                    "MAX_DEPTH_EXCEEDED", f"stableStringify: nesting exceeds maximum depth of {MAX_DEPTH}"
                )
            vid = id(current)
            if vid in seen:
                raise CanonicalizationError("CIRCULAR_REFERENCE", "stableStringify: circular reference detected")
            seen.add(vid)

            for k in current.keys():
                if not isinstance(k, str):
                    raise CanonicalizationError(
                        "UNSUPPORTED_TYPE", f"stableStringify: object keys must be strings, got {type(k).__name__}"
                    )
                if k in _FORBIDDEN_KEYS:
                    raise CanonicalizationError(
                        "FORBIDDEN_KEY",
                        f'stableStringify: object key "{k}" is forbidden (QODIQA-PROTOCOL-SPEC.md §6.1)',
                    )

            sorted_keys = sorted(current.keys(), key=_utf16_key)
            work.append(("close_object", sorted_keys, vid))
            for k in reversed(sorted_keys):
                work.append(("value", current[k], depth + 1))
            continue

        # Leaf value.
        results.append(_encode_leaf(current))

    assert len(results) == 1
    return results[0]
