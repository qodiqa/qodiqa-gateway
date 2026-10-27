"""Extracts the literal dict argument of every `<expr>.sign.sign(<dict>)`
call whose source text contains '/ai/chat', from a Python source file (or
stdin, if the path argument is '-'), and prints them as a JSON array.

Free variables referenced inside the dict literal (but not defined by it)
are resolved against a small, fixed stub namespace representing typical
values a real caller would supply — see STUBS below. This is a companion to
test/helpers/extractSignRequest.js's JS/TS extractor: both exist so
test/guards/exampleRequestContract.conformance.test.js can validate each shipped
example's *actual* extracted request against the real server-side
implementation, instead of a hand-copied duplicate of it.

Usage: python extract_python_sign_calls.py <path-or-source.py | ->
  '-' reads the source from stdin (used for markdown-fenced code blocks,
  which have no file of their own).
"""

import ast
import json
import sys
import textwrap


class _Obj:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


STUBS = {
    "PROMPT": "Test prompt",
    "PROVIDER": None,
    "chat_body": {"prompt": "Test prompt"},
    "args": _Obj(user="anonymous", provider=None),
    "data": {},
    "req": _Obj(user_id="anonymous", method="POST", path="/ai/chat", body={}),
}


def find_sign_call_dict_sources(source):
    # Markdown-fenced blocks nested under a list item carry a uniform
    # leading-indentation prefix (e.g. "  signed = ...") that would
    # otherwise make module-level code an IndentationError.
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Matches `<anything>.sign.sign(...)`.
        if not (isinstance(func, ast.Attribute) and func.attr == "sign"):
            continue
        if not (isinstance(func.value, ast.Attribute) and func.value.attr == "sign"):
            continue
        if not node.args:
            continue
        arg = node.args[0]
        segment = ast.get_source_segment(source, arg)
        # a quoted '/ai/chat' path exactly, as the JS extractor requires (a '/v1/ai/chat' protocol-V2 example is covered by protocolV2.endToEnd)
        if segment and ("'/ai/chat'" in segment or '"/ai/chat"' in segment):
            found.append(segment)
    return found


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "-"
    if target == "-":
        source = sys.stdin.read()
    else:
        with open(target, "r", encoding="utf-8") as f:
            source = f.read()

    results = []
    for segment in find_sign_call_dict_sources(source):
        # Restricted eval: no builtins, only the dict/list/str literal
        # grammar plus the stub names a real call site might reference.
        value = eval(segment, {"__builtins__": {}}, dict(STUBS))  # noqa: S307
        results.append(value)

    json.dump(results, sys.stdout)


if __name__ == "__main__":
    main()
