"""drive the canonical Python SDK (sdk/python) against a REAL gateway.

Invoked by with one argument, a JSON file:
  {"baseUrl", "signToken", "apiKey", "recoveryCode", "prompt", "override"}
Prints one JSON object of observations on stdout. Every case is independent; an unexpected exception is recorded,
never raised, so the Jest side sees every result.
"""

from __future__ import annotations

import base64
import json
import sys
import uuid

from qodiqa import QodiqaClient
from qodiqa.exceptions import QodiqaError


GHOST = str(uuid.uuid4())  # a well-formed id that does not exist: past the step-up the handler answers 404


def b64(artifact: dict) -> str:
    return base64.b64encode(json.dumps(artifact, separators=(",", ":")).encode()).decode()


def main() -> None:
    cfg = json.load(open(sys.argv[1], encoding="utf8"))
    out: dict = {}
    c = QodiqaClient(base_url=cfg["baseUrl"], sign_token=cfg["signToken"], api_key=cfg["apiKey"])

    def body(prompt: str, stream: bool = False) -> dict:
        b = {"prompt": prompt, "provider": "llama", "model": "stub-model"}
        if stream:
            b["stream"] = True
        return b

    def sign(b: dict) -> dict:
        r = c.sign.sign({"request": {"method": "POST", "path": "/ai/chat", "body": b}, "payload": {"provider": "llama"}})
        return r["artifact"]

    def err(e: Exception) -> dict:
        return {"cls": type(e).__name__, "reason": getattr(e, "reason", None), "status": getattr(e, "status", None)}

    def case(name, fn):
        try:
            out[name] = {"ok": fn()}
        except QodiqaError as e:
            out[name] = {"err": err(e)}
        except Exception as e:  # noqa: BLE001 — recorded for the Jest side
            out[name] = {"unexpected": f"{type(e).__name__}: {e}"}

    def execute():
        b = body(f"{cfg['prompt']} [{uuid.uuid4()}]")
        r = c.chat.create(b64(sign(b)), b)
        return {"decision": r["decision"], "reason": r.get("reason"), "hasText": isinstance(r.get("aiText"), str)}

    def tampered(stream: bool):
        def run():
            b = body(f"{cfg['prompt']} [{uuid.uuid4()}]", stream)
            a = sign(b)
            sig = a["signature"]
            a["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
            if stream:
                return [e.get("event") for e in c.chat.stream(b64(a), b)]
            return c.chat.create(b64(a), b)
        return run

    def replay():
        b = body(f"{cfg['prompt']} [{uuid.uuid4()}]")
        art = b64(sign(b))
        c.chat.create(art, b)
        return c.chat.create(art, b)

    def policy_block(stream: bool):
        def run():
            b = body(cfg["override"], stream)
            if stream:
                return [e.get("event") for e in c.chat.stream(b64(sign(b)), b)]
            r = c.chat.create(b64(sign(b)), b)
            return {"decision": r["decision"], "reason": r.get("reason")}
        return run

    def stream_execute():
        b = body(f"{cfg['prompt']} [{uuid.uuid4()}]", True)
        return [e.get("event") for e in c.chat.stream(b64(sign(b)), b)]

    case("execute", execute)
    case("tampered_create", tampered(False))
    case("tampered_stream", tampered(True))
    case("replay_create", replay)
    case("policy_block_create", policy_block(False))
    case("policy_block_stream", policy_block(True))
    case("stream_execute", stream_execute)

    # MFA step-up on a gated mutation. A nonexistent webhook: once the step-up passes, the handler answers 404 —
    # proof the code was accepted without changing anything.
    def mfa_without_provider():
        return c.webhooks.delete(GHOST, "dev-local")

    def mfa_with_provider():
        m = QodiqaClient(base_url=cfg["baseUrl"], api_key=cfg["apiKey"], otp_provider=lambda: cfg["recoveryCode"])
        return m.webhooks.delete(GHOST, "dev-local")

    case("mfa_without_provider", mfa_without_provider)
    case("mfa_with_provider", mfa_with_provider)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
