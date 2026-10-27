"""QODIQA CLI — command-line interface for common SDK operations.

Usage:
    python cli.py health
    python cli.py keys
    python cli.py sign --method POST --path /ai/chat --user user_123 [--provider openai]
    python cli.py chat --artifact <b64> --prompt "Hello"
    python cli.py verify --artifact <b64> --method POST --path /ai/chat
    python cli.py audit --id <artifactId>
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from qodiqa import QodiqaClient
from qodiqa.exceptions import QodiqaError, RateLimitError, VerificationError


def build_client() -> QodiqaClient:
    return QodiqaClient(
        api_key=os.environ.get("QODIQA_API_KEY"),
        sign_token=os.environ.get("QODIQA_SIGN_TOKEN"),
        base_url=os.environ.get("QODIQA_BASE_URL", "http://localhost:3000"),
    )


def cmd_health(client: QodiqaClient, args: argparse.Namespace) -> None:
    result = client.health_check()
    print(json.dumps(result, indent=2))


def cmd_keys(client: QodiqaClient, args: argparse.Namespace) -> None:
    result = client.get_public_keys()
    for key in result.get("keys", []):
        print(f"  {key['keyId']} ({key['algorithm']}) — {key['status']}")


def cmd_sign(client: QodiqaClient, args: argparse.Namespace) -> None:
    body = json.loads(args.body) if args.body else {}
    # --provider is only meaningful when --path is /ai/chat, and only
    # required there once more than one AI provider is enabled server-side
    # (/sign auto-resolves it otherwise; 400 PROVIDER_REQUIRED if ambiguous).
    payload = {"userId": args.user}
    if args.provider:
        payload["provider"] = args.provider
    signed = client.sign.sign(
        {
            "request": {"method": args.method, "path": args.path, "body": body},
            "payload": payload,
            "ttl": args.ttl,
        }
    )
    artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
    print("Artifact ID:", signed["artifactId"])
    print("Artifact (base64):", artifact_b64)
    print("Expires at:", signed.get("meta", {}).get("expiresAt"))


def cmd_chat(client: QodiqaClient, args: argparse.Namespace) -> None:
    result = client.chat.create(args.artifact, {"prompt": args.prompt})
    print("Decision:", result["decision"])
    if result.get("aiText"):
        print("AI:", result["aiText"])
    elif result.get("reason"):
        print("Reason:", result["reason"])


def cmd_verify(client: QodiqaClient, args: argparse.Namespace) -> None:
    artifact = json.loads(base64.b64decode(args.artifact))
    result = client.verify.verify(
        args.artifact,
        {
            "artifact": artifact,
            "request": {"method": args.method, "path": args.path},
        },
    )
    print("Decision:", result["decision"])
    print("Reason:", result.get("reason"))


def cmd_audit(client: QodiqaClient, args: argparse.Namespace) -> None:
    result = client.get_audit_chain(args.id)
    print(json.dumps(result, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description="QODIQA CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health")
    sub.add_parser("keys")

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("--method", default="POST")
    p_sign.add_argument("--path", required=True)
    p_sign.add_argument("--body", default="")
    p_sign.add_argument("--user", default="anonymous")
    p_sign.add_argument("--provider", default=None)
    p_sign.add_argument("--ttl", type=int, default=300_000)

    p_chat = sub.add_parser("chat")
    p_chat.add_argument("--artifact", required=True)
    p_chat.add_argument("--prompt", required=True)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--artifact", required=True)
    p_verify.add_argument("--method", default="POST")
    p_verify.add_argument("--path", required=True)

    p_audit = sub.add_parser("audit")
    p_audit.add_argument("--id", required=True)

    args = parser.parse_args()

    COMMANDS = {
        "health": cmd_health,
        "keys": cmd_keys,
        "sign": cmd_sign,
        "chat": cmd_chat,
        "verify": cmd_verify,
        "audit": cmd_audit,
    }

    with build_client() as client:
        try:
            COMMANDS[args.command](client, args)
        except VerificationError as exc:
            print(f"Verification failed: {exc.message}", file=sys.stderr)
            sys.exit(2)
        except RateLimitError as exc:
            after = exc.retry_after
            msg = f"Rate limited. Retry after {after}s." if after else "Rate limited."
            print(msg, file=sys.stderr)
            sys.exit(3)
        except QodiqaError as exc:
            print(f"Error ({exc.status}): {exc.message}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
