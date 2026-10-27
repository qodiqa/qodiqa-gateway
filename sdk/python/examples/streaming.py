"""QODIQA SDK - streaming usage example.

Demonstrates both the synchronous and asynchronous `chat.stream()` APIs:
incremental token delivery, explicit cancellation (Ctrl+C), and typed error
handling.

Run:
    QODIQA_SIGN_TOKEN=<printed-signing-key> QODIQA_BASE_URL=http://localhost:3000 python examples/streaming.py
    QODIQA_SIGN_TOKEN=<printed-signing-key> python examples/streaming.py --async
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import signal
import sys

from qodiqa import AsyncQodiqaClient, QodiqaClient
from qodiqa.exceptions import QodiqaError, TimeoutError, VerificationError

BASE_URL = os.environ.get("QODIQA_BASE_URL", "http://localhost:3000")
SIGN_TOKEN = os.environ.get("QODIQA_SIGN_TOKEN")

# `stream: True` must be part of the exact body signed below — the server
# binds the artifact to this body via requestHash, so the same dict is reused
# for both the sign call and the stream call rather than reconstructed.
CHAT_BODY = {
    "prompt": "Explain how QODIQA enforces AI execution, in three sentences.",
    "model": "gpt-4",
    "stream": True,
}


def _print_event(event: dict) -> None:
    kind = event["event"]
    if kind == "stream_started":
        print(f"[{event['provider']}/{event['model']}]")
    elif kind == "chunk_forwarded":
        print(event["delta"], end="", flush=True)
    elif kind == "stream_completed":
        print(f"\n\ndone - {event['chunksTotal']} chunks, {event['bytesTotal']} bytes, {event['durationMs']}ms")
    elif kind == "stream_cancelled":
        print(f"\n\ncancelled: {event['reason']}")


def run_sync() -> None:
    client = QodiqaClient(sign_token=SIGN_TOKEN, base_url=BASE_URL, timeout=30.0)

    print("--- Signing ---")
    # payload.provider is omitted here — /sign auto-resolves it to the single
    # enabled AI provider. With more than one provider configured, pass
    # payload: {"provider": "openai"} explicitly (400 PROVIDER_REQUIRED
    # otherwise). See README.md "Quick start".
    signed = client.sign.sign(
        {
            "request": {"method": "POST", "path": "/ai/chat", "body": CHAT_BODY},
            "payload": {"userId": "streaming-example"},
            "ttl": 300_000,
        }
    )
    artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
    print("Artifact ID:", signed["artifactId"])

    print("\n--- Streaming ---")
    # Cancellation: keep a reference to the generator so Ctrl+C (SIGINT) can
    # close it deterministically from the signal handler — demonstrating that
    # breaking a `for` loop, an explicit `.close()`, and signal interruption
    # all release the connection the same way.
    stream = client.chat.stream(artifact_b64, CHAT_BODY)

    def on_sigint(signum, frame):
        print("\n[interrupted — closing stream]")
        stream.close()

    previous_handler = signal.signal(signal.SIGINT, on_sigint)
    try:
        for event in stream:
            _print_event(event)
    except VerificationError as exc:
        # Most common cause: CHAT_BODY signed above didn't include stream: True.
        print("\nartifact/request mismatch:", exc.message)
    except TimeoutError:
        print("\nstream exceeded its timeout budget")
    except QodiqaError as exc:
        print(f"\n[{exc.status or 'n/a'}] {exc.message} {exc.details}")
    finally:
        signal.signal(signal.SIGINT, previous_handler)
        client.close()


async def run_async() -> None:
    async with AsyncQodiqaClient(sign_token=SIGN_TOKEN, base_url=BASE_URL, timeout=30.0) as client:
        print("--- Signing ---")
        signed = await client.sign.sign(
            {
                "request": {"method": "POST", "path": "/ai/chat", "body": CHAT_BODY},
                "payload": {"userId": "streaming-example"},
                "ttl": 300_000,
            }
        )
        artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
        print("Artifact ID:", signed["artifactId"])

        print("\n--- Streaming ---")
        # `client.chat.stream(...)` is not itself awaited — only iterating it
        # is. Keep a reference so it can be closed deterministically (e.g.
        # from a cancellation path) instead of relying on garbage collection.
        stream = client.chat.stream(artifact_b64, CHAT_BODY)
        try:
            async for event in stream:
                _print_event(event)
        except VerificationError as exc:
            print("\nartifact/request mismatch:", exc.message)
        except TimeoutError:
            print("\nstream exceeded its timeout budget")
        except QodiqaError as exc:
            print(f"\n[{exc.status or 'n/a'}] {exc.message} {exc.details}")
        finally:
            await stream.aclose()


if __name__ == "__main__":
    if not SIGN_TOKEN:
        print("QODIQA_SIGN_TOKEN not set — start the server and copy the printed signing key.")
        sys.exit(0)

    if "--async" in sys.argv:
        asyncio.run(run_async())
    else:
        run_sync()
