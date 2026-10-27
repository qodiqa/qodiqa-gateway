"""Asynchronous client usage.

Configuration is read from the environment (see basic_client.py for the full
setup walkthrough):
  QODIQA_API_KEY    — ops API key (optional; only needed for ops-scoped routes)
  QODIQA_SIGN_TOKEN — signing token printed by `npm run dev` on startup
  QODIQA_BASE_URL   — defaults to http://localhost:3000
"""

import asyncio
import base64
import json
import os

from qodiqa import AsyncQodiqaClient
from qodiqa.exceptions import QodiqaError

API_KEY = os.environ.get("QODIQA_API_KEY")
SIGN_TOKEN = os.environ.get("QODIQA_SIGN_TOKEN")
BASE_URL = os.environ.get("QODIQA_BASE_URL", "http://localhost:3000")


async def main() -> None:
    async with AsyncQodiqaClient(
        api_key=API_KEY,
        sign_token=SIGN_TOKEN,
        base_url=BASE_URL,
    ) as client:
        # Health check
        health = await client.health_check()
        print("Status:", health["status"])

        # Sign a request. "provider" is omitted from payload here — /sign
        # auto-resolves it to the single enabled AI provider. With more than
        # one provider configured, pass "payload": {"provider": "openai"}
        # explicitly (400 PROVIDER_REQUIRED otherwise). See docs/sdk/python/api.md#sign.
        signed = await client.sign.sign(
            {
                "request": {
                    "method": "POST",
                    "path": "/ai/chat",
                    "body": {"prompt": "Hello"},
                },
                "payload": {"userId": "user_123"},
                "ttl": 300_000,
            }
        )
        artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
        print("Artifact ID:", signed["artifactId"])

        # Execute the AI chat
        try:
            chat = await client.chat.create(
                artifact_b64,
                {"prompt": "Hello, what can you do?"},
            )
            if chat["decision"] == "EXECUTE":
                print("AI response:", chat.get("aiText"))
            else:
                print("Request blocked:", chat.get("reason"))
        except QodiqaError as exc:
            print("Error:", exc.message)

        # List transparency entries
        entries = await client.transparency.list_entries({"page": 1, "pageSize": 5})
        print(f"Total transparency entries: {entries['data'].get('total', 0)}")


if __name__ == "__main__":
    asyncio.run(main())
