"""Basic synchronous client usage.

Prerequisites:
  1. Install the SDK locally (not yet published to PyPI — see README.md):
       pip install ./sdk/python
  2. Start the server:  npm run dev
     (prints a "Signing Token" to the console on startup)
  3. Run this example with that token:
       QODIQA_SIGN_TOKEN=<printed-token> python sdk/python/examples/basic_client.py

See ../../../QUICKSTART.md for the full walkthrough, including provisioning
PostgreSQL-backed consent (required for a genuine EXECUTE decision).
"""

import base64
import json
import os
import sys

from qodiqa import QodiqaClient
from qodiqa.exceptions import QodiqaError, VerificationError

BASE_URL = os.environ.get("QODIQA_BASE_URL", "http://localhost:3000")
SIGN_TOKEN = os.environ.get("QODIQA_SIGN_TOKEN")
PROVIDER = os.environ.get("QODIQA_PROVIDER")  # optional — only needed if more than one provider is configured
MODEL = os.environ.get("QODIQA_MODEL")  # optional — e.g. a model name pulled in a local Ollama instance
PROMPT = "Hello, what is 2 + 2?"

if not SIGN_TOKEN:
    sys.exit(
        "QODIQA_SIGN_TOKEN is not set.\n\n"
        "Start the server first, in another terminal:\n"
        "  npm run dev\n\n"
        "Copy the \"Signing Token\" it prints on startup, then re-run this example:\n"
        "  QODIQA_SIGN_TOKEN=<printed-token> python sdk/python/examples/basic_client.py\n"
    )

client = QodiqaClient(sign_token=SIGN_TOKEN, base_url=BASE_URL)

chat_body = {"prompt": PROMPT, **({"model": MODEL} if MODEL else {})}

# Health check
health = client.health_check()
print("Status:", health["status"])

# Sign the exact request we're about to make
sign_request = {"request": {"method": "POST", "path": "/ai/chat", "body": chat_body}}
if PROVIDER:
    sign_request["payload"] = {"provider": PROVIDER}

signed = client.sign.sign(sign_request)
print("Artifact ID:", signed["artifactId"])

artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()

try:
    chat = client.chat.create(artifact_b64, chat_body)
    if chat["decision"] == "EXECUTE":
        print("Decision:", chat["decision"])
        print("AI text: ", chat.get("aiText"))
    else:
        print("Decision:", chat["decision"])
        print("Blocked:  ", chat.get("reason"))
except VerificationError as exc:
    print("Verification failed:", exc.message)
except QodiqaError as exc:
    print("Error:", exc.message)
finally:
    client.close()
