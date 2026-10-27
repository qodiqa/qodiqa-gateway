"""Flask webhook handler — QODIQA signature verification.

IMPORTANT: Use ``request.get_data()`` to obtain the raw request bytes BEFORE
calling ``request.get_json()``.  The ``get_data()`` call caches the body so
it is safe to call both, but the order matters for stream-based middleware.
"""

from __future__ import annotations

import json
import os

from flask import Flask, Response, jsonify, request

from qodiqa import WebhookVerifier
from qodiqa.exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTimestampError,
    MalformedSignatureError,
)

WEBHOOK_SECRET = os.environ.get("QODIQA_WEBHOOK_SECRET", "dev_secret")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# WebhookVerifier — configure once, reuse per request
# ---------------------------------------------------------------------------

verifier = WebhookVerifier(WEBHOOK_SECRET)

# Secret rotation example:
# rotating_verifier = WebhookVerifier([NEW_SECRET, OLD_SECRET])


@app.post("/webhooks/qodiqa")
def handle_webhook() -> Response:
    signature = request.headers.get("X-QODIQA-Signature", "")
    timestamp = request.headers.get("X-QODIQA-Timestamp", "")

    # get_data() returns raw bytes; the body stream is cached so subsequent
    # calls to get_json() still work.
    raw_body: bytes = request.get_data()

    try:
        verifier.verify(body=raw_body, signature=signature, timestamp=timestamp)
    except ExpiredSignatureError as exc:
        return jsonify({"error": f"Replay detected: {exc.message}"}), 401
    except (InvalidSignatureError, MalformedSignatureError, InvalidTimestampError) as exc:
        return jsonify({"error": exc.message}), 401

    # Signature valid — process the event.
    event = json.loads(raw_body)
    app.logger.info("Received webhook event: %s", event.get("type"))

    # Dispatch on event["type"] to your own handler here.

    return jsonify({"received": True})


if __name__ == "__main__":
    app.run(debug=True, port=5001)
