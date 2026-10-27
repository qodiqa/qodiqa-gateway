"""FastAPI webhook handler — QODIQA signature verification.

IMPORTANT: Always read the raw request body with ``await request.body()``
BEFORE calling ``await request.json()``.  Reading JSON first consumes the
stream and the raw bytes are unavailable for signature verification.
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, HTTPException, Request, Response

from qodiqa import WebhookVerifier, verify_webhook_signature
from qodiqa.exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTimestampError,
    MalformedSignatureError,
)

WEBHOOK_SECRET = os.environ["QODIQA_WEBHOOK_SECRET"]

app = FastAPI(title="QODIQA Webhook Example")

# ---------------------------------------------------------------------------
# Option A: WebhookVerifier instance (preferred — configure once, reuse)
# ---------------------------------------------------------------------------

verifier = WebhookVerifier(WEBHOOK_SECRET)

# Secret rotation: pass a list of secrets during the transition period.
# rotating_verifier = WebhookVerifier([NEW_SECRET, OLD_SECRET])


@app.post("/webhooks/qodiqa")
async def handle_webhook(request: Request) -> Response:
    signature = request.headers.get("x-qodiqa-signature")
    timestamp = request.headers.get("x-qodiqa-timestamp")
    if not signature:
        raise HTTPException(status_code=400, detail="Missing X-QODIQA-Signature header")
    if not timestamp:
        raise HTTPException(status_code=400, detail="Missing X-QODIQA-Timestamp header")

    # Capture raw bytes FIRST — before any JSON parsing.
    raw_body = await request.body()

    try:
        verifier.verify(body=raw_body, signature=signature, timestamp=timestamp)
    except ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail=f"Replay detected: {exc.message}")
    except (InvalidSignatureError, MalformedSignatureError, InvalidTimestampError) as exc:
        raise HTTPException(status_code=401, detail=exc.message)

    # Signature is valid — parse and process the event.
    event = json.loads(raw_body)
    print(f"Received webhook event: {event.get('type')}")

    # Route event["type"] to your own handler, e.g.:
    # match event["type"]:
    #     case "sign.created":  await handle_sign_created(event)
    #     case "verify.failed": await handle_verify_failed(event)

    return Response(content='{"received":true}', media_type="application/json")


# ---------------------------------------------------------------------------
# Option B: convenience function
# ---------------------------------------------------------------------------

@app.post("/webhooks/qodiqa/v2")
async def handle_webhook_v2(request: Request) -> Response:
    signature = request.headers.get("x-qodiqa-signature", "")
    timestamp = request.headers.get("x-qodiqa-timestamp", "")
    raw_body = await request.body()

    try:
        verify_webhook_signature(
            body=raw_body,
            signature=signature,
            timestamp=timestamp,
            secret=WEBHOOK_SECRET,
        )
    except (
        InvalidSignatureError,
        ExpiredSignatureError,
        MalformedSignatureError,
        InvalidTimestampError,
    ) as exc:
        raise HTTPException(status_code=401, detail=exc.message)

    event = json.loads(raw_body)
    return Response(
        content=json.dumps({"received": True, "type": event.get("type")}),
        media_type="application/json",
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
