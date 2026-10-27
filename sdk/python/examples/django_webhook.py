"""Django webhook view — QODIQA signature verification.

IMPORTANT: Use ``request.body`` to obtain the raw bytes.  Django reads and
caches the body on first access, so calling ``request.body`` is safe at any
point in the view, but do NOT call ``request.POST`` or any other form-parsing
attribute first, as that can consume the stream.

To wire this view into Django's URL configuration::

    from django.urls import path
    from .webhook import qodiqa_webhook

    urlpatterns = [
        path("webhooks/qodiqa/", qodiqa_webhook, name="qodiqa-webhook"),
    ]
"""

from __future__ import annotations

import json
import logging
import os

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from qodiqa import WebhookVerifier
from qodiqa.exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTimestampError,
    MalformedSignatureError,
)

logger = logging.getLogger(__name__)

WEBHOOK_SECRET = os.environ.get("QODIQA_WEBHOOK_SECRET", "dev_secret")

verifier = WebhookVerifier(WEBHOOK_SECRET)

# Secret rotation example:
# verifier = WebhookVerifier([
#     os.environ["QODIQA_WEBHOOK_SECRET_NEW"],
#     os.environ["QODIQA_WEBHOOK_SECRET_OLD"],
# ])


@csrf_exempt
@require_POST
def qodiqa_webhook(request: HttpRequest) -> JsonResponse:
    """Django view for QODIQA webhook events."""
    signature = request.headers.get("X-QODIQA-Signature", "")
    timestamp = request.headers.get("X-QODIQA-Timestamp", "")

    # request.body is the raw bytes, cached by Django on first access.
    raw_body: bytes = request.body

    try:
        verifier.verify(body=raw_body, signature=signature, timestamp=timestamp)
    except ExpiredSignatureError as exc:
        logger.warning("QODIQA webhook replay attempt: %s", exc.message)
        return JsonResponse({"error": "Replay detected"}, status=401)
    except (InvalidSignatureError, MalformedSignatureError, InvalidTimestampError) as exc:
        logger.warning("QODIQA webhook verification failed: %s", exc.message)
        return JsonResponse({"error": exc.message}, status=401)

    # Signature verified — process the event.
    try:
        event = json.loads(raw_body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    event_type = event.get("type", "unknown")
    logger.info("Received QODIQA webhook event: %s", event_type)

    # Dispatch on event_type to your own handler, e.g.:
    # if event_type == "sign.created":
    #     handle_sign_created(event)
    # elif event_type == "verify.failed":
    #     handle_verify_failed(event)

    return JsonResponse({"received": True})
