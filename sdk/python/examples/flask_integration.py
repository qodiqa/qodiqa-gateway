"""Flask integration — synchronous signing and enforcement middleware.

Configuration is read from the environment (see ../examples/basic_client.py
for the full setup walkthrough):
  QODIQA_API_KEY    — ops API key (optional; only needed for ops-scoped routes)
  QODIQA_SIGN_TOKEN — signing token printed by `npm run dev` on startup
  QODIQA_BASE_URL   — defaults to http://localhost:3000
"""

from __future__ import annotations

import base64
import json
import os
from functools import wraps
from typing import Any, Callable

from flask import Flask, g, jsonify, request

from qodiqa import QodiqaClient
from qodiqa.exceptions import AuthenticationError, QodiqaError, VerificationError

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Client lifecycle
# ---------------------------------------------------------------------------


def get_client() -> QodiqaClient:
    if "qodiqa" not in g:
        g.qodiqa = QodiqaClient(
            api_key=os.environ.get("QODIQA_API_KEY"),
            sign_token=os.environ.get("QODIQA_SIGN_TOKEN"),
            base_url=os.environ.get("QODIQA_BASE_URL", "http://localhost:3000"),
        )
    return g.qodiqa


@app.teardown_appcontext
def close_client(exc: BaseException | None = None) -> None:
    client = g.pop("qodiqa", None)
    if client is not None:
        client.close()


# ---------------------------------------------------------------------------
# Enforcement decorator
# ---------------------------------------------------------------------------


def require_artifact(f: Callable) -> Callable:
    """Flask decorator: verify the artifact in the Authorization header."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Artifact "):
            return jsonify({"error": "Missing artifact header"}), 401

        artifact_b64 = auth[len("Artifact "):]
        try:
            verify_req = {
                "artifact": json.loads(base64.b64decode(artifact_b64)),
                "request": {
                    "method": request.method,
                    "path": request.path,
                    "body": request.get_json(silent=True) or {},
                },
            }
            result = get_client().verify.verify(artifact_b64, verify_req)
            if result.get("decision") != "EXECUTE":
                return jsonify({"error": "Blocked", "reason": result.get("reason")}), 403
        except VerificationError as exc:
            return jsonify({"error": exc.message}), 403
        except QodiqaError as exc:
            return jsonify({"error": exc.message}), 400

        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return jsonify(get_client().health_check())


@app.post("/sign")
def sign():
    data = request.get_json() or {}
    try:
        # "provider" is only meaningful when path is /ai/chat, and only
        # required there once more than one AI provider is enabled
        # server-side (/sign auto-resolves it otherwise; 400
        # PROVIDER_REQUIRED if ambiguous). Not exposed as a request field
        # here for brevity — pass "payload": {"provider": "..."} if needed.
        signed = get_client().sign.sign(
            {
                "request": {
                    "method": data.get("method", "POST"),
                    "path": data.get("path", "/"),
                    "body": data.get("body", {}),
                },
                "payload": {"userId": data.get("userId", "anonymous")},
                "ttl": data.get("ttl", 300_000),
            }
        )
        artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
        return jsonify({"artifactId": signed["artifactId"], "artifactB64": artifact_b64})
    except AuthenticationError as exc:
        return jsonify({"error": exc.message}), 401
    except QodiqaError as exc:
        return jsonify({"error": exc.message}), 400


@app.post("/chat")
@require_artifact
def chat():
    data = request.get_json() or {}
    artifact_b64 = request.headers["Authorization"][len("Artifact "):]
    try:
        result = get_client().chat.create(artifact_b64, {"prompt": data.get("prompt", "")})
        return jsonify(result)
    except QodiqaError as exc:
        return jsonify({"error": exc.message}), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)
