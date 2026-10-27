"""FastAPI integration — request signing and enforcement middleware.

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
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from qodiqa import AsyncQodiqaClient
from qodiqa.exceptions import AuthenticationError, QodiqaError, VerificationError

# ---------------------------------------------------------------------------
# App lifecycle — shared client
# ---------------------------------------------------------------------------

_client: AsyncQodiqaClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    _client = AsyncQodiqaClient(
        api_key=os.environ.get("QODIQA_API_KEY"),
        sign_token=os.environ.get("QODIQA_SIGN_TOKEN"),
        base_url=os.environ.get("QODIQA_BASE_URL", "http://localhost:3000"),
    )
    yield
    await _client.aclose()


app = FastAPI(title="QODIQA FastAPI Example", lifespan=lifespan)


def get_client() -> AsyncQodiqaClient:
    assert _client is not None, "Client not initialised"
    return _client


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SignRequest(BaseModel):
    path: str
    method: str = "POST"
    body: Dict[str, Any] = {}
    user_id: str = "anonymous"


class ChatRequest(BaseModel):
    prompt: str
    artifact_b64: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health(client: AsyncQodiqaClient = Depends(get_client)):
    return await client.health_check()


@app.post("/sign")
async def sign_request(
    req: SignRequest,
    client: AsyncQodiqaClient = Depends(get_client),
):
    try:
        # "provider" is only meaningful when req.path is /ai/chat, and only
        # required there once more than one AI provider is enabled
        # server-side (/sign auto-resolves it otherwise; 400
        # PROVIDER_REQUIRED if ambiguous). Not exposed as a request field
        # here for brevity — pass "payload": {"provider": "..."} if needed.
        signed = await client.sign.sign(
            {
                "request": {"method": req.method, "path": req.path, "body": req.body},
                "payload": {"userId": req.user_id},
                "ttl": 300_000,
            }
        )
        artifact_b64 = base64.b64encode(json.dumps(signed["artifact"]).encode()).decode()
        return {"artifactId": signed["artifactId"], "artifactB64": artifact_b64}
    except AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=exc.message)
    except QodiqaError as exc:
        raise HTTPException(status_code=400, detail=exc.message)


@app.post("/chat")
async def chat(
    req: ChatRequest,
    client: AsyncQodiqaClient = Depends(get_client),
):
    try:
        result = await client.chat.create(req.artifact_b64, {"prompt": req.prompt})
        return result
    except VerificationError as exc:
        raise HTTPException(status_code=403, detail=f"Verification failed: {exc.message}")
    except QodiqaError as exc:
        raise HTTPException(status_code=400, detail=exc.message)


@app.post("/verify")
async def verify(
    req: ChatRequest,
    client: AsyncQodiqaClient = Depends(get_client),
):
    verify_request = {
        "artifact": json.loads(base64.b64decode(req.artifact_b64)),
        "request": {"method": "POST", "path": "/chat", "body": {"prompt": req.prompt}},
    }
    try:
        result = await client.verify.verify(req.artifact_b64, verify_request)
        return result
    except VerificationError as exc:
        raise HTTPException(status_code=403, detail=exc.message)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
