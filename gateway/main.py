from __future__ import annotations

import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from models import TimestampToken, ClusterStatus
from orchestrator import Orchestrator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

THRESHOLD = int(os.getenv("THRESHOLD", "3"))
MAX_SIGNERS = int(os.getenv("MAX_SIGNERS", "5"))
AGGREGATOR_URL = os.getenv("AGGREGATOR_URL", "http://aggregator:8082")

app = FastAPI(title="FROST Timestamp Authority", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = Orchestrator(
    threshold=THRESHOLD,
    max_signers=MAX_SIGNERS,
    aggregator_url=AGGREGATOR_URL,
)


class RegisterRequest(BaseModel):
    callback_url: str
    x25519_pub_key: str


class RegisterResponse(BaseModel):
    participant_id: int


class TimestampRequest(BaseModel):
    document_hash: str


class VerifyRequest(BaseModel):
    document_hash: str
    token: TimestampToken


# --- Registration ---

@app.post("/api/register", response_model=RegisterResponse)
async def register_signer(req: RegisterRequest):
    pid = orchestrator.register_signer(req.callback_url, req.x25519_pub_key)
    logger.info(f"Signer registered: participant_id={pid}, url={req.callback_url}")
    return RegisterResponse(participant_id=pid)


# --- DKG ---

@app.post("/api/dkg/start")
async def start_dkg():
    if not orchestrator.registration_complete:
        raise HTTPException(400, "Not all signers registered yet")
    if orchestrator.dkg_complete:
        return {"status": "already_complete"}
    try:
        result = await orchestrator.run_dkg()
        return {"status": "complete", **result}
    except Exception as e:
        logger.error(f"DKG failed: {e}", exc_info=True)
        raise HTTPException(500, f"DKG failed: {e}")


# --- Timestamping ---

@app.post("/api/timestamp", response_model=TimestampToken)
async def create_timestamp(req: TimestampRequest):
    if not orchestrator.dkg_complete:
        raise HTTPException(400, "DKG not complete — cluster not ready")
    try:
        token = await orchestrator.create_timestamp(req.document_hash)
        return token
    except Exception as e:
        logger.error(f"Timestamp failed: {e}", exc_info=True)
        raise HTTPException(500, f"Timestamping failed: {e}")


# --- Verification ---

@app.post("/api/verify")
async def verify_timestamp(req: VerifyRequest):
    if not orchestrator.dkg_complete:
        raise HTTPException(400, "DKG not complete — cluster not ready")
    try:
        result = await orchestrator.verify_token(req.document_hash, req.token)
        return result
    except Exception as e:
        logger.error(f"Verification failed: {e}", exc_info=True)
        raise HTTPException(500, f"Verification failed: {e}")


# --- Status ---

@app.get("/api/status", response_model=ClusterStatus)
async def cluster_status():
    return orchestrator.get_status()


# --- Frontend ---

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def index():
    return FileResponse("static/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
