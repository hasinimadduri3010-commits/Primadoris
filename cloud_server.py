"""
cloud_server.py - FastAPI Trusted Cloud Server.

Port: 8000
Responsibilities:
- Model attestation with single-use challenge nonces and HMAC quotes   (Layer 2)
- Node state management and token revocation / quarantine               (Layer 3 response)
- Split inference decision head (CloudHead)                             (Layer 4)
- Central audit event logging
"""

import json
import math
import time
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import torch
import uvicorn
from fastapi import FastAPI, HTTPException, status, Query
from pydantic import BaseModel

from config import (
    GOLDEN_PATH,
    CLOUD_HEAD_PATH,
    DEVICE_KEY,
)
from split_model import CloudHead
from attestation import verify_quote

# -----------------------------------------------------------------------------
# In-Memory State
# -----------------------------------------------------------------------------
# Nonces: nonce_str -> {"device_id": str, "created_at": float, "used": bool}
nonces: Dict[str, Dict[str, Any]] = {}
NONCE_EXPIRE_SEC = 60
NONCE_CLEANUP_SEC = 300  # forget very old nonces so memory doesn't grow

# Tokens: token_str -> {"device_id": str, "created_at": float, "expires_at": float, "revoked": bool}
tokens: Dict[str, Dict[str, Any]] = {}
TOKEN_EXPIRE_SEC = 600  # 10 minutes

# Node statuses: device_id -> {"status": str, "reason": str, "last_seen": str}
nodes: Dict[str, Dict[str, str]] = {}

# Central event log
events: List[Dict[str, Any]] = []

# Golden hash (from factory provisioning) and the cloud-side decision head
golden_hash: str = ""
cloud_head: Optional[CloudHead] = None

# Embedding anomaly threshold (L2 norm)
MAX_EMBEDDING_NORM = 50.0


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def now_iso() -> str:
    """Current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def log_event(source: str, layer: int, level: str, message: str) -> Dict[str, Any]:
    """Central logging helper. Record: {"ts","source","layer" 1-4,"level","message"}."""
    record = {
        "ts": now_iso(),
        "source": source,
        "layer": layer,
        "level": level,
        "message": message,
    }
    events.append(record)
    return record


def update_node(device_id: str, status_str: str, reason_str: str):
    """Updates in-memory node status and last_seen timestamp."""
    nodes[device_id] = {
        "status": status_str,
        "reason": reason_str,
        "last_seen": now_iso(),
    }


def revoke_tokens(device_id: str) -> int:
    """Revokes every active token belonging to a device. Returns how many were revoked."""
    count = 0
    for tok_data in tokens.values():
        if tok_data["device_id"] == device_id and not tok_data["revoked"]:
            tok_data["revoked"] = True
            count += 1
    return count


def load_artifacts(quiet: bool = False):
    """Loads the golden hash (GOLDEN_PATH) and the decision head (CLOUD_HEAD_PATH)."""
    global golden_hash, cloud_head

    # 1. Golden hash (Layer 2)
    if GOLDEN_PATH.exists():
        try:
            with open(GOLDEN_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            golden_hash = data.get("weights_sha256", "").strip().lower()
            if not quiet:
                log_event("cloud", 2, "info", f"Loaded golden hash: {golden_hash[:12]}...")
        except Exception as exc:
            log_event("cloud", 2, "critical", f"Failed to load golden hash: {exc}")
    else:
        log_event("cloud", 2, "warn", f"Golden path not found at {GOLDEN_PATH}. Run train_model.py.")

    # 2. CloudHead (Layer 4)
    head = CloudHead()
    if CLOUD_HEAD_PATH.exists():
        try:
            state_dict = torch.load(CLOUD_HEAD_PATH, map_location="cpu", weights_only=True)
            head.load_state_dict(state_dict)
            if not quiet:
                log_event("cloud", 4, "info", "Loaded CloudHead decision model weights.")
        except Exception as exc:
            log_event("cloud", 4, "critical", f"Failed to load CloudHead weights: {exc}")
    else:
        log_event("cloud", 4, "warn", f"CloudHead path not found at {CLOUD_HEAD_PATH}. Run train_model.py.")

    head.eval()
    cloud_head = head


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Runs once when the server starts (also when TestClient is used as a context manager)."""
    load_artifacts()
    log_event("cloud", 2, "info", "Cloud server started on port 8000.")
    yield


app = FastAPI(
    title="SentinelEdge AI Cloud Server",
    description="Trusted cloud backend for model attestation, split inference, and event logging.",
    version="1.0.0",
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class VerifyRequest(BaseModel):
    device_id: str
    nonce: str
    weights_hash: str
    signature: str


class VerifyResponse(BaseModel):
    ok: bool
    token: Optional[str] = None
    reason: str


class InferRequest(BaseModel):
    device_id: str
    token: str
    embedding: List[float]


class InferResponse(BaseModel):
    prediction: int
    confidence: float


class QuarantineRequest(BaseModel):
    device_id: str
    reason: str


class ResetRequest(BaseModel):
    device_id: str


class EventRequest(BaseModel):
    source: str
    layer: int
    level: str
    message: str


def reject_attestation(device_id: str, reason: str, level: str, detail: str) -> VerifyResponse:
    """Common failure path: revoke old tokens, mark REJECTED, log, return the failure response."""
    revoked = revoke_tokens(device_id)
    update_node(device_id, "REJECTED", reason)
    extra = f" Revoked {revoked} active token(s)." if revoked else ""
    log_event("cloud", 2, level, f"Attestation rejected for '{device_id}': {detail}{extra}")
    return VerifyResponse(ok=False, token=None, reason=reason)


# -----------------------------------------------------------------------------
# Cloud API Endpoints
# -----------------------------------------------------------------------------
@app.get("/attest/challenge", summary="Request Attestation Challenge Nonce")
async def get_challenge(device_id: str = Query(..., description="Target device ID")):
    """Generates a random single-use nonce for the device. It expires in 60 seconds."""
    now = time.time()
    for old in [n for n, d in nonces.items() if now - d["created_at"] > NONCE_CLEANUP_SEC]:
        del nonces[old]

    nonce = secrets.token_hex(16)
    nonces[nonce] = {"device_id": device_id, "created_at": now, "used": False}

    if device_id not in nodes:
        update_node(device_id, "UNKNOWN", "challenge requested")
    else:
        nodes[device_id]["last_seen"] = now_iso()

    log_event("cloud", 2, "info", f"Issued single-use challenge nonce for device '{device_id}'.")
    return {"nonce": nonce}


@app.post("/attest/verify", response_model=VerifyResponse, summary="Verify Attestation Quote")
async def post_verify(payload: VerifyRequest):
    """
    1. Checks nonce exists, is unused, is not expired and belongs to this device.
    2. Verifies the HMAC quote with DEVICE_KEY.
    3. Compares weights_hash to the factory golden hash.
    Success: issues a 10-minute token, node TRUSTED.
    Failure: revokes the device's old tokens, node REJECTED with a clear reason.
    """
    now = time.time()
    device_id = payload.device_id

    # 1. Nonce checks
    nonce_data = nonces.get(payload.nonce)
    if nonce_data is None:
        return reject_attestation(device_id, "replayed nonce", "warn", "replayed nonce (unknown or expired nonce).")
    if nonce_data["used"]:
        return reject_attestation(device_id, "replayed nonce", "warn", "replayed nonce (already used).")
    if now - nonce_data["created_at"] > NONCE_EXPIRE_SEC:
        nonce_data["used"] = True
        return reject_attestation(device_id, "replayed nonce", "warn", "nonce expired (older than 60s).")
    if nonce_data["device_id"] != device_id:
        nonce_data["used"] = True
        return reject_attestation(device_id, "replayed nonce", "warn", "nonce was issued to a different device.")

    # Consume the nonce immediately so it can never be reused
    nonce_data["used"] = True

    # 2. Signature check (simulated TPM quote)
    if not verify_quote(DEVICE_KEY, payload.nonce, payload.weights_hash, payload.signature):
        return reject_attestation(device_id, "bad signature", "critical", "bad signature (HMAC mismatch).")

    # 3. Compare model weights hash to the factory golden hash
    if not golden_hash:
        load_artifacts(quiet=True)
    if not golden_hash:
        return reject_attestation(device_id, "golden hash missing", "critical", "cloud has no golden hash (run train_model.py).")

    if payload.weights_hash.strip().lower() != golden_hash:
        return reject_attestation(
            device_id,
            "hash mismatch",
            "critical",
            f"hash mismatch. Received {payload.weights_hash[:12]}..., expected {golden_hash[:12]}...",
        )

    # 4. Verified: issue token and mark TRUSTED
    token = secrets.token_hex(32)
    tokens[token] = {
        "device_id": device_id,
        "created_at": now,
        "expires_at": now + TOKEN_EXPIRE_SEC,
        "revoked": False,
    }
    update_node(device_id, "TRUSTED", "attestation verified")
    log_event("cloud", 2, "info", f"Attestation verified for device '{device_id}'. Issued session token.")
    return VerifyResponse(ok=True, token=token, reason="verified")


@app.post("/infer", response_model=InferResponse, summary="Execute Split Inference Tail")
async def post_infer(payload: InferRequest):
    """Receives the edge embedding and returns the final prediction (Layer 4)."""
    now = time.time()
    device_id = payload.device_id

    def deny(detail: str, log_msg: str):
        log_event("cloud", 4, "warn", f"Inference rejected for '{device_id}': {log_msg}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    # 1. Token validation
    token_data = tokens.get(payload.token)
    if token_data is None:
        deny("invalid token", "token missing or invalid.")
    if token_data["revoked"]:
        deny("token revoked", "token revoked.")
    if now > token_data["expires_at"]:
        deny("token expired", "token expired.")
    if token_data["device_id"] != device_id:
        deny("token device mismatch", "token does not belong to this device.")

    current_status = nodes.get(device_id, {}).get("status", "UNKNOWN")
    if current_status in ("QUARANTINED", "REJECTED"):
        deny(f"device {current_status.lower()}", f"device state is {current_status}.")

    # 2. Embedding sanity checks (the cloud must not blindly trust the edge)
    embedding = payload.embedding
    if len(embedding) != 32:
        deny(
            f"wrong embedding length: expected 32, got {len(embedding)}",
            f"wrong embedding length {len(embedding)} (expected 32).",
        )
    if any(math.isnan(x) or math.isinf(x) for x in embedding):
        deny("embedding contains NaN or Inf", "embedding contains NaN or Inf.")
    norm = math.sqrt(sum(x * x for x in embedding))
    if norm > MAX_EMBEDDING_NORM:
        deny(
            f"abnormally large embedding norm: {norm:.2f}",
            f"abnormally large norm ({norm:.2f} > {MAX_EMBEDDING_NORM}).",
        )

    # 3. Run the decision head
    if cloud_head is None:
        load_artifacts(quiet=True)
    try:
        with torch.no_grad():
            emb_tensor = torch.tensor([embedding], dtype=torch.float32)
            probs = torch.softmax(cloud_head(emb_tensor), dim=1)
            pred_class = int(torch.argmax(probs, dim=1).item())
            confidence = float(probs[0, pred_class].item())
    except Exception as exc:
        log_event("cloud", 4, "critical", f"Inference forward pass failed: {exc}")
        raise HTTPException(status_code=500, detail="Inference computation error")

    update_node(device_id, "TRUSTED", "inference completed")
    log_event("cloud", 4, "info", f"Inference computed for '{device_id}': class {pred_class} (confidence {confidence:.4f}).")
    return InferResponse(prediction=pred_class, confidence=round(confidence, 4))


@app.post("/quarantine", summary="Quarantine Edge Device")
async def post_quarantine(payload: QuarantineRequest):
    """Quarantines an edge device and revokes all of its tokens."""
    revoked = revoke_tokens(payload.device_id)
    update_node(payload.device_id, "QUARANTINED", payload.reason)
    log_event(
        "cloud",
        3,
        "critical",
        f"Quarantined device '{payload.device_id}': {payload.reason}. Revoked {revoked} active token(s).",
    )
    return {"ok": True}


@app.post("/reset", summary="Reset Device State")
async def post_reset(payload: ResetRequest):
    """Demo reset: revoke tokens, node back to UNKNOWN, reload golden hash and head."""
    revoke_tokens(payload.device_id)
    update_node(payload.device_id, "UNKNOWN", "demo reset")
    load_artifacts(quiet=True)
    log_event("cloud", 2, "info", f"Reset state for device '{payload.device_id}'.")
    return {"ok": True}


@app.get("/nodes", summary="List All Edge Node Statuses")
async def get_nodes():
    """Status, reason and last_seen for every known edge device."""
    return nodes


@app.post("/events", summary="Submit Central Event")
async def post_event(payload: EventRequest):
    """Appends an event record from scanner, cloud, edge, or dashboard."""
    record = log_event(payload.source, payload.layer, payload.level, payload.message)
    return {"ok": True, "event": record}


@app.get("/events", summary="Query Event Log")
async def get_events(limit: int = Query(50, description="Max number of events to return (newest first)")):
    """Central audit log, newest first."""
    return list(reversed(events))[:limit]


# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
