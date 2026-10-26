"""
api_client.py
=============
Client library for SentinelEdge AI dashboard per ARCHITECTURE.md.
Connects the Streamlit UI to:
  - Cloud Server (FastAPI, Port 8000)
  - Edge Agent (FastAPI, Port 8001)

Maintains an in-memory Live API Communication Log ring-buffer for Judge Transparency.
"""

import requests
import json
import time
from typing import Dict, Any, List, Optional
import config

# In-memory communication log buffer
API_COMMUNICATION_LOG: List[str] = []
MAX_LOG_ENTRIES = 100


def _log_wire_exchange(method: str, url: str, req_body: Optional[Any], status_code: Optional[int], resp_data: Optional[Any], error: Optional[str] = None):
    """Formats and records an HTTP wire transaction in terminal style."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time()*1000)%1000:03d}Z"
    
    lines = []
    lines.append(f">>> [{ts}] HTTP REQUEST: {method.upper()} {url}")
    lines.append(f"    Host: {url.split('/')[2]}")
    lines.append("    User-Agent: SentinelEdge-Dashboard/1.0 (Streamlit Port 8501)")
    lines.append("    Accept: application/json")
    if req_body is not None:
        lines.append("    Content-Type: application/json")
        body_json = json.dumps(req_body, indent=2)
        indented_body = "\n".join("      " + line for line in body_json.splitlines())
        lines.append(f"    Payload:\n{indented_body}")
    
    if error:
        lines.append(f"<<< [{ts}] CONNECTION FAILURE -> {error}")
    else:
        lines.append(f"<<< [{ts}] HTTP RESPONSE: Status {status_code} OK")
        lines.append("    Content-Type: application/json")
        if resp_data is not None:
            resp_json = json.dumps(resp_data, indent=2) if isinstance(resp_data, (dict, list)) else str(resp_data)
            indented_resp = "\n".join("      " + line for line in resp_json.splitlines())
            lines.append(f"    Response Body:\n{indented_resp}")
    
    lines.append("-" * 75)
    
    entry = "\n".join(lines)
    API_COMMUNICATION_LOG.append(entry)
    if len(API_COMMUNICATION_LOG) > MAX_LOG_ENTRIES:
        API_COMMUNICATION_LOG.pop(0)


def get_api_communication_log() -> str:
    """Returns the full live API communication log as a single string."""
    if not API_COMMUNICATION_LOG:
        return "[API LOG INITIALIZED] Awaiting requests between Dashboard (:8501), Cloud (:8000), and Edge (:8001)..."
    return "\n\n".join(reversed(API_COMMUNICATION_LOG))


def clear_api_communication_log():
    """Clears the live communication log."""
    global API_COMMUNICATION_LOG
    API_COMMUNICATION_LOG = []


# =====================================================================
# CLOUD API CLIENT (PORT 8000)
# =====================================================================

def cloud_get_challenge(device_id: str = config.DEFAULT_DEVICE_ID, timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/attest/challenge?device_id={device_id}"
    try:
        resp = requests.get(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("GET", url, None, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("GET", url, None, None, None, error=str(e))
        return {"error": str(e), "nonce": None}


def cloud_verify_attestation(device_id: str, nonce: str, weights_hash: str, signature: str, timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/attest/verify"
    payload = {
        "device_id": device_id,
        "nonce": nonce,
        "weights_hash": weights_hash,
        "signature": signature
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"ok": False, "token": None, "reason": f"Connection error: {str(e)}"}


def cloud_infer(device_id: str, token: str, embedding: List[float], timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/infer"
    payload = {
        "device_id": device_id,
        "token": token,
        "embedding": embedding
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"error": str(e)}


def cloud_quarantine(device_id: str, reason: str, timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/quarantine"
    payload = {"device_id": device_id, "reason": reason}
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"ok": False, "error": str(e)}


def cloud_reset(device_id: str = config.DEFAULT_DEVICE_ID, timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/reset"
    payload = {"device_id": device_id}
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"ok": False, "error": str(e)}


def cloud_get_nodes(timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/nodes"
    try:
        resp = requests.get(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("GET", url, None, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("GET", url, None, None, None, error=str(e))
        return {}


def cloud_get_events(limit: int = 50, timeout: float = 0.5) -> List[Dict[str, Any]]:
    url = f"{config.CLOUD_URL}/events?limit={limit}"
    try:
        resp = requests.get(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("GET", url, None, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("GET", url, None, None, None, error=str(e))
        return []


def cloud_post_event(source: str, layer: int, level: str, message: str, timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.CLOUD_URL}/events"
    payload = {"source": source, "layer": layer, "level": level, "message": message}
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"error": str(e)}


# =====================================================================
# EDGE API CLIENT (PORT 8001)
# =====================================================================

def edge_get_status(timeout: float = 0.5) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/status"
    try:
        resp = requests.get(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("GET", url, None, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("GET", url, None, None, None, error=str(e))
        return {"state": "OFFLINE", "error": str(e)}


def edge_boot(timeout: float = 1.0) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/boot"
    try:
        resp = requests.post(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, {}, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, {}, None, None, error=str(e))
        return {"ok": False, "state": "OFFLINE", "reason": str(e)}


def edge_reattest(timeout: float = 1.0) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/reattest"
    try:
        resp = requests.post(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, {}, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, {}, None, None, error=str(e))
        return {"ok": False, "reason": str(e)}


def edge_infer(sample_index: int = 0, timeout: float = 1.0) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/infer"
    payload = {"sample_index": sample_index}
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, payload, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, payload, None, None, error=str(e))
        return {"ok": False, "reason": str(e)}


def edge_attack(kind: str, timeout: float = 1.0) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/attack/{kind}"
    try:
        resp = requests.post(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, {}, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, {}, None, None, error=str(e))
        return {"ok": False, "detail": str(e)}


def edge_attack_reset(timeout: float = 1.0) -> Dict[str, Any]:
    url = f"{config.EDGE_URL}/attack/reset"
    try:
        resp = requests.post(url, timeout=timeout)
        data = resp.json()
        _log_wire_exchange("POST", url, {}, resp.status_code, data)
        return data
    except Exception as e:
        _log_wire_exchange("POST", url, {}, None, None, error=str(e))
        return {"ok": False, "detail": str(e)}
