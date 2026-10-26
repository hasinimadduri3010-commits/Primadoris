"""API client for the Primadoris / SentinelEdge AI dashboard.

This module is the ONLY way the dashboard talks to the Edge and Cloud backends.
When ``USE_MOCK = True``, all calls are served by a realistic in-memory simulation.
When ``USE_MOCK = False``, calls hit the live Cloud and Edge FastAPI services
configured in ``config.py`` using ``requests`` with ``timeout=3``.
No function ever raises an exception; failures always return ``{"error": "<message>"}``.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

import config

USE_MOCK = True
REQUEST_TIMEOUT = 3

# ---------------------------------------------------------------------------
# In-memory simulation state (used when USE_MOCK = True)
# ---------------------------------------------------------------------------

_GOLDEN_HASH = hashlib.sha256(b"primadoris-factory-golden-edge-extractor-v1").hexdigest()
_TAMPERED_HASH = hashlib.sha256(b"tampered-malicious-weights-payload").hexdigest()

_DEMO_SAMPLES: List[Dict[str, Any]] = [
    {
        "sample_index": 0,
        "name": "Normal Telemetry #0 (Turbine Vibration)",
        "true_label": "NORMAL",
        "predicted_label": "NORMAL",
        "confidence": 0.982,
        "features": [0.12, -0.04, 0.31, 0.08, -0.11, 0.25, 0.03, -0.07],
    },
    {
        "sample_index": 1,
        "name": "Anomaly Probe #1 (Bearing Overheat)",
        "true_label": "ANOMALY",
        "predicted_label": "ANOMALY",
        "confidence": 0.946,
        "features": [1.85, 2.10, -1.42, 1.77, 2.31, -0.95, 1.64, 2.02],
    },
    {
        "sample_index": 2,
        "name": "Normal Telemetry #2 (Steady Pressure)",
        "true_label": "NORMAL",
        "predicted_label": "NORMAL",
        "confidence": 0.971,
        "features": [0.05, 0.09, -0.02, 0.14, -0.06, 0.11, 0.04, 0.01],
    },
    {
        "sample_index": 3,
        "name": "Anomaly Probe #3 (Voltage Spike)",
        "true_label": "ANOMALY",
        "predicted_label": "ANOMALY",
        "confidence": 0.918,
        "features": [-2.04, 1.92, 2.45, -1.68, 1.55, 2.12, -1.89, 1.74],
    },
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _initial_mock_state() -> Dict[str, Any]:
    now = _utc_now()
    return {
        "device_id": config.DEVICE_ID,
        "state": "RUNNING",  # RUNNING | QUARANTINED | LOCKED_DOWN
        "weights_hash": _GOLDEN_HASH,
        "golden_hash": _GOLDEN_HASH,
        "hash_match": True,
        "file_tampered": False,
        "memory_drift_active": False,
        "token_valid": True,
        "session_token": "tok-edge01-7f9a2c4e",
        "drift_history": [0.009, 0.011, 0.010, 0.012, 0.008, 0.010, 0.011, 0.009],
        "last_attestation": now,
        "updated_at": now,
        "events": [
            {
                "id": 1,
                "timestamp": now,
                "device_id": config.DEVICE_ID,
                "source": "edge",
                "layer": "Layer 2 - Attestation",
                "level": "INFO",
                "message": f"Verified edge_extractor.pt SHA-256 ({_GOLDEN_HASH[:12]}...) against golden.json.",
            },
            {
                "id": 2,
                "timestamp": now,
                "device_id": config.DEVICE_ID,
                "source": "cloud",
                "layer": "Layer 2 - Attestation",
                "level": "INFO",
                "message": f"HMAC attestation succeeded for {config.DEVICE_ID}. Node state -> RUNNING.",
            },
            {
                "id": 3,
                "timestamp": now,
                "device_id": config.DEVICE_ID,
                "source": "edge",
                "layer": "Layer 3 - Canary Probing",
                "level": "INFO",
                "message": "Canary embedding baseline verified (relative drift = 0.009 < 0.10).",
            },
        ],
    }


_MOCK: Dict[str, Any] = _initial_mock_state()


def _append_mock_event(source: str, layer: str, level: str, message: str) -> Dict[str, Any]:
    event_id = len(_MOCK["events"]) + 1
    evt = {
        "id": event_id,
        "timestamp": _utc_now(),
        "device_id": config.DEVICE_ID,
        "source": str(source),
        "layer": str(layer),
        "level": str(level).upper(),
        "message": str(message),
    }
    _MOCK["events"].append(evt)
    _MOCK["updated_at"] = evt["timestamp"]
    return evt


def _step_mock_drift() -> float:
    """Advance simulated canary drift one tick and return current drift."""
    if _MOCK["state"] == "LOCKED_DOWN":
        current = _MOCK["drift_history"][-1] if _MOCK["drift_history"] else 0.0
        return float(current)

    if _MOCK["memory_drift_active"]:
        last = _MOCK["drift_history"][-1] if _MOCK["drift_history"] else 0.12
        next_val = min(0.35, round(max(0.12, last + random.uniform(0.005, 0.025)), 4))
        _MOCK["drift_history"].append(next_val)
        if next_val >= config.CANARY_DRIFT_THRESHOLD and _MOCK["state"] != "QUARANTINED":
            _MOCK["state"] = "QUARANTINED"
            _MOCK["token_valid"] = False
            _append_mock_event(
                source="cloud",
                layer="Layer 3 - Canary Probing",
                level="CRITICAL",
                message=(
                    f"Canary drift {next_val:.3f} exceeded threshold "
                    f"{config.CANARY_DRIFT_THRESHOLD:.2f}. Node QUARANTINED and token revoked."
                ),
            )
    else:
        next_val = round(random.uniform(0.007, 0.014), 4)
        _MOCK["drift_history"].append(next_val)

    if len(_MOCK["drift_history"]) > 40:
        _MOCK["drift_history"] = _MOCK["drift_history"][-40:]

    _MOCK["updated_at"] = _utc_now()
    return float(_MOCK["drift_history"][-1])


def _build_mock_status(step_drift: bool = True) -> Dict[str, Any]:
    current_drift = _step_mock_drift() if step_drift else float(_MOCK["drift_history"][-1])
    return {
        "device_id": _MOCK["device_id"],
        "state": _MOCK["state"],
        "drift": current_drift,
        "current_drift": current_drift,
        "drift_threshold": config.CANARY_DRIFT_THRESHOLD,
        "drift_history": list(_MOCK["drift_history"]),
        "weights_hash": _MOCK["weights_hash"],
        "golden_hash": _MOCK["golden_hash"],
        "hash_match": _MOCK["hash_match"],
        "file_tampered": _MOCK["file_tampered"],
        "memory_drift_active": _MOCK["memory_drift_active"],
        "token_valid": _MOCK["token_valid"],
        "session_token": _MOCK["session_token"] if _MOCK["token_valid"] else None,
        "last_attestation": _MOCK["last_attestation"],
        "updated_at": _MOCK["updated_at"],
    }


# ---------------------------------------------------------------------------
# Safe HTTP request helper (used when USE_MOCK = False)
# ---------------------------------------------------------------------------

def _safe_request(method: str, url: str, **kwargs: Any) -> Any:
    """Perform an HTTP request with timeout=3 and never raise."""
    try:
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        response = requests.request(method, url, **kwargs)
        if response.status_code >= 400:
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    err_msg = payload.get("error") or payload.get("detail") or f"HTTP {response.status_code}"
                    return {"error": str(err_msg)}
            except Exception:
                pass
            return {"error": f"HTTP {response.status_code}: {response.text.strip() or response.reason}"}

        if not response.content:
            return {"status": "ok"}
        return response.json()
    except Exception as exc:
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Public API functions
# ---------------------------------------------------------------------------

def get_edge_status() -> Dict[str, Any]:
    """Fetch current status and canary telemetry from the Edge service."""
    try:
        if USE_MOCK:
            return _build_mock_status(step_drift=True)

        data = _safe_request("GET", f"{config.EDGE_URL}/status")
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /status"}
    except Exception as exc:
        return {"error": str(exc)}


def get_nodes() -> Dict[str, Any]:
    """Fetch registered edge nodes and their attestation state from the Cloud service."""
    try:
        if USE_MOCK:
            status = _build_mock_status(step_drift=False)
            node_info = {
                "device_id": status["device_id"],
                "state": status["state"],
                "drift": status["drift"],
                "drift_threshold": status["drift_threshold"],
                "weights_hash": status["weights_hash"],
                "golden_hash": status["golden_hash"],
                "hash_match": status["hash_match"],
                "token_valid": status["token_valid"],
                "last_attestation": status["last_attestation"],
                "updated_at": status["updated_at"],
            }
            return {
                "nodes": [node_info],
                "count": 1,
            }

        data = _safe_request("GET", f"{config.CLOUD_URL}/nodes")
        if isinstance(data, list):
            return {"nodes": data, "count": len(data)}
        if isinstance(data, dict):
            if "error" not in data and "nodes" not in data:
                nodes_list = [
                    v if isinstance(v, dict) else {"device_id": k, "state": v}
                    for k, v in data.items()
                ]
                return {"nodes": nodes_list, "count": len(nodes_list), **data}
            return data
        return {"error": "Unexpected response format from cloud /nodes"}
    except Exception as exc:
        return {"error": str(exc)}


def get_events(limit: int = 50) -> Dict[str, Any]:
    """Fetch security and attestation audit events (newest first)."""
    try:
        limit = max(1, int(limit))
        if USE_MOCK:
            events_desc = list(reversed(_MOCK["events"]))[:limit]
            return {"events": events_desc, "count": len(events_desc)}

        data = _safe_request("GET", f"{config.CLOUD_URL}/events", params={"limit": limit})
        if isinstance(data, list):
            return {"events": data[:limit], "count": len(data[:limit])}
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from cloud /events"}
    except Exception as exc:
        return {"error": str(exc)}


def post_event(source: str, layer: str, level: str, message: str) -> Dict[str, Any]:
    """Record a new audit event on the Cloud service."""
    try:
        if USE_MOCK:
            evt = _append_mock_event(source=source, layer=layer, level=level, message=message)
            return {"status": "ok", "event": evt}

        payload = {
            "device_id": config.DEVICE_ID,
            "source": source,
            "layer": layer,
            "level": level,
            "message": message,
        }
        data = _safe_request("POST", f"{config.CLOUD_URL}/events", json=payload)
        if isinstance(data, dict):
            return data
        return {"status": "ok"}
    except Exception as exc:
        return {"error": str(exc)}


def boot_node() -> Dict[str, Any]:
    """Trigger the Edge node boot sequence (disk hash check + Cloud attestation)."""
    try:
        if USE_MOCK:
            now = _utc_now()
            _MOCK["last_attestation"] = now
            if _MOCK["file_tampered"]:
                _MOCK["state"] = "LOCKED_DOWN"
                _MOCK["weights_hash"] = _TAMPERED_HASH
                _MOCK["hash_match"] = False
                _MOCK["token_valid"] = False
                _append_mock_event(
                    source="edge",
                    layer="Layer 2 - Attestation",
                    level="CRITICAL",
                    message=(
                        f"Secure boot FAILED! Disk weights hash ({_TAMPERED_HASH[:12]}...) "
                        f"does not match golden hash ({_GOLDEN_HASH[:12]}...). Node LOCKED_DOWN."
                    ),
                )
                _append_mock_event(
                    source="cloud",
                    layer="Layer 2 - Attestation",
                    level="CRITICAL",
                    message=f"Boot attestation rejected for {config.DEVICE_ID}: integrity failure -> LOCKED_DOWN.",
                )
            else:
                _MOCK["state"] = "RUNNING"
                _MOCK["weights_hash"] = _GOLDEN_HASH
                _MOCK["hash_match"] = True
                _MOCK["memory_drift_active"] = False
                _MOCK["token_valid"] = True
                _MOCK["session_token"] = f"tok-edge01-{random.randint(100000, 999999):06x}"
                _MOCK["drift_history"].append(round(random.uniform(0.008, 0.012), 4))
                if len(_MOCK["drift_history"]) > 40:
                    _MOCK["drift_history"] = _MOCK["drift_history"][-40:]
                _append_mock_event(
                    source="edge",
                    layer="Layer 2 - Attestation",
                    level="INFO",
                    message=f"Boot check passed: edge_extractor.pt matches golden hash ({_GOLDEN_HASH[:12]}...).",
                )
                _append_mock_event(
                    source="cloud",
                    layer="Layer 2 - Attestation",
                    level="INFO",
                    message=f"Node {config.DEVICE_ID} attested via TPM HMAC key. State -> RUNNING.",
                )
            return _build_mock_status(step_drift=False)

        data = _safe_request("POST", f"{config.EDGE_URL}/boot")
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /boot"}
    except Exception as exc:
        return {"error": str(exc)}


def reattest() -> Dict[str, Any]:
    """Request an immediate re-attestation handshake between Edge and Cloud."""
    try:
        if USE_MOCK:
            now = _utc_now()
            _MOCK["last_attestation"] = now
            if _MOCK["file_tampered"]:
                _MOCK["state"] = "LOCKED_DOWN"
                _MOCK["hash_match"] = False
                _MOCK["token_valid"] = False
                _append_mock_event(
                    source="edge",
                    layer="Layer 2 - Attestation",
                    level="CRITICAL",
                    message="Re-attestation failed: tampered weights detected on disk -> LOCKED_DOWN.",
                )
            elif _MOCK["memory_drift_active"]:
                _MOCK["state"] = "QUARANTINED"
                _MOCK["token_valid"] = False
                curr_drift = _MOCK["drift_history"][-1] if _MOCK["drift_history"] else 0.15
                _append_mock_event(
                    source="cloud",
                    layer="Layer 3 - Canary Probing",
                    level="WARNING",
                    message=(
                        f"Re-attestation denied: runtime canary drift ({curr_drift:.3f}) "
                        f"exceeds {config.CANARY_DRIFT_THRESHOLD:.2f}. Reset node to clear memory drift."
                    ),
                )
            else:
                _MOCK["state"] = "RUNNING"
                _MOCK["token_valid"] = True
                _MOCK["session_token"] = f"tok-edge01-{random.randint(100000, 999999):06x}"
                _append_mock_event(
                    source="cloud",
                    layer="Layer 2 - Attestation",
                    level="INFO",
                    message=f"Re-attestation verified for {config.DEVICE_ID}. Fresh session token issued.",
                )
            return _build_mock_status(step_drift=False)

        data = _safe_request("POST", f"{config.EDGE_URL}/reattest")
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /reattest"}
    except Exception as exc:
        return {"error": str(exc)}


def reset_node() -> Dict[str, Any]:
    """Restore Edge node weights and memory to the factory-provisioned golden state."""
    try:
        if USE_MOCK:
            now = _utc_now()
            _MOCK["state"] = "RUNNING"
            _MOCK["weights_hash"] = _GOLDEN_HASH
            _MOCK["golden_hash"] = _GOLDEN_HASH
            _MOCK["hash_match"] = True
            _MOCK["file_tampered"] = False
            _MOCK["memory_drift_active"] = False
            _MOCK["token_valid"] = True
            _MOCK["session_token"] = f"tok-edge01-{random.randint(100000, 999999):06x}"
            _MOCK["drift_history"] = [0.009, 0.011, 0.010, 0.009, 0.011, 0.010]
            _MOCK["last_attestation"] = now
            _append_mock_event(
                source="edge",
                layer="Layer 2 - Attestation",
                level="INFO",
                message="Node reset: restored golden edge_extractor.pt weights and cleared runtime memory.",
            )
            _append_mock_event(
                source="cloud",
                layer="Layer 2 - Attestation",
                level="INFO",
                message=f"Node {config.DEVICE_ID} re-provisioned and attested -> RUNNING.",
            )
            return _build_mock_status(step_drift=False)

        data = _safe_request("POST", f"{config.EDGE_URL}/reset")
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /reset"}
    except Exception as exc:
        return {"error": str(exc)}


def run_attack(kind: str) -> Dict[str, Any]:
    """Trigger a simulated adversary attack against the Edge node.

    Supported kinds:
    - ``"memory_drift"`` (or ``"bit_flip"``): perturbs in-memory weights so canary drift
      climbs past 0.10 and transitions the node to ``QUARANTINED``.
    - ``"tamper_file"``: corrupts ``edge_extractor.pt`` on disk so the next ``boot_node()``
      transitions the node to ``LOCKED_DOWN``.
    """
    try:
        kind_norm = (kind or "").strip().lower()
        if USE_MOCK:
            if kind_norm in ("memory_drift", "bit_flip", "silent_drift"):
                _MOCK["memory_drift_active"] = True
                _MOCK["drift_history"].extend([0.058, 0.114, 0.168, 0.212])
                if len(_MOCK["drift_history"]) > 40:
                    _MOCK["drift_history"] = _MOCK["drift_history"][-40:]
                _MOCK["state"] = "QUARANTINED"
                _MOCK["token_valid"] = False
                current_drift = _MOCK["drift_history"][-1]
                label = "bit-flip in runtime weight tensor" if kind_norm == "bit_flip" else "in-memory weight perturbation (memory_drift)"
                _append_mock_event(
                    source="attacker",
                    layer="Layer 3 - Canary Probing",
                    level="WARNING",
                    message=f"Attack injected: {label} on edge extractor.",
                )
                _append_mock_event(
                    source="edge",
                    layer="Layer 3 - Canary Probing",
                    level="CRITICAL",
                    message=(
                        f"Canary embedding drift spiked to {current_drift:.3f} "
                        f"(threshold {config.CANARY_DRIFT_THRESHOLD:.2f})!"
                    ),
                )
                _append_mock_event(
                    source="cloud",
                    layer="Layer 4 - Split Inference",
                    level="CRITICAL",
                    message=f"Zero-Trust Gate quarantined {config.DEVICE_ID} and revoked session token.",
                )
                status = _build_mock_status(step_drift=False)
                return {
                    "status": "attack_executed",
                    "attack": kind_norm,
                    "message": (
                        f"In-memory weights perturbed. Canary drift climbed to {current_drift:.3f} "
                        f"(> {config.CANARY_DRIFT_THRESHOLD:.2f}); node is now QUARANTINED."
                    ),
                    **status,
                }

            if kind_norm in ("tamper_file", "disk_tamper"):
                _MOCK["file_tampered"] = True
                _MOCK["weights_hash"] = _TAMPERED_HASH
                _MOCK["hash_match"] = False
                _append_mock_event(
                    source="attacker",
                    layer="Layer 2 - Attestation",
                    level="WARNING",
                    message=(
                        f"Attack injected: edge_extractor.pt overwritten on disk "
                        f"(new SHA-256: {_TAMPERED_HASH[:12]}...). Call boot_node() to trigger Secure Boot check."
                    ),
                )
                status = _build_mock_status(step_drift=False)
                return {
                    "status": "attack_executed",
                    "attack": "tamper_file",
                    "message": "Model file tampered on disk. Next boot_node() will trigger LOCKED_DOWN.",
                    **status,
                }

            return {"error": f"Unknown attack kind: '{kind}'. Expected 'memory_drift' or 'tamper_file'."}

        data = _safe_request("POST", f"{config.EDGE_URL}/attack", json={"kind": kind})
        if isinstance(data, dict) and "error" in data and "404" in data["error"]:
            data = _safe_request("POST", f"{config.EDGE_URL}/attack/{kind}")
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /attack"}
    except Exception as exc:
        return {"error": str(exc)}


def run_inference(sample_index: int) -> Dict[str, Any]:
    """Run split edge-to-cloud inference on a demo sample."""
    try:
        idx = int(sample_index)
        if USE_MOCK:
            sample = _DEMO_SAMPLES[idx % len(_DEMO_SAMPLES)]
            state = _MOCK["state"]
            current_drift = float(_MOCK["drift_history"][-1]) if _MOCK["drift_history"] else 0.01

            if state != "RUNNING":
                reason = (
                    f"Inference rejected by Cloud Zero-Trust Gate: node {config.DEVICE_ID} "
                    f"is {state} (session token revoked)."
                )
                _append_mock_event(
                    source="cloud",
                    layer="Layer 4 - Split Inference",
                    level="ERROR",
                    message=f"Blocked split-inference request for sample #{idx}: node is {state}.",
                )
                return {
                    "status": "blocked",
                    "allowed": False,
                    "blocked": True,
                    "state": state,
                    "device_id": config.DEVICE_ID,
                    "sample_index": idx,
                    "sample_name": sample["name"],
                    "reason": reason,
                    "error": reason,
                }

            latency_ms = round(random.uniform(11.5, 24.0), 2)
            _append_mock_event(
                source="cloud",
                layer="Layer 4 - Split Inference",
                level="INFO",
                message=(
                    f"Split inference sample #{idx} ({sample['name']}) -> "
                    f"{sample['predicted_label']} ({sample['confidence'] * 100:.1f}% conf, {latency_ms} ms)."
                ),
            )
            return {
                "status": "ok",
                "allowed": True,
                "blocked": False,
                "state": state,
                "device_id": config.DEVICE_ID,
                "sample_index": idx,
                "sample_name": sample["name"],
                "true_label": sample["true_label"],
                "prediction": sample["predicted_label"],
                "predicted_label": sample["predicted_label"],
                "confidence": sample["confidence"],
                "drift": current_drift,
                "hmac_verified": True,
                "latency_ms": latency_ms,
                "timestamp": _utc_now(),
            }

        data = _safe_request("POST", f"{config.EDGE_URL}/infer", json={"sample_index": idx})
        if isinstance(data, dict) and "error" in data and "404" in data["error"]:
            data = _safe_request("POST", f"{config.EDGE_URL}/inference", json={"sample_index": idx})
        if isinstance(data, dict):
            return data
        return {"error": "Unexpected response format from edge /infer"}
    except Exception as exc:
        return {"error": str(exc)}
