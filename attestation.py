"""
attestation.py - Cryptographic Attestation Protocol for Edge Devices.

Implements model weights integrity hashing, quote generation (simulating
a TPM quote with HMAC-SHA256), verification, and the attestation handshake.
"""

import hashlib
import hmac
from typing import Dict, Any

import requests

HTTP_TIMEOUT_SEC = 5  # short, so a missing cloud server fails fast on stage


def compute_weights_hash(state_dict: dict) -> str:
    """
    Deterministic SHA-256 over every tensor in the state dict.

    For each key (sorted) we hash: key name, dtype, shape, then the raw tensor bytes.
    That means a flipped bit, a changed shape or a changed dtype all change the digest.
    Call this on the LIVE model's state_dict to catch in-memory tampering.
    """
    hasher = hashlib.sha256()
    for key in sorted(state_dict.keys()):
        tensor = state_dict[key]
        if hasattr(tensor, "detach"):  # torch tensor
            arr = tensor.detach().cpu().contiguous()
            hasher.update(f"{key}|{arr.dtype}|{list(arr.shape)}|".encode("utf-8"))
            hasher.update(arr.numpy().tobytes())
        elif hasattr(tensor, "tobytes"):  # numpy array
            hasher.update(f"{key}|{tensor.dtype}|{list(tensor.shape)}|".encode("utf-8"))
            hasher.update(tensor.tobytes())
        else:  # raw bytes fallback
            hasher.update(f"{key}|raw|".encode("utf-8"))
            hasher.update(bytes(tensor))
    return hasher.hexdigest()


def make_quote(key: bytes, nonce: str, weights_hash: str) -> str:
    """
    Simulates a hardware TPM (Trusted Platform Module) quote.
    Generates an HMAC-SHA256 signature using the device's sealed key over
    the challenge nonce and the model weights hash.
    In production the key never leaves the TPM and the TPM measures the state itself.
    """
    msg = f"{nonce}:{weights_hash}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_quote(key: bytes, nonce: str, weights_hash: str, signature: str) -> bool:
    """
    Verifies the simulated TPM quote with a constant-time comparison.
    Compares BYTES, so garbage or non-ASCII signatures return False instead of raising.
    """
    expected = make_quote(key, nonce, weights_hash).encode("utf-8")
    provided = str(signature).strip().lower().encode("utf-8")
    return hmac.compare_digest(expected, provided)


def run_handshake(
    cloud_url: str,
    device_id: str,
    key: bytes,
    state_dict: dict,
) -> Dict[str, Any]:
    """
    Executes the attestation handshake with the cloud server:
    1. Computes local weights SHA-256 hash.
    2. Requests a challenge nonce via GET /attest/challenge?device_id=...
    3. Generates a TPM quote (HMAC-SHA256) over the nonce and weights_hash.
    4. Submits verification request to POST /attest/verify.

    Returns:
        {"ok": bool, "token": str | None, "reason": str}
    Never raises.
    """
    try:
        weights_hash = compute_weights_hash(state_dict)
        base = cloud_url.rstrip("/")

        # Step 1: Request challenge nonce
        resp = requests.get(
            f"{base}/attest/challenge",
            params={"device_id": device_id},
            timeout=HTTP_TIMEOUT_SEC,
        )
        if resp.status_code != 200:
            return {
                "ok": False,
                "token": None,
                "reason": f"Challenge request failed with HTTP {resp.status_code}: {resp.text}",
            }

        nonce = resp.json().get("nonce")
        if not nonce:
            return {"ok": False, "token": None, "reason": "Cloud response missing challenge nonce."}

        # Step 2: Sign quote simulating TPM
        signature = make_quote(key, nonce, weights_hash)

        # Step 3: Submit verification quote to cloud
        payload = {
            "device_id": device_id,
            "nonce": nonce,
            "weights_hash": weights_hash,
            "signature": signature,
        }
        v_resp = requests.post(f"{base}/attest/verify", json=payload, timeout=HTTP_TIMEOUT_SEC)
        if v_resp.status_code == 200:
            data = v_resp.json()
            return {
                "ok": bool(data.get("ok", False)),
                "token": data.get("token"),
                "reason": data.get("reason", ""),
            }
        return {
            "ok": False,
            "token": None,
            "reason": f"Verification failed with HTTP {v_resp.status_code}: {v_resp.text}",
        }
    except requests.exceptions.RequestException as exc:
        return {"ok": False, "token": None, "reason": f"cloud unreachable ({exc.__class__.__name__})"}
    except Exception as exc:
        return {"ok": False, "token": None, "reason": str(exc)}
