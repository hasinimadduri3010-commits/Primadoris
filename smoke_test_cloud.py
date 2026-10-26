"""
smoke_test_cloud.py - Proof-of-correctness smoke tests for the Cloud Server attestation flow.

Tests run in-process via FastAPI TestClient (no external server needed).
Startup hooks fire inside `with TestClient(app) as client:`.

Tests:
1. Good handshake: correct hash + valid HMAC => ok=True, token, node TRUSTED
2. Wrong hash: tampered hash, valid HMAC => reason "hash mismatch", node REJECTED
3. Replayed nonce: reuse same nonce => reason "replayed nonce", node REJECTED
4. Bad signature: valid hash, tampered signature => reason "bad signature", node REJECTED
5. Happy-path /infer: fresh token + baseline embedding => 200, prediction int 0-9
6. /infer with 31-float embedding => 403
7. /quarantine then /infer with same token => 403, node QUARANTINED
8. Failed attestation revokes old token: attest bad hash, old token => 403
9. /reset => node UNKNOWN, old token => 403

Exit code 0 on full pass, non-zero on any failure.
"""

import json
import sys

from fastapi.testclient import TestClient

from cloud_server import app
from config import DEVICE_ID, DEVICE_KEY, GOLDEN_PATH, BASELINE_PATH
from attestation import make_quote

# ── Load golden hash from file (GOLDEN_PATH must exist) ─────────────────────
if not GOLDEN_PATH.exists():
    print("ERROR: models/golden.json not found. Run 'python train_model.py' first.")
    sys.exit(1)

with open(GOLDEN_PATH, "r", encoding="utf-8") as _f:
    _golden = json.load(_f)
GOLDEN_HASH: str = _golden["weights_sha256"].strip().lower()

# ── Load baseline embeddings ─────────────────────────────────────────────────
if not BASELINE_PATH.exists():
    print("ERROR: models/baseline.json not found. Run 'python train_model.py' first.")
    sys.exit(1)

with open(BASELINE_PATH, "r", encoding="utf-8") as _f:
    _baseline = json.load(_f)
BASELINE_EMB = _baseline["embeddings"][0]   # 32-dim float list

# ── Test harness ─────────────────────────────────────────────────────────────
failures = 0


def check(label: str, condition: bool, detail: str = ""):
    global failures
    tag = "PASS" if condition else "FAIL"
    line = f"  [{tag}] {label}"
    if not condition and detail:
        line += f"  --  {detail}"
    print(line)
    if not condition:
        failures += 1


# ── Helper: obtain a fresh, valid nonce ──────────────────────────────────────
def get_nonce(client, device_id: str = DEVICE_ID) -> str:
    r = client.get("/attest/challenge", params={"device_id": device_id})
    assert r.status_code == 200, f"challenge failed: {r.text}"
    return r.json()["nonce"]


def do_verify(client, device_id: str, nonce: str, weights_hash: str, signature: str) -> dict:
    r = client.post("/attest/verify", json={
        "device_id": device_id,
        "nonce": nonce,
        "weights_hash": weights_hash,
        "signature": signature,
    })
    assert r.status_code == 200, f"verify endpoint returned {r.status_code}: {r.text}"
    return r.json()


def node_status(client, device_id: str = DEVICE_ID) -> str:
    return client.get("/nodes").json().get(device_id, {}).get("status", "UNKNOWN")


def good_attest(client, device_id: str = DEVICE_ID) -> str:
    """Perform a complete successful attestation and return the token."""
    nonce = get_nonce(client, device_id)
    sig = make_quote(DEVICE_KEY, nonce, GOLDEN_HASH)
    resp = do_verify(client, device_id, nonce, GOLDEN_HASH, sig)
    assert resp["ok"], f"good_attest failed: {resp}"
    return resp["token"]


# ════════════════════════════════════════════════════════════════════════════
# All tests run inside the context manager so startup hooks fire
# ════════════════════════════════════════════════════════════════════════════
with TestClient(app) as client:

    # ── 1. Good handshake ────────────────────────────────────────────────────
    print("\n=== Test 1: Good handshake ===")
    nonce1 = get_nonce(client)
    sig1 = make_quote(DEVICE_KEY, nonce1, GOLDEN_HASH)
    resp1 = do_verify(client, DEVICE_ID, nonce1, GOLDEN_HASH, sig1)

    check("ok == True",            resp1["ok"] is True,            str(resp1))
    check("token present",         bool(resp1.get("token")),       str(resp1))
    check("reason == 'verified'",  resp1["reason"] == "verified",  str(resp1))
    check("node is TRUSTED",       node_status(client) == "TRUSTED")

    # ── 2. Wrong hash ────────────────────────────────────────────────────────
    print("\n=== Test 2: Wrong hash ===")
    client.post("/reset", json={"device_id": DEVICE_ID})

    bad_hash = "b" * 64
    nonce2 = get_nonce(client)
    sig2 = make_quote(DEVICE_KEY, nonce2, bad_hash)          # valid sig over bad hash
    resp2 = do_verify(client, DEVICE_ID, nonce2, bad_hash, sig2)

    check("ok == False",               resp2["ok"] is False,                  str(resp2))
    check("reason == 'hash mismatch'", resp2["reason"] == "hash mismatch",    str(resp2))
    check("token is None",             resp2.get("token") is None,            str(resp2))
    check("node is REJECTED",          node_status(client) == "REJECTED")

    # ── 3. Replayed nonce ────────────────────────────────────────────────────
    print("\n=== Test 3: Replayed nonce ===")
    client.post("/reset", json={"device_id": DEVICE_ID})

    nonce3 = get_nonce(client)
    sig3 = make_quote(DEVICE_KEY, nonce3, GOLDEN_HASH)
    resp3a = do_verify(client, DEVICE_ID, nonce3, GOLDEN_HASH, sig3)   # first use
    check("first use ok == True",      resp3a["ok"] is True,               str(resp3a))

    resp3b = do_verify(client, DEVICE_ID, nonce3, GOLDEN_HASH, sig3)   # replay
    check("replay ok == False",                resp3b["ok"] is False,                  str(resp3b))
    check("replay reason == 'replayed nonce'", resp3b["reason"] == "replayed nonce",   str(resp3b))
    check("replay token is None",              resp3b.get("token") is None,            str(resp3b))
    check("node is REJECTED after replay",     node_status(client) == "REJECTED")

    # ── 4. Bad signature ─────────────────────────────────────────────────────
    print("\n=== Test 4: Bad signature ===")
    client.post("/reset", json={"device_id": DEVICE_ID})

    nonce4 = get_nonce(client)
    resp4 = do_verify(client, DEVICE_ID, nonce4, GOLDEN_HASH, "deadbeefdeadbeef")
    check("ok == False",               resp4["ok"] is False,                   str(resp4))
    check("reason == 'bad signature'", resp4["reason"] == "bad signature",     str(resp4))
    check("token is None",             resp4.get("token") is None,             str(resp4))
    check("node is REJECTED",          node_status(client) == "REJECTED")

    # ── 5. Happy-path /infer ─────────────────────────────────────────────────
    print("\n=== Test 5: Happy-path /infer ===")
    client.post("/reset", json={"device_id": DEVICE_ID})
    good_token5 = good_attest(client)

    r5 = client.post("/infer", json={
        "device_id": DEVICE_ID,
        "token":     good_token5,
        "embedding": BASELINE_EMB,
    })
    check("status 200",            r5.status_code == 200,                         r5.text)
    if r5.status_code == 200:
        d5 = r5.json()
        check("prediction is int 0-9",
              isinstance(d5.get("prediction"), int) and 0 <= d5["prediction"] <= 9,
              str(d5))
        check("confidence in (0,1]",
              isinstance(d5.get("confidence"), float) and 0 < d5["confidence"] <= 1.0,
              str(d5))

    # ── 6. /infer with wrong embedding length ────────────────────────────────
    print("\n=== Test 6: /infer with 31-float embedding ===")
    r6 = client.post("/infer", json={
        "device_id": DEVICE_ID,
        "token":     good_token5,
        "embedding": [0.1] * 31,
    })
    check("status 403 for wrong length", r6.status_code == 403, r6.text)

    # ── 7. /quarantine then /infer ───────────────────────────────────────────
    print("\n=== Test 7: /quarantine then /infer ===")
    client.post("/reset", json={"device_id": DEVICE_ID})
    token7 = good_attest(client)

    q7 = client.post("/quarantine", json={"device_id": DEVICE_ID, "reason": "smoke test"})
    check("/quarantine returns ok=True", q7.json().get("ok") is True, q7.text)
    check("node is QUARANTINED",         node_status(client) == "QUARANTINED")

    r7 = client.post("/infer", json={
        "device_id": DEVICE_ID,
        "token":     token7,
        "embedding": BASELINE_EMB,
    })
    check("/infer after quarantine returns 403", r7.status_code == 403, r7.text)

    # ── 8. Failed attestation revokes old token ──────────────────────────────
    print("\n=== Test 8: Failed attest revokes old token ===")
    client.post("/reset", json={"device_id": DEVICE_ID})
    old_token8 = good_attest(client)           # get a valid token first

    # Now attest with a wrong hash — this REJECTED branch must revoke old_token8
    nonce8b = get_nonce(client)
    sig8b = make_quote(DEVICE_KEY, nonce8b, "c" * 64)
    resp8b = do_verify(client, DEVICE_ID, nonce8b, "c" * 64, sig8b)
    check("wrong-hash attest rejected", resp8b["ok"] is False, str(resp8b))

    r8 = client.post("/infer", json={
        "device_id": DEVICE_ID,
        "token":     old_token8,
        "embedding": BASELINE_EMB,
    })
    check("old token revoked after failed attest => 403", r8.status_code == 403, r8.text)

    # ── 9. /reset wipes token and sets node UNKNOWN ──────────────────────────
    print("\n=== Test 9: /reset ===")
    client.post("/reset", json={"device_id": DEVICE_ID})
    token9 = good_attest(client)

    client.post("/reset", json={"device_id": DEVICE_ID})
    check("node is UNKNOWN after reset", node_status(client) == "UNKNOWN")

    r9 = client.post("/infer", json={
        "device_id": DEVICE_ID,
        "token":     token9,
        "embedding": BASELINE_EMB,
    })
    check("token invalid after reset => 403", r9.status_code == 403, r9.text)


# ── Summary ──────────────────────────────────────────────────────────────────
print()
if failures == 0:
    print("ALL SMOKE TESTS PASSED")
    sys.exit(0)
else:
    print(f"{failures} SMOKE TEST(S) FAILED")
    sys.exit(1)
