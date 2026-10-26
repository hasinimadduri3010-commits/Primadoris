"""
make_test_files.py
===================
Generates test pickle (.pkl) files for the SentinelEdge AI Bytecode Scanner:
1. safe_model.pkl: Normal serialized Python dictionary representing model weights.
2. malicious_model.pkl: Uses __reduce__ to request builtins.eval (eval payload trick)
   to simulate arbitrary code execution without triggering OS filter blocks.
"""

import pickle
import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass


class MockMaliciousPayload:
    """
    Mock malicious object utilizing Python's __reduce__ deserialization mechanism.
    When unpickled, __reduce__ instructs the pickle machine to invoke builtins.eval("1 + 1").
    This simulates arbitrary code execution (RCE) safely without invoking os.system.
    """
    def __reduce__(self):
        return (eval, ("1 + 1",))


def create_safe_model(path: str = "safe_model.pkl") -> str:
    """Creates a benign pickle file containing dictionary data."""
    safe_data = {
        "model_name": "Hackathon_Model_v1",
        "weights": [0.5, 0.8, 0.1, 0.9],
        "metadata": {"version": 1.0, "status": "verified"}
    }
    with open(path, "wb") as f:
        pickle.dump(safe_data, f)
    print(f"[+] Generated safe model: {path}")
    return path


def create_malicious_model(path: str = "malicious_model.pkl") -> str:
    """Creates a malicious pickle file with a __reduce__ eval payload."""
    payload = MockMaliciousPayload()
    with open(path, "wb") as f:
        pickle.dump(payload, f)
    print(f"[!] Generated malicious test model: {path}")
    return path


def make_test_files():
    """Generates both test pickle files."""
    create_safe_model("safe_model.pkl")
    create_malicious_model("malicious_model.pkl")


if __name__ == "__main__":
    make_test_files()
