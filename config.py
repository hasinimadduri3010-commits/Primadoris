# Shared by every module. Only Member 4 edits this file.
from pathlib import Path

ROOT = Path(__file__).parent
MODELS_DIR = ROOT / "models"
SAMPLES_DIR = ROOT / "samples"

CLOUD_URL = "http://127.0.0.1:8000"
EDGE_URL = "http://127.0.0.1:8001"

DEVICE_ID = "edge-01"
DEVICE_KEY = b"simulated-tpm-sealed-key"  # stands in for a key locked inside a TPM

EDGE_WEIGHTS_PATH = MODELS_DIR / "edge_extractor.pt"
CLOUD_HEAD_PATH = MODELS_DIR / "cloud_head.pt"
GOLDEN_PATH = MODELS_DIR / "golden.json"      # known-good hash from "factory provisioning"
BASELINE_PATH = MODELS_DIR / "baseline.json"  # canary inputs + expected embeddings
DEMO_SAMPLES_PATH = MODELS_DIR / "demo_samples.json"

CANARY_INTERVAL_SEC = 3
CANARY_DRIFT_THRESHOLD = 0.10  # 10% relative drift => quarantine
<<<<<<< HEAD
"""
config.py
=========
Global configuration for SentinelEdge AI / Primadoris per ARCHITECTURE.md.
Defines endpoints, ports, device identities, and file paths.
"""

import os

# Server Endpoints (all local per ARCHITECTURE.md)
CLOUD_HOST = "127.0.0.1"
CLOUD_PORT = 8000
CLOUD_URL = f"http://{CLOUD_HOST}:{CLOUD_PORT}"

EDGE_HOST = "127.0.0.1"
EDGE_PORT = 8001
EDGE_URL = f"http://{EDGE_HOST}:{EDGE_PORT}"

DASHBOARD_PORT = 8501

# Default Device Configuration
DEFAULT_DEVICE_ID = "edge-node-01"
ATTESTATION_KEY = b"sentineledge-tpm-secret-key-32bytes!"

# Model Artifact Directories & Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

EDGE_EXTRACTOR_PATH = os.path.join(MODELS_DIR, "edge_extractor.pt")
CLOUD_HEAD_PATH = os.path.join(MODELS_DIR, "cloud_head.pt")
GOLDEN_JSON_PATH = os.path.join(MODELS_DIR, "golden.json")
BASELINE_JSON_PATH = os.path.join(MODELS_DIR, "baseline.json")
DEMO_SAMPLES_JSON_PATH = os.path.join(MODELS_DIR, "demo_samples.json")

# Canary & Drift Detection Defaults
DEFAULT_DRIFT_THRESHOLD = 0.05
DEFAULT_CANARY_INTERVAL = 2.0
=======
>>>>>>> 09af56f294fc0dfed26f0cf54bd07433192ba04d
