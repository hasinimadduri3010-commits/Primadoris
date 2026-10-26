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
