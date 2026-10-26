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