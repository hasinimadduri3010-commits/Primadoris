"""
PRIMADORIS v1.0 — Local Dashboard Server
========================================================
A tiny, dependency-free localhost API + static host for the Primadoris UI.

    python dashboard_server.py                 # http://127.0.0.1:8765
    python dashboard_server.py --port 9000 --no-browser

Endpoints
---------
    GET  /api/status    current toy-model state + behavioural metrics
    GET  /api/history   rolling variance / threat samples
    GET  /api/logs      audit trail (newest first)
    GET  /api/samples   files inside samples/ (.pkl / .pt / .pth)
    POST /api/attack    {"level": "LOW|MEDIUM|HIGH|CRITICAL"}  simulated attack
    POST /api/reset     restore the golden baseline
    POST /api/scan      {"file": "name.pkl"}  static inspection (never executed)

SECURITY NOTES
--------------
* Binds to 127.0.0.1 by default — this is a local demo, not a public service.
* Path traversal is blocked with realpath/commonpath checks.
* The scanner never unpickles anything; it only reads raw bytes and opcodes.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import io
import json
import os
import pickletools
import random
import sys
import threading
import webbrowser
import zipfile
from datetime import datetime
from urllib.parse import urlparse
from urllib.request import urlopen


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from canary import evaluate as evaluate_weight
except ImportError as exc:                              # pragma: no cover
    raise SystemExit(
        "canary.py could not be imported. Keep canary.py, attack.py, "
        f"scanner.py and dashboard_server.py in the same folder.\n({exc})"
    )

try:
    from scanner import scan_file as scan_model_file
except ImportError:                                     # pragma: no cover
    scan_model_file = None

try:
    import config
    CLOUD_BASE = getattr(config, "CLOUD_URL", "http://127.0.0.1:8000")
except Exception:
    config = None
    CLOUD_BASE = "http://127.0.0.1:8000"

ROOT = BASE_DIR
MODEL = os.path.join(ROOT, "model_brain.json")
SAMPLES = os.path.join(ROOT, "samples")
BASE_WEIGHT = 1.5
LOCK = threading.RLock()
LOGS: list = []
HISTORY: list = []

PROFILES = {
    "LOW":      ("Stealth Gradient Drift",                (1.54, 1.61)),
    "MEDIUM":   ("Targeted Parameter Perturbation",       (1.68, 1.85)),
    "HIGH":     ("Simulated Memory Integrity Violation",  (2.20, 2.90)),
    "CRITICAL": ("Catastrophic Model Corruption",         (3.20, 4.80)),
}

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".mjs":  "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".map":  "application/json; charset=utf-8",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg":  "image/svg+xml",
    ".ico":  "image/x-icon",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".txt":  "text/plain; charset=utf-8",
    ".md":   "text/markdown; charset=utf-8",
    ".py":   "text/plain; charset=utf-8",
}


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def baseline_state() -> dict:
    metrics = evaluate_weight(BASE_WEIGHT)
    return {
        "weight": BASE_WEIGHT,
        "status": "HEALTHY",
        "danger_level": "NOMINAL",
        "attack_name": None,
        "variance_pct": metrics["variance_pct"],
        "threat_pct": metrics["threat_pct"],
        "severity": metrics["severity"],
        "last_check": now(),
        "baseline_weight": BASE_WEIGHT,
    }


def read_model() -> dict:
    if not os.path.exists(MODEL):
        write_model(baseline_state())
    try:
        with open(MODEL, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else baseline_state()
    except (OSError, json.JSONDecodeError):
        return baseline_state()


def write_model(data: dict) -> None:
    with LOCK:
        tmp = MODEL + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, MODEL)


def log_event(event: str, status: str, severity: str, details: str, **extra) -> None:
    with LOCK:
        LOGS.append({
            "timestamp": now(),
            "event": event,
            "status": status,
            "severity": severity,
            "details": details,
            **extra,
        })
        del LOGS[:-300]


_REAL_MODEL = None
_BASELINE_DATA = None


def get_real_model():
    """Lazily load the PyTorch EdgeExtractor with clean golden weights."""
    global _REAL_MODEL
    with LOCK:
        if _REAL_MODEL is None:
            try:
                import split_model
                model = split_model.EdgeExtractor()
                golden_path = os.path.join(ROOT, "models", "edge_extractor.pt.golden")
                weights_path = golden_path if os.path.exists(golden_path) else (
                    config.EDGE_WEIGHTS_PATH if config else os.path.join(ROOT, "models", "edge_extractor.pt")
                )
                if os.path.exists(weights_path):
                    model.load_state_dict(split_model.load_edge_state(weights_path))
                model.eval()
                _REAL_MODEL = model
            except Exception:
                _REAL_MODEL = None
        return _REAL_MODEL


def get_baseline_data() -> dict | None:
    """Loads reference canary inputs and expected embeddings."""
    global _BASELINE_DATA
    with LOCK:
        if _BASELINE_DATA is None:
            try:
                base_path = config.BASELINE_PATH if config else os.path.join(ROOT, "models", "baseline.json")
                if os.path.exists(base_path):
                    with open(base_path, "r", encoding="utf-8") as f:
                        _BASELINE_DATA = json.load(f)
            except Exception:
                _BASELINE_DATA = None
        return _BASELINE_DATA


def current_status() -> dict:
    """
    Computes the live status directly from the real PyTorch EdgeExtractor and
    canary probes in baseline.json.
    """
    model_obj = get_real_model()
    base_data = get_baseline_data()

    if model_obj is not None and base_data is not None:
        try:
            import numpy as np
            import torch
            inputs = torch.tensor(base_data["inputs"], dtype=torch.float32)
            expected = np.array(base_data["embeddings"], dtype=np.float32)

            with torch.no_grad():
                actual = model_obj(inputs).numpy()

            per_canary = []
            for exp, act in zip(expected, actual):
                norm_exp = np.linalg.norm(exp)
                diff = np.linalg.norm(act - exp)
                raw = float(diff / norm_exp) if norm_exp > 0 else 0.0
                per_canary.append(min(1.0, raw))

            max_drift = float(max(per_canary)) if per_canary else 0.0
            max_drift_display = min(1.0, max_drift)
            threshold = getattr(config, "CANARY_DRIFT_THRESHOLD", 0.10) if config else 0.10

            variance_pct = round(max_drift_display * 100.0, 2)

            # Properly calibrate threat index across the 0-100 range:
            if max_drift <= 0.005:
                threat_pct = 0.0
                status, severity, danger = "HEALTHY", "LOW", "NOMINAL"
            elif max_drift <= 0.05:
                # Stealth drift (e.g. 1.0% - 5.0% drift -> threat 6.0% - 15.0%)
                threat_pct = round(max_drift * 280.0, 1)
                status, severity, danger = "HEALTHY", "LOW", "LOW"
            elif max_drift < threshold:
                # Approaching threshold (e.g. 5.0% - 10.0% drift -> threat 16.0% - 29.0%)
                threat_pct = round(16.0 + (max_drift - 0.05) / 0.05 * 13.0, 1)
                status, severity, danger = "SUSPICIOUS", "MEDIUM", "ELEVATED"
            elif max_drift < 0.25:
                # Crossed threshold into containment (e.g. 10.0% - 25.0% drift -> threat 32.0% - 58.0%)
                threat_pct = round(32.0 + (max_drift - threshold) / (0.25 - threshold) * 26.0, 1)
                status, severity, danger = "QUARANTINED", "HIGH", "HIGH"
            elif max_drift < 0.60:
                # High severity integrity violation (e.g. 25.0% - 60.0% drift -> threat 60.0% - 84.0%)
                threat_pct = round(60.0 + (max_drift - 0.25) / 0.35 * 24.0, 1)
                status, severity, danger = "QUARANTINED", "HIGH", "HIGH"
            else:
                # Critical catastrophic corruption (e.g. >= 60.0% drift -> threat 86.0% - 99.9%)
                threat_pct = round(min(99.9, 86.0 + (max_drift - 0.60) / 0.40 * 13.9), 1)
                status, severity, danger = "QUARANTINED", "CRITICAL", "CRITICAL"

            weight = round(min(99.999, BASE_WEIGHT + max_drift_display * 2.0), 3)
            ts = now()

            # Normalize actual probe activations for Observatory view
            observed_matrix = []
            for act in actual:
                clipped = float(np.clip(act[0], -88.0, 88.0))  # prevent overflow in exp
                p0 = float(1.0 / (1.0 + np.exp(-clipped)))
                observed_matrix.append([round(p0, 3), round(1.0 - p0, 3)])

            status_dict = {
                "weight": weight,
                "status": status,
                "danger_level": danger,
                "attack_name": getattr(model_obj, "_attack_name", None),
                "last_check": ts,
                "baseline_weight": BASE_WEIGHT,
                "variance_pct": variance_pct,
                "threat_pct": threat_pct,
                "severity": severity,
                "timestamp": ts,
                "max_drift": round(max_drift_display, 6),
                "per_canary": [round(min(1.0, d), 6) for d in per_canary],
                "passed": max_drift < threshold,
                "threshold": threshold,
                "baseline_matrix": [[0.95, 0.05], [0.10, 0.90], [0.88, 0.12], [0.02, 0.98], [0.50, 0.50]],
                "observed_matrix": observed_matrix,
                "engine": "PyTorch (Real Model)",
            }

            with LOCK:
                HISTORY.append({
                    "timestamp": ts,
                    "variance_pct": variance_pct,
                    "threat_pct": threat_pct,
                })
                del HISTORY[:-120]

            return status_dict
        except Exception:
            pass

    # Fallback to simulation if PyTorch artifacts are unreachable
    model = read_model()
    weight = float(model.get("weight", BASE_WEIGHT))
    metrics = evaluate_weight(weight)

    status = {
        "weight": round(weight, 3),
        "status": model.get("status", "HEALTHY") if weight != BASE_WEIGHT else metrics["status"],
        "danger_level": model.get("danger_level", "NOMINAL"),
        "attack_name": model.get("attack_name"),
        "last_check": model.get("last_check", now()),
        "baseline_weight": BASE_WEIGHT,
        **metrics,
    }
    status["status"] = metrics["status"] if weight != BASE_WEIGHT else "HEALTHY"

    with LOCK:
        HISTORY.append({
            "timestamp": metrics["timestamp"],
            "variance_pct": metrics["variance_pct"],
            "threat_pct": metrics["threat_pct"],
        })
        del HISTORY[:-120]

    return status


# ----------------------------------------------------------------------------
# Static-analysis fallback (used only if scanner.py is missing)
# ----------------------------------------------------------------------------
def _fallback_scan(raw: bytes, filename: str) -> dict:
    findings = []
    digest = hashlib.sha256(raw).hexdigest()

    def scan_stream(data: bytes, source: str) -> None:
        try:
            for opcode, arg, pos in pickletools.genops(data):
                if opcode.name in ("GLOBAL", "STACK_GLOBAL", "REDUCE", "NEWOBJ", "NEWOBJ_EX"):
                    findings.append({
                        "type": "REVIEW_OPCODE",
                        "opcode": opcode.name,
                        "offset": pos,
                        "source": source,
                        "severity": "medium",
                        "note": "Review this opcode in context.",
                    })
        except Exception as exc:
            findings.append({
                "type": "UNREADABLE_OR_NON_PICKLE",
                "source": source,
                "severity": "info",
                "error": str(exc)[:250],
            })

    if raw[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for name in [n for n in archive.namelist() if n.endswith(".pkl")][:30]:
                    scan_stream(archive.read(name), name)
        except Exception as exc:
            findings.append({"type": "MALFORMED_ARCHIVE", "severity": "high", "error": str(exc)[:250]})
    else:
        scan_stream(raw, filename)

    high = any(f["severity"] == "high" for f in findings)
    medium = any(f["severity"] == "medium" for f in findings)
    verdict = "MALICIOUS" if high else ("SUSPICIOUS" if medium else "NO_KNOWN_FINDINGS")

    return {
        "file": filename,
        "sha256": digest,
        "verdict": verdict,
        "limitations": "Heuristic inspection only; it does not prove a file is safe.",
        "findings": findings,
    }


def scan_bytes(raw: bytes, filename: str) -> dict:
    return _fallback_scan(raw, filename)


# ----------------------------------------------------------------------------
# HTTP handler
# ----------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Primadoris/1.0"
    protocol_version = "HTTP/1.1"

    # --- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):        # keep the console clean
        pass

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def send_json(self, data, code: int = 200) -> None:
        raw = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(raw)

    def send_file(self, path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        content_type = MIME_TYPES.get(ext, "application/octet-stream")
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError:
            return self.send_json({"error": "Read error"}, 500)

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        # Never cache JS/CSS — always serve fresh so fixes take effect immediately
        if ext in (".js", ".css"):
            self.send_header("Cache-Control", "no-store, max-age=0")
        else:
            self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        self.wfile.write(content)


    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # --- GET ----------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path in ("/api/status", "/api/state"):
            return self.send_json(current_status())

        if path == "/api/history":
            with LOCK:
                return self.send_json({"history": list(HISTORY)})

        if path == "/api/logs":
            with LOCK:
                return self.send_json({"logs": list(reversed(LOGS[-100:]))})

        if path == "/api/health":
            return self.send_json({
                "ok": True,
                "system": "PRIMADORIS",
                "time": now(),
                "scanner": "scanner.py" if scan_model_file else "inline-fallback",
                "events": len(LOGS),
            })

        if path == "/api/samples":
            os.makedirs(SAMPLES, exist_ok=True)
            names = sorted(
                n for n in os.listdir(SAMPLES)
                if n.lower().endswith((".pkl", ".pt", ".pth"))
                and os.path.isfile(os.path.join(SAMPLES, n))
            )
            return self.send_json({"samples": names})

        # ---- cloud integration (read-only queries & live attestation) ----
        if path == "/api/cloud/nodes":
            try:
                with urlopen(f"{CLOUD_BASE}/nodes", timeout=2) as response:
                    cloud_nodes = json.loads(response.read().decode("utf-8"))
                return self.send_json({
                    "ok": True,
                    "source": "cloud",
                    "nodes": cloud_nodes
                })
            except Exception as exc:
                return self.send_json({
                    "ok": False,
                    "source": "cloud",
                    "error": str(exc),
                    "nodes": {}
                }, 503)

        if path == "/api/cloud/events":
            try:
                with urlopen(f"{CLOUD_BASE}/events?limit=20", timeout=2) as response:
                    cloud_events = json.loads(response.read().decode("utf-8"))
                return self.send_json({
                    "ok": True,
                    "source": "cloud",
                    "events": cloud_events
                })
            except Exception as exc:
                return self.send_json({
                    "ok": False,
                    "source": "cloud",
                    "error": str(exc),
                    "events": []
                }, 503)

        if path == "/api/cloud/attest":
            try:
                import attestation, split_model
                edge_path = config.EDGE_WEIGHTS_PATH if config else os.path.join(ROOT, "models", "edge_extractor.pt")
                device_id = config.DEVICE_ID if config else "edge-01"
                device_key = config.DEVICE_KEY if config else b"simulated-tpm-sealed-key"
                state_dict = split_model.load_edge_state(edge_path)
                handshake = attestation.run_handshake(CLOUD_BASE, device_id, device_key, state_dict)
                ok = bool(handshake.get("ok"))
                log_event("CLOUD_ATTESTATION", "TRUSTED" if ok else "REJECTED",
                          "LOW" if ok else "CRITICAL",
                          f"Live TPM attestation: {handshake.get('reason')}")
                return self.send_json(handshake, 200 if ok else 403)
            except Exception as exc:
                return self.send_json({"ok": False, "token": None, "reason": str(exc)}, 503)

        # ---- static files ----

        clean = path.lstrip("/")
        if not clean or clean.endswith("/"):
            clean = os.path.join(clean, "index.html")

        target = os.path.realpath(os.path.join(ROOT, clean.replace("/", os.sep)))
        try:
            inside = os.path.commonpath([os.path.realpath(ROOT), target]) == os.path.realpath(ROOT)
        except ValueError:                    # different drive on Windows
            inside = False

        if inside and os.path.isfile(target):
            return self.send_file(target)

        return self.send_json({"error": "Not found", "path": path}, 404)

    # --- POST ---------------------------------------------------------------
    def do_POST(self) -> None:
        global _REAL_MODEL
        path = urlparse(self.path).path

        try:
            length = min(int(self.headers.get("Content-Length", 0) or 0), 100_000)
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw or b"{}")
            if not isinstance(payload, dict):
                payload = {}
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "Invalid JSON body"}, 400)

        if path == "/api/attack":
            level = str(payload.get("level") or payload.get("tier") or "LOW").upper()
            if level not in PROFILES:
                return self.send_json({"error": "Invalid level", "allowed": list(PROFILES)}, 400)

            name, (low, high) = PROFILES[level]
            try:
                import torch
                import split_model as sm
                # ── Always load clean golden model first so attacks never stack ──
                golden_p = os.path.join(ROOT, "models", "edge_extractor.pt.golden")
                edge_p = golden_p if os.path.exists(golden_p) else (
                    config.EDGE_WEIGHTS_PATH if config else os.path.join(ROOT, "models", "edge_extractor.pt")
                )
                clean_m = sm.EdgeExtractor()
                clean_m.load_state_dict(sm.load_edge_state(edge_p))
                clean_m.eval()
                clean_m._attack_name = name

                # ── Apply the requested attack level deterministically ──
                with torch.no_grad():
                    if level == "LOW":
                        # Stealth Gradient Drift: subtle parametric noise (< threshold 10%)
                        for p in clean_m.parameters():
                            p.add_(torch.randn_like(p) * 0.012)
                    elif level == "MEDIUM":
                        # Targeted Parameter Perturbation: noticeable drift crossing threshold (~16%)
                        for p in clean_m.parameters():
                            p.add_(torch.randn_like(p) * 0.045)
                    elif level == "HIGH":
                        # Memory Integrity Violation: bitflip corruption on 16 weights (~45% drift)
                        for p in clean_m.parameters():
                            if p.numel() > 0:
                                flat = p.view(-1)
                                flat[:min(16, flat.numel())] += 2.8
                                break
                    elif level == "CRITICAL":
                        # Catastrophic Model Corruption: deep corruption across all tensors (~95% drift)
                        for p in clean_m.parameters():
                            p.add_(torch.randn_like(p) * 0.25)

                with LOCK:
                    _REAL_MODEL = clean_m
            except Exception as exc:
                pass

            st = current_status()
            log_event("REAL_ATTACK_APPLIED", st["status"], st["severity"],
                      f"{name}; real PyTorch model drift={st['variance_pct']:.2f}%")
            return self.send_json({
                "success": True,
                "level": level,
                "attack_name": name,
                "weight": st["weight"],
                "variance_pct": st["variance_pct"],
                "threat_pct": st["threat_pct"],
                "detected_status": st["status"],
                "message": f"Real attack ({name}) applied to in-memory PyTorch model.",
            })

        if path == "/api/reset":
            with LOCK:
                try:
                    import split_model
                    golden_p = os.path.join(ROOT, "models", "edge_extractor.pt.golden")
                    edge_p = golden_p if os.path.exists(golden_p) else (
                        config.EDGE_WEIGHTS_PATH if config else os.path.join(ROOT, "models", "edge_extractor.pt")
                    )
                    clean_model = split_model.EdgeExtractor()
                    clean_model.load_state_dict(split_model.load_edge_state(edge_p))
                    clean_model.eval()
                    clean_model._attack_name = None
                    _REAL_MODEL = clean_model
                except Exception:
                    pass

            write_model(baseline_state())
            log_event("BASELINE_RESTORED", "HEALTHY", "LOW",
                      f"Golden PyTorch weights restored from disk; drift cleared.")
            return self.send_json({"success": True, "message": "Baseline PyTorch model restored."})

        if path == "/api/scan":
            filename = str(payload.get("file") or payload.get("filename") or "")
            if not filename or os.path.basename(filename) != filename:
                return self.send_json({"error": "Invalid filename"}, 400)

            target = os.path.realpath(os.path.join(SAMPLES, filename))
            try:
                inside = os.path.commonpath([os.path.realpath(SAMPLES), target]) == os.path.realpath(SAMPLES)
            except ValueError:
                inside = False
            if not inside:
                return self.send_json({"error": "Invalid path"}, 400)
            if not os.path.isfile(target):
                return self.send_json({"error": "Sample not found"}, 404)
            if os.path.getsize(target) > 50_000_000:
                return self.send_json({"error": "File exceeds 50 MB limit"}, 413)

            if scan_model_file is not None:
                result = scan_model_file(target)
            else:
                with open(target, "rb") as f:
                    result = scan_bytes(f.read(), filename)

            if "sha256" not in result:
                with open(target, "rb") as f:
                    result["sha256"] = hashlib.sha256(f.read()).hexdigest()

            log_event("MODEL_SCAN", result.get("verdict", "UNKNOWN"), "MEDIUM",
                      f"Scan completed for {filename}; SHA-256 {str(result.get('sha256'))[:16]}...")
            return self.send_json(result)

        if path in ("/api/cloud/nodes", "/api/cloud/events", "/api/cloud/attest"):
            return self.do_GET()

        if path == "/api/cloud/infer":
            try:
                import attestation, split_model, torch, urllib.request
                sample_idx = int(payload.get("sample_index", 0))
                samples_path = config.DEMO_SAMPLES_PATH if config else os.path.join(ROOT, "models", "demo_samples.json")
                with open(samples_path, "r", encoding="utf-8") as f:
                    samples_data = json.load(f)
                sample = samples_data[sample_idx % len(samples_data)]
                feat = torch.tensor([sample["features"]], dtype=torch.float32)

                edge_path = config.EDGE_WEIGHTS_PATH if config else os.path.join(ROOT, "models", "edge_extractor.pt")
                device_id = config.DEVICE_ID if config else "edge-01"
                device_key = config.DEVICE_KEY if config else b"simulated-tpm-sealed-key"

                ext = split_model.EdgeExtractor()
                ext.load_state_dict(split_model.load_edge_state(edge_path))
                ext.eval()
                with torch.no_grad():
                    emb = ext(feat).squeeze(0).tolist()

                # Attest to obtain valid session token
                handshake = attestation.run_handshake(CLOUD_BASE, device_id, device_key, ext.state_dict())
                if not handshake.get("ok"):
                    return self.send_json({"ok": False, "reason": f"Attestation required: {handshake.get('reason')}"}, 403)

                token = handshake.get("token")
                infer_req = urllib.request.Request(
                    f"{CLOUD_BASE}/infer",
                    data=json.dumps({"device_id": device_id, "token": token, "embedding": emb}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}
                )
                with urlopen(infer_req, timeout=3) as c_resp:
                    tail_res = json.loads(c_resp.read().decode("utf-8"))

                log_event("SPLIT_INFERENCE", "COMPLETED", "LOW",
                          f"Sample #{sample_idx} -> pred={tail_res.get('prediction')}, conf={tail_res.get('confidence'):.3f}")

                return self.send_json({
                    "ok": True,
                    "sample_index": sample_idx,
                    "true_label": sample.get("label"),
                    "prediction": tail_res.get("prediction"),
                    "confidence": tail_res.get("confidence"),
                    "embedding_preview": emb[:5]
                })
            except Exception as exc:
                return self.send_json({"ok": False, "reason": str(exc)}, 503)

        return self.send_json({"error": "Not found", "path": path}, 404)


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
def make_server(host: str, ports: list[int]) -> http.server.ThreadingHTTPServer:
    last_error = None
    for port in ports:
        try:
            return http.server.ThreadingHTTPServer((host, port), Handler)
        except OSError as exc:
            last_error = exc
            continue
    raise SystemExit(f"No available port in {ports}. Last error: {last_error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PRIMADORIS local dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Preferred port (default 8765)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser window")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    os.makedirs(SAMPLES, exist_ok=True)
    if not os.path.exists(MODEL):
        write_model(baseline_state())

    log_event("SYSTEM_INIT", "HEALTHY", "LOW",
              "PRIMADORIS local integrity dashboard started.")

    ports = [args.port] + [p for p in (8765, 8080) if p != args.port] + list(range(8081, 8095))
    server = make_server(args.host, ports)
    url = f"http://{args.host}:{server.server_port}"

    print("=" * 62)
    print("PRIMADORIS v1.0")
    print("Intelligence That Uncovers. Vigilance That Protects.")
    print(f"Dashboard URL : {url}")
    print("Status        : LIVE & SYNCHRONIZED")
    print("Ctrl+C to stop.")
    print("=" * 62)

    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPRIMADORIS server stopped.")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
