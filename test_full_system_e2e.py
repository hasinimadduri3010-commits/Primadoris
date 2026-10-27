"""
test_full_system_e2e.py
========================
Comprehensive End-to-End Test Suite verifying the full integration:
  Layer 1: Static Bytecode Scanner (safe vs. malicious .pkl)
  Layer 2: Cloud Attestation Handshake (HMAC-SHA256 TPM quote)
  Layer 3: Behavioral Canary Simulation and Baseline Verification
  Layer 4: Split Inference Tail Execution across Edge & Cloud
  Frontend & Dashboard Server: Static assets, API proxying, event ingestion
"""

import json
import threading
import time
import unittest
import urllib.request
import urllib.error

import uvicorn
from fastapi.testclient import TestClient

import config
import dashboard_server
import cloud_server
from scanner import scan_file
import attestation
import split_model


class TestFullSystemE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cloud_port = 8000
        cls.cloud_uvicorn = None
        cls.cloud_thread = None

        # Check if cloud server is already running on port 8000
        cloud_running = False
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/nodes", timeout=1) as resp:
                if resp.status == 200:
                    cloud_running = True
        except Exception:
            cloud_running = False

        if not cloud_running:
            server_config = uvicorn.Config(
                cloud_server.app,
                host="127.0.0.1",
                port=cls.cloud_port,
                log_level="error"
            )
            cls.cloud_uvicorn = uvicorn.Server(server_config)
            cls.cloud_thread = threading.Thread(target=cls.cloud_uvicorn.run, daemon=True)
            cls.cloud_thread.start()
            time.sleep(1.0)

        # 2. Start Dashboard Server on port 8798
        cls.dash_port = 8798
        cls.dash_server = dashboard_server.make_server("127.0.0.1", [cls.dash_port])
        cls.dash_thread = threading.Thread(target=cls.dash_server.serve_forever, daemon=True)
        cls.dash_thread.start()

        cls.dash_url = f"http://127.0.0.1:{cls.dash_port}"
        cls.cloud_url = f"http://127.0.0.1:{cls.cloud_port}"
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.dash_server.shutdown()
        cls.dash_server.server_close()
        if cls.cloud_uvicorn:
            cls.cloud_uvicorn.should_exit = True

    def _get(self, base, path):
        req = urllib.request.Request(f"{base}{path}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read()

    def _post_json(self, base, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{base}{path}",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    # ------------------------------------------------------------------------
    # Layer 1: Scanner Tests
    # ------------------------------------------------------------------------
    def test_01_layer1_safe_model_scan(self):
        status, data = self._post_json(self.dash_url, "/api/scan", {"file": "safe_model.pkl"})
        self.assertEqual(status, 200)
        self.assertEqual(data.get("verdict"), "SAFE")
        self.assertIn("findings", data)
        self.assertIn("sha256", data)

    def test_02_layer1_malicious_model_scan(self):
        status, data = self._post_json(self.dash_url, "/api/scan", {"file": "evil_system.pkl"})
        self.assertEqual(status, 200)
        self.assertEqual(data.get("verdict"), "MALICIOUS")
        self.assertTrue(len(data.get("findings", [])) > 0)
        self.assertIn("sha256", data)

    # ------------------------------------------------------------------------
    # Dashboard Frontend Serving
    # ------------------------------------------------------------------------
    def test_03_dashboard_serves_html_and_css(self):
        status, body = self._get(self.dash_url, "/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("PRIMADORIS", text)
        self.assertIn("THE ABYSS", text)
        self.assertIn("THREAT LAB", text)
        self.assertIn("OBSERVATORY", text)
        self.assertIn("BLACK BOX", text)

        # Verify CSS is served
        c_status, c_body = self._get(self.dash_url, "/css/styles.css")
        self.assertEqual(c_status, 200)
        self.assertTrue(len(c_body) > 100)

    # ------------------------------------------------------------------------
    # Layer 2: Cloud Integration & Live Attestation
    # ------------------------------------------------------------------------
    def test_04_cloud_proxy_nodes_and_events(self):
        status, nodes = self._post_json(self.dash_url, "/api/cloud/nodes", {})
        self.assertEqual(status, 200)
        self.assertTrue(nodes.get("ok"))
        self.assertEqual(nodes.get("source"), "cloud")

        status, events = self._post_json(self.dash_url, "/api/cloud/events", {})
        self.assertEqual(status, 200)
        self.assertTrue(events.get("ok"))
        self.assertEqual(events.get("source"), "cloud")

    def test_05_layer2_live_tpm_attestation_handshake(self):
        status, data = self._post_json(self.dash_url, "/api/cloud/attest", {})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIsNotNone(data.get("token"))
        self.assertEqual(data.get("reason"), "verified")

        # Verify cloud node state transitioned to TRUSTED
        status, nodes_resp = self._post_json(self.dash_url, "/api/cloud/nodes", {})
        self.assertEqual(status, 200)
        nodes = nodes_resp.get("nodes", {})
        self.assertIn(config.DEVICE_ID, nodes)
        self.assertEqual(nodes[config.DEVICE_ID]["status"], "TRUSTED")

    # ------------------------------------------------------------------------
    # Layer 4: Split Inference Tail Execution
    # ------------------------------------------------------------------------
    def test_06_layer4_split_edge_to_cloud_inference(self):
        status, data = self._post_json(self.dash_url, "/api/cloud/infer", {"sample_index": 0})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIn("prediction", data)
        self.assertIn("confidence", data)
        self.assertIn("embedding_preview", data)
        self.assertEqual(len(data["embedding_preview"]), 5)
        self.assertIsInstance(data["prediction"], int)
        self.assertTrue(0 <= data["prediction"] <= 9)

    # ------------------------------------------------------------------------
    # Layer 3: Attack Simulation and Baseline Restoration
    # ------------------------------------------------------------------------
    def test_07_layer3_simulation_and_reset(self):
        status, data = self._post_json(self.dash_url, "/api/attack", {"level": "HIGH"})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        self.assertIn(data.get("detected_status"), ["SUSPICIOUS", "QUARANTINED"])

        status, r_data = self._post_json(self.dash_url, "/api/reset", {})
        self.assertEqual(status, 200)
        self.assertTrue(r_data.get("success"))

        status, body = self._get(self.dash_url, "/api/status")
        s_data = json.loads(body.decode("utf-8"))
        self.assertEqual(s_data.get("status"), "HEALTHY")


if __name__ == "__main__":
    unittest.main()
