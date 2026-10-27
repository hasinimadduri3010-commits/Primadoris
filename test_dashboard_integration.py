"""
test_dashboard_integration.py
==============================
End-to-end integration test suite verifying that dashboard_server.py,
the Layer 1 scanner, and the cloud adapter work together properly.
"""

import json
import threading
import time
import unittest
import urllib.request
import urllib.error

import dashboard_server
from scanner import scan_file


class TestDashboardIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = 8799
        cls.server = dashboard_server.make_server("127.0.0.1", [cls.port])
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _get(self, path):
        req = urllib.request.Request(f"{self.base_url}{path}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, resp.read()

    def _post_json(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_01_index_html_served(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("PRIMADORIS", text)
        self.assertIn("css/styles.css", text)

    def test_02_status_endpoint(self):
        status, body = self._get("/api/status")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("weight", data)
        self.assertIn("status", data)
        self.assertIn("variance_pct", data)

    def test_03_samples_endpoint(self):
        status, body = self._get("/api/samples")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("samples", data)
        self.assertIn("safe_model.pkl", data["samples"])

    def test_04_scan_safe_model(self):
        status, data = self._post_json("/api/scan", {"file": "safe_model.pkl"})
        self.assertEqual(status, 200)
        self.assertEqual(data.get("verdict"), "SAFE")

    def test_05_scan_malicious_model(self):
        status, data = self._post_json("/api/scan", {"file": "evil_system.pkl"})
        self.assertEqual(status, 200)
        self.assertEqual(data.get("verdict"), "MALICIOUS")
        self.assertTrue(len(data.get("findings", [])) > 0)

    def test_06_simulated_attack_and_reset(self):
        # 1. Trigger simulated attack
        status, data = self._post_json("/api/attack", {"level": "CRITICAL"})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("detected_status"), "QUARANTINED")

        # 2. Reset baseline
        status, reset_data = self._post_json("/api/reset", {})
        self.assertEqual(status, 200)
        self.assertTrue(reset_data.get("success"))

        # 3. Check status is healthy again
        status, body = self._get("/api/status")
        status_data = json.loads(body.decode("utf-8"))
        self.assertEqual(status_data.get("status"), "HEALTHY")


if __name__ == "__main__":
    unittest.main()
