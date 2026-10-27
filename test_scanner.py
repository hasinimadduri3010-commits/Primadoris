"""
test_scanner.py
===============
Test suite for Primadoris AI Layer 1 Bytecode Scanner (scanner.py).
Verifies:
  1. Exact dictionary structure compliance per ARCHITECTURE.md.
  2. Safe model detection (verdict == 'SAFE').
  3. Malicious model detection (verdict == 'MALICIOUS') and threat details.
  4. Proper error handling for missing files.
"""

import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

from scanner import scan_file
from make_test_files import make_test_files, create_safe_model, create_malicious_model


def assert_schema(result: dict):
    """Asserts that the scan_file result matches the exact ARCHITECTURE.md contract."""
    required_keys = {"verdict", "findings", "opcodes_scanned", "bytes_scanned", "opcode_preview"}
    assert isinstance(result, dict), f"Result must be a dict, got {type(result)}"
    assert set(result.keys()) == required_keys, (
        f"Mismatch in keys. Expected {required_keys}, got {set(result.keys())}"
    )

    # Validate verdict
    assert result["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS"), (
        f"Invalid verdict: {result['verdict']}"
    )

    # Validate numeric counts
    assert isinstance(result["opcodes_scanned"], int), "opcodes_scanned must be an int"
    assert result["opcodes_scanned"] > 0, "opcodes_scanned must be > 0"
    assert isinstance(result["bytes_scanned"], int), "bytes_scanned must be an int"
    assert result["bytes_scanned"] > 0, "bytes_scanned must be > 0"

    # Validate opcode_preview
    assert isinstance(result["opcode_preview"], list), "opcode_preview must be a list"
    assert len(result["opcode_preview"]) <= 200, "opcode_preview must not exceed 200 items"
    for item in result["opcode_preview"]:
        assert isinstance(item, dict), "Each opcode_preview item must be a dict"
        assert set(item.keys()) == {"offset", "opcode", "arg"}, (
            f"Invalid opcode_preview keys: {item.keys()}"
        )
        assert isinstance(item["offset"], int)
        assert isinstance(item["opcode"], str)
        assert isinstance(item["arg"], str)

    # Validate findings
    assert isinstance(result["findings"], list), "findings must be a list"
    for finding in result["findings"]:
        assert isinstance(finding, dict), "Each finding must be a dict"
        assert set(finding.keys()) == {"pass", "offset", "opcode", "detail", "severity"}, (
            f"Invalid finding keys: {finding.keys()}"
        )
        assert finding["pass"] in (1, 2), f"Finding pass must be 1 or 2, got {finding['pass']}"
        assert isinstance(finding["offset"], int)
        assert isinstance(finding["opcode"], str)
        assert isinstance(finding["detail"], str)
        assert finding["severity"] in ("high", "medium"), (
            f"Finding severity must be 'high' or 'medium', got {finding['severity']}"
        )


def test_safe_model():
    """Test scanner against a benign model file."""
    print("Testing safe_model.pkl...")
    create_safe_model("safe_model.pkl")

    result = scan_file("safe_model.pkl")
    assert_schema(result)

    assert result["verdict"] == "SAFE", f"Expected SAFE, got {result['verdict']}"
    assert len(result["findings"]) == 0, (
        f"Safe model should have 0 findings, got {result['findings']}"
    )
    print("  ✅ PASS: safe_model.pkl verified as SAFE with 0 findings.")


def test_malicious_model():
    """Test scanner against a malicious model containing eval payload."""
    print("Testing malicious_model.pkl...")
    create_malicious_model("malicious_model.pkl")

    result = scan_file("malicious_model.pkl")
    assert_schema(result)

    assert result["verdict"] == "MALICIOUS", (
        f"Expected MALICIOUS, got {result['verdict']}"
    )
    assert len(result["findings"]) > 0, "Expected at least 1 finding in malicious model"

    # Verify that builtins/eval was caught
    details = " ".join(f["detail"] for f in result["findings"])
    assert "eval" in details or "builtins" in details, (
        f"Findings did not detail the eval/builtins payload: {details}"
    )

    # Verify severity is high
    assert any(f["severity"] == "high" for f in result["findings"]), (
        "Malicious model must have at least one high-severity finding"
    )

    print(f"  ✅ PASS: malicious_model.pkl caught as MALICIOUS with {len(result['findings'])} findings.")


def test_missing_file():
    """Test that missing files raise FileNotFoundError."""
    print("Testing missing file handling...")
    try:
        scan_file("non_existent_model_12345.pkl")
        assert False, "Expected FileNotFoundError for non-existent file"
    except FileNotFoundError:
        print("  ✅ PASS: FileNotFoundError raised correctly.")


def run_all_tests():
    """Main execution entry point."""
    print("=" * 60)
    print("Running Primadoris AI Scanner Tests (test_scanner.py)")
    print("=" * 60)

    # Ensure test files exist
    make_test_files()

    test_safe_model()
    test_malicious_model()
    test_missing_file()

    print("=" * 60)
    print("🎉 ALL SCANNER TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        run_all_tests()
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
