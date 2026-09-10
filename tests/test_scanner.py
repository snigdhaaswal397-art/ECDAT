"""
test_scanner.py
===============
Tests for scanner.py orchestrator: deduplication, path normalization,
directory scanning, and malformed certificate warning artifacts.
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner import deduplicate_findings, scan_directory


def test_deduplicate_findings_removes_exact_duplicates():
    findings = [
        {
            "file_path": "samples/test.py",
            "line_number": 10,
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "evidence": None,
            "detection_method": "ast_call",
        },
        {
            "file_path": "samples/test.py",
            "line_number": 10,
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "evidence": None,
            "detection_method": "ast_call",
        },
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1


def test_deduplicate_findings_normalizes_windows_paths():
    findings = [
        {
            "file_path": "samples\\test.py",
            "line_number": 10,
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "evidence": None,
            "detection_method": "ast_call",
        },
        {
            "file_path": "samples/test.py",
            "line_number": 10,
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "evidence": None,
            "detection_method": "ast_call",
        },
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1


def test_scan_directory_creates_warning_for_malformed_certificate():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_cert_path = os.path.join(tmp_dir, "bad.crt")
        with open(bad_cert_path, "w", encoding="utf-8") as f:
            f.write("NOT A REAL CERTIFICATE\n")

        results = scan_directory(tmp_dir)
        warnings = [r for r in results if r.get("artifact_type") == "warning"]
        assert len(warnings) == 1
        assert warnings[0]["warning_type"] == "malformed_certificate"
        assert warnings[0]["confidence"] == 0.0
        assert "bad.crt" in warnings[0]["file_path"].replace("\\", "/")
