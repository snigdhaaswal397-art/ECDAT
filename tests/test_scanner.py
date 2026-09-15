"""
Tests for scanner.py: the orchestrator itself, not any individual detector.

This file did not exist in the uploaded project -- there was no test
coverage at all for scan_directory(), the schema normalization step
(_to_dict), the deduplication step (deduplicate_findings), or end-to-end
JSON output (empty directory -> [], mixed directory -> one combined array).
Added as part of the scanner audit; see spec sections 3, 11, 13, 14.

Run with: python -m pytest tests/test_scanner.py -v
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.scanner import scan_directory, deduplicate_findings, _to_dict
from scanner.models import Artifact


# ---------------------------------------------------------------------------
# scan_directory(): schema normalization, empty/mixed directories
# ---------------------------------------------------------------------------


def test_empty_directory_returns_empty_list(tmp_path):
    findings = scan_directory(str(tmp_path))
    assert findings == []


def test_scan_directory_always_returns_plain_dicts_never_artifact_objects(tmp_path):
    """
    Spec section 13: detectors internally return a mix of dict/Artifact,
    but scan_directory() must always hand back plain dicts so any caller
    (this scanner's own __main__, a future FastAPI endpoint, the CBOM
    module) never has to check isinstance(x, Artifact).
    """
    (tmp_path / "app.py").write_text(
        "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n"
    )
    (tmp_path / "app.js").write_text(
        'const crypto = require("crypto");\n'
        'const hash = crypto.createHash("sha256");\n'
    )
    findings = scan_directory(str(tmp_path))
    assert findings  # something was found
    for f in findings:
        assert isinstance(f, dict)
        assert not isinstance(f, Artifact)


def test_mixed_directory_produces_one_combined_array(tmp_path):
    (tmp_path / "app.py").write_text("import hashlib\nh = hashlib.sha256(b'x')\n")
    (tmp_path / "app.js").write_text(
        'const crypto = require("crypto");\n'
        'const h = crypto.createHash("md5");\n'
    )
    (tmp_path / "app.c").write_text(
        "#include <openssl/aes.h>\nAES_encrypt(in, out, &key);\n"
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN apt-get install -y openssl\n")

    findings = scan_directory(str(tmp_path))
    algorithms = {f.get("algorithm") for f in findings}
    assert "SHA-256" in algorithms
    assert "MD5" in algorithms
    assert "AES" in algorithms
    # every finding is a dict with the required core fields
    for f in findings:
        for required in ("artifact_id", "artifact_type", "detection_method", "confidence"):
            assert required in f


def test_unreadable_file_does_not_crash_the_whole_scan(tmp_path):
    """A single bad file must be skipped, not abort the entire scan."""
    good = tmp_path / "good.py"
    good.write_text("import hashlib\nh = hashlib.md5(b'x')\n")

    bad = tmp_path / "bad.py"
    bad.write_bytes(b"\xff\xfe\x00\x01 this is not valid text or python \x00")

    findings = scan_directory(str(tmp_path))
    assert any(f.get("algorithm") == "MD5" for f in findings)


# ---------------------------------------------------------------------------
# _to_dict(): the single normalization point
# ---------------------------------------------------------------------------


def test_to_dict_passes_through_plain_dicts_unchanged():
    d = {"artifact_type": "library", "algorithm": None}
    assert _to_dict(d) is d


def test_to_dict_converts_artifact_objects():
    a = Artifact(artifact_type="algorithm", algorithm="RSA", key_size=2048,
                 file_path="x.py", detection_method="ast_call", confidence=0.95,
                 line_number=1, code_snippet="RSA.generate(2048)")
    d = _to_dict(a)
    assert isinstance(d, dict)
    assert d["algorithm"] == "RSA"
    assert "artifact_id" in d


# ---------------------------------------------------------------------------
# deduplicate_findings(): exact-duplicate removal only
# ---------------------------------------------------------------------------


def test_exact_duplicate_is_removed():
    finding = {
        "file_path": "a.py", "line_number": 5, "artifact_type": "algorithm",
        "algorithm": "RSA", "evidence": None, "detection_method": "ast_call",
        "confidence": 0.95,
    }
    deduped = deduplicate_findings([dict(finding), dict(finding)])
    assert len(deduped) == 1


def test_same_algorithm_different_lines_both_kept():
    """Spec section 11: two genuinely different call sites using the same
    algorithm must NOT be collapsed into one."""
    f1 = {"file_path": "a.py", "line_number": 5, "artifact_type": "algorithm",
          "algorithm": "AES", "evidence": None, "detection_method": "ast_call", "confidence": 0.9}
    f2 = dict(f1, line_number=42)
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2


def test_windows_and_posix_paths_normalize_to_same_dedup_key():
    f1 = {"file_path": "samples\\app.py", "line_number": 5, "artifact_type": "algorithm",
          "algorithm": "AES", "evidence": None, "detection_method": "ast_call", "confidence": 0.9}
    f2 = dict(f1, file_path="samples/app.py")
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1


def test_deduplicate_preserves_order_of_first_occurrence():
    f1 = {"file_path": "a.py", "line_number": 1, "artifact_type": "algorithm",
          "algorithm": "RSA", "evidence": None, "detection_method": "ast_call", "confidence": 0.9}
    f2 = {"file_path": "b.py", "line_number": 1, "artifact_type": "algorithm",
          "algorithm": "AES", "evidence": None, "detection_method": "ast_call", "confidence": 0.9}
    deduped = deduplicate_findings([f1, f2, dict(f1)])
    assert [d["file_path"] for d in deduped] == ["a.py", "b.py"]


# ---------------------------------------------------------------------------
# CLI-level: valid JSON output, UTF-8, "[]" for zero findings
# ---------------------------------------------------------------------------


def _run_cli(args, cwd):
    scanner_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scanner", "scanner.py")
    return subprocess.run(
        [sys.executable, scanner_py] + args,
        cwd=cwd, capture_output=True, text=True, timeout=60,
    )


def test_cli_empty_directory_writes_valid_empty_json_array(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    output_path = tmp_path / "out.json"

    result = _run_cli([str(empty_dir), "-o", str(output_path)], cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr

    with open(output_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data == []


def test_cli_output_is_valid_utf8_json_with_indentation(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "app.py").write_text("import hashlib\nh = hashlib.sha256(b'x')\n")
    output_path = tmp_path / "out.json"

    result = _run_cli([str(src_dir), "-o", str(output_path)], cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr

    raw = output_path.read_bytes()
    raw.decode("utf-8")  # must not raise
    text = raw.decode("utf-8")
    assert "\n  " in text  # indented, human-readable, not a single line

    data = json.loads(text)
    assert isinstance(data, list)
    assert any(f["algorithm"] == "SHA-256" for f in data)


def test_cli_output_is_fully_overwritten_not_appended(tmp_path):
    """Running the scanner twice against different inputs must not leave
    stale findings from the first run mixed into the second run's output."""
    output_path = tmp_path / "out.json"

    dir1 = tmp_path / "d1"
    dir1.mkdir()
    (dir1 / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    r1 = _run_cli([str(dir1), "-o", str(output_path)], cwd=str(tmp_path))
    assert r1.returncode == 0, r1.stderr

    dir2 = tmp_path / "d2"
    dir2.mkdir()
    (dir2 / "b.py").write_text("import hashlib\nh = hashlib.sha256(b'x')\n")
    r2 = _run_cli([str(dir2), "-o", str(output_path)], cwd=str(tmp_path))
    assert r2.returncode == 0, r2.stderr

    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)
    algorithms = {d["algorithm"] for d in data}
    assert "SHA-256" in algorithms
    assert "MD5" not in algorithms  # first run's finding must be gone


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))