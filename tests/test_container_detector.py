"""
test_container_detector.py
============================

Standalone pytest test suite for container_detector.py.

Design goals given the constraints in the task:
    * Tests must NOT require pulling large external images.
    * Docker-lifecycle behavior (CLI missing, daemon down, image not
      found, temp-container cleanup, timeouts) is tested by mocking
      subprocess/shutil -- these run with or without Docker installed.
    * Filesystem/package/pattern discovery is tested directly against a
      locally-built fake "extracted image" directory tree -- no Docker
      needed for these either, and no real crypto material is used
      anywhere (all key/cert content is synthetic or reused from the
      existing samples/certificates/ test-only fixtures).
    * A genuine end-to-end integration test (`docker create` + `docker
      export` against a real local image) is included but SKIPPED
      cleanly when Docker is not actually available on the machine
      running the tests, per the task's explicit requirement. It never
      pulls a remote image -- it only runs if the caller has already
      built/has a local image and set ECDAT_TEST_IMAGE, keeping this
      suite fast and network-free by default.

Run with:
    python -m pytest tests/test_container_detector.py -v
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scanner", "detectors"))

from scanner.detectors import container_detector as cd
from scanner.detectors.container_detector import (
    ContainerDetectorError,
    scan_container_image,
)  # noqa: E402

SAMPLES_CERT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "samples", "certificates"
)


def _cert_sample(name: str) -> str:
    return os.path.join(SAMPLES_CERT_DIR, name)


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --------------------------------------------------------------------------- #
# 1. Docker CLI missing
# --------------------------------------------------------------------------- #


def test_docker_cli_missing_raises_clear_error(monkeypatch):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: None)
    with pytest.raises(ContainerDetectorError, match="Docker CLI"):
        scan_container_image("whatever:latest")


# --------------------------------------------------------------------------- #
# 2. Docker daemon unavailable
# --------------------------------------------------------------------------- #


def test_docker_daemon_unavailable_raises_clear_error(monkeypatch):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: "/usr/bin/docker")

    def fake_run_docker(args, docker_bin="docker", timeout=cd.DEFAULT_STEP_TIMEOUT, capture_stdout_to=None):
        if args[:1] == ["info"]:
            return _FakeCompletedProcess(returncode=1, stderr=b"Cannot connect to the Docker daemon")
        raise AssertionError("should not reach further docker calls")

    monkeypatch.setattr(cd, "_run_docker", fake_run_docker)

    with pytest.raises(ContainerDetectorError, match="daemon"):
        scan_container_image("whatever:latest")


# --------------------------------------------------------------------------- #
# 3. Image not found
# --------------------------------------------------------------------------- #


def test_image_not_found_raises_clear_error(monkeypatch):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: "/usr/bin/docker")

    def fake_run_docker(args, docker_bin="docker", timeout=cd.DEFAULT_STEP_TIMEOUT, capture_stdout_to=None):
        if args[:1] == ["info"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"24.0.0")
        if args[:1] == ["inspect"]:
            return _FakeCompletedProcess(returncode=1, stderr=b"Error: No such object: nonexistent:latest")
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(cd, "_run_docker", fake_run_docker)

    with pytest.raises(ContainerDetectorError, match="not found"):
        scan_container_image("nonexistent:latest")


def test_invalid_image_name_raises():
    with pytest.raises(ContainerDetectorError):
        scan_container_image("")


# --------------------------------------------------------------------------- #
# 4. Image metadata detection
# --------------------------------------------------------------------------- #


def test_image_metadata_openssl_entrypoint_detected():
    inspect_data = {
        "Config": {
            "Entrypoint": ["openssl", "s_client", "-connect", "example.com:443"],
            "Cmd": [],
            "Env": ["PATH=/usr/bin"],
            "Labels": {},
        }
    }
    findings = cd._metadata_summary_and_findings("test:latest", inspect_data)
    assert any(f.evidence and "openssl s_client" in f.evidence for f in findings)
    assert all(f.detection_method == "docker_inspect" for f in findings)


def test_image_metadata_tls_env_var_detected():
    inspect_data = {
        "Config": {
            "Entrypoint": [],
            "Cmd": [],
            "Env": ["TLS_VERSION=TLSv1.2"],
            "Labels": {},
        }
    }
    findings = cd._metadata_summary_and_findings("test:latest", inspect_data)
    protocol_findings = [f for f in findings if f.artifact_type == "protocol"]
    assert any(f.protocol == "TLSv1.2" for f in protocol_findings)


def test_image_metadata_with_no_crypto_evidence_is_empty():
    inspect_data = {
        "Config": {
            "Entrypoint": ["/bin/sh", "-c", "echo hello"],
            "Cmd": [],
            "Env": ["PATH=/usr/bin"],
            "Labels": {"maintainer": "nobody@example.com"},
        }
    }
    findings = cd._metadata_summary_and_findings("test:latest", inspect_data)
    assert findings == []


# --------------------------------------------------------------------------- #
# 11. Secret / environment-value redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("var_name", ["DB_PASSWORD", "API_TOKEN", "SECRET_KEY", "MY_PASSWD", "AUTH_TOKEN"])
def test_secret_env_var_values_are_redacted(var_name):
    inspect_data = {
        "Config": {
            "Entrypoint": [],
            "Cmd": [],
            "Env": [f"{var_name}=super-secret-value-12345"],
            "Labels": {},
        }
    }
    findings = cd._metadata_summary_and_findings("test:latest", inspect_data)
    serialized = str([f.to_dict() for f in findings])
    assert "super-secret-value-12345" not in serialized


def test_non_secret_env_var_can_still_be_scanned_for_crypto_evidence():
    inspect_data = {
        "Config": {
            "Entrypoint": [],
            "Cmd": [],
            "Env": ["TLS_VERSION=TLSv1.3"],
            "Labels": {},
        }
    }
    findings = cd._metadata_summary_and_findings("test:latest", inspect_data)
    assert any(f.protocol == "TLSv1.3" for f in findings)


# --------------------------------------------------------------------------- #
# 5. OpenSSL package detection / package discovery (dpkg + apk)
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_dpkg_fs(tmp_path):
    root = tmp_path / "rootfs"
    dpkg_dir = root / "var" / "lib" / "dpkg"
    dpkg_dir.mkdir(parents=True)
    (dpkg_dir / "status").write_text(
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 3.0.13-0ubuntu1\n"
        "\n"
        "Package: libssl-dev\n"
        "Status: install ok installed\n"
        "Version: 3.0.13-0ubuntu1\n"
        "\n"
        "Package: bash\n"
        "Status: install ok installed\n"
        "Version: 5.2.15\n"
        "\n"
    )
    return str(root)


def test_openssl_package_detected_via_dpkg(fake_dpkg_fs):
    findings = cd._scan_dpkg_status(fake_dpkg_fs)
    assert any(f.library == "OpenSSL" and f.dependency_version == "3.0.13-0ubuntu1" for f in findings)
    assert all(f.detection_method == "package_metadata" for f in findings)
    # non-crypto package must not appear
    assert not any(f.evidence and "bash" in f.evidence for f in findings)


def test_openssl_dev_headers_detected_via_dpkg(fake_dpkg_fs):
    findings = cd._scan_dpkg_status(fake_dpkg_fs)
    assert any(f.library == "OpenSSL (dev headers)" for f in findings)


def test_package_install_confidence_is_medium(fake_dpkg_fs):
    findings = cd._scan_dpkg_status(fake_dpkg_fs)
    for f in findings:
        assert 0.5 <= f.confidence <= 0.95
    # and never claims algorithm usage
    assert all(f.artifact_type == "library" and f.algorithm is None for f in findings)


@pytest.fixture
def fake_apk_fs(tmp_path):
    root = tmp_path / "rootfs"
    apk_dir = root / "lib" / "apk" / "db"
    apk_dir.mkdir(parents=True)
    (apk_dir / "installed").write_text(
        "P:openssl\nV:3.1.4-r5\n\n"
        "P:musl\nV:1.2.4-r2\n\n"
    )
    return str(root)


def test_openssl_package_detected_via_apk(fake_apk_fs):
    findings = cd._scan_apk_installed(fake_apk_fs)
    assert any(f.library == "OpenSSL" and f.dependency_version == "3.1.4-r5" for f in findings)


# --------------------------------------------------------------------------- #
# 6/7/8. Crypto configuration / RSA / TLS detection in filesystem files
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_config_fs(tmp_path):
    root = tmp_path / "rootfs"
    (root / "etc" / "nginx").mkdir(parents=True)
    (root / "etc" / "nginx" / "nginx.conf").write_text(
        "server {\n"
        "  ssl_protocols TLSv1.2 TLSv1.3;\n"
        "  # ssl_protocols TLSv1.0; (disabled, comment)\n"
        "}\n"
    )
    (root / "etc" / "app").mkdir(parents=True)
    (root / "etc" / "app" / "app.conf").write_text(
        "key_algorithm = RSA-2048\n"
        "cipher = AES-256-GCM\n"
        "digest = SHA-256\n"
    )
    return str(root)


def test_tls_configuration_detected(fake_config_fs):
    findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    protocol_findings = [f for f in findings if f.artifact_type == "protocol"]
    versions = {f.protocol for f in protocol_findings}
    assert "TLSv1.2" in versions
    assert "TLSv1.3" in versions


def test_commented_out_config_line_has_lower_confidence(fake_config_fs):
    findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    active = [f for f in findings if f.protocol == "TLSv1.2"]
    commented = [f for f in findings if f.protocol == "TLSv1.0"]
    assert active and commented
    assert commented[0].confidence < active[0].confidence


def test_rsa_configuration_detected_with_keysize(fake_config_fs):
    findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    rsa_findings = [f for f in findings if f.algorithm == "RSA"]
    assert any(f.key_size == 2048 for f in rsa_findings)


def test_aes_and_sha_configuration_detected(fake_config_fs):
    findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    algos = {f.algorithm for f in findings if f.algorithm}
    assert any(a and a.startswith("AES") for a in algos)
    assert "SHA-256" in algos


def test_ordinary_config_without_crypto_produces_no_findings(tmp_path):
    root = tmp_path / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "motd.conf").write_text("welcome=true\ncolor=blue\n")
    findings = cd._scan_filesystem(str(root), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    assert findings == []


# --------------------------------------------------------------------------- #
# 9. Certificate file discovery (delegated to certificate_detector)
# --------------------------------------------------------------------------- #


def test_certificate_file_discovered_and_parsed(tmp_path):
    root = tmp_path / "rootfs" / "etc" / "ssl" / "certs"
    root.mkdir(parents=True)
    shutil.copy(_cert_sample("rsa2048_cert.pem"), str(root / "server.pem"))

    findings = cd._scan_filesystem(str(tmp_path / "rootfs"), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    cert_findings = [f for f in findings if f.artifact_type == "certificate"]
    assert len(cert_findings) == 1
    assert cert_findings[0].algorithm == "RSA"
    assert cert_findings[0].key_size == 2048
    assert cert_findings[0].detection_method == "certificate_detector"
    assert cert_findings[0].certificate_subject


def test_private_key_only_pem_is_not_classified_as_certificate_in_container(tmp_path):
    root = tmp_path / "rootfs" / "etc" / "ssl" / "private"
    root.mkdir(parents=True)
    shutil.copy(_cert_sample("private_key_only.pem"), str(root / "server.pem"))

    findings = cd._scan_filesystem(str(tmp_path / "rootfs"), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    # certificate_detector correctly returns [] for a private-key-only PEM;
    # the container detector must not invent a certificate finding for it.
    assert not any(f.artifact_type == "certificate" for f in findings)


# --------------------------------------------------------------------------- #
# 10. Private-key detection without leaking contents
# --------------------------------------------------------------------------- #


def test_private_key_detected_without_exposing_contents(tmp_path):
    root = tmp_path / "rootfs" / "etc" / "ssh"
    root.mkdir(parents=True)
    (root / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "TESTFAKEKEYDATATESTFAKEKEYDATA\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    findings = cd._scan_filesystem(str(tmp_path / "rootfs"), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    key_findings = [f for f in findings if f.artifact_type == "private_key"]
    assert len(key_findings) == 1
    assert key_findings[0].algorithm == "RSA"

    serialized = str(key_findings[0].to_dict())
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert "TESTFAKEKEYDATATESTFAKEKEYDATA" not in serialized


def test_public_key_file_detected_as_public_not_private(tmp_path):
    root = tmp_path / "rootfs" / "etc" / "ssh"
    root.mkdir(parents=True)
    (root / "id_rsa.pub").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC test@example\n")

    findings = cd._scan_filesystem(str(tmp_path / "rootfs"), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    assert any(f.artifact_type == "public_key" for f in findings)
    assert not any(f.artifact_type == "private_key" for f in findings)


# --------------------------------------------------------------------------- #
# 12. Temporary container cleanup
# --------------------------------------------------------------------------- #


def test_temporary_container_is_always_removed_even_on_export_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: "/usr/bin/docker")

    calls = []

    def fake_run_docker(args, docker_bin="docker", timeout=cd.DEFAULT_STEP_TIMEOUT, capture_stdout_to=None):
        calls.append(list(args))
        if args[:1] == ["info"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"24.0.0")
        if args[:1] == ["inspect"]:
            return _FakeCompletedProcess(returncode=0, stdout=json.dumps([{"Config": {}}]).encode())
        if args[:1] == ["create"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"fakecontainerid123\n")
        if args[:1] == ["export"]:
            return _FakeCompletedProcess(returncode=1, stderr=b"export failed for test purposes")
        if args[:1] == ["rm"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"fakecontainerid123\n")
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(cd, "_run_docker", fake_run_docker)

    with pytest.raises(ContainerDetectorError):
        scan_container_image("fake:latest")

    rm_calls = [c for c in calls if c[:1] == ["rm"]]
    assert len(rm_calls) == 1
    assert "fakecontainerid123" in rm_calls[0]


def test_temporary_container_removed_on_success(monkeypatch, tmp_path):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: "/usr/bin/docker")

    calls = []

    # Build a minimal, valid (empty) tar to represent a successful export.
    import tarfile
    empty_tar_path = tmp_path / "empty.tar"
    with tarfile.open(str(empty_tar_path), "w"):
        pass

    def fake_run_docker(args, docker_bin="docker", timeout=cd.DEFAULT_STEP_TIMEOUT, capture_stdout_to=None):
        calls.append(list(args))
        if args[:1] == ["info"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"24.0.0")
        if args[:1] == ["inspect"]:
            return _FakeCompletedProcess(returncode=0, stdout=json.dumps([{"Config": {}}]).encode())
        if args[:1] == ["create"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"fakecontainerid456\n")
        if args[:1] == ["export"]:
            if capture_stdout_to:
                shutil.copy(str(empty_tar_path), capture_stdout_to)
            return _FakeCompletedProcess(returncode=0)
        if args[:1] == ["rm"]:
            return _FakeCompletedProcess(returncode=0, stdout=b"fakecontainerid456\n")
        raise AssertionError(f"unexpected docker call: {args}")

    monkeypatch.setattr(cd, "_run_docker", fake_run_docker)

    findings = scan_container_image("fake:latest")
    assert isinstance(findings, list)

    rm_calls = [c for c in calls if c[:1] == ["rm"]]
    assert len(rm_calls) == 1
    assert "fakecontainerid456" in rm_calls[0]


# --------------------------------------------------------------------------- #
# 13. Timeout handling
# --------------------------------------------------------------------------- #


def test_docker_command_timeout_raises_clear_error(monkeypatch):
    monkeypatch.setattr(cd.shutil, "which", lambda _bin: "/usr/bin/docker")

    def fake_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr(cd.subprocess, "run", fake_subprocess_run)

    with pytest.raises(ContainerDetectorError, match="timed out"):
        scan_container_image("whatever:latest")


# --------------------------------------------------------------------------- #
# 14. Empty / no-crypto image (filesystem-level)
# --------------------------------------------------------------------------- #


def test_empty_filesystem_produces_no_findings(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "readme.txt").write_text("hello world, nothing crypto-related here\n")
    findings = cd._scan_filesystem(str(root), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    assert findings == []


# --------------------------------------------------------------------------- #
# 15/16/17. Output fields, confidence values, source_type
# --------------------------------------------------------------------------- #


def test_output_fields_present_on_every_finding(fake_config_fs):
    findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    assert findings
    for f in findings:
        d = f.to_dict()
        for required_field in ("artifact_id", "artifact_type", "file_path", "line_number",
                                "detection_method", "confidence", "source_type"):
            assert required_field in d


def test_source_type_is_container_image_for_all_findings(fake_config_fs, fake_dpkg_fs):
    fs_findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    pkg_findings = cd._scan_dpkg_status(fake_dpkg_fs)
    for f in fs_findings + pkg_findings:
        assert f.to_dict()["source_type"] == "container_image"


def test_confidence_values_are_in_valid_range(fake_config_fs, fake_dpkg_fs):
    fs_findings = cd._scan_filesystem(fake_config_fs, timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    pkg_findings = cd._scan_dpkg_status(fake_dpkg_fs)
    for f in fs_findings + pkg_findings:
        assert 0.0 < f.confidence <= 1.0


def test_certificate_finding_confidence_is_high(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    shutil.copy(_cert_sample("rsa2048_cert.pem"), str(root / "server.pem"))
    findings = cd._scan_filesystem(str(root), timeout=10, max_files_scanned=1000, max_file_size_bytes=1_000_000)
    cert_findings = [f for f in findings if f.artifact_type == "certificate"]
    assert cert_findings[0].confidence >= 0.9


# --------------------------------------------------------------------------- #
# Path-traversal safety for tar extraction ("zip slip")
# --------------------------------------------------------------------------- #


def test_tar_extraction_rejects_path_traversal(tmp_path):
    import tarfile
    import io

    malicious_tar = tmp_path / "evil.tar"
    with tarfile.open(str(malicious_tar), "w") as tar:
        payload = b"malicious content"
        info = tarfile.TarInfo(name="../../etc/passwd_evil")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

        info2 = tarfile.TarInfo(name="safe_file.txt")
        payload2 = b"safe content"
        info2.size = len(payload2)
        tar.addfile(info2, io.BytesIO(payload2))

    dest = tmp_path / "extracted"
    dest.mkdir()
    cd._safe_extract_tar(str(malicious_tar), str(dest))

    # the traversal target must NOT have been created outside dest
    escaped_path = tmp_path.parent / "etc" / "passwd_evil"
    assert not escaped_path.exists()
    # but the safe file should extract normally
    assert (dest / "safe_file.txt").exists()


# --------------------------------------------------------------------------- #
# Genuine end-to-end integration test -- SKIPPED unless Docker is actually
# available on the machine AND the caller opts in with ECDAT_TEST_IMAGE, so
# this suite never pulls a remote image and never fails in CI without Docker.
# --------------------------------------------------------------------------- #


def _real_docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(["docker", "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def test_end_to_end_scan_of_local_image_integration():
    if not _real_docker_available():
        pytest.skip("Docker is not installed/running on this machine; skipping live integration test.")
    image = os.environ.get("ECDAT_TEST_IMAGE")
    if not image:
        pytest.skip("Set ECDAT_TEST_IMAGE to a locally-available image to run this integration test.")

    findings = scan_container_image(image)
    assert isinstance(findings, list)
    for f in findings:
        assert f["source_type"] == "container_image"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
