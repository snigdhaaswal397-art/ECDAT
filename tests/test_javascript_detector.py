from pathlib import Path

from scanner.detectors.javascript_detector import scan_javascript_file


def create_sample(tmp_path, filename, content):
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return file_path


def test_sha256_hash(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hash = crypto.createHash("sha256");
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "SHA-256"
        for artifact in artifacts
    )


def test_md5_hash(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hash = crypto.createHash("md5");
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "MD5"
        for artifact in artifacts
    )


def test_hmac(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hmac = crypto.createHmac("sha256", secret);
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "SHA-256"
        for artifact in artifacts
    )


def test_aes(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const cipher = crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "AES"
        for artifact in artifacts
    )


def test_rsa(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.ts",
        """
        const crypto = require("crypto");

        crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048
        });
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "RSA"
        for artifact in artifacts
    )


def test_import_only_is_low_confidence(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert len(artifacts) >= 1

    for artifact in artifacts:
        assert artifact.confidence < 0.5


def test_comments_are_not_detected(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        // crypto.createHash("md5")
        // AES encryption
        // RSA 2048
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert len(artifacts) == 0


def test_web_crypto(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.ts",
        """
        const digest = await crypto.subtle.digest(
            "SHA-256",
            data
        );
        """,
    )

    artifacts = scan_javascript_file(file_path)

    assert any(
        artifact.algorithm == "SHA-256"
        for artifact in artifacts
    )