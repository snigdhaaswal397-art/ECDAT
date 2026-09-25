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


def test_sha256_hash_does_not_also_report_md5_aes_rsa(tmp_path):
    """
    Regression test for the reported false-positive bug: a single
    crypto.createHash("sha256") call must report ONLY SHA-256 -- not MD5,
    AES, or RSA just because those words happen to appear elsewhere in the
    file. This is the negative assertion the original test suite was
    missing (every existing test only checked the right answer was
    PRESENT, never that wrong answers were ABSENT).
    """
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hash = crypto.createHash("sha256");
        """,
    )

    artifacts = scan_javascript_file(file_path)
    algorithms_for_this_call = {a.algorithm for a in artifacts if a.line_number == 4}

    assert algorithms_for_this_call == {"SHA-256"}


def test_md5_hash_does_not_also_report_sha256_aes_rsa(tmp_path):
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hash = crypto.createHash("md5");
        """,
    )

    artifacts = scan_javascript_file(file_path)
    algorithms_for_this_call = {a.algorithm for a in artifacts if a.line_number == 4}

    assert algorithms_for_this_call == {"MD5"}


def test_multiple_nearby_crypto_calls_do_not_contaminate_each_other(tmp_path):
    """
    Reproduces the exact scenario from samples/modern/crypto_test.js that
    surfaced the bug in practice: several different crypto operations sit
    within a few lines of each other in the same small file. Each call
    must be attributed only its OWN algorithm.
    """
    file_path = create_sample(
        tmp_path,
        "test.js",
        """
        const crypto = require("crypto");

        const hash = crypto.createHash("sha256");

        const oldHash = crypto.createHash("md5");

        const cipher = crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

        crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048
        });
        """,
    )

    artifacts = scan_javascript_file(file_path)

    by_line = {}
    for a in artifacts:
        by_line.setdefault(a.line_number, set()).add(a.algorithm)

    sha256_line = next(line for line, algos in by_line.items() if "SHA-256" in algos)
    md5_line = next(line for line, algos in by_line.items() if "MD5" in algos)
    aes_line = next(line for line, algos in by_line.items() if "AES" in algos)
    rsa_line = next(line for line, algos in by_line.items() if "RSA" in algos)

    assert by_line[sha256_line] == {"SHA-256"}
    assert by_line[md5_line] == {"MD5"}
    assert by_line[aes_line] == {"AES"}
    assert by_line[rsa_line] == {"RSA"}

    rsa_finding = next(a for a in artifacts if a.algorithm == "RSA")
    assert rsa_finding.key_size == 2048


def test_line_numbers_survive_a_preceding_block_comment(tmp_path):
    """
    Regression test for a related bug: comments used to be *deleted*
    before searching, which shifted every later match's character offset
    and produced wrong line numbers whenever a comment preceded the match.
    Comments are now masked (blanked, not removed) so offsets -- and line
    numbers -- stay correct.
    """
    file_path = create_sample(
        tmp_path,
        "test.js",
        "/* a comment\n"
        "spanning several\n"
        "lines */\n"
        'const crypto = require("crypto");\n'
        'const hash = crypto.createHash("sha256");\n',
    )

    artifacts = scan_javascript_file(file_path)
    hash_finding = next(a for a in artifacts if a.algorithm == "SHA-256")
    assert hash_finding.line_number == 5


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