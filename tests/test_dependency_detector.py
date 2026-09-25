"""
Unit tests for Cryptographic Library / Dependency detector.
"""

import os
import tempfile
from scanner.detectors.dependency_detector import scan_dependency_file


def test_requirements_txt_detection():
    content = """
cryptography==41.0.0
pycryptodome>=3.18.0
requests==2.31.0
"""
    with tempfile.NamedTemporaryFile("w", suffix="requirements.txt", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_dependency_file(f_path)
        assert len(results) == 2
        crypto_finding = next((r for r in results if "cryptography" in r.get("library", "").lower()), None)
        assert crypto_finding is not None
        assert crypto_finding.get("dependency_version") == "41.0.0"
        assert crypto_finding.get("artifact_type") == "library"
    finally:
        os.unlink(f_path)


def test_package_json_detection():
    content = """{
    "dependencies": {
        "crypto-js": "^4.1.1",
        "express": "^4.18.2"
    }
}"""
    with tempfile.NamedTemporaryFile("w", suffix="package.json", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_dependency_file(f_path)
        assert len(results) == 1
        assert results[0].get("library") == "crypto-js"
        assert results[0].get("dependency_version") == "4.1.1"
    finally:
        os.unlink(f_path)


def test_pom_xml_detection():
    content = """<project>
    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk15on</artifactId>
            <version>1.70</version>
        </dependency>
    </dependencies>
</project>"""
    with tempfile.NamedTemporaryFile("w", suffix="pom.xml", delete=False, encoding="utf-8") as f:
        f.write(content)
        f_path = f.name

    try:
        results = scan_dependency_file(f_path)
        assert len(results) == 1
        assert "Bouncy Castle" in results[0].get("library")
        assert results[0].get("dependency_version") == "1.70"
    finally:
        os.unlink(f_path)
