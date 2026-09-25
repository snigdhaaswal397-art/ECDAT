"""
ECDAT — Cryptographic Library / Dependency Detector
===================================================

Scans project dependency manifest files for cryptographic libraries and versions.

Supported Formats:
  - Python: requirements.txt, pyproject.toml
  - Java: pom.xml, build.gradle
  - JavaScript / TypeScript: package.json, package-lock.json
  - C / C++: CMakeLists.txt, conanfile.txt, vcpkg.json

Rules:
  - Detect crypto libraries and exact versions when specified.
  - If version is missing/unresolved, fallback strictly to "unknown" (never invent versions).
  - Keeps dependency findings compatible with the Artifact model (artifact_type="library").
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import os
import re
import xml.etree.ElementTree as ET

from scanner.models import (
    Artifact,
    CONFIDENCE_DEPENDENCY_SCAN,
)

# Known Crypto Libraries across ecosystems
KNOWN_CRYPTO_DEPENDENCIES = {
    # Python
    "cryptography": "cryptography (Python)",
    "pycryptodome": "PyCryptodome",
    "pycrypto": "PyCrypto",
    "pyopenssl": "pyOpenSSL",
    "pynacl": "PyNaCl (libsodium)",
    "passlib": "passlib",
    "bcrypt": "bcrypt",

    # Java / Maven / Gradle
    "bouncycastle": "Bouncy Castle",
    "bcprov-jdk15on": "Bouncy Castle Provider",
    "bcprov-jdk18on": "Bouncy Castle Provider",
    "bcpkix-jdk15on": "Bouncy Castle PKIX",
    "commons-crypto": "Apache Commons Crypto",
    "tink": "Google Tink",
    "conscrypt-openjdk-uber": "Conscrypt",

    # JS / Node
    "crypto-js": "crypto-js",
    "node-forge": "node-forge",
    "sodium-native": "sodium-native",
    "libsodium-wrappers": "libsodium-wrappers",
    "sjcl": "Stanford Javascript Crypto Library",
    "elliptic": "elliptic",
    "jsrsasign": "jsrsasign",

    # C / C++
    "openssl": "OpenSSL",
    "boringssl": "BoringSSL",
    "libsodium": "libsodium",
    "mbedtls": "mbed TLS",
    "gnutls": "GnuTLS",
    "wolfssl": "wolfSSL",
    "libgcrypt": "Libgcrypt",
}


def _parse_requirements_txt(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return artifacts

    for line_idx, line in enumerate(lines, start=1):
        sline = line.strip()
        if not sline or sline.startswith("#"):
            continue

        # Match package==version or package>=version
        m = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:[=><~]=?\s*([a-zA-Z0-9_\.\-]+))?", sline)
        if m:
            pkg_raw = m.group(1).lower()
            version = m.group(2) if m.group(2) else "unknown"
            if pkg_raw in KNOWN_CRYPTO_DEPENDENCIES:
                lib_name = KNOWN_CRYPTO_DEPENDENCIES[pkg_raw]
                artifacts.append(Artifact(
                    artifact_type="library",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="dependency_manifest",
                    confidence=CONFIDENCE_DEPENDENCY_SCAN,
                    library=lib_name,
                    dependency_version=version,
                    line_number=line_idx,
                    code_snippet=sline,
                ).to_dict())

    return artifacts


def _parse_pyproject_toml(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception:
        return artifacts

    for pkg_key, lib_name in KNOWN_CRYPTO_DEPENDENCIES.items():
        pattern = re.compile(rf'"{pkg_key}"\s*[:=]\s*"([^"]+)"', re.IGNORECASE)
        for m in pattern.finditer(text):
            ver = m.group(1) if m.group(1) else "unknown"
            artifacts.append(Artifact(
                artifact_type="library",
                algorithm=None,
                key_size=None,
                file_path=file_path,
                detection_method="dependency_manifest",
                confidence=CONFIDENCE_DEPENDENCY_SCAN,
                library=lib_name,
                dependency_version=ver,
                line_number=text.count("\n", 0, m.start()) + 1,
                code_snippet=m.group(0),
            ).to_dict())
    return artifacts


def _parse_package_json(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return artifacts

    deps = {}
    if isinstance(data, dict):
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

    for pkg_name, ver in deps.items():
        pkg_key = pkg_name.lower().strip()
        if pkg_key in KNOWN_CRYPTO_DEPENDENCIES:
            clean_ver = str(ver).replace("^", "").replace("~", "").strip() or "unknown"
            artifacts.append(Artifact(
                artifact_type="library",
                algorithm=None,
                key_size=None,
                file_path=file_path,
                detection_method="dependency_manifest",
                confidence=CONFIDENCE_DEPENDENCY_SCAN,
                library=KNOWN_CRYPTO_DEPENDENCIES[pkg_key],
                dependency_version=clean_ver,
                line_number=1,
                code_snippet=f'"{pkg_name}": "{ver}"',
            ).to_dict())

    return artifacts


def _parse_pom_xml(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        # strip namespaces
        for elem in root.iter():
            if "}" in elem.tag:
                elem.tag = elem.tag.split("}", 1)[1]

        for dep in root.iter("dependency"):
            art_id = dep.findtext("artifactId", "").strip().lower()
            ver = dep.findtext("version", "unknown").strip()
            if art_id in KNOWN_CRYPTO_DEPENDENCIES:
                artifacts.append(Artifact(
                    artifact_type="library",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="dependency_manifest",
                    confidence=CONFIDENCE_DEPENDENCY_SCAN,
                    library=KNOWN_CRYPTO_DEPENDENCIES[art_id],
                    dependency_version=ver if ver else "unknown",
                    line_number=1,
                    code_snippet=f"<artifactId>{art_id}</artifactId>",
                ).to_dict())
    except Exception:
        pass
    return artifacts


def _parse_build_gradle(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return artifacts

    for line_idx, line in enumerate(lines, start=1):
        sline = line.strip()
        for pkg_key, lib_name in KNOWN_CRYPTO_DEPENDENCIES.items():
            if pkg_key in sline.lower():
                m = re.search(r"['\"]([^'\"]+:[^'\"]+:([^'\"]+))['\"]", sline)
                ver = m.group(2) if m else "unknown"
                artifacts.append(Artifact(
                    artifact_type="library",
                    algorithm=None,
                    key_size=None,
                    file_path=file_path,
                    detection_method="dependency_manifest",
                    confidence=CONFIDENCE_DEPENDENCY_SCAN,
                    library=lib_name,
                    dependency_version=ver,
                    line_number=line_idx,
                    code_snippet=sline,
                ).to_dict())

    return artifacts


def _parse_cmake_lists(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return artifacts

    for line_idx, line in enumerate(lines, start=1):
        sline = line.strip()
        if "find_package" in sline.lower() or "target_link_libraries" in sline.lower():
            for pkg_key, lib_name in KNOWN_CRYPTO_DEPENDENCIES.items():
                if pkg_key in sline.lower():
                    m = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", sline)
                    ver = m.group(1) if m else "unknown"
                    artifacts.append(Artifact(
                        artifact_type="library",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="dependency_manifest",
                        confidence=CONFIDENCE_DEPENDENCY_SCAN,
                        library=lib_name,
                        dependency_version=ver,
                        line_number=line_idx,
                        code_snippet=sline,
                    ).to_dict())
    return artifacts


def scan_dependency_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Public entry point to parse a project dependency manifest file.
    """
    fname = os.path.basename(file_path).lower()

    if "requirements.txt" in fname:
        return _parse_requirements_txt(file_path)
    elif "pyproject.toml" in fname:
        return _parse_pyproject_toml(file_path)
    elif "package.json" in fname or "package-lock.json" in fname:
        return _parse_package_json(file_path)
    elif "pom.xml" in fname:
        return _parse_pom_xml(file_path)
    elif "build.gradle" in fname:
        return _parse_build_gradle(file_path)
    elif "cmakelists.txt" in fname or "conanfile.txt" in fname or "vcpkg.json" in fname:
        return _parse_cmake_lists(file_path)

    return []
