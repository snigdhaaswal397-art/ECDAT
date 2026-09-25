"""
ECDAT — Static Binary Cryptographic Detector
=============================================

Static inspection of compiled binary files (ELF & PE) for cryptographic evidence.

Target Binary Formats:
  - ELF (.so, executables)
  - PE (.exe, .dll)

Safety & Scope Rules:
  - NEVER executes binaries or performs dynamic analysis.
  - NEVER performs full reverse engineering or decompilation.
  - Extracts imported/exported symbols, linked library references, crypto API
    names, recognizable crypto strings, and embedded X.509 PEM certificates.
  - Malformed binaries are handled gracefully without aborting the scan.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import os
import re

import pefile
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

from scanner.models import (
    Artifact,
    CONFIDENCE_PATTERN_MATCH,
)

# Known Cryptographic Symbols & Functions in Binaries
CRYPTO_SYMBOL_MAP = {
    # OpenSSL / libcrypto
    "RSA_private_encrypt": ("RSA", "algorithm", "OpenSSL"),
    "RSA_public_decrypt": ("RSA", "algorithm", "OpenSSL"),
    "RSA_generate_key_ex": ("RSA", "algorithm", "OpenSSL"),
    "EVP_sha256": ("SHA-256", "hash", "OpenSSL"),
    "EVP_sha1": ("SHA-1", "hash", "OpenSSL"),
    "EVP_md5": ("MD5", "hash", "OpenSSL"),
    "EVP_sha512": ("SHA-512", "hash", "OpenSSL"),
    "AES_encrypt": ("AES", "algorithm", "OpenSSL"),
    "AES_cbc_encrypt": ("AES", "algorithm", "OpenSSL"),
    "AES_gcm_encrypt": ("AES", "algorithm", "OpenSSL"),
    "DES_ecb_encrypt": ("DES", "algorithm", "OpenSSL"),
    "EC_KEY_new": ("ECC", "algorithm", "OpenSSL"),
    "ECDSA_do_sign": ("ECDSA", "algorithm", "OpenSSL"),
    "HMAC_Init_ex": ("HMAC", "hash", "OpenSSL"),

    # Windows CNG / CryptoAPI
    "BCryptEncrypt": ("AES", "algorithm", "Windows CNG"),
    "BCryptDecrypt": ("AES", "algorithm", "Windows CNG"),
    "BCryptCreateHash": ("SHA-256", "hash", "Windows CNG"),
    "CryptGenKey": ("RSA", "algorithm", "Windows CryptoAPI"),
    "CryptEncrypt": ("RSA", "algorithm", "Windows CryptoAPI"),
}

KNOWN_CRYPTO_DLLS = {
    "libcrypto.so": "OpenSSL libcrypto",
    "libssl.so": "OpenSSL libssl",
    "ssleay32.dll": "OpenSSL SSLeay",
    "libeay32.dll": "OpenSSL SSLeay",
    "bcrypt.dll": "Windows CNG",
    "crypt32.dll": "Windows CryptoAPI",
    "libsodium.so": "libsodium",
    "libsodium.dll": "libsodium",
}

CERT_HEADER_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)


def _scan_pe_binary(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
    except Exception:
        return artifacts

    # Check imported DLLs & functions
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore").lower() if entry.dll else ""
            for lib_key, lib_desc in KNOWN_CRYPTO_DLLS.items():
                if lib_key in dll_name:
                    artifacts.append(Artifact(
                        artifact_type="library",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="binary_pe_import",
                        confidence=0.85,
                        library=lib_desc,
                        code_snippet=f"Imported DLL: {dll_name}",
                        evidence=f"PE imports linked library {dll_name}",
                    ).to_dict())

            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode("utf-8", errors="ignore")
                    if func_name in CRYPTO_SYMBOL_MAP:
                        alg, art_type, lib = CRYPTO_SYMBOL_MAP[func_name]
                        artifacts.append(Artifact(
                            artifact_type=art_type,
                            algorithm=alg,
                            key_size=None,
                            file_path=file_path,
                            detection_method="binary_pe_symbol",
                            confidence=0.90,
                            library=lib,
                            code_snippet=f"Imported symbol: {func_name}",
                            evidence=f"PE imports crypto function {func_name}",
                        ).to_dict())

    # Check exported functions
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode("utf-8", errors="ignore")
                if func_name in CRYPTO_SYMBOL_MAP:
                    alg, art_type, lib = CRYPTO_SYMBOL_MAP[func_name]
                    artifacts.append(Artifact(
                        artifact_type=art_type,
                        algorithm=alg,
                        key_size=None,
                        file_path=file_path,
                        detection_method="binary_pe_symbol",
                        confidence=0.90,
                        library=lib,
                        code_snippet=f"Exported symbol: {func_name}",
                        evidence=f"PE exports crypto function {func_name}",
                    ).to_dict())

    return artifacts


def _scan_elf_binary(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            # Iterate sections for symbol table & dynamic sections
            for section in elf.iter_sections():
                if section.name in (".dynstr", ".strtab"):
                    data = section.data().decode("utf-8", errors="ignore")
                    for symbol_name, (alg, art_type, lib) in CRYPTO_SYMBOL_MAP.items():
                        if symbol_name in data:
                            artifacts.append(Artifact(
                                artifact_type=art_type,
                                algorithm=alg,
                                key_size=None,
                                file_path=file_path,
                                detection_method="binary_elf_symbol",
                                confidence=0.85,
                                library=lib,
                                code_snippet=f"ELF symbol: {symbol_name}",
                                evidence=f"ELF binary contains symbol {symbol_name}",
                            ).to_dict())

                    for lib_key, lib_desc in KNOWN_CRYPTO_DLLS.items():
                        if lib_key in data:
                            artifacts.append(Artifact(
                                artifact_type="library",
                                algorithm=None,
                                key_size=None,
                                file_path=file_path,
                                detection_method="binary_elf_needed",
                                confidence=0.85,
                                library=lib_desc,
                                code_snippet=f"ELF dependency: {lib_key}",
                                evidence=f"ELF references {lib_key}",
                            ).to_dict())
    except Exception:
        pass

    return artifacts


def _scan_embedded_certificates(file_path: str) -> List[Dict[str, Any]]:
    artifacts = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        for match in CERT_HEADER_RE.finditer(data):
            artifacts.append(Artifact(
                artifact_type="certificate",
                algorithm=None,
                key_size=None,
                file_path=file_path,
                detection_method="binary_embedded_cert",
                confidence=0.95,
                code_snippet="Embedded PEM certificate block detected in binary",
                evidence="Embedded X.509 PEM certificate in binary bytes",
            ).to_dict())
    except Exception:
        pass

    return artifacts


def scan_binary_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Public entry point for static binary analysis.
    Supports ELF (.so, binary) and PE (.exe, .dll).
    """
    ext = os.path.splitext(file_path)[1].lower()
    artifacts: List[Dict[str, Any]] = []

    if ext in (".exe", ".dll"):
        artifacts.extend(_scan_pe_binary(file_path))
    elif ext in (".so", ".elf") or not ext:
        artifacts.extend(_scan_elf_binary(file_path))

    artifacts.extend(_scan_embedded_certificates(file_path))

    return artifacts
