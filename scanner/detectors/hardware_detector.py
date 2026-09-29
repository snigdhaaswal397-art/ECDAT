"""
ECDAT — Hardware & Infrastructure Detector
=========================================

Scans source code, configuration files, headers, and manifests for:
  - Hardware Security Modules (HSMs, PKCS#11, TPM)
  - Embedded / IoT / Firmware indicators (FreeRTOS, ESP-IDF, Zephyr, microcontroller headers)
  - Network MTU, packet buffer, and memory constraints
  - Database-level cryptographic logic (SQL crypto functions)

Emits standard Artifact dictionaries consistent with ECDAT scanner specifications.
"""

from typing import Any, Dict, List
import os
import re

from scanner.models import (
    Artifact,
    CONFIDENCE_CONFIG_EVIDENCE,
    CONFIDENCE_AST_CALL,
)

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

HSM_PATTERNS = [
    (r"\b(pkcs11|libpkcs11\.so|cryptoki\.h|C_Initialize|C_OpenSession)\b", "PKCS#11 HSM Interface"),
    (r"\b(SunPKCS11|SoftHSM|CloudHSM|YubiHSM|nCipher|SafeNet)\b", "Hardware Security Module (HSM) Library"),
    (r"\b(TPM2_Init|tpm2_tss|tpm2\.h|tpm2_createkey)\b", "TPM 2.0 Hardware Interface"),
    (r"\bKMIP\b|\bkmip_client\b", "KMIP Hardware Key Management Protocol"),
]

EMBEDDED_IOT_PATTERNS = [
    (r"\b(FreeRTOS|esp_idf|zephyr|CMSIS|MBED_TLS)\b", "Embedded/IoT Operating System"),
    (r"\b(avr/io\.h|stm32[f|l|g|h]\d+xx\.h|pico/stdlib\.h)\b", "Microcontroller Hardware Abstraction Layer"),
    (r"\b(microcode|firmware_update|flash_write_sector)\b", "Firmware / Microcode Logic"),
]

PACKET_MTU_PATTERNS = [
    (r"\b(MTU_SIZE|MAX_PACKET_SIZE|SO_SNDBUF|SO_RCVBUF)\b\s*=?\s*(\d+)", "Packet / Buffer Constraint"),
    (r"\b(MTU\s*=\s*\d+|packet_buffer_overflow|fixed_frame_size)\b", "Fixed Frame / MTU Constraint"),
    (r"\b(ISO8583|SWIFT_FIN|FIX_PROTOCOL)\b", "Legacy Banking / Financial Protocol"),
]

DB_CRYPTO_PATTERNS = [
    (r"\b(pgp_sym_encrypt|pgp_sym_decrypt|AES_ENCRYPT|AES_DECRYPT|DBMS_CRYPTO)\b", "Database-Level Cryptography"),
    (r"\b(UNHEX\(SHA2\(|ENCRYPTBYPASSPHRASE)\b", "SQL Column Encryption"),
]

def scan_hardware_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Scan a file for hardware, HSM, IoT, firmware, packet MTU, or DB crypto evidence.
    """
    artifacts: List[Dict[str, Any]] = []

    ext = os.path.splitext(file_path)[1].lower()
    fname = os.path.basename(file_path).lower()

    # Firmware binaries
    if ext in (".fw", ".hex", ".bin") and fname not in ("node_modules", "venv"):
        artifacts.append(
            Artifact(
                artifact_type="firmware",
                algorithm=None,
                key_size=None,
                file_path=file_path,
                detection_method="firmware_file_extension",
                confidence=0.90,
                evidence=f"Firmware binary file detected: {fname}",
            ).to_dict()
        )
        return artifacts

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return artifacts

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("*"):
            continue

        # 1. HSM
        for pattern, desc in HSM_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                artifacts.append(
                    Artifact(
                        artifact_type="hsm",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="hsm_pattern",
                        confidence=CONFIDENCE_AST_CALL,
                        code_snippet=line,
                        line_number=line_idx,
                        evidence=f"HSM evidence: {desc}",
                    ).to_dict()
                )

        # 2. Embedded / IoT
        for pattern, desc in EMBEDDED_IOT_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                artifacts.append(
                    Artifact(
                        artifact_type="embedded_iot",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="embedded_iot_pattern",
                        confidence=CONFIDENCE_CONFIG_EVIDENCE,
                        code_snippet=line,
                        line_number=line_idx,
                        evidence=f"Embedded/IoT evidence: {desc}",
                    ).to_dict()
                )

        # 3. Packet MTU / Buffer constraints
        for pattern, desc in PACKET_MTU_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                artifacts.append(
                    Artifact(
                        artifact_type="packet_constraint",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="packet_mtu_pattern",
                        confidence=CONFIDENCE_CONFIG_EVIDENCE,
                        code_snippet=line,
                        line_number=line_idx,
                        evidence=f"Packet/MTU constraint evidence: {desc}",
                    ).to_dict()
                )

        # 4. Database Cryptography
        for pattern, desc in DB_CRYPTO_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                artifacts.append(
                    Artifact(
                        artifact_type="database_crypto",
                        algorithm=None,
                        key_size=None,
                        file_path=file_path,
                        detection_method="db_crypto_pattern",
                        confidence=CONFIDENCE_AST_CALL,
                        code_snippet=line,
                        line_number=line_idx,
                        evidence=f"Database crypto evidence: {desc}",
                    ).to_dict()
                )

    return artifacts
