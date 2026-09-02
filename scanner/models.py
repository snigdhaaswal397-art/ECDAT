"""
ECDAT — Shared Artifact Model
===============================
Single source of truth for the shape of a "finding" that every detector
(Python, Java, C, and future JS/Docker/certificate/dependency/protocol
detectors) must produce.

WHY THIS FILE EXISTS (read this before touching it)
-----------------------------------------------------
Before this refactor, the Python logic (inside scanner.py) built its findings
using a local `Artifact` dataclass, while java_detector.py and c_detector.py
each had their own private `_artifact()` helper that hand-built a dict with
the "same" keys. That's three independent definitions of one contract. If a
future detector typos a key name (e.g. "keysize" instead of "key_size"), or
JSON-serializes an object that isn't quite the right shape, nothing catches
it until the CBOM step (classification.py) silently misreads the artifact or
crashes. Centralizing the schema here means every detector is *structurally*
forced to produce CBOM-compatible output — not just "hopefully consistent by
convention".

THE CBOM CONTRACT
-------------------
This exact set of fields is what cbom/classification.py and
cbom/cbom_generator.py already read from scanner_output.json. Do NOT rename
or remove any of these fields — doing so would break the existing,
already-working CBOM pipeline. New fields (language, mode, protocol,
evidence, etc.) can be added later as optional extras, but only additively.
"""

import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Confidence tiers
# ---------------------------------------------------------------------------
# These constants encode the same "evidence quality" philosophy the original
# c_detector.py header comment described informally: an AST-confirmed function
# call is much stronger evidence than a regex pattern match, which is in turn
# much stronger than "this file merely imports a crypto library". Making the
# tiers explicit constants (instead of a bare 0.95 / 0.7 / 0.3 typed out fresh
# in every detector file) means:
#   1. every detector agrees on what "high confidence" numerically means
#   2. a future adjustment (e.g. tuning 0.7 -> 0.65) happens in one place
#   3. a reader of any detector file can see *why* a number was chosen
CONFIDENCE_AST_CALL = 0.95        # confirmed function/API call, parsed via a real AST/parser
CONFIDENCE_PATTERN_MATCH = 0.7    # regex/pattern-based call detection (no real parser available)
CONFIDENCE_IMPORT_SIGNAL = 0.3    # import/dependency presence only — NOT confirmed usage
CONFIDENCE_DEPENDENCY_SCAN = 0.2  # crypto library found in a manifest file, even weaker than an import
CONFIDENCE_CONFIG_EVIDENCE = 0.5  # config/protocol evidence (e.g. Dockerfile, TLS config) — medium tier


@dataclass
class Artifact:
    """
    One detected cryptographic artefact / finding.

    Fields marked REQUIRED are the original CBOM contract fields and must
    always be present with these exact names. Fields marked OPTIONAL are
    later additions (language, mode, etc.) — safe to add to, never remove.
    """
    # --- REQUIRED: existing CBOM contract, do not rename/remove ---
    artifact_type: str              # "algorithm" | "hash" | "import_signal" | "certificate" | "protocol" | ...
    algorithm: str                  # e.g. "RSA", "AES", "MD5", or "UNSPECIFIED" for import-only signals
    key_size: Optional[int]         # bits, ONLY if explicitly present in the evidence — never guessed
    library: str                    # e.g. "Crypto.PublicKey", "cryptography", "openssl/rsa.h"
    file_path: str
    line_number: int
    code_snippet: str
    detection_method: str           # "ast_call" | "ast_import" | "pattern_match" | "dependency_scan" | ...
    confidence: float               # 0.0 - 1.0, see CONFIDENCE_* constants above
    artifact_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    # --- OPTIONAL: additive fields, safe to leave unset ---
    language: Optional[str] = None
    mode: Optional[str] = None
    protocol: Optional[str] = None
    evidence: Optional[str] = None
    dependency_version: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    source_type: Optional[str] = None

    def to_dict(self) -> dict:
        """
        Serialize to the plain dict shape written into scanner_output.json.
        Drops unset optional fields so the JSON output for existing detectors
        (Python/Java/C) stays byte-for-byte identical to before this refactor
        — no stray `"language": null` clutter appearing in output that used
        to not have it.
        """
        d = asdict(self)
        for optional_key in (
            "language", "mode", "protocol", "evidence", "dependency_version",
            "certificate_subject", "certificate_issuer", "certificate_expiry",
            "source_type",
        ):
            if d.get(optional_key) is None:
                d.pop(optional_key, None)
        return d
