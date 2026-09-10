from dataclasses import dataclass, field, asdict
from typing import Optional
import uuid

CONFIDENCE_AST_CALL = 0.95
CONFIDENCE_PATTERN_MATCH = 0.7
CONFIDENCE_IMPORT_SIGNAL = 0.3
CONFIDENCE_DEPENDENCY_SCAN = 0.2
CONFIDENCE_CONFIG_EVIDENCE = 0.5
@dataclass
class Artifact:
    artifact_type: str
    algorithm: Optional[str]
    key_size: Optional[int]
    file_path: str
    detection_method: str
    confidence: float

    library: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None

    artifact_id: str = field(
        default_factory=lambda: str(uuid.uuid4())[:8]
    )

    language: Optional[str] = None
    mode: Optional[str] = None
    protocol: Optional[str] = None
    evidence: Optional[str] = None
    dependency_version: Optional[str] = None
    curve: Optional[str] = None

    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[str] = None
    certificate_serial_number: Optional[str] = None
    certificate_not_before: Optional[str] = None
    certificate_version: Optional[int] = None
    certificate_signature_algorithm: Optional[str] = None
    certificate_ec_curve: Optional[str] = None
    certificate_subject_alternative_names: Optional[list] = None
    certificate_key_usage: Optional[list] = None
    certificate_extended_key_usage: Optional[list] = None
    certificate_source_format: Optional[str] = None
    certificate_password_protected: Optional[bool] = None
    certificate_note: Optional[str] = None

    source_type: Optional[str] = None
    warning_type: Optional[str] = None
    message: Optional[str] = None
    docker_instruction: Optional[str] = None
    evidence_type: Optional[str] = None

    def to_dict(self) -> dict:
        """
        Serialize to the plain dict shape written into scanner_output.json.

        Unset optional fields are omitted so each detector only outputs
        fields for which it has meaningful information.
        """
        d = asdict(self)

        optional_keys = (
            "library",
            "line_number",
            "code_snippet",

            "language",
            "mode",
            "protocol",
            "evidence",
            "dependency_version",
            "curve",

            "certificate_subject",
            "certificate_issuer",
            "certificate_expiry",
            "certificate_serial_number",
            "certificate_not_before",
            "certificate_version",
            "certificate_signature_algorithm",
            "certificate_ec_curve",
            "certificate_subject_alternative_names",
            "certificate_key_usage",
            "certificate_extended_key_usage",
            "certificate_source_format",
            "certificate_password_protected",
            "certificate_note",

            "source_type",
            "warning_type",
            "message",
            "docker_instruction",
            "evidence_type",
        )

        for key in optional_keys:
            if d.get(key) is None:
                d.pop(key, None)

        return d