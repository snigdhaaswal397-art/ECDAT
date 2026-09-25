"""
ECDAT — Discovery / Scanner Engine (orchestrator)
=================================================

This file's ONLY job is to:

1. recursively walk a target directory
2. determine what kind of file each discovered path is
3. call the matching detector
4. normalize detector results into dictionaries
5. remove exact duplicate findings
6. collect everything into one flat list
7. write scanner_output.json

It does NOT contain crypto-detection logic itself.

Run from ECDAT root:
    python scanner/scanner.py <directory_to_scan>

Run from inside scanner/:
    python scanner.py <directory_to_scan>

Container scan:
    python scanner/scanner.py --container python:3.12

Specify output:
    python scanner/scanner.py <directory_to_scan> -o output.json
"""

import argparse
import json
import os
import sys
from typing import Any


# ---------------------------------------------------------------------------
# Make scanner.* imports work regardless of how scanner.py is executed.
#
# Supported:
#     python -m scanner.scanner ...
#     python scanner/scanner.py ...
#     cd scanner
#     python scanner.py ...
# ---------------------------------------------------------------------------

_ECDAT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if _ECDAT_ROOT not in sys.path:
    sys.path.insert(0, _ECDAT_ROOT)


# ---------------------------------------------------------------------------
# Shared model
# ---------------------------------------------------------------------------

from scanner.models import Artifact


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

from scanner.detectors.container_detector import (
    scan_container_image,
    ContainerDetectorError,
)

from scanner.detectors.docker_detector import (
    scan_dockerfile,
    DockerDetectorError,
)

from scanner.detectors.python_detector import (
    scan_python_file,
)

from scanner.detectors.javascript_detector import (
    scan_javascript_file,
)

from scanner.detectors.certificate_detector import (
    scan_certificate,
    CertificateDetectorError,
)

from scanner.detectors.c_detector import (
    scan_c_file,
)


# Java is optional because it may depend on javalang.
try:
    from scanner.detectors.java_detector import scan_java_file
except ImportError:
    scan_java_file = None


# ---------------------------------------------------------------------------
# Directories that should never be scanned.
# ---------------------------------------------------------------------------

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "target",
    "build",
    "dist",
}


# ---------------------------------------------------------------------------
# File traversal
# ---------------------------------------------------------------------------

def _iter_project_files(directory: str):
    """
    Recursively yield every file under directory.

    Ignored directories are removed from dirnames in-place so os.walk()
    never descends into them.
    """

    for root, dirnames, files in os.walk(directory):

        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in IGNORED_DIRS
        ]

        for filename in files:
            yield os.path.join(root, filename)


# ---------------------------------------------------------------------------
# Result normalization
# ---------------------------------------------------------------------------

def _to_dict(artifact: Any) -> dict:
    """
    Convert a detector result into a plain dictionary.

    Some detectors may return Artifact objects while others return
    dictionaries.

    The scanner internally uses dictionaries so that:
        - scan_directory() has one consistent return type
        - deduplication is simple
        - JSON serialization is predictable
    """

    if isinstance(artifact, Artifact):
        return artifact.to_dict()

    if isinstance(artifact, dict):
        return artifact

    raise TypeError(
        f"Unsupported detector result type: "
        f"{type(artifact).__name__}"
    )


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

_DEDUP_KEY_FIELDS = (
    "file_path",
    "line_number",
    "artifact_type",
    "algorithm",
    "evidence",
    "detection_method",
)


def deduplicate_findings(
    findings: list[dict],
) -> list[dict]:
    """
    Remove exact duplicate findings.

    Two findings are considered duplicates only when all of these
    values are identical:

        file_path
        line_number
        artifact_type
        algorithm
        evidence
        detection_method

    The first occurrence is preserved.

    This is NOT CBOM-level deduplication.

    Example:

        AES.new(...) at line 10
        AES.new(...) at line 10

    -> one finding

    But:

        AES.new(...) at line 10
        AES.new(...) at line 20

    -> two findings
    """

    seen = set()
    deduped: list[dict] = []

    for finding in findings:

        file_path = finding.get("file_path")

        if file_path:
            normalized_path = os.path.normpath(
                str(file_path)
            ).replace("\\", "/")
        else:
            normalized_path = None

        key = (
            normalized_path,
            finding.get("line_number"),
            finding.get("artifact_type"),
            finding.get("algorithm"),
            finding.get("evidence"),
            finding.get("detection_method"),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(finding)

    return deduped


# ---------------------------------------------------------------------------
# Certificate conversion
# ---------------------------------------------------------------------------

def _certificate_to_artifact(
    cert: dict,
) -> Artifact:
    """
    Convert a certificate detector result into the shared Artifact model.
    """

    return Artifact(
        artifact_type=cert.get(
            "artifact_type",
            "certificate",
        ),

        algorithm=cert.get(
            "algorithm"
        ),

        key_size=cert.get(
            "key_size"
        ),

        file_path=cert.get(
            "file_path",
            "",
        ),

        detection_method=cert.get(
            "detection_method",
            "openssl",
        ),

        confidence=cert.get(
            "confidence",
            0.0,
        ),

        library=None,
        line_number=None,
        code_snippet=None,

        certificate_subject=cert.get(
            "subject"
        ),

        certificate_issuer=cert.get(
            "issuer"
        ),

        certificate_expiry=cert.get(
            "not_after"
        ),

        certificate_serial_number=cert.get(
            "serial_number"
        ),

        certificate_not_before=cert.get(
            "not_before"
        ),

        certificate_version=cert.get(
            "certificate_version"
        ),

        certificate_signature_algorithm=cert.get(
            "signature_algorithm"
        ),

        certificate_ec_curve=cert.get(
            "ec_curve"
        ),

        certificate_subject_alternative_names=cert.get(
            "subject_alternative_names"
        ),

        certificate_key_usage=cert.get(
            "key_usage"
        ),

        certificate_extended_key_usage=cert.get(
            "extended_key_usage"
        ),

        certificate_source_format=cert.get(
            "source_format"
        ),

        certificate_password_protected=cert.get(
            "password_protected"
        ),

        certificate_note=cert.get(
            "note"
        ),
    )


# ---------------------------------------------------------------------------
# Directory scanner
# ---------------------------------------------------------------------------

def scan_directory(
    directory: str,
) -> list[dict]:
    """
    Scan a directory recursively.

    Every detector result is normalized immediately into a dictionary.

    Returns:
        list[dict]
    """

    # IMPORTANT:
    #
    # This MUST be list[dict], not list[dict | Artifact].
    #
    # Every detector result is passed through _to_dict() before being
    # inserted into this list.
    all_artifacts: list[dict] = []

    skipped_java = 0

    for full_path in _iter_project_files(directory):

        fname = os.path.basename(full_path)

        try:

            # ---------------------------------------------------------------
            # Dockerfiles
            # ---------------------------------------------------------------

            if fname.lower().startswith("dockerfile"):

                try:

                    docker_results = scan_dockerfile(
                        full_path
                    )

                    all_artifacts.extend(
                        _to_dict(result)
                        for result in docker_results
                    )

                except DockerDetectorError as exc:

                    print(
                        f"  [warning] error scanning "
                        f"Dockerfile {full_path}: {exc}"
                    )

                continue

            # ---------------------------------------------------------------
            # Python
            # ---------------------------------------------------------------

            if fname.lower().endswith(".py"):

                python_results = scan_python_file(
                    full_path
                )

                all_artifacts.extend(
                    _to_dict(result)
                    for result in python_results
                )

            # ---------------------------------------------------------------
            # Java
            # ---------------------------------------------------------------

            elif fname.lower().endswith(".java"):

                if scan_java_file is not None:

                    java_results = scan_java_file(
                        full_path
                    )

                    all_artifacts.extend(
                        _to_dict(result)
                        for result in java_results
                    )

                else:

                    skipped_java += 1

            # ---------------------------------------------------------------
            # JavaScript / TypeScript
            # ---------------------------------------------------------------

            elif fname.lower().endswith(
                (
                    ".js",
                    ".jsx",
                    ".ts",
                    ".tsx",
                )
            ):

                javascript_results = scan_javascript_file(
                    full_path
                )

                all_artifacts.extend(
                    _to_dict(result)
                    for result in javascript_results
                )

            # ---------------------------------------------------------------
            # C / C++ headers and source
            # ---------------------------------------------------------------

            elif fname.lower().endswith(
                (
                    ".c",
                    ".h",
                    ".cpp",
                    ".cc",
                    ".cxx",
                    ".hpp",
                )
            ):

                c_results = scan_c_file(
                    full_path
                )

                all_artifacts.extend(
                    _to_dict(result)
                    for result in c_results
                )

            # ---------------------------------------------------------------
            # Certificates / key containers
            # ---------------------------------------------------------------

            elif fname.lower().endswith(
                (
                    ".pem",
                    ".crt",
                    ".cer",
                    ".der",
                    ".p12",
                    ".pfx",
                )
            ):

                try:

                    certificate_results = scan_certificate(
                        full_path
                    )

                    for certificate in certificate_results:

                        artifact = _certificate_to_artifact(
                            certificate
                        )

                        all_artifacts.append(
                            _to_dict(artifact)
                        )

                except CertificateDetectorError as exc:

                    print(
                        f"  [warning] error scanning "
                        f"certificate {full_path}: {exc}"
                    )

                    all_artifacts.append(
                        _to_dict(
                            Artifact(
                                artifact_type="warning",
                                algorithm=None,
                                key_size=None,
                                file_path=full_path,
                                detection_method="openssl",
                                confidence=0.0,
                                warning_type="malformed_certificate",
                                message=str(exc),
                            )
                        )
                    )

        except (
            OSError,
            UnicodeDecodeError,
        ) as exc:

            # A single bad file must never kill the entire scan.

            print(
                f"  [warning] skipped unreadable file "
                f"{full_path}: {exc}"
            )

            continue

        except Exception as exc:

            # Detector-specific unexpected errors should not prevent
            # the remaining project from being scanned.
            #
            # This is intentionally logged rather than silently ignored.

            print(
                f"  [warning] detector error for "
                f"{full_path}: {exc}"
            )

            continue

    # -----------------------------------------------------------------------
    # Java dependency warning
    # -----------------------------------------------------------------------

    if skipped_java:

        print(
            f"  [warning] {skipped_java} .java file(s) skipped — "
            f"install 'javalang' to enable Java scanning"
        )

    # -----------------------------------------------------------------------
    # Contract:
    #
    # Every item is already a plain dict.
    # -----------------------------------------------------------------------

    return all_artifacts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Command-line entry point.
    """

    parser = argparse.ArgumentParser(
        description=(
            "ECDAT cryptographic discovery scanner"
        )
    )

    parser.add_argument(
        "directory",
        nargs="?",
        help=(
            "Directory to scan for source code, "
            "Dockerfiles, and certificates"
        ),
    )

    parser.add_argument(
        "--container",
        dest="container_image",
        help=(
            "Docker container image to scan, "
            "e.g. python:3.12"
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        default="scanner_output.json",
        help=(
            "Output JSON file "
            "(default: scanner_output.json)"
        ),
    )

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Validate that at least one scan target was provided.
    # -----------------------------------------------------------------------

    if not args.directory and not args.container_image:

        parser.error(
            "provide either a directory or "
            "--container IMAGE"
        )

    # -----------------------------------------------------------------------
    # Scan directory
    # -----------------------------------------------------------------------

    results: list[dict] = []

    if args.directory:

        if not os.path.isdir(args.directory):

            parser.error(
                f"directory does not exist: "
                f"{args.directory}"
            )

        print(
            f"Scanning directory '{args.directory}'..."
        )

        results.extend(
            scan_directory(args.directory)
        )

    # -----------------------------------------------------------------------
    # Scan container image
    # -----------------------------------------------------------------------

    if args.container_image:

        print(
            f"Scanning container image "
            f"'{args.container_image}'..."
        )

        try:

            container_results = scan_container_image(
                args.container_image
            )

            results.extend(
                _to_dict(result)
                for result in container_results
            )

            print(
                f"  Container findings: "
                f"{len(container_results)}"
            )

        except ContainerDetectorError as exc:

            print(
                f"  [warning] error scanning container "
                f"'{args.container_image}': {exc}"
            )

    # -----------------------------------------------------------------------
    # Defensive normalization
    # -----------------------------------------------------------------------

    json_results = [
        _to_dict(result)
        for result in results
    ]

    # -----------------------------------------------------------------------
    # Exact duplicate removal
    # -----------------------------------------------------------------------

    before_deduplication = len(
        json_results
    )

    json_results = deduplicate_findings(
        json_results
    )

    removed = (
        before_deduplication
        - len(json_results)
    )

    if removed:

        print(
            f"  Removed {removed} "
            f"exact-duplicate finding(s)."
        )

    # -----------------------------------------------------------------------
    # Write JSON
    # -----------------------------------------------------------------------

    try:

        with open(
            args.output,
            "w",
            encoding="utf-8",
        ) as output_file:

            json.dump(
                json_results,
                output_file,
                indent=2,
                ensure_ascii=False,
            )

    except OSError as exc:

        print(
            f"[error] could not write output file "
            f"'{args.output}': {exc}"
        )

        sys.exit(1)

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    if args.directory and args.container_image:

        print(
            f"Scanned directory "
            f"'{args.directory}' and container "
            f"'{args.container_image}' — "
            f"{len(json_results)} artifacts detected."
        )

    elif args.directory:

        print(
            f"Scanned '{args.directory}' — "
            f"{len(json_results)} artifacts detected."
        )

    else:

        print(
            f"Scanned container "
            f"'{args.container_image}' — "
            f"{len(json_results)} artifacts detected."
        )

    print(
        f"Output written to {args.output}"
    )

    # -----------------------------------------------------------------------
    # High-confidence findings
    # -----------------------------------------------------------------------

    confirmed = [
        artifact
        for artifact in json_results
        if artifact.get("confidence", 0) >= 0.9
    ]

    print(
        f"  Confirmed "
        f"(high-confidence) detections: "
        f"{len(confirmed)}"
    )

    for artifact in confirmed:

        key_size = artifact.get(
            "key_size"
        )

        key_size_text = (
            f" ({key_size}-bit)"
            if key_size
            else ""
        )

        location = artifact.get(
            "file_path",
            "unknown file",
        )

        line_number = artifact.get(
            "line_number"
        )

        if line_number:
            location = (
                f"{location}:{line_number}"
            )

        algorithm = artifact.get(
            "algorithm",
            "Unknown",
        )

        snippet = artifact.get(
            "code_snippet"
        )

        if snippet:

            print(
                f"    [{location}] "
                f"{algorithm}"
                f"{key_size_text}  <- "
                f"{snippet}"
            )

        else:

            print(
                f"    [{location}] "
                f"{algorithm}"
                f"{key_size_text}"
            )


# ---------------------------------------------------------------------------
# Program entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()