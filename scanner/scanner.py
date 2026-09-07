"""
ECDAT — Discovery / Scanner Engine (orchestrator)
=====================================================
This file's ONLY job is:
  1. recursively walk a target directory
  2. figure out what kind of file each discovered path is
  3. call the matching language/artifact detector
  4. collect everything into one flat list
  5. write scanner_output.json

It does NOT contain any crypto-detection logic itself — that used to live
here (as CryptoASTVisitor for Python), but has been extracted into
python_detector.py so that every language has its own detector file with
the same shape (java_detector.py, c_detector.py, and future detectors).
This keeps scanner.py boring and easy to explain: it doesn't know anything
about Python/Java/C syntax, only which function to call for which file.

OUTPUT CONTRACT (unchanged from before this refactor — see models.py for
the authoritative field-by-field definition):
{
    "artifact_id": str,
    "artifact_type": str,
    "algorithm": str,
    "key_size": int or None,
    "library": str,
    "file_path": str,
    "line_number": int,
    "code_snippet": str,
    "detection_method": str,
    "confidence": float
}

Run: python scanner.py <directory_to_scan> [output.json]
"""

import json
import os
import sys
from scanner.models import Artifact

from scanner.detectors.python_detector import scan_python_file
from scanner.detectors.javascript_detector import scan_javascript_file

try:
    from scanner.detectors.java_detector import scan_java_file
except ImportError:
    scan_java_file = None

from scanner.detectors.c_detector import scan_c_file


# ---------------------------------------------------------------------------
# Directories to never descend into. These are either not source code
# (dependency caches, build output) or so large/irrelevant that scanning
# them wastes time and risks tripping over generated/binary junk. This was a
# known gap in the original scanner (section 20 of the spec) — os.walk had
# no ignore-list at all before this refactor.
# ---------------------------------------------------------------------------
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "target", "build", "dist",
}


def _iter_project_files(directory: str):
    """
    Recursively yield every file path under `directory`, skipping anything
    inside an IGNORED_DIRS directory. Kept as a small generator so
    scan_directory() stays focused on routing rather than walk mechanics.
    """
    for root, dirnames, files in os.walk(directory):
        # Prune ignored directories in-place so os.walk never descends into them
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in files:
            yield os.path.join(root, fname)


def scan_directory(directory: str) -> list[dict]:
    """
    Multi-language entry point. Routes each file to the right detector based
    on extension. This is the single function the CBOM pipeline (and anyone
    else) should call — they don't need to know which language-specific
    detector ran under the hood, only that they get back a uniform list of
    artifact dicts matching the output contract documented at the top of
    this file.
    """
    all_artifacts = []
    skipped_java = 0

    for full_path in _iter_project_files(directory):
        fname = os.path.basename(full_path)

        try:
            if fname.endswith(".py"):
                all_artifacts.extend(scan_python_file(full_path))

            elif fname.endswith(".java"):
                if scan_java_file is not None:
                    all_artifacts.extend(scan_java_file(full_path))
                else:
                    skipped_java += 1
            elif fname.endswith((".js", ".jsx", ".ts", ".tsx")):
                all_artifacts.extend(scan_javascript_file(full_path))

            elif fname.endswith((".c", ".h", ".cpp", ".cc")):
                all_artifacts.extend(scan_c_file(full_path))

        except (OSError, UnicodeDecodeError) as e:
            # A single unreadable/malformed file must never crash the whole
            # scan (spec section 21). Skip it, log it, keep going.
            print(f"  [warning] skipped unreadable file {full_path}: {e}")
            continue

    if skipped_java:
        print(f"  [warning] {skipped_java} .java file(s) skipped — install 'javalang' to enable Java scanning")

    return all_artifacts


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <directory_to_scan> [output.json]")
        sys.exit(1)

    target_dir = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "scanner_output.json"

    results = scan_directory(target_dir)

    json_results = [
        artifact.to_dict() if isinstance(artifact, Artifact) else artifact
        for artifact in results
        ]

    with open(output_path, "w") as f:
        json.dump(json_results, f, indent=2)

    print(f"Scanned '{target_dir}' — {len(results)} artifacts detected.")
    print(f"Output written to {output_path}")

    # Quick console summary
    confirmed = [
    a for a in json_results
    if a["detection_method"] == "ast_call"
    ]

    print(f"  Confirmed (high-confidence) detections: {len(confirmed)}")

    for a in confirmed:
        ks = f" ({a['key_size']}-bit)" if a["key_size"] else ""
        print(
            f"    [{a['file_path']}:{a['line_number']}] "
            f"{a['algorithm']}{ks}  <- {a['code_snippet']}"
        )