"""
ECDAT — Part 2: Duplicate Removal
====================================
Merges duplicate detections of the same artifact while preserving all
original metadata (every file/line it was found at, not just the first).

"Duplicate" here means: same algorithm + same key_size, appearing multiple
times (across one file or many). We do NOT deduplicate away the
occurrences — we collapse them into one CBOM entry with a list of
locations, because "this weak algorithm appears in 14 places" is exactly
the information a security team needs, and CBOM/SBOM tools deliberately
preserve provenance rather than discarding it.
"""

from collections import defaultdict


def _dedup_key(artifact: dict):
    """
    Two detections are 'the same artifact' if they share algorithm + key_size.
    Import-signal artifacts (algorithm='UNSPECIFIED') are grouped separately
    by library instead, since they don't represent a specific crypto choice.
    """
    if artifact["algorithm"] == "UNSPECIFIED":
        return ("import_signal", artifact["library"])
    return (artifact["algorithm"], artifact.get("key_size"))


def merge_duplicates(classified_artifacts: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for a in classified_artifacts:
        groups[_dedup_key(a)].append(a)

    merged = []
    for key, group in groups.items():
        # keep the highest-confidence detection's metadata as the "primary" record
        primary = max(group, key=lambda a: a["confidence"])

        occurrences = [
            {
                "file_path": a["file_path"],
                "line_number": a["line_number"],
                "code_snippet": a["code_snippet"],
                "detection_method": a["detection_method"],
                "confidence": a["confidence"],
            }
            for a in group
        ]

        merged_entry = {
            "cbom_entry_id": primary["artifact_id"],
            "algorithm": primary["algorithm"],
            "key_size": primary.get("key_size"),
            "cbom_category": primary["cbom_category"],
            "library": primary["library"],
            "occurrence_count": len(occurrences),
            "occurrences": occurrences,
            "max_confidence": max(a["confidence"] for a in group),
            "files_affected": sorted(set(o["file_path"] for o in occurrences)),
        }
        merged.append(merged_entry)

    # sort so the most-repeated (highest impact) artifacts appear first
    merged.sort(key=lambda e: e["occurrence_count"], reverse=True)
    return merged
