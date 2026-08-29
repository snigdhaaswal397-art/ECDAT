"""
ECDAT — Part 2: Pattern Recognition
======================================
Identifies repeated cryptographic usage across files and projects — i.e.
finds systemic patterns rather than one-off findings, which matters for
prioritization: "this weak algorithm is used consistently across the
codebase" is a much bigger finding than "it appears once."
"""


def find_cross_file_patterns(merged_entries: list[dict], min_files: int = 2) -> list[dict]:
    """
    Flags algorithms that appear in multiple distinct files — a sign of a
    systemic pattern (e.g. a shared utility library, a copy-pasted snippet,
    or an organization-wide habit) rather than an isolated mistake.
    """
    patterns = []
    for entry in merged_entries:
        if entry["algorithm"] == "UNSPECIFIED":
            continue
        if len(entry["files_affected"]) >= min_files:
            patterns.append({
                "algorithm": entry["algorithm"],
                "key_size": entry["key_size"],
                "pattern_type": "cross_file_repetition",
                "files_affected": entry["files_affected"],
                "total_occurrences": entry["occurrence_count"],
                "severity_signal": "high" if len(entry["files_affected"]) >= 3 else "medium",
            })
    return patterns


def find_language_spread(merged_entries: list[dict]) -> list[dict]:
    """
    Flags algorithms detected across multiple LANGUAGES (Python + Java + C),
    which signals an organization-wide standard/habit rather than a single
    team's mistake — genuinely useful for a "how deep does this go" story
    in your pitch.
    """
    def _ext(path: str) -> str:
        if path.endswith(".py"): return "Python"
        if path.endswith(".java"): return "Java"
        if path.endswith((".c", ".h", ".cpp", ".cc")): return "C"
        return "Other"

    spread = []
    for entry in merged_entries:
        if entry["algorithm"] == "UNSPECIFIED":
            continue
        langs = set(_ext(f) for f in entry["files_affected"])
        if len(langs) >= 2:
            spread.append({
                "algorithm": entry["algorithm"],
                "key_size": entry["key_size"],
                "pattern_type": "cross_language_spread",
                "languages": sorted(langs),
                "files_affected": entry["files_affected"],
            })
    return spread


def analyze_patterns(merged_entries: list[dict]) -> dict:
    return {
        "cross_file_patterns": find_cross_file_patterns(merged_entries),
        "cross_language_patterns": find_language_spread(merged_entries),
    }
