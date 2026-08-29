"""
ECDAT — Part 2: CBOM Generator (main orchestrator)
======================================================
Snigdha's module. Takes Part 1's raw scanner output and produces the final
standardized Cryptographic Bill of Materials (CBOM).

Pipeline: raw artifacts -> classify -> merge duplicates -> find patterns
          -> attach recommendations -> final CBOM document

Output format is deliberately structured to resemble the CycloneDX CBOM
spec (components list + metadata), so you can credibly say your output
"aligns with the CycloneDX CBOM standard" in your report/demo.

Run: python cbom_generator.py <scanner_output.json> [cbom_output.json]
"""

import json
import sys
from datetime import datetime, timezone

from classification import classify_all
from dedup import merge_duplicates
from pattern_recognition import analyze_patterns
from recommendation_db import attach_recommendations


def generate_cbom(raw_artifacts: list[dict]) -> dict:
    # Step 1: classify
    classified = classify_all(raw_artifacts)

    # Step 2: merge duplicates (preserving all occurrence metadata)
    merged = merge_duplicates(classified)

    # Step 3: pattern recognition across files/languages
    patterns = analyze_patterns(merged)

    # Step 4: attach PQC/hybrid recommendations
    components = attach_recommendations(merged)

    # Step 5: assemble final CBOM document
    quantum_vulnerable_count = sum(
        1 for c in components
        if c.get("recommendation") and not c["recommendation"]["already_quantum_safe"]
    )

    cbom = {
        "cbom_version": "1.0",
        "spec_alignment": "CycloneDX CBOM (structural alignment)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_unique_artifacts": len(components),
            "total_raw_detections": len(raw_artifacts),
            "quantum_vulnerable_artifacts": quantum_vulnerable_count,
            "files_scanned": sorted(set(
                f for c in components for f in c.get("files_affected", [])
            )),
            "categories": _category_breakdown(components),
        },
        "patterns": patterns,
        "components": components,
    }
    return cbom


def _category_breakdown(components: list[dict]) -> dict:
    breakdown = {}
    for c in components:
        cat = c["cbom_category"]
        breakdown[cat] = breakdown.get(cat, 0) + 1
    return breakdown


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cbom_generator.py <scanner_output.json> [cbom_output.json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "cbom_output.json"

    with open(input_path) as f:
        raw_artifacts = json.load(f)

    cbom = generate_cbom(raw_artifacts)

    with open(output_path, "w") as f:
        json.dump(cbom, f, indent=2)

    # Console summary
    print(f"CBOM generated from {len(raw_artifacts)} raw detections")
    print(f"  -> {cbom['summary']['total_unique_artifacts']} unique artifacts after dedup")
    print(f"  -> {cbom['summary']['quantum_vulnerable_artifacts']} quantum-vulnerable artifacts flagged")
    print(f"  -> Categories: {cbom['summary']['categories']}")
    print(f"  -> Cross-file patterns found: {len(cbom['patterns']['cross_file_patterns'])}")
    print(f"  -> Cross-language patterns found: {len(cbom['patterns']['cross_language_patterns'])}")
    print(f"\nTop findings:")
    for c in cbom["components"][:5]:
        if c["algorithm"] == "UNSPECIFIED":
            continue
        rec = c["recommendation"]["recommended_alternative"] if c["recommendation"] else "N/A"
        print(f"  {c['algorithm']} (key_size={c['key_size']}) — {c['occurrence_count']} occurrence(s) "
              f"across {len(c['files_affected'])} file(s) -> recommend: {rec}")
    print(f"\nFull CBOM written to {output_path}")
