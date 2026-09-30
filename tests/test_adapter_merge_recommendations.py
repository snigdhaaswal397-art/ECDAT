"""
test_adapter_merge_recommendations.py
======================================

Standalone pytest test suite for adapter.py's merge_recommendations().

Uses small hand-built fake CBOM/enriched inputs (not real scan data) to
verify both branches: algorithm_map (known algorithm) and
category_fallback (UNSPECIFIED algorithm, e.g. Certificate/Protocol).

Run with:
    python -m pytest tests/test_adapter_merge_recommendations.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cbom"))

from adapter import merge_recommendations  # noqa: E402


def _cbom_output(cbom_entry_id: str, cbom_category: str, algorithm: str) -> dict:
    return {
        "components": [
            {
                "cbom_entry_id": cbom_entry_id,
                "cbom_category": cbom_category,
                "algorithm": algorithm,
            }
        ]
    }


def _enriched(finding_id: str, algorithm: str) -> list[dict]:
    return [
        {
            "finding_id": finding_id,
            "algorithm": algorithm,
            "location": "fake/path",
        }
    ]


# --------------------------------------------------------------------------- #
# algorithm_map path (known, resolved algorithm)
# --------------------------------------------------------------------------- #


def test_known_algorithm_uses_algorithm_map():
    cbom_output = _cbom_output("rsa1", "Algorithm", "RSA")
    enriched = _enriched("rsa1_0", "RSA")

    result = merge_recommendations(cbom_output, enriched)

    assert result[0]["recommendation_source"] == "algorithm_map"
    assert "ML-KEM" in result[0]["recommendation"]["recommended_alternative"]


def test_known_algorithm_preserves_enriched_fields():
    cbom_output = _cbom_output("aes1", "Algorithm", "AES")
    enriched = _enriched("aes1_0", "AES")

    result = merge_recommendations(cbom_output, enriched)

    assert result[0]["location"] == "fake/path"
    assert result[0]["algorithm"] == "AES"


# --------------------------------------------------------------------------- #
# category_fallback path (UNSPECIFIED algorithm)
# --------------------------------------------------------------------------- #


def test_unspecified_certificate_uses_category_fallback():
    cbom_output = _cbom_output("cert1", "Certificate", "UNSPECIFIED")
    enriched = _enriched("cert1_0", "UNSPECIFIED")

    result = merge_recommendations(cbom_output, enriched)

    assert result[0]["recommendation_source"] == "category_fallback"
    assert result[0]["recommendation"] is not None
    assert "quantum-safe" in result[0]["recommendation"]["recommended_alternative"].lower()


def test_unspecified_protocol_uses_category_fallback():
    cbom_output = _cbom_output("proto1", "Protocol", "UNSPECIFIED")
    enriched = _enriched("proto1_0", "UNSPECIFIED")

    result = merge_recommendations(cbom_output, enriched)

    assert result[0]["recommendation_source"] == "category_fallback"
    assert "TLS" in result[0]["recommendation"]["recommended_alternative"]


def test_unspecified_unknown_category_has_no_fallback():
    cbom_output = _cbom_output("mystery1", "Library", "UNSPECIFIED")
    enriched = _enriched("mystery1_0", "UNSPECIFIED")

    result = merge_recommendations(cbom_output, enriched)

    assert result[0]["recommendation_source"] == "none"
    assert result[0]["recommendation"] is None


# --------------------------------------------------------------------------- #
# finding_id -> cbom_entry_id join correctness
# --------------------------------------------------------------------------- #


def test_multiple_occurrences_join_back_to_same_cbom_entry():
    cbom_output = _cbom_output("shared1", "Algorithm", "MD5")
    enriched = [
        {"finding_id": "shared1_0", "algorithm": "MD5", "location": "a"},
        {"finding_id": "shared1_1", "algorithm": "MD5", "location": "b"},
    ]

    result = merge_recommendations(cbom_output, enriched)

    assert len(result) == 2
    assert all(r["recommendation_source"] == "algorithm_map" for r in result)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))