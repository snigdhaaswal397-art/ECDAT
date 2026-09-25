"""
Layer classification (Section 5 of the design doc).

ECDAT already tells us *what kind* of thing it found (a certificate, a
TLS config block, an in-code crypto call, a container secret, ...). This
module maps that finding_type to one of the three QARS layers. The
mapping is a simple lookup table on purpose -- keep it easy to extend
as ECDAT's detectors grow.
"""

from __future__ import annotations

from .models import Finding, Layer

_TYPE_TO_LAYER = {
    # in transit: cryptography protecting data actively moving over a network
    "certificate": Layer.IN_TRANSIT,
    "tls_config": Layer.IN_TRANSIT,
    "protocol_handshake": Layer.IN_TRANSIT,
    "vpn_config": Layer.IN_TRANSIT,

    # in use: cryptography protecting data while a running service handles it
    "code_call": Layer.IN_USE,
    "in_memory_key": Layer.IN_USE,
    "service_config": Layer.IN_USE,

    # at rest: cryptography protecting data sitting in storage
    "container_secret": Layer.AT_REST,
    "disk_encryption": Layer.AT_REST,
    "stored_key": Layer.AT_REST,
    "database_encryption": Layer.AT_REST,
}

_DEFAULT_LAYER = Layer.IN_USE  # conservative fallback for unrecognised finding types


def classify_layer(finding: Finding) -> Layer:
    """Return the QARS layer a finding belongs to.

    Falls back to IN_USE for unrecognised finding_type values rather than
    raising, so new/unmapped scanner detectors don't break the pipeline --
    extend _TYPE_TO_LAYER instead of relying on the fallback long-term.
    """
    return _TYPE_TO_LAYER.get(finding.finding_type.lower(), _DEFAULT_LAYER)
