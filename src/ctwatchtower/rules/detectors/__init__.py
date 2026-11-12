"""Detectors: plain functions that return contributions.

No base class, no registry. There is exactly one caller (`scoring.engine`), and
detectors share no state.
"""

from ctwatchtower.rules.detectors.context import (
    detect_allowlist,
    detect_certificate,
    detect_post_enrichment,
    suppressed_by,
)
from ctwatchtower.rules.detectors.structure import detect_structure, detect_tlds
from ctwatchtower.rules.detectors.text import (
    AnchorHit,
    detect_anchors,
    detect_custom,
    detect_lures,
    detect_rules,
)

__all__ = [
    "AnchorHit",
    "detect_allowlist",
    "detect_anchors",
    "detect_certificate",
    "detect_custom",
    "detect_lures",
    "detect_post_enrichment",
    "detect_rules",
    "detect_structure",
    "detect_tlds",
    "suppressed_by",
]
