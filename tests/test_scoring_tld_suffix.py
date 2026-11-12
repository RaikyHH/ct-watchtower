"""Multi-part public suffixes against single-label rule lists (§5.2).

`cand.tld` carries the complete suffix (`co.uk`), while the specification's TLD lists
hold single labels. Without the widening in the detector, `uk` never fired on `.co.uk`.
"""

import pytest

from ctwatchtower.normalize.names import normalize
from ctwatchtower.rules.detectors.structure import detect_tlds
from ctwatchtower.rules.schema import RuleSet

RULES = RuleSet.model_validate(
    {
        "tenant": {"id": "t", "name": "T"},
        "tlds": {
            "groups": [{"name": "risky", "weight": 25, "list": ["uk", "top"]}],
            "overrides": [{"tld": ["de"], "weight": -10}],
        },
    }
)


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("shop.co.uk", 25.0),  # the list entry "uk", the suffix "co.uk"
        ("shop.uk", 25.0),
        ("shop.top", 25.0),
        ("shop.de", -10.0),  # an override holds over the last label too
        ("shop.com", 0.0),  # not listed
    ],
)
def test_a_single_label_rule_matches_a_multi_part_suffix(domain: str, expected: float) -> None:
    hits = detect_tlds(RULES, normalize(domain))
    assert sum(c.w for c in hits) == expected
