from __future__ import annotations

import pytest
from pydantic import ValidationError

from ctwatchtower.rules.schema import RuleSet

MINIMAL = {"tenant": {"id": "test-tenant", "name": "Test"}}


def test_minimal_ruleset_gets_the_documented_defaults() -> None:
    rs = RuleSet.model_validate(MINIMAL)
    assert rs.apiVersion == "ctwatchtower/v2" and rs.kind == "RuleSet"
    assert rs.tenant.enabled is True and rs.tenant.tlp == "clear"
    # Points, not per cent. Converted out of the earlier 35/60/80 on the saturation
    # scale, so that the same domains get the same severity.
    assert (rs.thresholds.persist, rs.thresholds.warning, rs.thresholds.alert) == (17, 37, 64)
    assert rs.scoring.require_anchor is True and rs.scoring.anchor_missing_cap == 9
    assert rs.scoring.max_combo_bonus == 40 and rs.scoring.top_n == 12
    assert rs.anchors == [] and rs.combos == [] and rs.notifications == []


def test_tenant_id_must_be_kebab_case() -> None:
    for bad in ("Test", "mit_unterstrich", "-vorne", "punkt.id", ""):
        with pytest.raises(ValidationError):
            RuleSet.model_validate({"tenant": {"id": bad, "name": "x"}})


def test_unknown_key_is_a_validation_error() -> None:
    with pytest.raises(ValidationError, match="satiration_k|extra"):
        RuleSet.model_validate(MINIMAL | {"scoring": {"satiration_k": 40}})


def test_description_is_allowed_on_every_node() -> None:
    rs = RuleSet.model_validate(
        MINIMAL
        | {
            "description": "Regelsatz",
            "thresholds": {"description": "Schwellen", "persist": 10},
            "anchors": [{"description": "Marken", "terms": ["paylio"], "weight": 30}],
        }
    )
    assert rs.thresholds.persist == 10


def test_terms_and_tld_lists_are_lowercased() -> None:
    rs = RuleSet.model_validate(
        MINIMAL
        | {
            "anchors": [{"terms": [" Paylio ", "Kavano", ""], "weight": 30}],
            "lures": [{"terms": ["LOGIN"], "weight": 14}],
            "tlds": {"groups": [{"name": "hoch", "weight": 25, "list": ["TOP", "XYZ"]}]},
            "allowlist": {"suppress": {"exact": ["Paylio.com"], "suffix": [".Paylio.com"]}},
        }
    )
    assert rs.anchors[0].terms == ["paylio", "kavano"]
    assert rs.lures[0].terms == ["login"]
    assert rs.tlds.groups[0].list_ == ["top", "xyz"]
    assert rs.allowlist.suppress.exact == ["paylio.com"]


def test_anchor_group_needs_at_least_one_term() -> None:
    with pytest.raises(ValidationError):
        RuleSet.model_validate(MINIMAL | {"anchors": [{"terms": [], "weight": 1}]})


def test_unknown_permutation_kind_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown permutation kind"):
        RuleSet.model_validate(
            MINIMAL
            | {
                "anchors": [
                    {
                        "terms": ["paylio"],
                        "weight": 30,
                        "match": {"permutations": {"enabled": True, "kinds": ["telepathie"]}},
                    }
                ]
            }
        )


def test_saturation_k_is_gone_with_the_curve() -> None:
    """The model no longer knows the key. Points are the score, there is nothing
    left to compress. The loader clears it out of old holdings, so that a running
    tenant does not fail on it (see test_rules_loader)."""
    with pytest.raises(ValidationError):
        RuleSet.model_validate(MINIMAL | {"scoring": {"saturation_k": 40}})


def test_permutation_index_only_covers_enabled_groups() -> None:
    rs = RuleSet.model_validate(
        MINIMAL
        | {
            "anchors": [
                {
                    "terms": ["paylio"],
                    "weight": 30,
                    "match": {"permutations": {"enabled": True, "kinds": ["omission"]}},
                },
                {"terms": ["kavano"], "weight": 30},
            ]
        }
    )
    assert "paylo" in rs.permutation_index["paylio"]
    assert "kavano" not in rs.permutation_index
    assert rs.anchor_terms == ("paylio", "kavano")


def test_ruleset_hash_is_stable_and_content_dependent() -> None:
    a = RuleSet.model_validate(MINIMAL)
    b = RuleSet.model_validate(MINIMAL)
    c = RuleSet.model_validate(MINIMAL | {"scoring": {"top_n": 5}})
    assert a.ruleset_hash == b.ruleset_hash != c.ruleset_hash
    assert len(a.ruleset_hash) == 16
