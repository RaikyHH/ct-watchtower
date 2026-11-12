"""Rules with AND/OR/NOT. The shape the interface builds them in.

Three levels, no nesting: terms in one line are OR, lines below one another are
AND, and rules add up with each other. `anchors` and `lures` are the special
case "a single line" and stay untouched by all this.
"""

from __future__ import annotations

import pytest
from test_scoring_support import make_candidate

from ctwatchtower.rules.loader import all_prefilter_terms
from ctwatchtower.rules.schema import (
    PATTERN_MAX_LENGTH,
    RuleSet,
    check_pattern,
)
from ctwatchtower.scoring.engine import score_candidate

BASE = {
    "tenant": {"id": "t", "name": "T"},
    "scoring": {"require_anchor": True, "anchor_missing_cap": 20},
}


def record(*rules: dict, **rest) -> RuleSet:
    return RuleSet.model_validate({**BASE, **rest, "rules": list(rules)})


def points(rs: RuleSet, domain: str) -> dict[str, float]:
    return {c.rule: c.pts for c in score_candidate(rs, make_candidate(domain)).contributions}


# ────────────────────────── AND / OR ──────────────────────────


def test_lines_are_joined_with_and() -> None:
    rs = record({
        "name": "Office with a place", "weight": 80, "tolerant": False,
        "all_of": [{"any_of": ["customercare", "customerdesk"]}, {"any_of": ["lakeside"]}],
    })
    assert points(rs, "customercare-lakeside.de") == {"rule:Office with a place": 80.0}
    assert points(rs, "customerdesk-lakeside.de") == {"rule:Office with a place": 80.0}
    # Either half on its own is not enough, and that is the whole point.
    assert points(rs, "customercare-elsewhere.de") == {}
    assert points(rs, "lakeside-utilities.de") == {}


def test_terms_of_one_line_are_joined_with_or() -> None:
    rs = record({"name": "Place", "weight": 30, "tolerant": False,
               "all_of": [{"any_of": ["lakeside", "hillside", "riverside"]}]})
    for place in ("lakeside", "hillside", "riverside"):
        assert points(rs, f"{place}-resident.de") == {"rule:Place": 30.0}
    assert points(rs, "elsewhere-resident.de") == {}


def test_rules_add_up() -> None:
    rs = record(
        {"name": "A", "weight": 30, "tolerant": False, "all_of": [{"any_of": ["alpha"]}]},
        {"name": "B", "weight": 20, "tolerant": False, "all_of": [{"any_of": ["beta"]}]},
    )
    assert points(rs, "alpha-beta.de") == {"rule:A": 30.0, "rule:B": 20.0}


def test_a_negated_line_prevents_the_hit() -> None:
    rs = record({
        "name": "Portal without an office", "weight": 30, "tolerant": False,
        "all_of": [{"any_of": ["portal"]}, {"any_of": ["staffportal"], "negate": True}],
    })
    assert points(rs, "portal-signin.de") == {"rule:Portal without an office": 30.0}
    assert points(rs, "staffportal-signin.de") == {}


def test_only_negated_lines_match_everything_the_prefilter_lets_through() -> None:
    # Degenerate but well defined: nothing forbidden present → the rule matches.
    rs = record({"name": "Only not", "weight": 10, "tolerant": False,
               "all_of": [{"any_of": ["forbidden"], "negate": True}]})
    assert points(rs, "benign.de") == {"rule:Only not": 10.0}
    assert points(rs, "forbidden.de") == {}


# ────────────────────────── Strength ──────────────────────────


def test_strength_is_that_of_the_weakest_line() -> None:
    """A chain is as strong as its weakest link: an exact hit beside a typo hit must
    not keep the full strength."""
    rs = record({"name": "Chain", "weight": 100, "counts_as_anchor": True,
               "all_of": [{"any_of": ["customercare"]}, {"any_of": ["lakeside"]}]})
    both_exact = score_candidate(rs, make_candidate("customercare-lakeside.de"))
    one_typo = score_candidate(rs, make_candidate("customercare-lakesdie.de"))
    assert both_exact.contributions[0].s == 1.0
    assert 0 < one_typo.contributions[0].s < 1.0
    assert one_typo.score < both_exact.score


def test_a_negated_line_does_not_push_the_strength_down() -> None:
    rs = record({"name": "N", "weight": 50, "tolerant": False,
               "all_of": [{"any_of": ["alpha"]}, {"any_of": ["forbidden"], "negate": True}]})
    assert score_candidate(rs, make_candidate("alpha.de")).contributions[0].s == 1.0


# ────────────────────── Tolerance instead of a dial ──────────────────────


def test_tolerant_recognises_spelling_variants_strict_does_not() -> None:
    tolerant = record({"name": "R", "weight": 45, "all_of": [{"any_of": ["velton"]}]})
    strict = record({"name": "R", "weight": 45, "tolerant": False,
                   "all_of": [{"any_of": ["velton"]}]})
    assert points(tolerant, "velton.de") and points(strict, "velton.de")
    for variant in ("veltn.de", "vellton.de"):
        assert points(tolerant, variant), variant
        assert not points(strict, variant), variant


@pytest.mark.parametrize(
    ("term", "variant", "detected"),
    [
        ("amt", "ant", False),           # under 5 characters: no typo tolerance at all
        # `arnt` matches all the same, but over the homoglyph skeleton (`rn` looks like
        # `m`), not over fuzzy. That is intended and holds at every length.
        ("amt", "arnt", True),
        ("velton", "veltonn", True),     # 6 characters: one deviation
        ("velton", "vlton1", False),     # two deviations: too far
        ("northvault", "northvualt", True),
    ],
)
def test_typo_width_hangs_on_the_word_length(term: str, variant: str, detected: bool) -> None:
    """The width is derived from the length instead of being set. Two deviations at
    eight letters matched `datanorte` in the live stream for an eight-letter name -
    exactly the value everyone else leaves standing too high."""
    rs = record({"name": "R", "weight": 45, "all_of": [{"any_of": [term]}]})
    assert bool(points(rs, f"{variant}-signin.de")) is detected


def test_an_explicit_match_beats_the_tolerance() -> None:
    """Rulesets taken over from `anchors` keep their setting."""
    rs = record({
        "name": "R", "weight": 45, "tolerant": True,
        "match": {"exact": True, "fuzzy": {"enabled": False}, "homoglyph": False},
        "all_of": [{"any_of": ["velton"]}],
    })
    assert points(rs, "velton.de") and not points(rs, "veltn.de")


# ────────────────────────── Patterns ──────────────────────────


def test_a_pattern_as_a_term() -> None:
    rs = record({"name": "M", "weight": 40, "all_of": [
        {"any_of": [{"pattern": "desk[-_.]?lake(side|view)"}]}]})
    assert points(rs, "desk-lakeside.de") == {"rule:M": 40.0}
    assert points(rs, "desklakeview.de") == {"rule:M": 40.0}
    assert points(rs, "desk-elsewhere.de") == {}


def test_a_pattern_is_never_fuzzed() -> None:
    """A pattern says for itself what it allows. Fuzzing it on top would mean
    overwriting what it says."""
    rs = record({"name": "M", "weight": 40, "tolerant": True,
               "all_of": [{"any_of": [{"pattern": "velton"}]}]})
    assert points(rs, "velton.de") and not points(rs, "veltn.de")


def test_a_word_and_a_pattern_in_the_same_line() -> None:
    rs = record({"name": "M", "weight": 40, "tolerant": False, "all_of": [
        {"any_of": ["alpha", {"pattern": "be[0-9]+ta"}]}]})
    assert points(rs, "alpha.de") == {"rule:M": 40.0}
    assert points(rs, "be42ta.de") == {"rule:M": 40.0}
    assert points(rs, "gamma.de") == {}


# ───────────────── The anchor relation and exceptions ─────────────────


def test_counts_as_anchor_lifts_the_cap() -> None:
    without = record({"name": "R", "weight": 60, "tolerant": False, "all_of": [{"any_of": ["alpha"]}]})
    with_anchor = record({"name": "R", "weight": 60, "tolerant": False, "counts_as_anchor": True,
                "all_of": [{"any_of": ["alpha"]}]})
    assert score_candidate(without, make_candidate("alpha.de")).score == 20
    assert score_candidate(without, make_candidate("alpha.de")).anchor_hit is False
    freed = score_candidate(with_anchor, make_candidate("alpha.de"))
    assert freed.anchor_hit is True and freed.score > 20


def test_a_weight_of_zero_does_not_anchor() -> None:
    rs = record({"name": "R", "weight": 0, "counts_as_anchor": True, "tolerant": False,
               "all_of": [{"any_of": ["alpha"]}]},
              tlds={"groups": [{"name": "high", "weight": 25, "list": ["top"]}]})
    assert score_candidate(rs, make_candidate("alpha.top")).score == 20


def test_exclude_and_owned_domains() -> None:
    rs = record({
        "name": "Brand", "weight": 45, "counts_as_anchor": True,
        "all_of": [{"any_of": ["velton"]}],
        "exclude": ["veltonia"], "owned_domains": ["velton.de"],
    })
    assert points(rs, "velton-login.top") == {"rule:Brand": 45.0}
    assert points(rs, "veltonia-reisen.de") == {}       # the exception
    assert points(rs, "intranet.velton.de") == {}       # a domain of their own


# ──────────────── The prefilter and checking patterns ────────────────


def test_the_words_of_the_rules_reach_the_prefilter() -> None:
    """The prefilter is an automaton over words. What is missing there is never
    scored - not even out of an AND line that does not suffice on its own."""
    rs = record({"name": "R", "weight": 80, "all_of": [
        {"any_of": ["customercare"]}, {"any_of": ["lakeside"]},
        {"any_of": [{"pattern": "xyz"}]},
    ]})
    terms = all_prefilter_terms([rs])
    assert {"customercare", "lakeside"} <= terms
    assert "xyz" not in terms  # an automaton over words cannot do patterns


def test_a_rule_made_only_of_patterns_is_reported_as_unreachable() -> None:
    rs = record(
        {"name": "Patterns only", "weight": 40, "all_of": [{"any_of": [{"pattern": "a[0-9]b"}]}]},
        {"name": "With a word", "weight": 40, "all_of": [
            {"any_of": [{"pattern": "a[0-9]b"}]}, {"any_of": ["velton"]}]},
        {"name": "Word negated only", "weight": 40, "all_of": [
            {"any_of": [{"pattern": "a[0-9]b"}]}, {"any_of": ["velton"], "negate": True}]},
    )
    assert rs.rules_without_prefilter == ("Patterns only", "Word negated only")


def test_patterns_are_translated_once_at_load_time() -> None:
    rs = record({"name": "M", "weight": 10, "all_of": [{"any_of": [{"pattern": "a[0-9]b"}]}]})
    assert set(rs.rule_patterns) == {"a[0-9]b"}
    assert rs.rule_patterns["a[0-9]b"].search("xa7bz")


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("(a+)+b", "quantifier inside a quantifier"),
        ("([a-z]+)*x", "quantifier inside a quantifier"),
        ("(a*)*c", "quantifier inside a quantifier"),
        ("(a|aa)+b", "takes too long"),
        ("(a|a?)+b", "takes too long"),
        ("(x|xx|xxx)+y", "takes too long"),
        ("(unklammer", "does not compile"),
        ("x" * (PATTERN_MAX_LENGTH + 1), "too long"),
    ],
)
def test_dangerous_patterns_are_refused(pattern: str, reason: str) -> None:
    """The patterns run on every certificate that passes the prefilter. An expression
    that backtracks exponentially brings the scorer to a halt, and that has to come
    out while saving, not in operation."""
    with pytest.raises(ValueError, match=reason):
        check_pattern(pattern)


@pytest.mark.parametrize(
    "pattern",
    ["amt[-_.]?stadt", "^(www|mail)[.]", "[0-9]{2,4}-bank", "(vpn|owa|citrix|sso)",
     "velton|veltongroup", "customercare[a-z0-9]*[-_.]?(stadt|dorf)"],
)
def test_usable_patterns_get_through(pattern: str) -> None:
    assert check_pattern(pattern).pattern == pattern


def test_a_dangerous_pattern_brings_down_the_whole_ruleset() -> None:
    """Do not skip it silently: a refused rule would mean somebody believes they are
    protected."""
    with pytest.raises(ValueError, match="quantifier"):
        record({"name": "M", "weight": 10, "all_of": [{"any_of": [{"pattern": "(a+)+b"}]}]})


# ───────────────────────── How it is written in YAML ─────────────────────


def test_a_word_as_a_string_a_pattern_as_a_mapping() -> None:
    rs = record({"name": "M", "weight": 10, "all_of": [{"any_of": ["Velton", {"pattern": "a[0-9]b"}]}]})
    terms = rs.rules[0].all_of[0].any_of
    assert (terms[0].text, terms[0].pattern) == ("velton", False)  # lower-cased
    assert (terms[1].text, terms[1].pattern) == ("a[0-9]b", True)
    assert rs.rules[0].words == ["velton"]


def test_an_empty_rule_is_refused() -> None:
    for broken in ({"name": "X", "weight": 10, "all_of": []},
                   {"name": "X", "weight": 10, "all_of": [{"any_of": []}]},
                   {"name": "", "weight": 10, "all_of": [{"any_of": ["a"]}]}):
        with pytest.raises(ValueError, match="at least|too_short|characters"):
            record(broken)


def test_the_ruleset_hash_changes_with_the_rules() -> None:
    a = record({"name": "R", "weight": 10, "all_of": [{"any_of": ["alpha"]}]})
    b = record({"name": "R", "weight": 11, "all_of": [{"any_of": ["alpha"]}]})
    assert a.ruleset_hash != b.ruleset_hash


def test_a_ruleset_survives_the_way_through_model_dump() -> None:
    """The form plays the API answer back. Terms stand there as `{text, pattern}`,
    no longer as a string."""
    original = record({"name": "M", "weight": 10, "counts_as_anchor": True,
                     "all_of": [{"any_of": ["velton", {"pattern": "a[0-9]b"}]},
                                {"any_of": ["login"], "negate": True}]})
    back = RuleSet.model_validate(original.model_dump(by_alias=True))
    assert back.ruleset_hash == original.ruleset_hash
    assert back.rules[0].words == ["velton", "login"]
    assert back.rules[0].prefilter_words == ["velton"]
    assert points(back, "velton.de") == {"rule:M": 10.0}
    assert points(back, "velton-login.de") == {}


def test_a_strict_rule_produces_no_permutations() -> None:
    """Permutations are generated typo variants. A rule that demands "spelled exactly
    like this" must not get them. Not over the prefilter either."""
    strict = record({"name": "R", "weight": 45, "tolerant": False,
                   "all_of": [{"any_of": ["velton"]}]})
    tolerant = record({"name": "R", "weight": 45, "all_of": [{"any_of": ["velton"]}]})
    assert strict.permutation_index == {}
    assert tolerant.permutation_index["velton"]


def test_negated_words_stay_out_of_the_prefilter() -> None:
    """Otherwise an everyday word out of an exclusion line would pull half the stream
    through the automaton. The rule demands precisely that it does not occur."""
    rs = record({"name": "R", "weight": 30, "all_of": [
        {"any_of": ["velton"]}, {"any_of": ["login", "signin"], "negate": True}]})
    terms = all_prefilter_terms([rs])
    assert "velton" in terms
    assert "login" not in terms and "signin" not in terms
    # For the permutations the negated word counts all the same: `signni` blocks too.
    assert points(rs, "velton-signni.de") == {}


def test_rules_deliver_the_tokens_for_combo_bonuses() -> None:
    """Combo bonuses hang on the tokens `anchor` and `lure`. A rule that establishes
    the brand relation is an anchor; every other one an additional reason. Without
    that mapping a ruleset would silently lose its bonuses on being rebuilt."""
    rs = record(
        {"name": "Brand", "weight": 45, "counts_as_anchor": True, "tolerant": False,
         "all_of": [{"any_of": ["velton"]}]},
        {"name": "Lure", "weight": 14, "tolerant": False, "all_of": [{"any_of": ["login"]}]},
        combos=[{"when": ["anchor", "lure"], "bonus": 20}],
    )
    both = score_candidate(rs, make_candidate("velton-login.de"))
    assert both.combos_applied == ["anchor+lure"]
    assert both.combo_bonus == 20

    brand_only = score_candidate(rs, make_candidate("velton.de"))
    assert brand_only.combos_applied == [] and brand_only.combo_bonus == 0


def test_one_rule_can_stand_on_its_own_in_a_combo() -> None:
    rs = record(
        {"name": "Brand", "weight": 45, "counts_as_anchor": True, "tolerant": False,
         "all_of": [{"any_of": ["velton"]}]},
        combos=[{"when": ["rule:Brand", "tld_group:high"], "bonus": 18}],
        tlds={"groups": [{"name": "high", "weight": 25, "list": ["top"]}]},
    )
    assert score_candidate(rs, make_candidate("velton.top")).combo_bonus == 18


def test_an_old_ruleset_is_refused_instead_of_scored_wrongly(tmp_path) -> None:
    """In `ctwatchtower/v1` the thresholds sat on the saturation scale, today they are
    points. Carrying on scoring a v1 set would mean alerting with the wrong thresholds -
    without anyone noticing. So refuse it loudly."""
    from ctwatchtower.rules.loader import RuleLoadError, load_ruleset

    path = tmp_path / "old.yaml"
    path.write_text(
        "apiVersion: ctwatchtower/v1\nkind: RuleSet\n"
        "tenant: {id: old, name: Old}\n"
        "thresholds: {persist: 35, warning: 60, alert: 80}\n"
        "anchors:\n  - {terms: [velton], weight: 45}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError, match="migrate_scoring"):
        load_ruleset(path)


def test_dots_do_not_join_labels_to_each_other() -> None:
    """The comparison removes hyphens and underscores, but no dots.

    `fastbank.database.example.com` would otherwise contain "bankdata", put together
    out of the end of one label and the beginning of the next. In the live stream that
    was exactly the reason for hits on names that have nothing to do with the brand.
    """
    rs = record({"name": "Brand", "weight": 45, "counts_as_anchor": True,
               "all_of": [{"any_of": ["bankdata"]}]})
    assert points(rs, "fastbank.database.example.com") == {}
    assert points(rs, "my.fastbank.database.de") == {}
    # The trick the shape is meant for still works.
    assert points(rs, "b-a-n-k-d-a-t-a.de") == {"rule:Brand": 45.0}
    assert points(rs, "bank_data-login.top") == {"rule:Brand": 45.0}
