"""The ruleset in sentences.

The explanation comes out of the validated model, not out of the form state,
otherwise it explains something other than what the engine does. These tests pin
exactly that down.
"""

from __future__ import annotations

import pytest
from conftest import copy_rule_base

from ctwatchtower.rules.prose import as_text, explain_ruleset
from ctwatchtower.rules.schema import RuleSet

BASE = {"tenant": {"id": "t", "name": "Sample Council"}}


def record(**rest) -> RuleSet:
    return RuleSet.model_validate({**BASE, **rest})


def text(rs: RuleSet, **kw) -> str:
    return as_text(explain_ruleset(rs, **kw))


def test_and_or_not_are_spelled_out() -> None:
    rs = record(rules=[{
        "name": "Council with a place name", "weight": 80, "counts_as_anchor": True,
        "tolerant": False,
        "all_of": [
            {"any_of": ["customercare", "customerdesk"]},
            {"any_of": ["lakeside"]},
            {"any_of": ["blog"], "negate": True},
        ],
    }])
    t = text(rs)
    assert "The domain contains “customercare” or “customerdesk”," in t
    assert "contains “lakeside”" in t
    assert "and does not contain “blog”" in t
    assert "Words have to be spelled exactly like this." in t


def test_points_need_no_conversion_any_more() -> None:
    """Points are the score. This used to say "80 points make score 86", the
    explanation had to bridge a formula that is gone."""
    rs = record(rules=[{"name": "R", "weight": 80, "all_of": [{"any_of": ["alpha"]}]}])
    paragraphs = explain_ruleset(rs)
    rule = next(a for a in paragraphs if a.title == "R")
    assert rule.rows[0] == "80 points."     # no conversion, no intermediate step


def test_a_tolerant_rule_says_what_else_it_catches() -> None:
    rs = record(rules=[{"name": "R", "weight": 45, "all_of": [{"any_of": ["lakesidedesk"]}]}])
    assert "typos" in text(rs) and "confusable" in text(rs)


def test_a_pattern_is_not_read_like_a_word() -> None:
    rs = record(rules=[{"name": "R", "weight": 25, "all_of": [
        {"any_of": [{"pattern": "a[0-9]{2}b"}]}, {"any_of": ["alpha"]}]}])
    assert "something matching the pattern a[0-9]{2}b" in text(rs)


def test_a_rule_without_a_word_is_explained_as_unreachable() -> None:
    """The prefilter works on words. A rule made only of patterns almost never
    fires. That has to be written down, otherwise somebody thinks they are covered."""
    rs = record(rules=[{"name": "Patterns only", "weight": 25,
                        "all_of": [{"any_of": [{"pattern": "a[0-9]b"}]}]}])
    paragraphs = explain_ruleset(rs)
    warnings = [a for a in paragraphs if a.kind == "warning"]
    assert warnings and "Patterns only" in warnings[0].title
    assert "at least one word" in warnings[0].rows[0]


def test_without_a_rule_it_says_nothing_will_be_found() -> None:
    paragraphs = explain_ruleset(record())
    assert [a.kind for a in paragraphs if a.kind == "warning"] == ["warning"]
    assert "Without a rule nothing is found" in as_text(paragraphs)


def test_exceptions_and_own_domains_are_listed() -> None:
    rs = record(rules=[{
        "name": "Brand", "weight": 45, "all_of": [{"any_of": ["lakesidedesk"]}],
        "exclude": ["lakesidegazette"], "owned_domains": ["lakesidedesk.de"],
    }])
    t = text(rs)
    assert "Except for: “lakesidegazette”." in t
    assert "our own infrastructure" in t


def test_thresholds_cap_and_combo_bonus() -> None:
    rs = record(
        thresholds={"persist": 30, "warning": 55, "alert": 70},
        scoring={"require_anchor": True, "anchor_missing_cap": 20, "max_combo_bonus": 40},
        combos=[{"when": ["anchor", "lure"], "bonus": 20}],
        rules=[{"name": "R", "weight": 45, "all_of": [{"any_of": ["alpha"]}]}],
    )
    t = text(rs)
    assert "From 55 points it warns, from 70 it alerts; below 30" in t
    assert "to 20 points at most" in t
    assert "points are added (20 points), at most 40 in all" in t


def test_without_the_anchor_requirement_the_cap_sentence_goes() -> None:
    rs = record(scoring={"require_anchor": False},
                rules=[{"name": "R", "weight": 45, "all_of": [{"any_of": ["alpha"]}]}])
    assert "establishes the brand reference, a domain" not in text(rs)


def test_suppressed_domains_are_listed() -> None:
    rs = record(allowlist={"suppress": {"exact": ["lakesidedesk.de"], "suffix": [".lakesidedesk.de"]}},
                rules=[{"name": "R", "weight": 45, "all_of": [{"any_of": ["alpha"]}]}])
    # Both spellings mean the same intention. Two entries for it would only be twice
    # as long.
    assert "Never reported" in text(rs)
    assert "“lakesidedesk.de” and everything under it." in text(rs)


def test_only_exact_suppression_stays_without_the_addition() -> None:
    rs = record(allowlist={"suppress": {"exact": ["other-company.de"]}},
                rules=[{"name": "R", "weight": 45, "all_of": [{"any_of": ["alpha"]}]}])
    assert "“other-company.de”." in text(rs)
    assert "everything under it" not in text(rs)


def test_inherited_groups_carry_a_kind_of_their_own() -> None:
    """So the UI can fold them away. They cannot be edited there."""
    rs = record(anchors=[{"description": "Brands", "terms": ["velton"], "weight": 45}],
                rules=[{"name": "Own", "weight": 30, "all_of": [{"any_of": ["alpha"]}]}])
    kinds = {a.title: a.kind for a in explain_ruleset(rs, with_inherited=True)}
    assert kinds["Own"] == "rule" and kinds["Brands"] == "inherited"


def test_inherited_groups_only_on_request() -> None:
    """In the form they already sit next to it marked "inherited"; otherwise the
    explanation shows what the user built themselves."""
    rs = record(
        anchors=[{"description": "Brands", "terms": ["velton"], "weight": 45}],
        lures=[{"description": "Lures", "terms": ["login"], "weight": 14}],
    )
    assert "velton" not in text(rs)
    with_them = text(rs, with_inherited=True)
    assert "Brands" in with_them and "“velton”" in with_them
    assert "Lures" in with_them and "on top of something else" in with_them


def test_a_group_without_a_description_gets_a_name() -> None:
    rs = record(anchors=[{"terms": ["velton"], "weight": 45}],
                lures=[{"terms": ["login"], "weight": 14}])
    t = text(rs, with_inherited=True)
    assert "Brand anchor" in t and "Lure terms" in t


def test_an_explicit_match_setting_is_named() -> None:
    rs = record(rules=[{
        "name": "R", "weight": 45, "match": {"exact": True, "homoglyph": True},
        "all_of": [{"any_of": ["velton"]}],
    }])
    assert "match setting of its own" in text(rs)


@pytest.mark.parametrize(
    ("terms", "expected"),
    [(["a"], "“a”"), (["a", "b"], "“a” or “b”"), (["a", "b", "c"], "“a”, “b” or “c”")],
)
def test_lists_read_like_a_sentence(terms: list[str], expected: str) -> None:
    rs = record(rules=[{"name": "R", "weight": 10, "all_of": [{"any_of": terms}]}])
    assert f"The domain contains {expected}." in text(rs)


# ---------------------------- through the API ----------------------------


def test_validate_returns_the_prose_too(tmp_path) -> None:
    """The form calls `validate` on every keystroke anyway. The explanation comes
    from there, so it never differs from what would be saved."""
    from ctwatchtower.app import create_app

    rules = copy_rule_base(tmp_path / "rules")
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        client = app.test_client()
        assert client.post("/api/v1/tenants",
                           json={"id": "check", "name": "Check"}).status_code == 201
        response = client.post(
            "/api/v1/tenants/check/rules/validate",
            json={"rules": [{"name": "Brand", "weight": 45, "counts_as_anchor": True,
                             "all_of": [{"any_of": ["velton"]}]}]},
        )
        data = response.get_json()
        assert data["valid"] is True
        title = [a["title"] for a in data["prose"]]
        assert "Brand" in title
        # Inherited groups belong in there: otherwise the column claims "no rule yet"
        # while rules from `includes` have been firing all along. What they are called
        # is in their own `description`; here it only matters that they are explained
        # at all. They carry a kind of their own so the UI can fold them away, because
        # they cannot be edited there and would otherwise push everything else out.
        assert [a for a in data["prose"] if a["kind"] == "inherited"], title
        assert any("45 points" in row for a in data["prose"] for row in a["rows"])
    finally:
        app.config["DB"].close()


def test_validate_reports_a_dangerous_pattern_instead_of_explaining_it(tmp_path) -> None:
    from ctwatchtower.app import create_app

    rules = copy_rule_base(tmp_path / "rules")
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        client = app.test_client()
        client.post("/api/v1/tenants", json={"id": "check", "name": "Check"})
        response = client.post(
            "/api/v1/tenants/check/rules/validate",
            json={"rules": [{"name": "M", "weight": 10,
                             "all_of": [{"any_of": [{"pattern": "(a+)+b"}]}]}]},
        )
        data = response.get_json()
        assert data["valid"] is False and "quantifier" in data["error"]
    finally:
        app.config["DB"].close()


def test_long_term_lists_get_cut_short() -> None:
    """Listing twenty lure words explains nothing, it only hides what sits next to
    them. The number is enough."""
    terms = [f"word{i}" for i in range(20)]
    rs = record(rules=[{"name": "R", "weight": 10, "all_of": [{"any_of": terms}]}])
    t = text(rs)
    assert "“word0”, “word1”" in t
    assert "and 12 more" in t
    assert "word19" not in t


def test_short_lists_stay_complete() -> None:
    rs = record(rules=[{"name": "R", "weight": 10,
                        "all_of": [{"any_of": ["alpha", "beta", "gamma"]}]}])
    assert "“alpha”, “beta” or “gamma”" in text(rs)
    assert "more" not in text(rs)


def test_the_prose_says_when_a_lure_only_counts_as_a_whole_word() -> None:
    """The difference decides how many hits there are, so it belongs in the sentence."""
    rs = record(lures=[{"description": "Lures", "terms": ["bridge"], "weight": 14,
                        "whole_word": True}])
    assert "contains, as a word of its own, “bridge”" in text(rs, with_inherited=True)

    loose = record(lures=[{"description": "Lures", "terms": ["bridge"], "weight": 14}])
    assert "contains “bridge”" in text(loose, with_inherited=True)
