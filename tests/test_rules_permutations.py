from __future__ import annotations

import pytest

from ctwatchtower.rules.permutations import permutations_for
from ctwatchtower.rules.schema import PERMUTATION_KINDS


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("omission", "paylo"),
        ("insertion", "paylioo"),
        ("transposition", "payilo"),
        ("replacement", "pay1io"),
        ("hyphenation", "pay-lio"),
        ("bitsquatting", "pailio"),
        ("vowel_swap", "paylie"),
        ("repetition", "payllio"),
    ],
)
def test_single_kind_produces_expected_variant(kind: str, expected: str) -> None:
    assert expected in permutations_for("paylio", [kind])


def test_double_char_collapses_doubled_letters() -> None:
    assert "paylio" in permutations_for("payllio", ["double_char"])


def test_tld_swap_only_applies_to_terms_with_a_dot() -> None:
    assert "velton.com" in permutations_for("velton.de", ["tld_swap"])
    assert permutations_for("velton", ["tld_swap"]) == set()


def test_term_itself_is_never_a_permutation() -> None:
    assert "paylio" not in permutations_for("paylio", PERMUTATION_KINDS)


def test_short_terms_are_skipped() -> None:
    # Permutations of `zelo` would be any three-letter sequence. Poison for the prefilter.
    assert permutations_for("zelo", PERMUTATION_KINDS) == set()


def test_unknown_kind_is_ignored_here_and_rejected_by_the_schema() -> None:
    assert permutations_for("paylio", ["gibtsnicht"]) == set()


def test_all_declared_kinds_have_a_generator() -> None:
    from ctwatchtower.rules.permutations import _GENERATORS

    assert set(_GENERATORS) == set(PERMUTATION_KINDS)


def test_engine_minimum_length_drops_short_terms_and_short_variants() -> None:
    # Four letters: no variants. Otherwise `zelo` would produce `ald`, `ali`, `adi`.
    assert permutations_for("zelo", PERMUTATION_KINDS) == set()
    variants = permutations_for("vendora", PERMUTATION_KINDS)
    assert "vendor" in variants and not any(len(v) < 5 for v in variants)
    # A ruleset may lower the bound deliberately.
    assert "zel" in permutations_for("zelo", ["omission"], min_length=3)


def test_short_permutations_never_reach_the_prefilter() -> None:
    from ctwatchtower.rules.loader import all_prefilter_terms
    from ctwatchtower.rules.schema import RuleSet

    rs = RuleSet.model_validate({
        "tenant": {"id": "t", "name": "T"},
        "anchors": [{"terms": ["zelo", "vendora"], "weight": 28,
                     "match": {"permutations": {"enabled": True}}}],
    })
    assert rs.permutation_index["zelo"] == frozenset()
    assert min(map(len, all_prefilter_terms([rs]))) >= 4  # `zelo` itself stays
