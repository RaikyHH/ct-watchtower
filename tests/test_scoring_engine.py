"""The scoring engine: every detector on its own, the formula, the explanation.

The property tests deliberately run without `hypothesis`. The three properties
required (§15.5) can be checked just as sharply with a fixed list of domains and a
seeded `random`, without one more dependency.
"""

from __future__ import annotations

import random
from datetime import UTC

import pytest
from test_scoring_support import make_candidate, make_cert

from ctwatchtower.rules.schema import RuleSet
from ctwatchtower.scoring.engine import saturate, score_candidate
from ctwatchtower.scoring.explain import Contribution, severity_for

BASE = {"tenant": {"id": "test", "name": "Test"}, "scoring": {"require_anchor": False}}

DOMAINS = [
    "paylio.com",
    "payli0-secure-login.top",
    "vantabank.de.clientportal.cfd",
    "xn--pylio-4ve.com",
    "www.example.de",
    "a.b.c.d.e.f.example.xyz",
    "d1a2b3c4e5f6.cloudfront.net",
    "velton.shop",
    "*.wildcard-test.click",
]


def ruleset(**overrides) -> RuleSet:
    return RuleSet.model_validate(BASE | overrides)


def points(rs: RuleSet, domain: str, **kw) -> dict[str, float]:
    result = score_candidate(rs, make_candidate(domain), **kw)
    return {c.rule: c.pts for c in result.contributions}


def anchor(weight: float = 30, **match) -> dict:
    return {"anchors": [{"terms": ["paylio"], "weight": weight, "match": match}]}


# ───────────────────── Anchors (the §6.2 strength table) ─────────────────────


def test_anchor_exact_has_strength_one() -> None:
    rs = ruleset(**anchor(exact=True))
    result = score_candidate(rs, make_candidate("paylio-login.top"))
    hit = result.contributions[0]
    assert (hit.rule, hit.type, hit.s, hit.pts) == ("anchor:paylio", "exact", 1.0, 30.0)
    assert result.anchor_hit is True


def test_anchor_matches_across_separators() -> None:
    # "pay-lio" is "paylio" once the separators are gone: the trick from §4.2
    assert "anchor:paylio" in points(ruleset(**anchor(exact=True)), "pay-lio.top")


def test_anchor_homoglyph_has_strength_095() -> None:
    rs = ruleset(**anchor(exact=True, homoglyph=True))
    hit = score_candidate(rs, make_candidate("payli0.top")).contributions[0]
    assert (hit.type, hit.s, hit.pts) == ("homoglyph", 0.95, 28.5)


def test_anchor_permutation_has_strength_09() -> None:
    rs = ruleset(**anchor(exact=True, permutations={"enabled": True, "kinds": ["repetition"]}))
    hit = score_candidate(rs, make_candidate("payllio.top")).contributions[0]
    assert (hit.type, hit.s, hit.pts) == ("permutation", 0.9, 27.0)


def test_permutations_do_not_straddle_separators() -> None:
    rs = ruleset(anchors=[{"terms": ["korvex"], "weight": 30,
                           "match": {"permutations": {"enabled": True, "kinds": ["omission"]}}}])
    assert "anchor:korvex" in points(rs, "korvx-parcel.top")
    assert points(rs, "blithe-mesa-2581.chatgpt.site") == {}


@pytest.mark.parametrize(
    ("domain", "variant"),
    [
        ("stellx-notice.top", "stellx"),            # a token between hyphens
        ("login.stellx.top", "stellx"),
        ("stel-lax.top", "stel-lax"),               # the hyphen variant as a whole
        ("endless-tellaxy.com", None),              # `tellax` in the middle of a word
        ("stellxx.top", None),
    ],
)
def test_permutations_match_only_at_token_boundaries(domain: str, variant: str | None) -> None:
    rs = ruleset(anchors=[{"terms": ["stellax"], "weight": 30, "match": {
        "exact": False, "permutations": {"enabled": True, "kinds": ["omission", "hyphenation"]}}}])
    got = score_candidate(rs, make_candidate(domain)).contributions
    hits = [c for c in got if c.rule == "anchor:stellax"]
    assert bool(hits) is (variant is not None)
    assert rs.permutation_patterns["stellax"].search(domain) is None or variant is not None


def test_anchor_fuzzy_strength_follows_the_distance_formula() -> None:
    rs = ruleset(anchors=[{"terms": ["vantabank"], "weight": 30,
                           "match": {"fuzzy": {"enabled": True, "max_distance": 2}}}])
    one = score_candidate(rs, make_candidate("vantabonk.top")).contributions[0]
    two = score_candidate(rs, make_candidate("vontobank.top")).contributions[0]
    assert one.type == "fuzzy" and one.s == pytest.approx(1 - 1 / 3, abs=1e-4)
    assert two.s == pytest.approx(1 - 2 / 3, abs=1e-4)


@pytest.mark.parametrize(("term", "domain", "hit"), [
    ("paylio", "paylia.top", True),       # 6 characters: one deviation
    ("paylio", "payylia.top", False),     # two would be a third of the brand
    ("stellax", "cluster-local.top", False),
    ("vantabank", "vontobank.top", True),  # from 8 characters on: two
])
def test_fuzzy_allows_at_most_a_quarter_of_the_term_length(term: str, domain: str, hit: bool) -> None:
    rs = ruleset(anchors=[{"terms": [term], "weight": 30,
                           "match": {"exact": False, "fuzzy": {"enabled": True, "max_distance": 2}}}])
    assert bool(points(rs, domain)) is hit


def test_quarter_cap_can_be_lifted_per_group() -> None:
    rs = ruleset(anchors=[{"terms": ["korvex"], "weight": 35, "match": {"exact": False, "fuzzy": {
        "enabled": True, "max_distance": 2, "allow_distance_above_quarter": True}}}])
    hit = score_candidate(rs, make_candidate("en-bridge-korvaxx.pages.dev")).contributions[0]
    assert (hit.rule, hit.s) == ("anchor:korvex", pytest.approx(1 / 3, abs=1e-4))


def test_anchor_fuzzy_respects_min_term_length() -> None:
    rs = ruleset(anchors=[{"terms": ["paylio"], "weight": 30,
                           "match": {"fuzzy": {"enabled": True, "max_distance": 2,
                                               "min_term_length": 99}}}])
    assert points(rs, "paylia.top") == {}


def test_fuzzy_default_minimum_length_is_five() -> None:
    rs = ruleset(anchors=[{"terms": ["zelo", "paylio"], "weight": 28,
                           "match": {"fuzzy": {"enabled": True}}}])
    assert points(rs, "duzel.dk") == {}, "zelo has 4 characters: no fuzzy"
    assert "anchor:paylio" in points(rs, "paylxo.top")


def test_fuzzy_compares_whole_tokens_not_arbitrary_substrings() -> None:
    rs = ruleset(anchors=[{"terms": ["paylio"], "weight": 30,
                           "match": {"fuzzy": {"enabled": True, "max_distance": 2}}}])
    # A token between hyphens: `paylxo` is one deviation.
    assert points(rs, "paylxo-secure-login.top")["anchor:paylio"] == pytest.approx(20.0)
    # No token lies close enough; the middle of a label does not count.
    assert points(rs, "xxpaylxoxx.top") == {}
    # Several close tokens: the nearest one counts, once.
    assert points(rs, "paylxo-paylia.top") == {"anchor:paylio": 20.0}
    assert points(rs, "paylia-payypxl-paylxo.top") == {"anchor:paylio": 20.0}


@pytest.mark.parametrize(
    ("domain", "hit"),
    [
        ("vexa-sale.shop", True),     # a whole token
        ("vexa.de", True),
        ("v-e-x-a.top", True),        # the separator-free label
        ("venexamultimarcas.com.br", False),
        ("vexashop.de", False),       # deliberately: short terms only as a token
    ],
)
def test_short_terms_match_only_as_whole_token(domain: str, hit: bool) -> None:
    rs = ruleset(anchors=[{"terms": ["vexa"], "weight": 28, "match": {"homoglyph": True}}])
    assert ("anchor:vexa" in points(rs, domain)) is hit


def test_short_terms_as_homoglyph_need_the_token_too() -> None:
    rs = ruleset(anchors=[{"terms": ["zelo"], "weight": 30,
                           "match": {"exact": False, "homoglyph": True}}])
    assert "anchor:zelo" in points(rs, "ze1o-parcel.top")
    assert points(rs, "aze1ox.top") == {}


def test_excluded_words_are_taken_out_before_matching_the_group() -> None:
    group = {"terms": ["stellax"], "weight": 35, "exclude": ["Stellar"],
             "match": {"homoglyph": True, "fuzzy": {"enabled": True},
                       "permutations": {"enabled": True}}}
    rs = ruleset(anchors=[group])
    assert "stellar" not in rs.permutation_index["stellax"], "not in the prefilter either"
    assert points(rs, "stellar.massmo.io") == {}
    assert points(rs, "my-stellar-app.com") == {}
    # The brand itself and real variants beside the word still match.
    assert "anchor:stellax" in points(rs, "stellax-stellar.com")
    assert "anchor:stellax" in points(rs, "stellar.stellxx.top")


def test_hit_inside_an_owned_domain_is_not_an_imitation() -> None:
    rs = ruleset(anchors=[{"terms": ["vendora"], "weight": 28, "owned_domains": ["VendoraAWS.com"]}],
                 structure={"brand_in_subdomain_only": {"weight": 35}})
    assert points(rs, "s3.ap-south-1.vendoraaws.com") == {}
    # The subdomain no longer counts for this brand either ...
    assert points(rs, "xnotexistsamazonaf-45bb.vpce.vendoraaws.com") == {}
    # ... but it does for other brands.
    other = ruleset(anchors=[{"terms": ["vendora"], "weight": 28, "owned_domains": ["vendoraaws.com"]},
                             {"terms": ["paylio"], "weight": 30}])
    assert points(other, "paylio-login.s3.vendoraaws.com") == {"anchor:paylio": 30.0}
    assert "anchor:vendora" in points(rs, "vendoraaws.com.evil.top")


def test_an_anchor_group_is_one_signal() -> None:
    rs = ruleset(anchors=[{"terms": ["veltongroup", "velton-group"], "weight": 45,
                           "match": {"permutations": {"enabled": True}}}])
    result = score_candidate(rs, make_candidate("veltongroup-login.top"))
    assert [(c.rule, c.pts, c.detail) for c in result.contributions] == [
        ("anchor:veltongroup", 45.0, "also: velton-group")]
    # If only the second term matches, it carries the signal.
    # (`meine-firrma` is generated only as a variant of `velton-group`; permutations
    # do not hold across the separator-free form.)
    only = score_candidate(rs, make_candidate("velton-ggroup.top")).contributions
    assert [(c.rule, c.type, c.detail) for c in only] == [("anchor:velton-group", "permutation", None)]


def test_disabled_match_kinds_do_not_fire() -> None:
    rs = ruleset(anchors=[{"terms": ["paylio"], "weight": 30, "match": {"exact": False}}])
    assert points(rs, "paylio.top") == {}
    assert points(ruleset(**anchor(exact=True)), "payli0.top") == {}


def test_strongest_match_per_term_wins_and_each_term_counts_once() -> None:
    rs = ruleset(**anchor(exact=True, homoglyph=True))
    result = score_candidate(rs, make_candidate("paylio.payli0.top"))
    assert [c.rule for c in result.contributions] == ["anchor:paylio"]
    assert result.contributions[0].s == 1.0


@pytest.mark.parametrize("weights", [(45, 20), (20, 45)])
def test_term_in_two_anchor_groups_counts_once_with_the_stronger_group(weights) -> None:
    # Typical: the same term arrives over an include and out of the own file.
    rs = ruleset(anchors=[{"terms": ["paylio"], "weight": w} for w in weights])
    assert points(rs, "paylio-login.top") == {"anchor:paylio": 45.0}


# ───────────────────────── Lures, custom, TLDs ───────────────────────────────


def test_lures_fire_once_per_term() -> None:
    rs = ruleset(lures=[{"terms": ["login", "account"], "weight": 14}])
    assert points(rs, "login-account-login.top") == {"lure:login": 14.0, "lure:account": 14.0}


def _brand_with_a_lure_inside(**match) -> RuleSet:
    """The brand `myvelton` carries the lure `my` inside it."""
    return ruleset(anchors=[{"terms": ["myvelton"], "weight": 45, "match": match}],
                   lures=[{"terms": ["my", "desk", "login"], "weight": 7}])


@pytest.mark.parametrize(
    ("domain", "lures"),
    [
        ("myvelton-login.top", {"lure:login"}),       # `my` sits inside the brand
        ("my-velton.top", set()),                     # over the separator-free form too
        ("my-myvelton.top", {"lure:my"}),             # an occurrence of its own counts
        ("myveltonmy.top", {"lure:my"}),
        ("myve1ton-login.top", {"lure:login"}),       # where the skeleton matched
        ("myveltonn-login.top", {"lure:login"}),      # where the permutation matched
        ("myveltxn.top", set()),                      # where the fuzzy token matched
    ],
)
def test_lure_inside_the_anchor_match_does_not_count(domain: str, lures: set[str]) -> None:
    rs = _brand_with_a_lure_inside(homoglyph=True, permutations={"enabled": True, "kinds": ["repetition"]},
                         fuzzy={"enabled": True})
    got = points(rs, domain)
    assert "anchor:myvelton" in got
    assert {r for r in got if r.startswith("lure:")} == lures


def test_lures_count_normally_without_an_anchor_hit() -> None:
    assert set(points(_brand_with_a_lure_inside(exact=False), "my-desk-login.top")) == {
        "lure:my", "lure:desk", "lure:login"}


def test_skeleton_match_with_shifted_positions_does_not_hide_lures() -> None:
    # `rn → m` makes the skeleton shorter than the name: the positions do not line up,
    # so in doubt the lure counts.
    got = points(_brand_with_a_lure_inside(exact=False, homoglyph=True), "myveltondesk.top")
    assert "anchor:myvelton" in got and "lure:desk" in got


def test_lure_inside_a_longer_lure_does_not_count() -> None:
    rs = ruleset(lures=[{"terms": ["secure", "login"], "weight": 14},
                        {"terms": ["securitydesk"], "weight": 7}])
    assert points(rs, "login-securitydesk.top") == {"lure:login": 14.0, "lure:securitydesk": 7.0}
    # An occurrence of its own still counts.
    assert set(points(rs, "secure-securitydesk.top")) == {"lure:secure", "lure:securitydesk"}


def test_custom_regex_rule() -> None:
    rs = ruleset(custom=[{"id": "otp", "regex": "otp[-_.]?release", "weight": 26}])
    assert points(rs, "pushotp-release.top") == {"custom:otp": 26.0}
    assert points(rs, "benign.top") == {}


def test_custom_rule_can_stand_in_for_an_anchor() -> None:
    """A brand that only comes about out of two words must not suffocate under the cap.

    An example: an authority has no brand name. You recognise it by an administrative
    term standing beside a place name. Neither of the two words works as an anchor on
    its own; the place name alone would report every driving school in town.
    """
    rules = {
        "scoring": {"require_anchor": True, "anchor_missing_cap": 20},
        "tlds": {"groups": [{"name": "high", "weight": 25, "list": ["top"]}]},
    }
    rule = {"id": "office-place", "regex": "customercare[-_.]?lakeside", "weight": 30}

    without_anchor = RuleSet.model_validate(
        {"tenant": {"id": "t", "name": "T"}, "custom": [rule]} | rules
    )
    capped = score_candidate(without_anchor, make_candidate("customercare-lakeside.top"))
    assert capped.anchor_hit is False and capped.score == 20

    with_anchor = RuleSet.model_validate(
        {"tenant": {"id": "t", "name": "T"}, "custom": [rule | {"counts_as_anchor": True}]} | rules
    )
    freed = score_candidate(with_anchor, make_candidate("customercare-lakeside.top"))
    assert freed.anchor_hit is True and freed.score > 20

    # If the rule does not match, the cap stays. The switch alone anchors nothing.
    beside = score_candidate(with_anchor, make_candidate("drivingschool-lakeside.top"))
    assert beside.anchor_hit is False and beside.score == 20


def test_custom_anchor_with_weight_zero_does_not_lift_the_cap() -> None:
    # As with real anchors: a weight of 0 means switched off, not "counts anyway".
    rs = RuleSet.model_validate({
        "tenant": {"id": "t", "name": "T"},
        "scoring": {"require_anchor": True, "anchor_missing_cap": 20},
        "tlds": {"groups": [{"name": "high", "weight": 25, "list": ["top"]}]},
        "custom": [{"id": "off", "regex": ".*", "weight": 0, "counts_as_anchor": True}],
    })
    assert score_candidate(rs, make_candidate("anything.top")).score == 20


def test_tld_groups_overrides_and_default() -> None:
    rs = ruleset(
        tlds={
            "default_weight": 3,
            "groups": [{"name": "hochriskant", "weight": 25, "list": ["top", "de"]}],
            "overrides": [{"tld": ["de"], "weight": -10}],
        }
    )
    assert points(rs, "x.top") == {"tld:hochriskant:top": 25.0}
    assert points(rs, "x.de") == {"tld:override:de": -10.0}, "an override beats a group"
    assert points(rs, "x.com") == {"tld:default:com": 3.0}


# ─────────────────── The structure (every rule on its own) ───────────────────


def test_label_count_is_capped() -> None:
    rs = ruleset(structure={"label_count": {"baseline": 2, "weight_per_extra_label": 8, "max_weight": 32}})
    assert points(rs, "example.com") == {}
    assert points(rs, "a.b.example.com")["structure:label_count"] == 16.0
    assert points(rs, "a.b.c.d.e.f.example.com")["structure:label_count"] == 32.0


def test_brand_in_subdomain_only() -> None:
    rs = ruleset(**anchor(exact=True), structure={"brand_in_subdomain_only": {"weight": 35}})
    assert points(rs, "paylio.com.angreifer.top")["structure:brand_in_subdomain_only"] == 35.0
    assert "structure:brand_in_subdomain_only" not in points(rs, "paylio-login.top")


def test_brand_in_subdomain_only_inherits_the_anchor_strength() -> None:
    # A nine-letter brand, so a distance of 2 stays within the quarter rule and the
    # strength becomes 1/3.
    rs = ruleset(anchors=[{"terms": ["vantabank"], "weight": 35,
                           "match": {"exact": False, "fuzzy": {"enabled": True, "max_distance": 2}}},
                          {"terms": ["vantabank"], "weight": 30, "match": {"homoglyph": True}}],
                 structure={"brand_in_subdomain_only": {"weight": 36}})
    got = score_candidate(rs, make_candidate("vontobank.example.top")).contributions
    rule = next(c for c in got if c.rule == "structure:brand_in_subdomain_only")
    assert (rule.s, rule.pts) == (pytest.approx(1 / 3, abs=1e-4), 12.0)
    # Several anchors: the strongest one counts.
    got = score_candidate(rs, make_candidate("vantab4nk.example.top")).contributions
    rule = next(c for c in got if c.rule == "structure:brand_in_subdomain_only")
    assert (rule.s, rule.detail) == (0.95, "vantabank")


def test_hyphen_count_threshold_and_cap() -> None:
    rs = ruleset(structure={"hyphen_count": {"threshold": 2, "weight_per_hyphen": 5, "max_weight": 20}})
    assert points(rs, "a-b.top") == {}
    assert points(rs, "a-b-c.top")["structure:hyphen_count"] == 10.0
    assert points(rs, "a-b-c-d-e-f.top")["structure:hyphen_count"] == 20.0


def test_total_length_counts_only_the_excess() -> None:
    rs = ruleset(structure={"total_length": {"threshold": 10, "weight_per_char": 0.5, "max_weight": 15}})
    assert points(rs, "kurz.top") == {}
    assert points(rs, "zwanzig-zeichen.top")["structure:total_length"] == 4.5


def test_digit_ratio_and_entropy_are_threshold_rules() -> None:
    rs = ruleset(
        structure={"digit_ratio": {"threshold": 0.15, "weight": 10},
                   "shannon_entropy": {"threshold": 3.0, "weight": 12}}
    )
    assert points(rs, "aaaa.top") == {}
    assert points(rs, "ab12.top")["structure:digit_ratio"] == 10.0
    assert points(rs, "abcdefghij.top")["structure:shannon_entropy"] == 12.0


def test_punycode_can_require_an_anchor() -> None:
    gated = ruleset(structure={"punycode": {"weight": 18, "only_if_anchor_matched": True}})
    assert points(gated, "xn--pylio-4ve.com") == {}
    free = ruleset(structure={"punycode": {"weight": 18, "only_if_anchor_matched": False}})
    assert points(free, "xn--pylio-4ve.com")["structure:punycode"] == 18.0
    with_anchor = ruleset(**anchor(exact=True, homoglyph=True),
                          structure={"punycode": {"weight": 18}})
    assert points(with_anchor, "xn--pylio-4ve.com")["structure:punycode"] == 18.0


def test_numeric_lookalike_needs_a_digit_and_a_lookalike_anchor_hit() -> None:
    rs = ruleset(**anchor(exact=True, homoglyph=True), structure={"numeric_lookalike": {"weight": 20}})
    assert points(rs, "payli0.top")["structure:numeric_lookalike"] == 20.0
    assert "structure:numeric_lookalike" not in points(rs, "paylio1.top")  # the anchor is exact
    assert "structure:numeric_lookalike" not in points(rs, "paylio.top")   # no digit


# ──────────────────────────── The certificate (§2.3) ─────────────────────────


def test_certificate_detectors_stay_silent_without_a_certificate() -> None:
    """The UI test field calls the same function without a certificate context."""
    rs = ruleset(certificate={"san_count": {"threshold": 2, "weight": 10}})
    assert points(rs, "x.top", cert=None) == {}


def test_certificate_san_count_and_brand_fanout() -> None:
    rs = ruleset(
        **anchor(exact=True),
        certificate={"san_count": {"threshold": 3, "weight": 10},
                     "san_brand_fanout": {"min_matching_sans": 3, "weight": 25}},
    )
    cert = make_cert(["paylio-a.top", "paylio-b.top", "paylio-c.top", "egal.top"])
    got = points(rs, "paylio-a.top", cert=cert)
    assert got["cert:san_count"] == 10.0 and got["cert:san_brand_fanout"] == 25.0
    assert "cert:san_brand_fanout" not in points(rs, "paylio-a.top", cert=make_cert(["paylio-a.top"]))


def test_certificate_issuer_groups_and_validity() -> None:
    rs = ruleset(
        certificate={
            "issuer_groups": [{"name": "kostenlos", "weight": 5, "match": ["Let's Encrypt"]}],
            "validity_days": {"enabled": True, "max_days": 10, "weight": 7},
        }
    )
    got = points(rs, "x.top", cert=make_cert())
    assert got["cert:issuer:kostenlos"] == 5.0 and got["cert:validity_days"] == 7.0
    other = make_cert(issuer_o="DigiCert Inc", not_after="2027-09-15T10:20:00Z")
    assert points(rs, "x.top", cert=other) == {}


def test_certificate_ev_group_uses_the_issuer_name() -> None:
    rs = ruleset(certificate={"issuer_groups": [{"name": "ev_ov", "weight": -15, "match_ev": True}]})
    ev = make_cert(issuer_cn="DigiCert EV RSA CA G2", issuer_o="DigiCert Inc")
    assert points(rs, "x.top", cert=ev)["cert:issuer:ev_ov"] == -15.0
    assert points(rs, "x.top", cert=make_cert()) == {}


# ──────────────── The enrichment (phase 2) and the allowlist ─────────────────


def test_post_enrichment_is_silent_in_phase_one() -> None:
    rs = ruleset(post_enrichment={"no_resolution": {"weight": 8}})
    result = score_candidate(rs, make_candidate("x.top"))
    assert result.phase == 1 and result.contributions == []


def test_domain_age_picks_the_most_specific_rule() -> None:
    rs = ruleset(
        post_enrichment={
            "domain_age": [
                {"max_age_days": 1, "weight": 30},
                {"max_age_days": 7, "weight": 22},
                {"max_age_days": 30, "weight": 12},
                {"min_age_days": 365, "weight": -25},
            ]
        }
    )
    assert points(rs, "x.top", enrichment={"domain_age_days": 0})["post:domain_age"] == 30.0
    assert points(rs, "x.top", enrichment={"domain_age_days": 5})["post:domain_age"] == 22.0
    assert points(rs, "x.top", enrichment={"domain_age_days": 400})["post:domain_age"] == -25.0
    assert points(rs, "x.top", enrichment={"domain_age_days": 100}) == {}


def test_remaining_post_enrichment_rules() -> None:
    rs = ruleset(
        post_enrichment={
            "privacy_registrar": {"weight": 10},
            "nameserver_patterns": {"weight": 12, "regex": [r"(^|\.)cloudns\."]},
            "no_resolution": {"weight": 8},
            "parking_detected": {"weight": -20},
        }
    )
    got = points(
        rs,
        "x.top",
        enrichment={
            "privacy_registrar": True,
            "nameservers": ["ns1.cloudns.net"],
            "no_resolution": True,
            "parking_detected": True,
        },
    )
    assert got == {
        "post:privacy_registrar": 10.0,
        "post:nameserver_patterns": 12.0,
        "post:no_resolution": 8.0,
        "post:parking_detected": -20.0,
    }
    assert points(rs, "x.top", enrichment={"nameservers": ["ns1.example.com"]}) == {}


def test_phase_two_is_derived_from_the_enrichment_argument() -> None:
    rs = ruleset()
    assert score_candidate(rs, make_candidate("x.top"), enrichment={"domain_age_days": 3}).phase == 2
    assert score_candidate(rs, make_candidate("x.top"), phase=2).phase == 2


def test_allowlist_suppress_short_circuits_everything() -> None:
    rs = ruleset(
        **anchor(exact=True),
        allowlist={"suppress": {"exact": ["paylio.com"], "suffix": [".paylio.com"],
                                "regex": [r"^ok-\d+\.top$"]}},
    )
    for domain in ("paylio.com", "www.paylio.com", "ok-42.top"):
        result = score_candidate(rs, make_candidate(domain))
        assert result.suppressed and result.score == 0 and result.severity is None
        assert result.matched and result.contributions == []
    assert not score_candidate(rs, make_candidate("paylio.top")).suppressed


def test_allowlist_downweight_subtracts_points() -> None:
    rs = ruleset(
        **anchor(exact=True),
        allowlist={"downweight": [{"match": {"suffix": [".pages.dev"]}, "weight": -30, "note": "Cloud"}]},
    )
    result = score_candidate(rs, make_candidate("paylio.pages.dev"))
    assert result.contributions[-1].pts == -30.0 and result.contributions[-1].detail == "Cloud"
    assert result.raw == 0.0, "a negative intermediate result is clamped to 0"
    assert result.score == 0


# ─────────────────────── The formula and the combos ──────────────────────────


@pytest.mark.parametrize(
    ("raw", "score"), [(10, 22), (20, 39), (40, 63), (60, 78), (80, 86), (120, 95), (200, 99)]
)
def test_saturation_curve_matches_the_table_in_6_2(raw: float, score: int) -> None:
    assert saturate(raw, 40) == score


def test_saturation_is_monotonic_and_bounded() -> None:
    values = [saturate(raw, 40) for raw in range(0, 500, 5)]
    assert values[0] == 0 and max(values) <= 100
    assert values == sorted(values)


def test_points_are_the_score() -> None:
    """No step in between the sum and the score. A curve used to compress the sum, and
    80 points gave a score of 86. That misled people while they were tuning."""
    rs = ruleset(
        **anchor(30, exact=True),
        lures=[{"terms": ["login"], "weight": 14}],
        combos=[{"when": ["anchor", "lure"], "bonus": 15}],
    )
    result = score_candidate(rs, make_candidate("paylio-login.com"))
    assert result.raw == 44.0 and result.combo_bonus == 15
    assert result.raw_effective == 59.0
    assert result.combos_applied == ["anchor+lure"]
    assert result.score == 59          # the sum plus the bonus, nothing else


def test_the_score_is_capped_at_a_hundred() -> None:
    rs = ruleset(**anchor(100, exact=True), lures=[{"terms": ["login"], "weight": 60}])
    assert score_candidate(rs, make_candidate("paylio-login.com")).score == 100


def test_combo_bonus_is_capped() -> None:
    """Two combinations at once must not pull the score up without limit."""
    combos = [{"when": ["anchor"], "bonus": 30}, {"when": ["lure"], "bonus": 30}]
    rs = ruleset(
        **anchor(30, exact=True),
        lures=[{"terms": ["login"], "weight": 14}],
        combos=combos,
        scoring={"max_combo_bonus": 40},
    )
    result = score_candidate(rs, make_candidate("paylio-login.com"))
    assert result.combo_bonus == 40 and len(result.combos_applied) == 2
    assert result.score == 44 + 40


def test_combo_tokens_cover_structure_tld_and_domain_age() -> None:
    rs = ruleset(
        **anchor(30, exact=True),
        structure={"brand_in_subdomain_only": {"weight": 35}},
        tlds={"groups": [{"name": "hochriskant", "weight": 25, "list": ["top"]}]},
        post_enrichment={"domain_age": [{"max_age_days": 30, "weight": 12}]},
        combos=[
            {"when": ["anchor", "tld_group:hochriskant"], "bonus": 16},
            {"when": ["brand_in_subdomain_only"], "bonus": 6},
            {"when": ["anchor", "domain_age:<7d"], "bonus": 19},
        ],
    )
    result = score_candidate(
        rs, make_candidate("paylio.com.angreifer.top"), enrichment={"domain_age_days": 2}
    )
    assert set(result.combos_applied) == {
        "anchor+tld_group:hochriskant", "brand_in_subdomain_only", "anchor+domain_age:<7d"
    }


def test_require_anchor_caps_the_score() -> None:
    rules = {
        "lures": [{"terms": ["login"], "weight": 14}],
        "tlds": {"groups": [{"name": "high", "weight": 25, "list": ["top"]}]},
    }
    capped = RuleSet.model_validate(
        {"tenant": {"id": "test", "name": "T"},
         "scoring": {"require_anchor": True, "anchor_missing_cap": 20}} | rules
    )
    result = score_candidate(capped, make_candidate("login.top"))
    assert result.anchor_hit is False and result.score == 20
    assert score_candidate(ruleset(**rules), make_candidate("login.top")).score > 20


def test_score_is_zero_when_everything_is_negative() -> None:
    rs = ruleset(tlds={"groups": [{"name": "gut", "weight": -50, "list": ["de"]}]})
    result = score_candidate(rs, make_candidate("beispiel.de"))
    assert result.raw == 0.0 and result.score == 0


@pytest.mark.parametrize(
    ("score", "severity"),
    [(0, None), (16, None), (17, "info"), (36, "info"), (37, "warning"), (63, "warning"),
     (64, "alert"), (100, "alert")],
)
def test_severity_thresholds(score: int, severity: str | None) -> None:
    assert severity_for(score, ruleset().thresholds) == severity


# ───────────────────────── The explanation object (§6.4) ─────────────────────


def test_contribution_points_are_weight_times_strength() -> None:
    assert Contribution("r", w=30, s=0.95).pts == 28.5
    assert Contribution("r", w=-30, s=1.0).to_dict() == {"rule": "r", "w": -30, "s": 1.0, "pts": -30.0}


def test_contributions_are_truncated_to_top_n_but_matched_is_complete() -> None:
    terms = [f"marke{i}" for i in range(20)]
    rs = ruleset(anchors=[{"terms": [t], "weight": 5} for t in terms],
                 scoring={"require_anchor": False, "top_n": 12})
    result = score_candidate(rs, make_candidate("-".join(terms) + ".top"))
    assert len(result.contributions) == 12 and len(result.matched) == 20


def test_contributions_are_sorted_by_absolute_impact() -> None:
    rs = ruleset(
        **anchor(30, exact=True),
        lures=[{"terms": ["login"], "weight": 14}],
        allowlist={"downweight": [{"match": {"suffix": [".top"]}, "weight": -50}]},
    )
    result = score_candidate(rs, make_candidate("paylio-login.top"))
    assert [abs(c.pts) for c in result.contributions] == [50.0, 30.0, 14.0]


def test_result_serialises_for_the_json_column() -> None:
    rs = ruleset(**anchor(30, exact=True), lures=[{"terms": ["login"], "weight": 14}],
                 combos=[{"when": ["anchor", "lure"], "bonus": 15}])
    payload = score_candidate(rs, make_candidate("paylio-login.top")).to_dict()
    assert payload["score"] > 0 and payload["tenant"] == "test"
    assert payload["ruleset_hash"] == rs.ruleset_hash
    assert payload["combos_applied"] == ["anchor+lure"]
    assert payload["contributions"][0] == {
        "rule": "anchor:paylio", "w": 30.0, "s": 1.0, "pts": 30.0, "type": "exact"
    }


# ───────────────────────────── Property-Tests ────────────────────────────────

FULL = {
    "tenant": {"id": "test", "name": "T"},
    "anchors": [{"terms": ["paylio", "vantabank", "velton"], "weight": 30,
                 "match": {"exact": True, "homoglyph": True,
                           "fuzzy": {"enabled": True, "max_distance": 2},
                           "permutations": {"enabled": True}}}],
    "lures": [{"terms": ["login", "secure", "clientportal"], "weight": 14}],
    "structure": {"label_count": {}, "brand_in_subdomain_only": {"weight": 35},
                  "hyphen_count": {}, "total_length": {}, "digit_ratio": {"threshold": 0.15, "weight": 10},
                  "shannon_entropy": {"threshold": 3.6, "weight": 12},
                  "punycode": {"weight": 18}, "numeric_lookalike": {"weight": 20}},
    "tlds": {"groups": [{"name": "hochriskant", "weight": 25, "list": ["top", "xyz", "cfd", "click"]}],
             "overrides": [{"tld": ["de"], "weight": -10}]},
    "combos": [{"when": ["anchor", "lure"], "bonus": 15}],
}


@pytest.mark.parametrize("domain", DOMAINS)
@pytest.mark.parametrize("max_combo_bonus", [0, 25, 100])
def test_score_always_within_zero_and_hundred(domain: str, max_combo_bonus: float) -> None:
    scoring = {"require_anchor": False, "max_combo_bonus": max_combo_bonus}
    rs = RuleSet.model_validate(FULL | {"scoring": scoring})
    result = score_candidate(rs, make_candidate(domain), enrichment={"domain_age_days": 1})
    assert 0 <= result.score <= 100
    assert result.raw >= 0


def test_rule_order_does_not_change_the_result() -> None:
    rng = random.Random(1312)
    reference = None
    for _ in range(8):
        shuffled = dict(FULL)
        shuffled["anchors"] = [{**FULL["anchors"][0],
                                "terms": rng.sample(FULL["anchors"][0]["terms"], 3)}]
        shuffled["lures"] = [{**FULL["lures"][0], "terms": rng.sample(FULL["lures"][0]["terms"], 3)}]
        groups = FULL["tlds"]["groups"][0]
        shuffled["tlds"] = {**FULL["tlds"],
                            "groups": [{**groups, "list": rng.sample(groups["list"], 4)}]}
        rs = RuleSet.model_validate(shuffled)
        scores = [score_candidate(rs, make_candidate(d)).score for d in DOMAINS]
        assert reference is None or scores == reference
        reference = scores


def test_a_rule_with_weight_zero_changes_nothing() -> None:
    plain = RuleSet.model_validate(FULL)
    padded = RuleSet.model_validate(
        FULL
        | {
            "lures": FULL["lures"] + [{"terms": ["a", "com", "www", "e"], "weight": 0}],
            "custom": [{"id": "leer", "regex": ".*", "weight": 0}],
        }
    )
    for domain in DOMAINS:
        cand = make_candidate(domain)
        before, after = score_candidate(plain, cand), score_candidate(padded, cand)
        assert before.score == after.score and before.raw == after.raw
        assert before.combos_applied == after.combos_applied


# ───────────────────── Edge cases of the helper functions ────────────────────


def test_empty_text_has_no_entropy() -> None:
    from ctwatchtower.rules.detectors.structure import shannon_entropy

    assert shannon_entropy("") == 0.0
    assert shannon_entropy("ab") == 1.0


def test_candidate_without_tld_gets_no_tld_points() -> None:
    # Names without a valid TLD are discarded by the normalisation already (§4.1.5),
    # so the detector never sees them. The guard is checked all the same, built directly.
    rs = ruleset(tlds={"default_weight": 5})
    cand = make_candidate("example.com")
    cand.tld = ""
    assert score_candidate(rs, cand).contributions == []


def test_skeleton_with_a_different_label_count_falls_back_to_the_whole_name() -> None:
    rs = ruleset(**anchor(exact=False, homoglyph=True))
    cand = make_candidate("payli0.top")
    cand.skeleton = "paylio"  # rn→m and the like can swallow labels
    assert score_candidate(rs, cand).contributions[0].type == "homoglyph"


def test_certificate_dates_may_arrive_as_datetime_or_as_garbage() -> None:
    from datetime import datetime

    rs = ruleset(certificate={"validity_days": {"enabled": True, "max_days": 10, "weight": 7}})
    typed = make_cert(
        not_before=datetime(2026, 9, 15, tzinfo=UTC),
        not_after=datetime(2026, 9, 21, tzinfo=UTC),
    )
    assert points(rs, "x.top", cert=typed)["cert:validity_days"] == 7.0
    assert points(rs, "x.top", cert=make_cert(not_after="the day after tomorrow")) == {}
    assert points(rs, "x.top", cert=make_cert(not_before=None)) == {}


def test_detail_survives_the_json_round_trip() -> None:
    rs = ruleset(structure={"label_count": {}})
    payload = score_candidate(rs, make_candidate("a.b.example.com")).to_dict()
    assert payload["contributions"][0]["detail"] == "4 labels"


# ─────────────────── Registrar-Listen (Markenschutz, Privacy) ────────────────

BRAND = {"brand_protection_registrar": {"weight": -40, "list_file": "data/registrar_brand_protection.yaml"}}


def test_brand_protection_registrar_matches_name_part_case_insensitive() -> None:
    rs = ruleset(post_enrichment=BRAND)
    got = score_candidate(rs, make_candidate("vendora.dev"), enrichment={"registrar": "MarkMonitor Inc."})
    hit = got.contributions[0]
    assert (hit.rule, hit.pts, hit.detail) == ("post:brand_protection_registrar", -40.0, "MarkMonitor Inc.")


def test_brand_protection_registrar_matches_iana_id_without_name() -> None:
    rs = ruleset(post_enrichment=BRAND)
    got = points(rs, "x.com", enrichment={"registrar_iana_id": "299"})
    assert got == {"post:brand_protection_registrar": -40.0}
    detail = score_candidate(rs, make_candidate("x.com"), enrichment={"registrar_iana_id": 299})
    assert detail.contributions[0].detail == "IANA 299"


def test_retail_registrars_are_not_brand_protection() -> None:
    rs = ruleset(post_enrichment=BRAND)
    for registrar in ("NameCheap, Inc.", "Amazon Registrar, Inc.", "Cloudflare, Inc.", "GoDaddy.com, LLC"):
        assert points(rs, "x.com", enrichment={"registrar": registrar, "registrar_iana_id": 1068}) == {}
    assert points(rs, "x.com", enrichment={"domain_age_days": 3}) == {}  # no registrar known


def test_registrar_rule_without_list_or_with_missing_file_stays_silent(caplog) -> None:
    rs = ruleset(post_enrichment={"brand_protection_registrar": {"weight": -40}})
    assert points(rs, "x.com", enrichment={"registrar": "MarkMonitor Inc."}) == {}
    missing = {"weight": -40, "list_file": "data/missing.yaml"}
    rs = ruleset(post_enrichment={"brand_protection_registrar": missing})
    assert points(rs, "x.com", enrichment={"registrar": "MarkMonitor Inc."}) == {}
    assert points(rs, "x.com", enrichment={"registrar": "MarkMonitor Inc."}) == {}
    assert caplog.text.count("missing.yaml") == 1  # report once, not on every finding


def test_privacy_registrar_reads_its_list_and_picks_up_edits(tmp_path) -> None:
    lst = tmp_path / "risk.yaml"
    lst.write_text("registrars: [shady registrar]\n", encoding="utf-8")
    rs = ruleset(post_enrichment={"privacy_registrar": {"weight": 10, "list_file": str(lst)}})
    got = points(rs, "x.top", enrichment={"registrar": "Shady Registrar LLC"})
    assert got == {"post:privacy_registrar": 10.0}
    assert points(rs, "x.top", enrichment={"registrar": "Other Ltd"}) == {}
    import os

    lst.write_text("registrars: [other]\niana_ids: [7]\n", encoding="utf-8")
    os.utime(lst, (1, 2_000_000_000))  # an mtime certainly other than at the first read
    assert points(rs, "x.top", enrichment={"registrar": "Other Ltd"}) == {"post:privacy_registrar": 10.0}
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    rs = ruleset(post_enrichment={"privacy_registrar": {"weight": 10, "list_file": str(empty)}})
    assert points(rs, "x.top", enrichment={"registrar": "Other Ltd"}) == {}


def _lures(whole_word: bool):
    return ruleset(
        **anchor(30, exact=True),
        lures=[{"terms": ["bridge", "login"], "weight": 14, "whole_word": whole_word}],
    )


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("paylio-bridge.com", True),       # separated by a hyphen
        ("bridge.paylio.com", True),       # a label of its own
        ("paylio.bridge2.com", True),      # a digit bounds the word
        ("paylioabridgeintelligence.com", False),  # sits inside a longer word
        ("paylio-abridged.com", False),
    ],
)
def test_a_lure_as_a_whole_word(domain: str, expected: bool) -> None:
    """`bridge` in `bridgeintelligence` lures nobody. With `whole_word` the term counts
    only where it stands on its own."""
    hits = points(_lures(True), domain)
    assert ("lure:bridge" in hits) is expected


def test_without_the_option_substrings_still_count() -> None:
    """The default does not change: phishing domains like to write words together
    (`loginportal`), and that should keep working."""
    assert "lure:bridge" in points(_lures(False), "paylioabridgeintelligence.com")
    assert "lure:login" in points(_lures(False), "paylio-loginportal.com")
    assert "lure:login" not in points(_lures(True), "paylio-loginportal.com")
