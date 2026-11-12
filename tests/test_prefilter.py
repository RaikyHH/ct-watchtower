"""The prefilter. The set of terms is passed in directly, not over the loader."""

from ctwatchtower.normalize.names import normalize
from ctwatchtower.normalize.prefilter import Prefilter

TERMS = ["paylio", "vantabank", "vendora", "login", "account"]


def hits(name: str) -> list[str]:
    pf = Prefilter(TERMS)
    cand = normalize(name)
    assert cand is not None
    return pf.hits(cand)


def test_plain_hit():
    assert hits("paylio-account.top") == ["account", "paylio"]


def test_hit_only_via_skeleton():
    assert hits("pаyli0.com") == ["paylio"]
    assert hits("vendor4-1ogin.de") == ["login", "vendora"]


def test_hit_only_via_dotless_form():
    assert hits("pay.lio.example.com") == ["paylio"]
    assert hits("vanta-bank.de") == ["vantabank"]


def test_no_hit_for_ordinary_names():
    assert hits("www.wikipedia.org") == []


def test_hits_are_written_to_the_candidate():
    pf = Prefilter(TERMS)
    cand = normalize("vantabank-security.de")
    pf.hits(cand)
    assert cand.prefilter_hits == ["vantabank"]


def test_pass_ratio_metric():
    pf = Prefilter(TERMS)
    for name in ["paylio.top", "a.com", "b.com", "c.com"]:
        pf.hits(normalize(name))
    assert pf.seen == 4 and pf.passed == 1
    assert pf.pass_ratio == 0.25


def test_empty_ruleset_passes_nothing():
    pf = Prefilter([])
    assert pf.hits(normalize("paylio.com")) == []
    assert pf.pass_ratio == 0.0
