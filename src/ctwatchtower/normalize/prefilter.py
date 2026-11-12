"""Prefilter (§4.2): one Aho-Corasick automaton across all tenants.

Matched against `name`, `skeleton` and the separator-free form. The last one
catches separator tricks (`paypa1-secure` -> `paypalsecure`).
"""

import re
from collections.abc import Iterable, Mapping

import ahocorasick

from ctwatchtower.normalize.names import CandidateName

_SEP = re.compile(r"[^a-z0-9]+")


def _dotless(value: str) -> str:
    return _SEP.sub("", value)


class Prefilter:
    """Stage 1. Only names with at least one hit reach rule evaluation.

    `terms` is either a set of terms or `{term: tenant ids}`. With that mapping
    `tenants_for` says which tenants have to run stage 2 at all (§4.2: stage 2
    runs per tenant).
    """

    def __init__(self, terms: Iterable[str] | Mapping[str, Iterable[str]]) -> None:
        self.automaton = ahocorasick.Automaton()
        self.owners: dict[str, frozenset[str]] | None = None
        if isinstance(terms, Mapping):
            self.owners = {
                t.strip().lower(): frozenset(ids) for t, ids in terms.items() if t and t.strip()
            }
        self.terms = {t.strip().lower() for t in terms if t and t.strip()}
        for term in self.terms:
            self.automaton.add_word(term, term)
        if self.terms:
            self.automaton.make_automaton()
        self.seen = 0
        self.passed = 0

    def hits(self, cand: CandidateName) -> list[str]:
        """Hits as a sorted list; also sets `cand.prefilter_hits`."""
        self.seen += 1
        found: set[str] = set()
        if self.terms:
            for haystack in (cand.name, cand.skeleton, _dotless(cand.skeleton), _dotless(cand.name)):
                for _, term in self.automaton.iter(haystack):
                    found.add(term)
        cand.prefilter_hits = sorted(found)
        if found:
            self.passed += 1
        return cand.prefilter_hits

    def tenants_for(self, hits: Iterable[str]) -> frozenset[str] | None:
        """Tenants the hits belong to. `None`: built without a mapping, so all of them."""
        if self.owners is None:
            return None
        return frozenset().union(*(self.owners.get(t, ()) for t in hits))

    @property
    def pass_ratio(self) -> float:
        """Metric `prefilter_pass_ratio`. Above 0.02 the ruleset is too unspecific."""
        return self.passed / self.seen if self.seen else 0.0


def build_from_rulesets(rulesets: list) -> Prefilter:
    """One automaton over all loaded rulesets."""
    # Imported here: the loader lives in the rules package and may be missing at
    # import time.
    from ctwatchtower.rules.loader import all_prefilter_terms

    owners: dict[str, set[str]] = {}
    for rs in rulesets:
        for term in all_prefilter_terms([rs]):
            owners.setdefault(term, set()).add(rs.tenant.id)
    return Prefilter(owners)


if __name__ == "__main__":
    from ctwatchtower.normalize.names import normalize

    pf = Prefilter(["paylio", "vantabank", "login"])
    assert pf.hits(normalize("pаyli0-login.top")) == ["login", "paylio"]
    assert pf.hits(normalize("www.example.com")) == []
    routed = Prefilter({"paylio": ["fin"], "login": ["fin", "shop"], "vendora": ["shop"]})
    assert routed.tenants_for(routed.hits(normalize("vend0ra.de"))) == {"shop"}
    assert routed.tenants_for(routed.hits(normalize("paylio-login.top"))) == {"fin", "shop"}
    print("ok", pf.pass_ratio)
