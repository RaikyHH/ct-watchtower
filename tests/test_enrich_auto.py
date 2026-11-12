"""Enrichment without a click, from a threshold per tenant upwards.

Without it the campaigns stay empty: they bundle by registrar, nameserver and
network, and those are enriched details. A bundle made of findings that were all
clicked one by one is no bundle.

**Nothing is queried here.** Every test replaces the enricher with a fake and
checks *whether* it would have been requested, not what comes back.
`tests/conftest.py` allows loopback only in any case.
"""

from __future__ import annotations

import pytest
from conftest import copy_rule_base
from test_scoring_support import make_cert

from ctwatchtower import db
from ctwatchtower.config import settings
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RuleStore

RULESET = """
tenant: {id: velton, name: Velton GmbH}
thresholds: {persist: 10, info: 20, warning: 40, alert: 70, enrich_from: 80}
scoring: {require_anchor: false}
anchors:
  - terms: [velton]
    weight: 45
lures:
  - terms: [login, security, account]
    weight: 20
"""


class Enricher:
    """Remembers the requests instead of asking."""

    # `Pipeline.metrics()` reads this. The fake has to have it, otherwise the test
    # ends up checking only itself.
    active = 0
    queued = 0

    def __init__(self, response: str = "queued"):
        self.requested: list[str] = []
        self.response = response
        self.quota = type("Zaehler", (), {"status": staticmethod(lambda: None)})()
        self.cache = type("Cache", (), {"hit_ratio": 0.0})()

    def request(self, finding_id: str) -> str:
        self.requested.append(finding_id)
        return self.response


@pytest.fixture
def pipe(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "enrich_enabled", True)
    monkeypatch.setattr(settings, "enrich_auto", False)
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "velton.yaml").write_text(RULESET, encoding="utf-8")
    p = Pipeline(db.connect(tmp_path / "a.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")
    p.rulesets(force=True)
    p.enricher = Enricher()
    yield p
    p.conn.close()


def hit(pipe, domain: str) -> int:
    events = pipe.process(make_cert([domain]))
    assert events, f"the test setup: {domain} produces no finding"
    return events[0]["score"]


def test_nothing_is_requested_without_the_main_switch(pipe) -> None:
    """`enrich_from` stands in every ruleset, in old ones too. If the threshold took
    effect without the switch, an existing installation would start asking by itself
    at the next start. Exactly the incident of 2026-09-19."""
    assert hit(pipe, "velton-security-login.de") >= 80
    assert pipe.enricher.requested == []


def test_with_the_switch_it_is_requested_from_the_threshold_upwards(pipe, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_auto", True)
    assert hit(pipe, "velton-security-login.de") >= 80
    assert len(pipe.enricher.requested) == 1
    assert pipe.auto_enriched == 1


def test_below_the_threshold_it_stays_with_the_click(pipe, monkeypatch) -> None:
    """The point of the threshold: not every finding costs a query at someone
    else's registry."""
    monkeypatch.setattr(settings, "enrich_auto", True)
    score = hit(pipe, "velton.de")
    assert score < 80, "the test setup: the finding should lie below the threshold"
    assert pipe.enricher.requested == []


def test_every_tenant_has_a_threshold_of_its_own(tmp_path, monkeypatch) -> None:
    """A loud tenant should not drag a quiet one along with it."""
    monkeypatch.setattr(settings, "enrich_enabled", True)
    monkeypatch.setattr(settings, "enrich_auto", True)
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "velton.yaml").write_text(RULESET, encoding="utf-8")
    (rules / "laut.yaml").write_text(
        RULESET.replace("id: velton, name: Velton GmbH", "id: laut, name: Laut")
        .replace("enrich_from: 80", "enrich_from: 100"),
        encoding="utf-8",
    )
    p = Pipeline(db.connect(tmp_path / "b.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")
    p.rulesets(force=True)
    p.enricher = Enricher()

    events = p.process(make_cert(["velton-security-login.de"]))
    assert len(events) == 2, "both tenants find the name"
    # Only the one with the lower threshold requests it.
    assert len(p.enricher.requested) == 1
    p.conn.close()


def test_an_exhausted_budget_reports_itself_once(pipe, monkeypatch, caplog) -> None:
    """The daily cap is the hard brake. It holds until tomorrow, and logging it on
    every finding would only fill the log."""
    import logging

    caplog.set_level(logging.INFO, logger="ctwatchtower.pipeline")
    monkeypatch.setattr(settings, "enrich_auto", True)
    pipe.enricher = Enricher(response="quota")
    for name in ("velton-security-login.de", "velton-account-login.de",
                 "velton-login-security.de"):
        hit(pipe, name)
    assert len(pipe.enricher.requested) == 3, "it is attempted; the worker brakes"
    assert pipe.auto_enriched == 0, "only what was really queued gets counted"
    assert caplog.text.count("daily enrichment cap reached") == 1


def test_a_switched_off_enrichment_trumps_the_automatic_mode(pipe, monkeypatch) -> None:
    """`ENRICH_ENABLED=false` trumps everything. A switched-on automatic switch too."""
    monkeypatch.setattr(settings, "enrich_auto", True)
    monkeypatch.setattr(settings, "enrich_enabled", False)
    assert hit(pipe, "velton-security-login.de") >= 80
    assert pipe.enricher.requested == []
    assert pipe.auto_enriched == 0


def test_the_system_screen_shows_the_state(pipe, monkeypatch) -> None:
    """Whoever switches this on should see what it sets off."""
    monkeypatch.setattr(settings, "enrich_auto", True)
    hit(pipe, "velton-security-login.de")
    m = pipe.metrics()
    assert m["auto_on"] is True
    assert m["auto_enriched"] == 1
