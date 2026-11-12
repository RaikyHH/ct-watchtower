"""Trial mode (§15.2): a ruleset runs along without waking anyone.

`shadow: true` stood in the schema for a long time and did nothing; whoever set it
got reports and feed entries all the same. A setting that brings about the opposite
of what it promises is worse than none.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import copy_rule_base

from ctwatchtower.app import create_app
from ctwatchtower.normalize.names import CertContext, normalize
from ctwatchtower.rules.loader import load_ruleset

TRIAL = """
shadow: true
tenant: {id: trial, name: Trial}
anchors:
  - terms: [velton]
    weight: 80
thresholds: {persist: 10, warning: 20, alert: 30, feed_from: 10}
"""


@pytest.fixture
def app(tmp_path):
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "trial.yaml").write_text(TRIAL, encoding="utf-8")
    application = create_app(
        db_path=tmp_path / "ctw.sqlite3", rules_dir=rules, start_pipeline=False
    )
    yield application


@pytest.fixture
def pipeline(app):
    p = app.config["PIPELINE"]
    p.rulesets(force=True)
    return p


def _certificate(name: str) -> dict:
    from datetime import UTC, datetime

    cert = CertContext(
        log_id="t", idx=1, seen_at=datetime.now(UTC), not_before=None, not_after=None,
        issuer_cn="", issuer_o="Let's Encrypt", serial="", sha256=f"{1:064x}",
        is_precert=False, names=[name],
    )
    return cert


def test_trial_mode_produces_findings_but_no_report(pipeline, monkeypatch):
    reported = []
    monkeypatch.setattr(
        pipeline.notifier, "offer", lambda event: reported.append(event) or True
    )
    events = pipeline.process(_certificate("velton-login.top"))
    assert events, "the finding should come about all the same - it just must not report"
    assert reported == []


def test_trial_mode_serves_no_feed(app):
    client = app.test_client()
    for kind in ("indicators.csv", "indicators.json", "indicators.jsonl", "domains.txt"):
        response = client.get(f"/feed/trial/{kind}")
        assert response.status_code == 409, kind
        assert "trial mode" in response.get_json()["error"]


def test_without_shadow_everything_stays_as_before(tmp_path):
    """The counter-check: the same ruleset without the flag reports and serves."""
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "armed.yaml").write_text(
        TRIAL.replace("shadow: true", "").replace("id: trial", "id: armed"), encoding="utf-8"
    )
    application = create_app(
        db_path=tmp_path / "ctw2.sqlite3", rules_dir=rules, start_pipeline=False
    )
    pipeline = application.config["PIPELINE"]
    pipeline.rulesets(force=True)

    reported = []
    pipeline.notifier.offer = lambda event: reported.append(event) or True
    assert pipeline.process(_certificate("velton-login.top"))
    assert len(reported) == 1
    assert application.test_client().get("/feed/armed/domains.txt").status_code == 200


def test_the_rules_screen_says_so(app):
    text = app.test_client().get("/rules?t=trial").get_data(as_text=True)
    assert "Trial mode" in text
    assert Path(app.config["RULES_DIR"]).is_dir()


def test_the_schema_accepts_the_flag(tmp_path):
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "trial.yaml").write_text(TRIAL, encoding="utf-8")
    assert load_ruleset(rules / "trial.yaml", root=rules).shadow is True
    assert normalize("velton-login.top") is not None
