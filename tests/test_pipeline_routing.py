"""The pipeline: stage 2 only for the tenants that matched (§4.2), one candidate per certificate."""

from datetime import UTC, datetime

from ctwatchtower import db
from ctwatchtower.normalize.names import CertContext
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RuleStore

RULESET = """
apiVersion: ctwatchtower/v2
kind: RuleSet
tenant: {{ id: {id}, name: {id} }}
anchors:
  - terms: [{term}]
    weight: 60
    match: {{ exact: true }}
"""


def _cert(*names: str) -> CertContext:
    now = datetime.now(UTC)
    return CertContext("log", 1, now, None, None, "", "", "", "".join(names), False, list(names))


def _pipeline(tmp_path) -> Pipeline:
    rules = tmp_path / "rules"
    rules.mkdir()
    for tid, term in (("fin", "velton"), ("shop", "quorix")):
        (rules / f"{tid}.yaml").write_text(RULESET.format(id=tid, term=term), encoding="utf-8")
    return Pipeline(db.connect(tmp_path / "p.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")


def test_only_tenants_whose_terms_hit_are_scored(tmp_path):
    pipe = _pipeline(tmp_path)
    events = pipe.process(_cert("velton-login.top"))
    assert [e["tenant"] for e in events] == ["fin"]
    assert pipe.counters["score"] == 1  # "shop" was never scored at all
    assert pipe.prefilter().tenants_for(["quorix"]) == {"shop"}


def test_wildcard_and_apex_count_as_one_certificate(tmp_path):
    pipe = _pipeline(tmp_path)
    pipe.process(_cert("*.velton-login.top", "velton-login.top"))
    rows = pipe.conn.execute("SELECT cert_count FROM findings").fetchall()
    assert [r[0] for r in rows] == [1]
