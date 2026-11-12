"""Rescoring older findings: what it touches and what it leaves alone."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest
from conftest import copy_rule_base

from ctwatchtower import db
from ctwatchtower.normalize.names import CertContext, normalize
from ctwatchtower.rules.loader import load_ruleset
from ctwatchtower.scoring.engine import score_candidate

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

RULESET = """
tenant: {id: velton, name: Velton}
anchors:
  - terms: [velton]
    weight: 45
lures:
  - terms: [login]
    weight: 20
"""


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    module = importlib.import_module("rescore")
    yield importlib.reload(module)
    sys.modules.pop("rescore", None)


@pytest.fixture
def world(tmp_path):
    """A ruleset, a database and three findings with deliberately wrong values."""
    rules = copy_rule_base(tmp_path / "rules")
    (rules / "velton.yaml").write_text(RULESET, encoding="utf-8")
    rs = load_ruleset(rules / "velton.yaml", root=rules)

    conn = db.connect(tmp_path / "ctw.sqlite3")
    db.sync_tenants(conn, [rs])

    def add(domain: str, score: int, severity: str, status: str = "new") -> str:
        cand = normalize(domain)
        cert = CertContext(
            log_id="t", idx=1, seen_at=db.datetime.now(db.UTC), not_before=None,
            not_after=None, issuer_cn="", issuer_o="Let's Encrypt", serial="",
            sha256=f"{abs(hash(domain)):064x}"[:64], is_precert=False, names=[domain],
        )
        fid, _ = db.upsert_finding(
            conn, "velton", cand, cert, score=score, severity=severity,
            explanation={"stale": True},
        )
        conn.execute("UPDATE findings SET status=? WHERE id=?", (status, fid))
        conn.commit()
        return fid

    return rs, conn, add


def test_a_dry_run_changes_nothing(tool, world):
    rs, conn, add = world
    fid = add("velton-login.top", 99, "alert")
    tool.rescore(conn, rs, write=False)
    row = conn.execute("SELECT score, explanation FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["score"] == 99
    assert json.loads(row["explanation"]) == {"stale": True}


def test_writing_puts_score_and_explanation_on_todays_state(tool, world):
    rs, conn, add = world
    fid = add("velton-login.top", 99, "alert")
    expected = score_candidate(rs, normalize("velton-login.top"))

    tool.rescore(conn, rs, write=True)
    row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    assert row["score"] == expected.score != 99
    assert row["severity"] == expected.severity
    # The explanation has to match the score, otherwise the panel shows contributions
    # that do not add up to the number next to them.
    assert sum(c["pts"] for c in json.loads(row["explanation"])["contributions"]) > 0


def test_what_falls_below_the_threshold_disappears(tool, world):
    rs, conn, add = world
    fid = add("completely-benign.de", 80, "alert")
    tool.rescore(conn, rs, write=True)
    assert conn.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone() is None


@pytest.mark.parametrize("status", ["confirmed", "reported"])
def test_judged_findings_stay_even_below_the_threshold(tool, world, status):
    """A judgement made by hand does not get overwritten by a rule change."""
    rs, conn, add = world
    fid = add("completely-benign.de", 80, "alert", status=status)
    tool.rescore(conn, rs, write=True)
    row = conn.execute("SELECT score, status FROM findings WHERE id=?", (fid,)).fetchone()
    assert row is not None and row["status"] == status
    assert row["score"] == 80, "the old value stays as long as the finding holds"


def test_the_enrichment_result_is_dropped(tool, world):
    """`score_enriched` belonged to the old scoring; leaving it would mean showing two
    numbers from different times next to each other."""
    rs, conn, add = world
    # Once with and once without a change to the score, both paths have to clear it.
    fitting = score_candidate(rs, normalize("velton-login.top"))
    for domain, score in (("velton-login.top", 99), ("velton-login.top", fitting.score)):
        conn.execute("DELETE FROM findings")
        conn.commit()
        fid = add(domain, score, fitting.severity or "info")
        conn.execute(
            "UPDATE findings SET score_enriched=12, enrich_note='old', registrar='Example'"
            " WHERE id=?",
            (fid,),
        )
        conn.commit()
        tool.rescore(conn, rs, write=True)
        row = conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        assert row["score_enriched"] is None and row["enrich_note"] is None
        # The enrichment itself cost queries and stays.
        assert row["registrar"] == "Example"


def test_sibling_names_from_the_certificate_count(tool, world):
    """A certificate often carries several names. The row holds the strongest score
    while `domain` holds the name seen first. Scoring only that one would talk such
    findings down."""
    rs, conn, add = world
    fid = add("velton.de", 10, "info")
    conn.execute(
        "UPDATE findings SET related_names=? WHERE id=?",
        ('["login.velton.de", "mail.velton.de"]', fid),
    )
    conn.commit()

    domain_only = score_candidate(rs, normalize("velton.de"))
    with_lure = score_candidate(rs, normalize("login.velton.de"))
    assert with_lure.score > domain_only.score, "the test setup does not hold"

    tool.rescore(conn, rs, write=True)
    assert conn.execute("SELECT score FROM findings WHERE id=?", (fid,)).fetchone()[0] == (
        with_lure.score
    )
