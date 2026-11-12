"""The feed exports (§10.2, §11): what belongs in them, how they look, when a `304` comes."""

from __future__ import annotations

import csv
import io
import json

import pytest
from test_scoring_support import make_cert

from ctwatchtower import db
from ctwatchtower.app import create_app
from ctwatchtower.normalize.names import normalize

RULESET = """
tenant: {id: velton, name: Velton, tlp: amber}
thresholds: {persist: 25, info: 30, warning: 45, alert: 60, enrich_from: 50, feed_from: 60}
anchors:
  - terms: [velton]
    weight: 45
lures:
  - terms: [login, account]
    weight: 14
tlds:
  groups:
    - {name: hochriskant, weight: 25, list: [top, cfd]}
"""


@pytest.fixture
def app(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "velton.yaml").write_text(RULESET, encoding="utf-8")
    app = create_app(db_path=tmp_path / "f.sqlite3", rules_dir=rules, start_pipeline=False)
    # Without a running pipeline nobody creates the tenant row that `findings` points at.
    db.sync_tenants(app.config["DB"], app.config["RULES"].rulesets)
    yield app
    app.config["DB"].close()


def seed(app, domain: str, score: int, severity: str, status: str = "new", **fields) -> str:
    conn = app.config["DB"]
    fid, _ = db.upsert_finding(
        conn, "velton", normalize(domain), make_cert(domain),
        score=score, severity=severity,
        explanation={"matched": ["anchor:velton", "lure:login"]},
    )
    if status != "new" or fields:
        sets = ", ".join(f"{k}=?" for k in ("status", *fields))
        conn.execute(f"UPDATE findings SET {sets} WHERE id=?", (status, *fields.values(), fid))
    conn.commit()
    return fid


def test_only_what_reaches_the_feed_threshold_and_was_not_discarded(app) -> None:
    seed(app, "velton-login.top", 95, "alert")  # in
    seed(app, "velton-account.cfd", 70, "alert")  # in
    seed(app, "velton-weak.com", 40, "info")  # below feed_from 60
    seed(app, "velton-fp.top", 90, "alert", status="false_positive")
    seed(app, "velton-gone.top", 90, "alert", status="suppressed")

    body = app.test_client().get("/feed/velton/domains.txt").get_data(as_text=True)
    assert sorted(body.split()) == ["velton-account.cfd", "velton-login.top"]


def test_the_blocklist_names_the_watched_name_not_the_provider(app) -> None:
    """A blocklist must never contain a provider's apex.

    `velton-kunde.zendesk.com` is a suspicion against the tenant of a subdomain.
    If `zendesk.com` stood in the file for it, the first resolver to read it would
    block out the whole provider. That is not protection, that is an outage.
    """
    seed(app, "velton-kunde.zendesk.com", 95, "alert")
    seed(app, "velton-login.top", 95, "alert")

    names = app.test_client().get("/feed/velton/domains.txt").get_data(as_text=True).split()
    assert "zendesk.com" not in names
    assert sorted(names) == ["velton-kunde.zendesk.com", "velton-login.top"]


def test_the_csv_has_a_bom_a_header_line_and_pipe_separated_lists(app) -> None:
    seed(app, "velton-login.top", 95, "alert",
         nameservers='["ns1.example.net", "ns2.example.net"]', registrar="Example Registrar")
    raw = app.test_client().get("/feed/velton/indicators.csv").get_data()
    assert raw.startswith(b"\xef\xbb\xbf"), "Excel needs the BOM (§11.1)"
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert list(rows[0]) == list(__import__("ctwatchtower.export", fromlist=["x"]).CSV_COLUMNS)
    assert rows[0]["domain"] == "velton-login.top"
    assert rows[0]["matched_rules"] == "anchor:velton|lure:login", "a pipe, not a comma"
    assert rows[0]["nameservers"] == "ns1.example.net|ns2.example.net"


def test_the_json_carries_a_header_and_a_reason_per_indicator(app) -> None:
    seed(app, "velton-login.top", 95, "alert")
    doc = app.test_client().get("/feed/velton/indicators.json").get_json()
    assert doc["feed"]["name"] == "ct-watchtower/velton"
    assert doc["feed"]["tlp"] == "amber" and doc["feed"]["count"] == 1
    ind = doc["indicators"][0]
    # Without a reason the feed would be a bare verdict (§16.3, §16.5).
    assert ind["matched_rules"] == ["anchor:velton", "lure:login"]
    assert ind["confidence"] == ind["score"] == 95
    assert ind["valid_until"] > ind["first_seen"]
    assert ind["references"]["crtsh"].endswith("velton-login.top")


def test_the_jsonl_is_one_line_per_finding(app) -> None:
    seed(app, "velton-login.top", 95, "alert")
    seed(app, "velton-account.cfd", 70, "alert")
    text = app.test_client().get("/feed/velton/indicators.jsonl").get_data(as_text=True)
    rows = [json.loads(z) for z in text.strip().splitlines()]
    assert len(rows) == 2 and {z["type"] for z in rows} == {"domain"}


def test_since_serves_only_the_delta(app) -> None:
    seed(app, "velton-old.top", 95, "alert")
    app.config["DB"].execute("UPDATE findings SET last_seen='2020-01-01T00:00:00+00:00'")
    seed(app, "velton-new.top", 95, "alert")
    app.config["DB"].commit()
    body = app.test_client().get("/feed/velton/domains.txt?since=2021-01-01T00:00:00+00:00")
    assert body.get_data(as_text=True).split() == ["velton-new.top"]


def test_the_etag_answers_the_second_fetch_with_a_304(app) -> None:
    seed(app, "velton-login.top", 95, "alert")
    client = app.test_client()
    first = client.get("/feed/velton/indicators.json")
    assert first.status_code == 200 and first.headers["ETag"]
    assert first.headers["X-Feed-Count"] == "1" and first.headers["Last-Modified"]

    again = client.get("/feed/velton/indicators.json",
                        headers={"If-None-Match": first.headers["ETag"]})
    assert again.status_code == 304 and not again.get_data()

    seed(app, "velton-account.cfd", 70, "alert")  # the data changes
    after = client.get("/feed/velton/indicators.json",
                        headers={"If-None-Match": first.headers["ETag"]})
    assert after.status_code == 200 and after.headers["ETag"] != first.headers["ETag"]


def test_an_unknown_tenant_gives_a_404(app) -> None:
    assert app.test_client().get("/feed/does-not-exist/domains.txt").status_code == 404


def test_feeds_demand_the_same_token_as_the_api(app, monkeypatch) -> None:
    seed(app, "velton-login.top", 95, "alert")
    monkeypatch.setitem(app.config, "API_TOKEN", "secret")
    client = app.test_client()
    assert client.get("/feed/velton/domains.txt").status_code == 401
    ok = client.get("/feed/velton/domains.txt", headers={"Authorization": "Bearer secret"})
    assert ok.status_code == 200
