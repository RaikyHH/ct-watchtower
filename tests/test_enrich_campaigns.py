"""Campaign clustering (§17.1, addendum §4). All the way into the API and the campaign cards."""

from __future__ import annotations

import json

import pytest
from test_enrich_worker import DNS, RULESET, YOUNG, Dns, Registry, drain
from test_scoring_support import make_cert

from ctwatchtower.app import create_app
from ctwatchtower.config import settings
from ctwatchtower.enrich.campaigns import cluster
from ctwatchtower.enrich.worker import Enricher


class PerDomain(Registry):
    """A registry fake with an answer of its own per registrable domain."""

    def __init__(self, answers: dict[str, dict]) -> None:
        super().__init__()
        self.answers = answers

    def lookup(self, registrable: str) -> dict:
        return dict(self.answers.get(registrable, {}))


class PerName(Dns):
    def __init__(self, answers: dict[str, dict]) -> None:
        super().__init__()
        self.answers = answers

    def resolve(self, name: str) -> dict:
        return dict(self.answers.get(name, DNS))


@pytest.fixture(autouse=True)
def _enrichment_on(monkeypatch):
    """Campaigns bundle by enriched details, so the switch has to be on. Set here
    instead of left to the environment, so the CI sees what the developer sees."""
    monkeypatch.setattr(settings, "enrich_enabled", True)


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "api_token", None)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    app = create_app(db_path=tmp_path / "c.sqlite3", rules_dir=rules, start_pipeline=False)
    yield app
    app.config["DB"].close()


OTHER = {"registrar": "Other Registrar", "created": YOUNG["created"], "nameservers": ["ns.other.example"]}
FAR_DNS = dict(DNS, a=["198.51.100.7"])


def enrich(app, hosts: list[str], registry=None, dns=None):
    pipe = app.config["PIPELINE"]
    pipe.enricher = Enricher(pipe, registration=registry or Registry(YOUNG), resolver=dns or Dns(DNS))
    for host in hosts:
        pipe.process(make_cert([host]))
    # Enrichment happens only on an explicit request per finding (§16). So campaigns
    # always come about out of findings somebody requested by hand.
    for row in pipe.conn.execute("SELECT id FROM findings").fetchall():
        pipe.request_enrichment(row["id"])
    drain(pipe)
    return pipe


def campaign_ids(pipe) -> dict[str, str | None]:
    return {
        r["domain"]: r["campaign_id"] for r in pipe.conn.execute("SELECT domain, campaign_id FROM findings")
    }


def test_shared_registrar_nameservers_and_net_form_one_stable_campaign(app) -> None:
    registry = PerDomain({"velton-login.com": YOUNG, "velton-login.net": YOUNG, "velton-secure.org": OTHER})
    dns = PerName({"velton-secure.org": FAR_DNS})
    pipe = enrich(app, ["velton-login.com", "velton-login.net", "velton-secure.org"], registry, dns)

    assert pipe.run_campaigns() == 1
    ids = campaign_ids(pipe)
    assert ids["velton-login.com"] == ids["velton-login.net"] is not None
    assert ids["velton-secure.org"] is None  # a cluster size of 1: no campaign_id
    row = pipe.conn.execute("SELECT * FROM campaigns").fetchone()
    assert row["cluster_key"] == "namesilo, llc / dns1.harmonweb.net,dns2.harmonweb.net / 216.198.79.0/24"

    # A restart computes afresh. The campaign keeps its row and its "active since".
    pipe.conn.execute("UPDATE campaigns SET first_seen='2026-01-01T00:00:00+00:00'")
    pipe.run_campaigns()
    again = pipe.conn.execute("SELECT id, first_seen FROM campaigns").fetchall()
    assert [(r["id"], r["first_seen"]) for r in again] == [(row["id"], "2026-01-01T00:00:00+00:00")]


def test_bridging_finding_merges_clusters_and_keeps_the_oldest_campaign(app) -> None:
    # a/b and c/d: the same registrar and the same nameservers, but different /24 networks.
    other_net = PerName(
        {"velton-c.com": dict(DNS, a=["198.51.100.7"]), "velton-d.com": dict(DNS, a=["198.51.100.8"])}
    )
    pipe = enrich(app, ["velton-a.com", "velton-b.com", "velton-c.com", "velton-d.com"], dns=other_net)
    assert pipe.run_campaigns() == 2
    old = campaign_ids(pipe)["velton-a.com"]
    pipe.conn.execute("UPDATE campaigns SET first_seen='2020-01-01T00:00:00+00:00' WHERE id=?", (old,))

    # e lies in both networks and joins the two clusters into one.
    other_net.answers["velton-e.com"] = dict(DNS, a=["216.198.79.9", "198.51.100.9"])
    enrich(app, ["velton-e.com"], dns=other_net)
    assert pipe.run_campaigns() == 1
    assert set(campaign_ids(pipe).values()) == {old}
    rows = pipe.conn.execute("SELECT id, first_seen FROM campaigns").fetchall()
    assert [(r["id"], r["first_seen"]) for r in rows] == [(old, "2020-01-01T00:00:00+00:00")]


def test_false_positives_suppressed_and_unenriched_findings_do_not_cluster(app) -> None:
    pipe = enrich(app, ["velton-a.com", "velton-b.com"])
    assert pipe.run_campaigns() == 1
    pipe.conn.execute("UPDATE findings SET status='false_positive' WHERE domain='velton-a.com'")
    assert pipe.run_campaigns() == 0
    assert set(campaign_ids(pipe).values()) == {None}
    assert pipe.conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == 0  # leere Kampagne weg


def test_findings_without_any_feature_are_not_joined(app) -> None:
    empty = {"a": [], "aaaa": [], "ns": [], "mx": [], "cname": [], "txt": [], "nxdomain": True}
    pipe = enrich(app, ["velton-a.com", "velton-b.com"], Registry({}), Dns(empty))
    assert pipe.run_campaigns() == 0
    pipe.conn.execute("UPDATE findings SET a_records=? ", (json.dumps(["not-an-ip", "2001:db8::1"]),))
    assert cluster(pipe.conn) == 0


def test_campaign_api_and_cards_render_real_clusters(app) -> None:
    pipe = enrich(app, ["velton-login.com", "velton-login.net"])
    pipe.run_campaigns()
    client = app.test_client()
    body = client.get("/api/v1/campaigns?tenant=banking").get_json()
    assert body["total"] == 1 and body["items"][0]["size"] == 2
    assert body["items"][0]["registrar"] == "NameSilo, LLC"
    # The findings' score, not the enriched one: campaigns bundle what stands in the
    # list. The value raised by phase 2 used to stand here.
    hoechster = max(r["score"] for r in app.config["DB"].execute("SELECT score FROM findings"))
    assert body["items"][0]["max_score"] == hoechster
    html = client.get("/ui/campaigns?t=banking").get_data(as_text=True)
    assert "NameSilo, LLC" in html and "2 findings" in html and "velton-login" in html
