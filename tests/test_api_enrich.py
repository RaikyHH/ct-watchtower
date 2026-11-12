"""`POST /api/v1/findings/<id>/enrich`. The only way to RDAP, WHOIS and DoH (§10.1).

No test here touches the network: the enrichment thread is never started
(`start_pipeline=False`), and the request only puts an entry into the queue.
"""

from __future__ import annotations

import pytest
from conftest import copy_rule_base
from test_api_routes import ANCHORS, cert

from ctwatchtower.app import create_app
from ctwatchtower.config import settings
from ctwatchtower.enrich import worker


@pytest.fixture
def make_app(tmp_path, monkeypatch):
    """An app factory: `enrich_enabled` has to stand *before* `create_app`, since the
    pipeline decides in the constructor whether there is an enricher at all."""

    def build(*, enrich: bool):
        monkeypatch.setattr(settings, "api_token", None)
        monkeypatch.setattr(settings, "enrich_enabled", enrich)
        rules = tmp_path / "rules"
        if not rules.exists():
            copy_rule_base(rules)
        app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
        return app

    return build


@pytest.fixture
def setup(make_app):
    def build(*, enrich: bool = True):
        app = make_app(enrich=enrich)
        client = app.test_client()
        assert client.post("/api/v1/tenants", json={"id": "velton", "name": "Velton"}).status_code == 201
        assert client.patch("/api/v1/tenants/velton/rules", json=ANCHORS).status_code == 200
        pipeline = app.config["PIPELINE"]
        pipeline.rulesets(force=True)
        events = pipeline.process(cert("velton-login.top"))
        assert events, "the test anchor has to produce a finding"
        return app, client, events[0]["id"]

    return build


def test_unknown_finding_is_404(setup):
    _, client, _ = setup()
    res = client.post("/api/v1/findings/does-not-exist/enrich")
    assert res.status_code == 404
    assert res.get_json()["status"] == "unknown"
    assert res.get_json()["error"]


def test_queued_then_pending(setup):
    app, client, fid = setup()
    res = client.post(f"/api/v1/findings/{fid}/enrich")
    assert res.status_code == 202
    assert res.get_json() == {"status": "queued", "enrich_state": "pending"}
    assert app.config["PIPELINE"].enricher.queued == 1

    again = client.post(f"/api/v1/findings/{fid}/enrich")
    assert again.status_code == 200
    assert again.get_json() == {"status": "pending", "enrich_state": "pending"}
    assert app.config["PIPELINE"].enricher.queued == 1, "clicking twice does not queue it twice"


def test_freshly_enriched_is_not_requeued(setup):
    app, client, fid = setup()
    conn = app.config["DB"]
    conn.execute(
        "UPDATE findings SET enrich_state='done', enriched_at=datetime('now') WHERE id=?", (fid,)
    )
    conn.commit()
    res = client.post(f"/api/v1/findings/{fid}/enrich")
    assert res.status_code == 200
    assert res.get_json() == {"status": "done", "enrich_state": "done"}
    assert app.config["PIPELINE"].enricher.queued == 0


def test_disabled_when_enrichment_is_off(setup):
    app, client, fid = setup(enrich=False)
    # "Off" is the switch now, not a missing object: otherwise the enrichment could
    # not be switched on without a restart.
    assert app.config["PIPELINE"].enricher.queued == 0
    res = client.post(f"/api/v1/findings/{fid}/enrich")
    assert res.status_code == 200
    assert res.get_json() == {"status": "disabled", "enrich_state": "skipped"}


def test_quota_carries_the_counters_so_the_ui_can_say_when(setup, monkeypatch):
    app, client, fid = setup()
    monkeypatch.setattr(settings, "enrich_rdap_daily", 0)
    monkeypatch.setattr(settings, "enrich_doh_daily", 0)
    monkeypatch.setattr(settings, "enrich_whois_fallback", False)
    res = client.post(f"/api/v1/findings/{fid}/enrich")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] == "quota"
    assert body["enrich_state"] == "skipped"
    assert body["quota"] == app.config["PIPELINE"].metrics()["enrich_quota"]
    assert app.config["PIPELINE"].enricher.queued == 0


def test_busy_when_the_queue_is_full(setup, monkeypatch):
    app, client, fid = setup()
    monkeypatch.setattr(worker, "MAX_QUEUE", 0)
    res = client.post(f"/api/v1/findings/{fid}/enrich")
    assert res.status_code == 200
    assert res.get_json()["status"] == "busy"


ENRICH_FIELDS = (
    "registrar",
    "domain_created",
    "domain_expires",
    "epp_status",
    "nameservers",
    "a_records",
    "has_mx",
    "asn",
    "country",
    "enrich_state",
    "enriched_at",
    "escalated_at",
    "status_note",
    "domain_changed",
)


def test_detail_carries_every_enrichment_field(setup):
    _, client, fid = setup()
    body = client.get(f"/api/v1/findings/{fid}").get_json()
    assert ENRICH_FIELDS == tuple(f for f in ENRICH_FIELDS if f in body)
