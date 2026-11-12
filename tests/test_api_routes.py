"""Test client coverage for every route: the happy path plus the error case that
checks the validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import copy_rule_base
from ruamel.yaml import YAML

from ctwatchtower.app import create_app
from ctwatchtower.config import settings
from ctwatchtower.normalize.names import CertContext

REPO_RULES = Path(__file__).resolve().parents[1] / "rules"

ANCHORS = {
    "anchors": [
        {
            "terms": ["velton"],
            "weight": 45,
            "match": {"exact": True, "homoglyph": True},
        }
    ]
}


def cert(*names: str) -> CertContext:
    return CertContext(
        log_id="oak2026h1",
        idx=42,
        seen_at=datetime.now(UTC),
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC),
        issuer_cn="R11",
        issuer_o="Let's Encrypt",
        serial="01",
        sha256="".join(names)[:16].ljust(64, "0"),
        is_precert=False,
        names=list(names),
    )


@pytest.fixture
def app(tmp_path, monkeypatch):
    # `settings` is an import singleton: an API_TOKEN out of the developer's
    # environment or .env must not lock the suite out.
    monkeypatch.setattr(settings, "api_token", None)
    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(
        db_path=tmp_path / "t.sqlite3",
        rules_dir=rules,
        start_pipeline=False,
    )
    app.config["SSE_KEEPALIVE"] = 0.1
    yield app
    app.config["DB"].close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def tenant(client):
    """A tenant that has been created, with an anchor that really does fire."""
    assert client.post("/api/v1/tenants", json={"id": "velton", "name": "Velton"}).status_code == 201
    assert client.patch("/api/v1/tenants/velton/rules", json=ANCHORS).status_code == 200
    return "velton"


@pytest.fixture
def finding(app, client, tenant):
    pipeline = app.config["PIPELINE"]
    pipeline.rulesets(force=True)
    events = pipeline.process(cert("velton-login.top", "www.velton-login.top"))
    assert events, "the test anchor has to produce a finding"
    return events[0]


# ─────────────────────────── The scaffolding ──────────────────────────


def test_healthz(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_status(client, tenant):
    body = client.get("/api/v1/status").get_json()
    assert body["tenants"] == 1
    assert body["findings"] == 0
    assert body["ingest_connected"] is False


def test_bearer_token_required(app, client, tenant):
    app.config["API_TOKEN"] = "secret"
    assert client.get("/api/v1/status").status_code == 401
    ok = client.get("/api/v1/status", headers={"Authorization": "Bearer secret"})
    assert ok.status_code == 200
    assert client.get("/healthz").status_code == 200  # liveness stays open


# ────────────────────────── Mandanten ─────────────────────────


def test_tenants_list_hides_template_and_examples(client, tenant):
    items = client.get("/api/v1/tenants").get_json()["items"]
    assert [t["id"] for t in items] == ["velton"]
    assert items[0]["anchors"] == 1


def test_create_tenant_rejects_bad_id(client):
    for bad in ("../etc/passwd", "Velton", "mit_unterstrich", ""):
        assert client.post("/api/v1/tenants", json={"id": bad}).status_code == 400


def test_create_tenant_never_overwrites(client, tenant):
    resp = client.post("/api/v1/tenants", json={"id": "velton", "name": "Zweiter"})
    assert resp.status_code == 409


def test_api_token_comes_from_settings(tmp_path, monkeypatch):
    # The singleton is built at import time. The test environment sets the field
    # directly, and create_app reads it when it is called.
    monkeypatch.setattr(settings, "api_token", "from-settings")
    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        client = app.test_client()
        assert client.get("/api/v1/status").status_code == 401
        ok = client.get("/api/v1/status", headers={"Authorization": "Bearer from-settings"})
        assert ok.status_code == 200
    finally:
        app.config["DB"].close()


def test_delete_tenant_without_findings(client, tenant, app):
    assert client.delete("/api/v1/tenants/velton").status_code == 204
    assert not (Path(app.config["RULES_DIR"]) / "velton.yaml").exists()
    assert client.delete("/api/v1/tenants/velton").status_code == 404


def test_delete_tenant_with_findings_needs_force(client, finding, app):
    path = Path(app.config["RULES_DIR"]) / "velton.yaml"
    resp = client.delete("/api/v1/tenants/velton")
    assert resp.status_code == 409
    body = resp.get_json()
    assert set(body) == {"error", "findings"} and body["findings"] == 1
    assert path.exists()
    assert client.get(f"/api/v1/findings/{finding['id']}").status_code == 200
    # only the exact tenant id confirms it. A flag or a typo does not
    assert client.delete("/api/v1/tenants/velton?force=true").status_code == 409
    assert client.delete("/api/v1/tenants/velton?confirm=velto").status_code == 409


def test_delete_tenant_with_typed_confirmation_removes_findings(client, finding, app):
    assert client.delete("/api/v1/tenants/velton?confirm=velton").status_code == 204
    assert not (Path(app.config["RULES_DIR"]) / "velton.yaml").exists()
    assert client.get(f"/api/v1/findings/{finding['id']}").status_code == 404


# ──────────────────────────── The rules ───────────────────────────────


def test_get_rules(client, tenant):
    body = client.get("/api/v1/tenants/velton/rules").get_json()
    assert body["tenant"]["id"] == "velton"
    assert body["thresholds"]["persist"] == 17   # points, not per cent
    assert body["anchors"][0]["terms"] == ["velton"]


def test_get_rules_unknown_tenant(client):
    assert client.get("/api/v1/tenants/gibtsnicht/rules").status_code == 404


def test_patch_rules_writes_yaml_and_keeps_comments(client, tenant, app):
    resp = client.patch(
        "/api/v1/tenants/velton/rules", json={"thresholds": {"persist": 20}}
    )
    assert resp.status_code == 200
    assert resp.get_json()["rules"]["thresholds"]["persist"] == 20
    text = (Path(app.config["RULES_DIR"]) / "velton.yaml").read_text(encoding="utf-8")
    assert "persist: 20" in text
    assert "# The base for a new tenant" in text  # the round trip kept the comment


def test_patch_rules_replaces_lists(client, tenant):
    resp = client.patch("/api/v1/tenants/velton/rules", json={"anchors": []})
    assert resp.get_json()["rules"]["anchors"] == []


def test_patch_rules_invalid_is_rejected_and_file_unchanged(client, tenant, app):
    path = Path(app.config["RULES_DIR"]) / "velton.yaml"
    before = path.read_text(encoding="utf-8")
    resp = client.patch("/api/v1/tenants/velton/rules", json={"scoring": {"top_n": -5}})
    assert resp.status_code == 422
    assert path.read_text(encoding="utf-8") == before


def test_rule_file_owned_by_someone_else_is_still_saveable(client, tenant, app, monkeypatch):
    """In the volume a rule file was owned by `root`, and every save failed.
    So it is written beside it and renamed: that needs rights on the directory,
    not on the file."""
    echt = Path.write_text

    def verweigert(self, *args, **kwargs):
        if self.name == "velton.yaml":  # the target file itself is locked
            raise PermissionError(13, "Permission denied")
        return echt(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", verweigert)
    resp = client.patch("/api/v1/tenants/velton/rules", json={"scoring": {"top_n": 5}})
    assert resp.status_code == 200
    path = Path(app.config["RULES_DIR"]) / "velton.yaml"
    assert YAML(typ="safe").load(path.read_text(encoding="utf-8"))["scoring"]["top_n"] == 5


def test_unwritable_rules_directory_explains_itself(client, tenant, monkeypatch):
    """A bare "HTTP 500" sends the user looking for a rule error that does not
    exist."""

    def verweigert(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr("ctwatchtower.api.routes.os.replace", verweigert)
    resp = client.patch("/api/v1/tenants/velton/rules", json={"scoring": {"top_n": 5}})
    assert resp.status_code == 422
    assert "not writable" in resp.get_json()["error"]


def test_put_rules(client, tenant):
    resp = client.put(
        "/api/v1/tenants/velton/rules",
        json={"tenant": {"id": "velton", "name": "Velton AG"}, "anchors": ANCHORS["anchors"]},
    )
    assert resp.status_code == 200
    assert resp.get_json()["rules"]["tenant"]["name"] == "Velton AG"
    assert "yaml" in resp.get_json()


def test_put_rules_requires_object(client, tenant):
    assert client.put("/api/v1/tenants/velton/rules", json=["nope"]).status_code == 400


def test_validate_rules(client, tenant, app):
    path = Path(app.config["RULES_DIR"]) / "velton.yaml"
    before = path.read_text(encoding="utf-8")
    ok = client.post("/api/v1/tenants/velton/rules/validate", json={"thresholds": {"alert": 90}})
    assert ok.get_json()["valid"] is True
    bad = client.post("/api/v1/tenants/velton/rules/validate", json={"thresholds": {"alert": "hoch"}})
    assert bad.get_json()["valid"] is False
    assert "error" in bad.get_json()
    assert path.read_text(encoding="utf-8") == before  # nichts gespeichert


# ─────────────────────────── Findings ─────────────────────────


def test_pipeline_creates_finding(finding):
    assert finding["tenant"] == "velton"
    assert finding["domain"] == "velton-login.top"
    assert finding["score"] >= 35
    assert finding["severity"] in ("info", "warning", "alert")


def test_findings_list_and_filters(client, finding):
    items = client.get("/api/v1/findings").get_json()["items"]
    assert len(items) >= 1
    assert isinstance(items[0]["explanation"], dict)
    assert client.get("/api/v1/findings?tenant=velton&min_score=1").get_json()["items"]
    assert client.get("/api/v1/findings?tenant=andere").get_json()["items"] == []
    assert client.get("/api/v1/findings?q=velton").get_json()["items"]
    assert client.get("/api/v1/findings?max_score=0").get_json()["items"] == []
    assert client.get("/api/v1/findings?tld=top").get_json()["items"]
    assert client.get("/api/v1/findings?status=new").get_json()["items"]
    assert client.get("/api/v1/findings?since=2099-01-01").get_json()["items"] == []
    assert client.get("/api/v1/findings?until=2099-01-01").get_json()["items"]


def test_findings_cursor_pagination(app, client, tenant):
    pipeline = app.config["PIPELINE"]
    pipeline.rulesets(force=True)
    for n in range(3):
        pipeline.process(cert(f"velton-login{n}.top"))

    first = client.get("/api/v1/findings?limit=2").get_json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = client.get(f"/api/v1/findings?limit=2&cursor={first['next_cursor']}").get_json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    seen = {f["id"] for f in first["items"] + second["items"]}
    assert len(seen) == 3


def test_findings_rejects_unknown_sort_and_cursor(client):
    assert client.get("/api/v1/findings?sort=domain").status_code == 400
    assert client.get("/api/v1/findings?limit=viele").status_code == 400
    assert client.get("/api/v1/findings?cursor=broken.").status_code == 400


def test_finding_detail(client, finding):
    assert client.get(f"/api/v1/findings/{finding['id']}").get_json()["id"] == finding["id"]
    assert client.get("/api/v1/findings/gibtsnicht").status_code == 404


def test_patch_finding_status(client, finding):
    body = client.patch(
        f"/api/v1/findings/{finding['id']}", json={"status": "confirmed", "note": "checked"}
    ).get_json()
    assert body["status"] == "confirmed" and body["status_note"] == "checked"
    assert client.patch(f"/api/v1/findings/{finding['id']}", json={"status": "huh"}).status_code == 400
    assert client.patch(f"/api/v1/findings/{finding['id']}", json={}).status_code == 400
    assert client.patch("/api/v1/findings/gibtsnicht", json={"status": "new"}).status_code == 404


# ───────────────────── Kampagnen, Statistik ───────────────────


def test_campaigns(app, client, tenant):
    conn = app.config["DB"]
    conn.execute(
        "INSERT INTO campaigns (id, tenant_id, cluster_key, first_seen, last_seen)"
        " VALUES ('c1','velton','registrar:acme','2026-09-01','2026-09-02')"
    )
    conn.commit()
    body = client.get("/api/v1/campaigns?sort=largest&limit=8&offset=0").get_json()
    assert body["total"] == 1 and body["items"][0]["id"] == "c1"
    assert client.get("/api/v1/campaigns?sort=alphabetisch").status_code == 400


def test_stats_daily(app, client, tenant, finding):
    """The counting happens in `findings`, not in `daily_stats`: nobody writes that
    table, which is why the route served an empty list for years."""
    heute = datetime.now(UTC).strftime("%Y-%m-%d")
    entry = client.get("/api/v1/stats/daily?tenant=velton").get_json()["items"][-1]
    assert entry["day"] == heute
    assert entry["findings_total"] >= 1
    assert entry["findings_info"] + entry["findings_warn"] + entry["findings_alert"] == (
        entry["findings_total"]
    )
    # Another tenant does not see the numbers.
    assert client.get("/api/v1/stats/daily?tenant=fremd").get_json()["items"] == []
    assert client.get("/api/v1/stats/daily?days=x").status_code == 400


# ──────────────────────────── Lookup ──────────────────────────


def test_lookup_uses_the_pipeline_scorer(client, tenant):
    body = client.post("/api/v1/lookup", json={"domain": "velton-login.top", "tenant": "velton"})
    result = body.get_json()["result"]
    assert result["score"] > 0
    assert result["anchor_hit"] is True
    assert any(c["rule"].startswith("anchor:") for c in result["contributions"])


def test_lookup_with_unsaved_ruleset(client, tenant):
    rules = client.get("/api/v1/tenants/velton/rules").get_json()
    rules["thresholds"]["persist"] = 1
    body = client.post("/api/v1/lookup", json={"domain": "velton-login.top", "rules": rules})
    assert body.get_json()["result"]["severity"] is not None


def test_lookup_validation(client, tenant):
    assert client.post("/api/v1/lookup", json={}).status_code == 400
    assert client.post("/api/v1/lookup", json={"domain": "10.0.0.1"}).status_code == 400
    assert client.post("/api/v1/lookup", json={"domain": "x.de", "tenant": "weg"}).status_code == 404
    bad = client.post("/api/v1/lookup", json={"domain": "x.de", "rules": {"tenant": {}}})
    assert bad.status_code == 422


# ──────────────────────────── System ──────────────────────────


def test_system_metrics(client, tenant):
    body = client.get("/api/v1/system/metrics").get_json()
    assert [n["id"] for n in body["nodes"]] == ["ingest", "normalize", "prefilter", "score", "enrich"]
    assert set(body) >= {"certs_per_sec", "queue_depth_pct", "active_enrichments", "cache_hit_ratio"}
    assert body["ct_logs"][0]["state"] == "disconnected"


def test_queue_history_is_a_ring_buffer(app, client):
    pipeline = app.config["PIPELINE"]
    for n in range(70):
        pipeline.queue_history.append({"t": str(n), "depth_pct": n})
    body = client.get("/api/v1/system/queue-history").get_json()
    assert body["capacity"] == 60 and len(body["items"]) == 60
    assert body["items"][0]["t"] == "10"


# ───────────────────────────── SSE ────────────────────────────


def test_stream_pushes_findings_and_filters(app, client, tenant):
    resp = client.get("/api/v1/stream?tenant=velton&min_score=10")
    chunks = iter(resp.response)
    assert next(chunks) == b": connected\n\n"

    broker = app.config["PIPELINE"].broker
    assert broker.subscribers == 1
    broker.publish({"id": "a", "tenant": "other", "score": 99})  # the wrong tenant
    broker.publish({"id": "b", "tenant": "velton", "score": 5})  # unter min_score
    broker.publish({"id": "c", "tenant": "velton", "score": 80})

    payload = next(chunks).decode()  # the two filtered ones do not get through at all
    assert payload.startswith("id: c\nevent: finding\n")
    assert json.loads(payload.split("data: ", 1)[1])["score"] == 80

    resp.close()
    assert broker.subscribers == 0  # the subscriber queue was cleared away


def test_stream_sends_keepalive_comments(client):
    resp = client.get("/api/v1/stream")
    chunks = iter(resp.response)
    assert next(chunks) == b": connected\n\n"
    assert next(chunks) == b": keep-alive\n\n"
    assert resp.headers["X-Accel-Buffering"] == "no"
    assert resp.headers["Content-Type"].startswith("text/event-stream")
    resp.close()


def test_stream_rejects_bad_min_score(client):
    assert client.get("/api/v1/stream?min_score=hoch").status_code == 400


def test_app_starts_without_certstream_server(tmp_path):
    """The normal case while developing: no websocket server reachable."""
    rules = tmp_path / "rules"
    copy_rule_base(rules)
    app = create_app(
        db_path=tmp_path / "s.sqlite3",
        rules_dir=rules,
        certstream_url="ws://127.0.0.1:1/nichts-da",
    )
    try:
        assert app.test_client().get("/healthz").status_code == 200
        assert app.test_client().get("/api/v1/system/metrics").get_json()["nodes"]
    finally:
        app.config["PIPELINE"].stop()
        app.config["DB"].close()


def test_an_overlong_tenant_id_is_refused(client) -> None:
    # The id becomes the file name. Without an upper bound a typo creates a
    # 200-character file that no file system handles cleanly any more.
    r = client.post("/api/v1/tenants", json={"id": "x" * 65, "name": "X"})
    assert r.status_code == 400
    assert client.post("/api/v1/tenants", json={"id": "x" * 64, "name": "X"}).status_code == 201


def test_shipped_building_blocks_are_brought_along(tmp_path) -> None:
    """In the container the volume covers the image's version of `rules/`.

    Without a sync, an existing installation lacks every building block that came
    along after its first start. That is exactly what made loading a ruleset with
    `includes: [common/post_enrichment.yaml]` fail on 2026-09-22.
    """
    from ctwatchtower.app import sync_shipped_rules

    shipped_dir = tmp_path / "rules-shipped"
    (shipped_dir / "common").mkdir(parents=True)
    (shipped_dir / "common" / "new.yaml").write_text("lures: []\n", encoding="utf-8")
    (shipped_dir / "_template.yaml").write_text("tenant: {id: t, name: T}\n", encoding="utf-8")

    target = tmp_path / "rules"
    (target / "common").mkdir(parents=True)
    (target / "customer.yaml").write_text("# belongs to the user\n", encoding="utf-8")

    renewed = sync_shipped_rules(target, shipped=shipped_dir)

    assert (target / "common" / "new.yaml").is_file(), "neuer Baustein nachgezogen"
    assert (target / "_template.yaml").is_file(), "Vorlage nachgezogen"
    assert (target / "customer.yaml").read_text(encoding="utf-8") == "# belongs to the user\n"
    assert any(e.endswith("new.yaml") for e in renewed)
    assert sync_shipped_rules(target, shipped=shipped_dir) == [], "a second pass changes nothing"


def test_without_an_image_copy_nothing_happens(tmp_path) -> None:
    """Development without a container: `rules/` is the original itself."""
    from ctwatchtower.app import sync_shipped_rules

    assert sync_shipped_rules(tmp_path, shipped=tmp_path / "does-not-exist") == []


def test_parallel_validations_do_not_eat_each_others_temp_file(client, tenant):
    """The rules screen sets the check off on every key press. If two ran against
    the same temporary file, one read what the other was just deleting - and the
    browser showed "the explanation is unreachable"."""
    import threading

    ergebnisse: list[int] = []

    def validate() -> None:
        response = client.post(
            "/api/v1/tenants/velton/rules/validate", json={"scoring": {"top_n": 9}}
        )
        ergebnisse.append(response.status_code)

    faeden = [threading.Thread(target=validate) for _ in range(8)]
    for f in faeden:
        f.start()
    for f in faeden:
        f.join()
    assert ergebnisse == [200] * 8
