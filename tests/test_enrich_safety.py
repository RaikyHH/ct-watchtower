"""Protecting other people's infrastructure (§16): off by
default, no call without a way to make contact, hard daily caps, automatic only from an alert upwards.

No test here touches the network: the transport is a fake, and where a real client
could come about, the missing contact detail prevents it already.
"""

from __future__ import annotations

import threading

import httpx
import pytest
from test_enrich_rdap import BOOT, VRSN, boot
from test_enrich_worker import RULESET
from test_scoring_support import make_cert

from ctwatchtower import db
from ctwatchtower.config import Settings, settings
from ctwatchtower.enrich.doh import Resolver
from ctwatchtower.enrich.net import Cache, Defer, Quota, client, daily_limits
from ctwatchtower.enrich.rdap import Registration
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RuleStore


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("echter Netzzugriff im Test")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    monkeypatch.setattr("socket.create_connection", refuse)


def pipeline(tmp_path) -> Pipeline:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    return Pipeline(db.connect(tmp_path / "s.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")


def node(pipe: Pipeline) -> str:
    return next(n for n in pipe.metrics()["nodes"] if n["id"] == "enrich")["state"]


# ─────────────────────────────── Standardwerte ───────────────────────────────


def test_defaults_touch_no_registry_and_no_resolver() -> None:
    fresh = Settings(_env_file=None)
    assert fresh.enrich_enabled is False
    assert fresh.enrich_whois_fallback is False
    assert fresh.ct_user_agent == "CT-Watchtower"
    assert (fresh.enrich_rdap_daily, fresh.enrich_rdap_daily_per_server) == (200, 50)
    assert (fresh.enrich_whois_daily, fresh.enrich_doh_daily) == (20, 2000)


def test_env_example_and_compose_keep_enrichment_off() -> None:
    from ctwatchtower.config import REPO_ROOT

    env = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nENRICH_ENABLED=false" in env and "\nENRICH_WHOIS_FALLBACK=false" in env
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "ENRICH_ENABLED: ${ENRICH_ENABLED:-false}" in compose
    assert "ENRICH_WHOIS_FALLBACK: ${ENRICH_WHOIS_FALLBACK:-false}" in compose
    assert "CT_USER_AGENT: ${CT_USER_AGENT:-CT-Watchtower}" in compose


def test_disabled_pipeline_runs_clean_and_reports_off(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_enabled", False)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-login.com"]))
    # The enricher always exists. Switching off happens at the switch, not at the
    # constructor, otherwise `enrich_enabled` would need a restart.
    row = pipe.conn.execute("SELECT id, enrich_state FROM findings").fetchone()
    assert pipe.request_enrichment(row["id"]) == "disabled" and node(pipe) == "off"
    assert pipe.enricher.queued == 0
    assert row["enrich_state"] == "skipped"
    assert pipe.metrics()["enrich_quota"] is None


# ───────────────────── A user agent without an identity ──────────────────


def test_user_agent_is_the_bare_product_name() -> None:
    """No email, no URL, no repository link. The user's decision."""
    agent = client("application/dns-json").headers["User-Agent"]
    assert agent == "CT-Watchtower"
    assert not any(zeichen in agent for zeichen in ("@", "http", "github", "+"))


# ──────────────────── Enrichment only on request ─────────────────────────


def test_pipeline_never_enriches_by_itself(tmp_path, monkeypatch) -> None:
    """Even with the enrichment switched on the pipeline queues nothing.

    Registries allow single queries, not automated mass queries (§16).
    """
    monkeypatch.setattr(settings, "enrich_enabled", True)
    pipe = pipeline(tmp_path)
    for domain in ("velton-login.com", "velton-security-login.top", "velton-account.cfd"):
        pipe.process(make_cert([domain]))
    rows = [dict(r) for r in pipe.conn.execute("SELECT domain, score, enrich_state FROM findings")]
    assert rows, "the test setup: there have to be findings"
    assert {r["enrich_state"] for r in rows} == {"skipped"}
    assert pipe.enricher.queued == 0


def test_request_is_the_only_way_in(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_enabled", True)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-security-login.top"]))
    fid = pipe.conn.execute("SELECT id FROM findings").fetchone()["id"]

    assert pipe.request_enrichment("does-not-exist") == "unknown"
    assert pipe.request_enrichment(fid) == "queued"
    assert pipe.enricher.queued == 1
    assert pipe.conn.execute("SELECT enrich_state FROM findings").fetchone()["enrich_state"] == "pending"
    assert pipe.request_enrichment(fid) == "pending", "clicking twice does not queue it twice"


def test_request_refuses_when_enrichment_is_off(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_enabled", False)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-security-login.top"]))
    fid = pipe.conn.execute("SELECT id FROM findings").fetchone()["id"]
    assert pipe.request_enrichment(fid) == "disabled"


def test_request_refuses_when_the_daily_limit_is_reached(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_enabled", True)
    monkeypatch.setattr(settings, "enrich_rdap_daily", 0)
    monkeypatch.setattr(settings, "enrich_doh_daily", 0)
    monkeypatch.setattr(settings, "enrich_whois_fallback", False)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-security-login.top"]))
    fid = pipe.conn.execute("SELECT id FROM findings").fetchone()["id"]
    assert pipe.request_enrichment(fid) == "quota"
    assert pipe.enricher.queued == 0


# ───────────────────────────── Tagesgrenzen ──────────────────────────────────


def test_daily_limits_defer_until_tomorrow_and_survive_a_restart(tmp_path, monkeypatch, caplog) -> None:
    monkeypatch.setattr(settings, "enrich_rdap_daily_per_server", 2)
    path = tmp_path / "q.sqlite3"
    quota = Quota(db.connect(path), threading.Lock())
    limits = daily_limits("rdap", "rdap.verisign.com")
    quota.take(limits)
    quota.take(limits)
    with pytest.raises(Defer) as exc:
        quota.take(limits)
    assert 0 < exc.value.wait <= 86_400
    with pytest.raises(Defer):
        quota.take(limits)
    assert caplog.text.count("daily cap rdap:rdap.verisign.com") == 1  # einmal geloggt
    quota.take(daily_limits("rdap", "rdap.nic.fr"))  # anderer Server: eigenes Kontingent

    restarted = Quota(db.connect(path), threading.Lock())  # neuer Prozess, neue Verbindung
    with pytest.raises(Defer):
        restarted.take(limits)
    status = restarted.status()
    assert status["counts"] == {"rdap": 3, "rdap:rdap.verisign.com": 2, "rdap:rdap.nic.fr": 1}
    assert status["exhausted"] == ["rdap:rdap.verisign.com"]


def test_exhausted_quota_means_no_request_at_all(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_rdap_daily", 1)
    monkeypatch.setattr(settings, "enrich_doh_daily", 0)
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return boot() if str(request.url) == BOOT else httpx.Response(404)

    conn = db.connect(":memory:")
    cache = Cache(conn, threading.Lock())
    reg = Registration(cache, http=httpx.Client(transport=httpx.MockTransport(handler)))
    assert reg.lookup("a.com") == {}
    reg.limits.buckets.clear()
    with pytest.raises(Defer):
        reg.lookup("b.com")
    assert urls == [BOOT, VRSN + "a.com"]  # b.com never went out

    dns = Resolver(cache, http=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(Defer):
        dns.resolve("a.com")
    assert len(urls) == 2


def test_whois_counts_against_its_own_small_limit(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_whois_fallback", True)
    monkeypatch.setattr(settings, "enrich_whois_daily", 1)
    asked: list[str] = []

    def whois(server: str, query: str) -> str:
        asked.append(server)
        return "whois:        whois.cnnic.cn\n"

    conn = db.connect(":memory:")
    reg = Registration(Cache(conn, threading.Lock()), whois=whois,
                       http=httpx.Client(transport=httpx.MockTransport(lambda r: boot())))
    with pytest.raises(Defer):
        reg.lookup("vendoraaws.com.cn")  # the IANA referral uses up the one query
    assert asked == ["whois.iana.org"]


def test_unknown_finding_is_unknown_even_when_enrichment_is_off(tmp_path, monkeypatch) -> None:
    """Reporting "off" about a finding that does not exist would be a false answer."""
    monkeypatch.setattr(settings, "enrich_enabled", False)
    pipe = pipeline(tmp_path)
    assert pipe.request_enrichment("does-not-exist") == "unknown"
    pipe.process(make_cert(["velton-security-login.top"]))
    fid = pipe.conn.execute("SELECT id FROM findings").fetchone()["id"]
    assert pipe.request_enrichment(fid) == "disabled"


def test_legacy_pending_rows_are_never_picked_up_after_a_restart(tmp_path, monkeypatch) -> None:
    """The incident of 2026-09-19: one container start set off 83 enrichments.

    Findings from the time of automatic enrichment stood at `pending`. `recover()`
    picked them up at the start. Queries nobody had asked for. A request has to be
    provable (`enrich_requested_at`); the state alone does not suffice.
    """
    monkeypatch.setattr(settings, "enrich_enabled", True)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-security-login.top"]))
    # Reconstruct the leftover: pending, but never requested
    pipe.conn.execute("UPDATE findings SET enrich_state='pending', enrich_requested_at=NULL")
    pipe.conn.commit()
    assert pipe.enricher.recover() == 0, "without a request nothing is picked up"

    # And the migration quietly settles such leftovers when the database is opened
    path = pipe.conn.execute("PRAGMA database_list").fetchone()["file"]
    pipe.conn.close()
    frisch = db.connect(path)
    state = frisch.execute("SELECT enrich_state FROM findings").fetchone()["enrich_state"]
    frisch.close()
    assert state == "skipped"


def test_a_real_request_survives_a_restart(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "enrich_enabled", True)
    pipe = pipeline(tmp_path)
    pipe.process(make_cert(["velton-security-login.top"]))
    fid = pipe.conn.execute("SELECT id FROM findings").fetchone()["id"]
    assert pipe.request_enrichment(fid) == "queued"
    assert pipe.conn.execute("SELECT enrich_requested_at FROM findings").fetchone()[0] is not None
    assert pipe.enricher.recover() == 1, "what was requested does get picked up"


# ─────────────────────── Ziele im eigenen Netz ───────────────────────


@pytest.mark.parametrize(
    "host", ["localhost", "127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1"]
)
def test_no_way_into_our_own_network(host: str) -> None:
    """RDAP servers redirect, and that means another party decides the target.

    If the redirect points at a cloud's metadata endpoint or into the internal
    network, the enrichment would be a tool for reaching behind the firewall from
    outside. The check happens at the connection, not at the URL.
    """
    from ctwatchtower.enrich.net import _is_public

    _is_public.cache_clear()
    assert _is_public(host) is False


def test_public_targets_stay_reachable() -> None:
    from ctwatchtower.enrich.net import _is_public

    _is_public.cache_clear()
    assert _is_public("8.8.8.8") is True
    # A name that does not exist: the connection fails by itself right away anyway.
    assert _is_public("surely-does-not-exist.invalid") is True


def test_the_transport_refuses_internal_targets() -> None:
    import httpx

    from ctwatchtower.enrich.net import BlockedTarget, PublicNetworkTransport

    transport = PublicNetworkTransport()
    with pytest.raises(BlockedTarget, match="public network"):
        transport.handle_request(httpx.Request("GET", "https://127.0.0.1/domain/x"))


def test_a_scan_counter_does_not_cripple_the_system_screen(tmp_path, monkeypatch) -> None:
    """A click on "start the analysis" must not drag the enrichment down with it.

    `Quota.status()` computes over *all* the stored counters. The analysis puts
    `scan:urlscan` there. As long as that key had no limit on record, `limit_of`
    threw a KeyError, and with that the system screen and every enrichment request
    served an HTTP 500 until the day was over.
    """
    from ctwatchtower.enrich.net import limit_of

    monkeypatch.setattr(settings, "scan_daily", 25)
    conn = db.connect(tmp_path / "q.sqlite3")
    try:
        quota = Quota(conn, threading.Lock())
        quota.take({"scan:urlscan": 25})
        state = quota.status()                      # must not throw
        assert state["counts"]["scan:urlscan"] == 1
        assert "scan:urlscan" not in state["exhausted"]
        assert limit_of("scan:urlscan") == 25

        # And a key nobody has provided for yet brings nothing down either.
        quota.take({"voellig:new": 1})
        assert quota.status()["counts"]["voellig:new"] == 1
    finally:
        conn.close()
