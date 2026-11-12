"""The enrichment thread, phase-2 rescoring (§7.9) and the tie-in to the pipeline.

The registry and the resolver are fakes carrying data out of the recorded answers -
except in the GDPR end-to-end test, which runs the real `Registration` against a
mock transport answer carrying a registrant vcard.
"""

from __future__ import annotations

import heapq
import json
import threading
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from test_enrich_rdap import BOOT, PII, VRSN, boot, rdap_with_registrant
from test_scoring_support import make_cert

from ctwatchtower import db
from ctwatchtower.enrich.net import Cache, Defer, Transient
from ctwatchtower.enrich.rdap import Registration
from ctwatchtower.enrich.worker import MAX_ATTEMPTS, RETRY_DELAYS, Enricher, enrich_key, enrichment_for
from ctwatchtower.normalize.names import normalize
from ctwatchtower.pipeline import Pipeline
from ctwatchtower.rules.loader import RuleStore
from ctwatchtower.scoring.engine import score_candidate

RULESET = """
apiVersion: ctwatchtower/v2
kind: RuleSet
tenant: { id: banking, name: Krypto }
thresholds: { persist: 17, info: 24, warning: 37, alert: 64, enrich_from: 28 }
anchors:
  - terms: [velton]
    weight: 40
    match: { exact: true }
  - terms: [quorix]
    weight: 20
    match: { exact: true }
lures:
  - terms: [login]
    weight: 14
post_enrichment:
  domain_age:
    - { max_age_days: 7, weight: 22 }
    - { min_age_days: 365, weight: -25 }
  brand_protection_registrar: { weight: -40, list_file: data/registrar_brand_protection.yaml }
  no_resolution: { weight: 8 }
  parking_detected: { weight: -20 }
"""


def days_ago(n: int) -> str:
    return (datetime.now(UTC) - timedelta(days=n)).isoformat()


YOUNG = {
    "registrar": "NameSilo, LLC",
    "registrar_iana_id": 1479,
    "created": days_ago(5),
    "nameservers": ["dns1.harmonweb.net", "dns2.harmonweb.net"],
    "epp_status": ["clientTransferProhibited"],
}
BRAND = {"registrar": "Nom-IQ Limited dba Com Laude", "registrar_iana_id": 470, "created": days_ago(2800)}
DNS = {
    "a": ["216.198.79.1"],
    "aaaa": [],
    "ns": ["dns1.harmonweb.net"],
    "mx": ["lledgerr.com"],
    "cname": [],
    "txt": [],
    "nxdomain": False,
}


class Registry:
    def __init__(self, answer=None, error: Exception | None = None) -> None:
        self.answer, self.error, self.calls = answer or {}, error, []

    def lookup(self, registrable: str) -> dict:
        self.calls.append(registrable)
        if self.error:
            raise self.error
        return dict(self.answer)


class Dns(Registry):
    def resolve(self, name: str) -> dict:
        return self.lookup(name)


def pipeline(tmp_path, registry=None, dns=None) -> Pipeline:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    pipe = Pipeline(db.connect(tmp_path / "e.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")
    pipe.enricher = Enricher(pipe, registration=registry or Registry(YOUNG), resolver=dns or Dns(DNS))
    return pipe


def seed(pipe, *domains: str) -> list[str]:
    """Create findings and request them explicitly. The only way into the enrichment.

    The pipeline queues nothing by itself (§16): registries allow single queries,
    not automated mass queries.
    """
    pipe.process(make_cert(list(domains)))
    ids = [r["id"] for r in pipe.conn.execute("SELECT id FROM findings WHERE enrich_state!='pending'")]
    for fid in ids:
        pipe.request_enrichment(fid)
    return ids


def drain(pipe: Pipeline, *, force: bool = False) -> None:
    """Work off the due jobs synchronously; `force` pulls the retries forward too."""
    enr = pipe.enricher
    for _ in range(len(enr.heap)):  # only what is in there now - retries stay put
        if force or enr.heap[0].due <= time.monotonic():
            enr.run(heapq.heappop(enr.heap))


def finding(pipe: Pipeline, domain: str) -> dict:
    row = pipe.conn.execute("SELECT * FROM findings WHERE domain=?", (domain,)).fetchone()
    return dict(row) if row else {}


# ───────────────────── The tie-in to the pipeline ────────────────────────


def test_only_the_requested_finding_is_queued_and_process_never_waits(tmp_path) -> None:
    """Requesting happens per finding; the scorer never waits on the network for it."""
    pipe = pipeline(tmp_path, registry=Registry(error=AssertionError("does not run in the scorer")))
    t = time.perf_counter()
    pipe.process(make_cert(["velton-login.com", "quorix.com"]))
    assert time.perf_counter() - t < 1.0  # no network, no waiting in the scorer path
    assert pipe.enricher.queued == 0, "the pipeline queues nothing by itself"

    pipe.request_enrichment(finding(pipe, "velton-login.com")["id"])
    assert finding(pipe, "velton-login.com")["enrich_state"] == "pending"
    assert finding(pipe, "quorix.com")["enrich_state"] == "skipped"  # niemand hat gefragt
    assert pipe.enricher.queued == 1


def test_the_score_stays_put_and_the_enrichment_stands_beside_it(tmp_path) -> None:
    """A score that changes while somebody is looking at the finding is the opposite
    of helpful: a 90 becomes a 15, and nobody knows whether they misread it.

    So the enrichment writes its result into a column of its own. `score`,
    `severity` and `explanation` keep describing the same state of affairs, and
    passen zueinander.
    """
    pipe = pipeline(tmp_path)
    sub = pipe.broker.subscribe()
    seed(pipe, "velton-login.com")
    before = finding(pipe, "velton-login.com")
    drain(pipe)
    after = finding(pipe, "velton-login.com")

    assert after["score"] == before["score"] and after["severity"] == before["severity"]
    assert json.loads(after["explanation"])["phase"] == 1
    # A young domain weighs more. That stands beside it, not in the score.
    assert after["score_enriched"] > before["score"]
    assert "domain_age" in after["enrich_note"]

    # The enrichment's fields are there all the same; only the scoring does not touch them.
    assert after["enrich_state"] == "done" and after["registrar"] == "NameSilo, LLC"
    assert json.loads(after["nameservers"]) == YOUNG["nameservers"]
    assert json.loads(after["a_records"]) == ["216.198.79.1"] and after["has_mx"] == 1
    events = [sub.get_nowait() for _ in range(sub.qsize())]
    assert [e["action"] for e in events] == ["insert", "enrich"]


def test_rescoring_is_the_same_scoring_function(tmp_path) -> None:
    pipe = pipeline(tmp_path)
    cert = make_cert(["velton-login.com"])
    pipe.process(cert)
    pipe.request_enrichment(finding(pipe, "velton-login.com")["id"])
    drain(pipe)
    rs = pipe.rulesets()[0]
    direct = score_candidate(
        rs, normalize("velton-login.com"), cert, enrichment=enrichment_for(YOUNG, DNS), phase=2
    )
    # The enrichment computes with the same function as the pipeline; only the result
    # lands in `score_enriched` instead of in `score`.
    assert finding(pipe, "velton-login.com")["score_enriched"] == direct.score


def test_a_brand_protection_registrar_is_reported_instead_of_silently_suppressed(tmp_path) -> None:
    """A brand protection registrar almost always means: infrastructure of their own.
    The finding used to vanish by itself on that. Now it stays and says what the
    enrichment turned up. Whoever closes it decides that for themselves."""
    pipe = pipeline(tmp_path, registry=Registry(BRAND))
    seed(pipe, "velton-login.com")
    before = finding(pipe, "velton-login.com")
    drain(pipe)
    row = finding(pipe, "velton-login.com")
    assert row["status"] == "new", "no longer silently suppressed"
    assert row["score"] == before["score"] and row["severity"] == before["severity"]
    assert row["score_enriched"] < row["score"]
    assert "brand_protection_registrar" in row["enrich_note"]


def test_triage_decision_is_not_overwritten_by_phase_two(tmp_path) -> None:
    pipe = pipeline(tmp_path, registry=Registry(BRAND))
    seed(pipe, "velton-login.com")
    pipe.conn.execute("UPDATE findings SET status='confirmed'")
    drain(pipe)
    assert finding(pipe, "velton-login.com")["status"] == "confirmed"


def test_cache_key_is_the_registrable_domain(tmp_path) -> None:
    conn = db.connect(":memory:")
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        return boot() if str(request.url) == BOOT else httpx.Response(200, text="{}")

    reg = Registration(
        Cache(conn, threading.Lock()), http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    pipe = pipeline(tmp_path, registry=reg)
    for host in ("a.velton-login.com", "b.velton-login.com", "velton-login.com"):
        pipe.enricher.gather(normalize(host))
    assert urls == [BOOT, VRSN + "velton-login.com"]  # one RDAP query for three hostnames
    assert pipe.enricher.resolver.calls == ["velton-login.com"] * 3  # a fake without a cache


def test_private_suffix_hosts_skip_rdap_of_the_platform() -> None:
    cand = normalize("trezore-bridge-download.pages.dev")
    assert cand.registrable == "pages.dev" and enrich_key(cand) == "trezore-bridge-download.pages.dev"
    registry, dns = Registry(BRAND), Dns(DNS)
    enr = Enricher.__new__(Enricher)
    enr.registration, enr.resolver = registry, dns
    reg, _ = enr.gather(cand)
    assert reg == {} and registry.calls == [] and dns.calls == ["trezore-bridge-download.pages.dev"]


def test_parking_and_nxdomain_signals() -> None:
    parked = enrichment_for({"nameservers": ["NS1.SEDOPARKING.COM".lower()]}, {"nxdomain": False, "mx": []})
    assert parked["parking_detected"] is True and parked["has_mx"] is False
    gone = enrichment_for({}, {"nxdomain": True, "ns": [], "mx": []})
    assert gone == {"no_resolution": True, "parking_detected": False, "has_mx": False}
    assert enrichment_for({}, {}) == {}  # DoH off: no DNS signals, not even a "False"


# ─────────────────────── Errors and retries ─────────────────────────────


def test_failed_enrichment_retries_twice_then_gives_up_without_touching_the_finding(tmp_path) -> None:
    pipe = pipeline(tmp_path, registry=Registry(error=Transient("rdap weg")))
    seed(pipe, "velton-login.com")
    phase1 = finding(pipe, "velton-login.com")
    delays = []
    for attempt in range(1, MAX_ATTEMPTS + 1):
        drain(pipe, force=True)
        row = finding(pipe, "velton-login.com")
        assert row["enrich_attempts"] == attempt
        if pipe.enricher.heap:
            delays.append(round(pipe.enricher.heap[0].due - time.monotonic()))
    assert delays == [RETRY_DELAYS[0], RETRY_DELAYS[1]] and sum(RETRY_DELAYS) == 24 * 3600
    assert row["enrich_state"] == "failed" and pipe.enricher.queued == 0
    for col in ("score", "severity", "status", "explanation"):
        assert row[col] == phase1[col]
    assert row["registrar"] is None and row["a_records"] is None


def test_program_errors_count_as_attempts_too(tmp_path, caplog) -> None:
    pipe = pipeline(tmp_path, dns=Dns(error=KeyError("broken")))
    seed(pipe, "velton-login.com")
    drain(pipe)
    assert finding(pipe, "velton-login.com")["enrich_attempts"] == 1 and "velton-login.com" in caplog.text


def test_defer_requeues_without_counting_an_attempt(tmp_path) -> None:
    pipe = pipeline(tmp_path, registry=Registry(error=Defer(600)))
    seed(pipe, "velton-login.com")
    drain(pipe)
    assert finding(pipe, "velton-login.com")["enrich_attempts"] == 0
    assert 590 < pipe.enricher.heap[0].due - time.monotonic() <= 600


def test_full_queue_drops_instead_of_blocking(tmp_path, monkeypatch) -> None:
    import ctwatchtower.enrich.worker as worker

    monkeypatch.setattr(worker, "MAX_QUEUE", 0)
    pipe = pipeline(tmp_path)
    seed(pipe, "velton-login.com")
    assert pipe.enricher.queued == 0 and pipe.enricher.dropped == 1
    assert finding(pipe, "velton-login.com")["enrich_state"] == "pending"  # recover() picks it up


def test_deleted_finding_or_removed_tenant(tmp_path) -> None:
    pipe = pipeline(tmp_path)
    seed(pipe, "velton-login.com")
    pipe.conn.execute("DELETE FROM findings")
    drain(pipe)  # no error, nothing to do
    seed(pipe, "velton-login.com")
    job = pipe.enricher.heap[0]
    job.tenant_id = "weg"
    sub = pipe.broker.subscribe()
    drain(pipe)
    assert isinstance(sub.get_nowait()["score"], int)  # the SSE filter compares `score < min_score`
    row = finding(pipe, "velton-login.com")
    assert (
        row["enrich_state"] == "done" and row["registrar"] == "NameSilo, LLC" and row["escalated_at"] is None
    )


# ────────────────────────────── DSGVO-Durchstich ────────────────────────────


def test_registrant_data_never_reaches_findings_or_cache(tmp_path) -> None:
    """§16.2 along the whole way: an RDAP answer with a registrant vcard → pipeline → DB."""
    pipe = pipeline(tmp_path)
    answer = rdap_with_registrant()
    reg = Registration(
        pipe.enricher.cache,
        http=httpx.Client(
            transport=httpx.MockTransport(
                lambda r: (
                    boot()
                    if str(r.url) == BOOT
                    else (
                        httpx.Response(200, json=answer)
                        if str(r.url) == VRSN + "lledgerr.com"
                        else httpx.Response(404)
                    )
                )
            )
        ),
    )
    pipe.enricher.registration = reg
    seed(pipe, "velton-login.lledgerr.com")
    drain(pipe)
    row = finding(pipe, "velton-login.lledgerr.com")
    assert row["registrar"] == "NameSilo, LLC" and row["domain_created"].startswith("2026-09-13")
    dump = "\n".join(pipe.conn.iterdump())
    for needle in PII:
        assert needle not in dump


# ────────────────────────────────── Neustart ──────────────────────────────────


def test_recover_requeues_open_jobs_but_not_for_removed_tenants(tmp_path) -> None:
    pipe = pipeline(tmp_path)
    seed(pipe, "velton-login.com", "quorix.com")
    pipe.conn.execute("UPDATE findings SET enrich_state='pending'")  # requested, not finished
    pipe.conn.execute("INSERT INTO tenants (id, name) VALUES ('weg', 'weg')")
    pipe.conn.execute("UPDATE findings SET tenant_id='weg' WHERE domain='quorix.com'")
    fresh = Enricher(pipe, registration=Registry(YOUNG), resolver=Dns(DNS))
    assert fresh.recover() == 1
    job = fresh.heap[0]
    assert job.cand.name == "velton-login.com" and job.cert.names == ["velton-login.com", "quorix.com"]
    assert job.cert.issuer_o == "Let's Encrypt"


def test_thread_runs_and_stops_with_the_pipeline(tmp_path) -> None:
    pipe = pipeline(tmp_path)
    seed(pipe, "velton-login.com")
    pipe.start()
    try:
        for _ in range(50):
            if finding(pipe, "velton-login.com")["enrich_state"] == "done":
                break
            time.sleep(0.05)
        assert finding(pipe, "velton-login.com")["enrich_state"] == "done"
        metrics = pipe.metrics()
        assert next(n for n in metrics["nodes"] if n["id"] == "enrich")["state"] == "ok"
        assert metrics["enrich_queue"] == 0
    finally:
        pipe.stop()
    assert not any(t.is_alive() for t in threading.enumerate() if t.name == "enricher")


def test_enrichment_can_be_switched_off(tmp_path, monkeypatch) -> None:
    from ctwatchtower.config import settings

    monkeypatch.setattr(settings, "enrich_enabled", False)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "banking.yaml").write_text(RULESET, encoding="utf-8")
    pipe = Pipeline(db.connect(tmp_path / "off.sqlite3"), RuleStore(rules), url="ws://127.0.0.1:1")
    seed(pipe, "velton-login.com")
    # The enricher is always built, so that the switch can be thrown at runtime.
    # So what gets checked is what it does, not whether it exists.
    assert finding(pipe, "velton-login.com")["enrich_state"] == "skipped"
    assert pipe.request_enrichment(finding(pipe, "velton-login.com")["id"]) == "disabled"
    assert pipe.enricher.queued == 0, "nothing queued, so nothing queried either"
    metrics = pipe.metrics()
    assert next(n for n in metrics["nodes"] if n["id"] == "enrich")["state"] == "off"
    assert metrics["cache_hit_ratio"] == 0.0


@pytest.fixture(autouse=True)
def _enrichment_on(monkeypatch):
    """These tests drive the enricher, so the switch has to be on.

    Set here and not left to the environment: otherwise the result would depend on
    whether a `.env` happens to lie beside the suite, and the CI would see something
    other than the developer.
    """
    from ctwatchtower.config import settings

    monkeypatch.setattr(settings, "enrich_enabled", True)


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch):
    """A safety net: a forgotten stub must never reach a real server."""

    def refuse(*a, **kw):
        raise AssertionError("a real network access in a test")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    monkeypatch.setattr("ctwatchtower.enrich.rdap._whois_query", refuse)


def test_existing_database_gets_the_new_columns(tmp_path) -> None:
    import sqlite3

    path = tmp_path / "alt.sqlite3"
    old = sqlite3.connect(path)
    new = ("enrich_attempts", "domain_changed", "escalated_at")  # Schema vor Stufe 4
    lines = [ln for ln in db.SCHEMA.splitlines() if not ln.strip().startswith(new)]
    old.executescript("\n".join(lines).split("-- Anreicherungs-Cache")[0])
    old.commit()
    old.close()
    conn = db.connect(path)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(findings)")}
    assert {"enrich_attempts", "domain_changed", "escalated_at"} <= cols
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "enrich_cache" in tables
    conn.close()
