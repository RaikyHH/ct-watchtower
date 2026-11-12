"""Background pipeline and metrics layer (§2, addendum §5).

One process, several threads: ingest (websocket), worker (normalise -> prefilter ->
scoring -> `upsert_finding` -> SSE), enrichment (its own queue, §7.1), campaign
clustering (hourly), retention, and a sampler that writes the queue depth into a
ring buffer.

Without a reachable CertStream server the ingest thread runs into its backoff and
the app stays usable. That is the normal case while developing.
"""

from __future__ import annotations

import json
import logging
import queue
import sqlite3
import threading
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

from ctwatchtower.config import settings
from ctwatchtower.db import cache_purge, connect, purge_old_findings, sync_tenants, upsert_finding
from ctwatchtower.enrich.campaigns import cluster
from ctwatchtower.enrich.net import Defer, Transient
from ctwatchtower.enrich.scan import MAX_POLLS, ScanError, submit
from ctwatchtower.enrich.scan import SERVICES as SCAN_SERVICES
from ctwatchtower.enrich.scan import is_ready as scan_ready
from ctwatchtower.enrich.worker import Enricher
from ctwatchtower.ingest.certstream import CertStreamIngest
from ctwatchtower.normalize.names import CertContext, normalize
from ctwatchtower.normalize.prefilter import build_from_rulesets
from ctwatchtower.notify import Notifier
from ctwatchtower.rules.loader import RuleStore
from ctwatchtower.scoring.engine import score_candidate

log = logging.getLogger(__name__)

# The 5 stations of the system screen (§12, addendum §5).
PIPELINE_NODES = (
    ("ingest", "CT ingest"),
    ("normalize", "Normalisation"),
    ("prefilter", "Prefilter"),
    ("score", "Scoring"),
    ("enrich", "Enrichment"),
)

RATE_WINDOW = 10.0  # seconds, sliding window for certificates/s
SAMPLE_INTERVAL = 2.0  # seconds between two queue measurements
RULES_TTL = 5.0  # seconds before the worker asks the RuleStore again
RETENTION_FIRST = 60.0  # seconds after the start: containers do get restarted
RETENTION_INTERVAL = 24 * 3600.0
CAMPAIGN_INTERVAL = 3600.0  # §17.1: hourly


class Broker:
    """SSE fan-out: one subscriber queue per connection."""

    def __init__(self) -> None:
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self, maxsize: int = 200) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Deliberately simple: a client that is too slow loses events
                # instead of slowing the pipeline. A persistent cursor if that
                # ever becomes a problem.
                pass

    @property
    def subscribers(self) -> int:
        with self._lock:
            return len(self._subs)


def _initial_scan_state(service: str) -> str:
    """After submitting: `running`, if completion can be polled for."""
    entry = SCAN_SERVICES.get(service)
    return "running" if entry and entry.status_pattern else "unknown"


class Pipeline:
    """Ingest -> normalise -> prefilter -> scoring -> DB -> SSE."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        store: RuleStore,
        *,
        url: str | None = None,
        queue_size: int | None = None,
    ) -> None:
        self.conn = conn
        # Deliberately simple: one global lock around the SQLite connection. Enough
        # for one process; separate connections per thread if that measurably slows
        # things down.
        self.db_lock = threading.Lock()
        self.store = store
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size or settings.ingest_queue_size)
        self.ingest = CertStreamIngest(self.queue, url=url)
        self.broker = Broker()
        self.stop_event = threading.Event()
        self.queue_history: deque[dict[str, Any]] = deque(maxlen=60)
        self.counters = dict.fromkeys((n for n, _ in PIPELINE_NODES), 0)
        self.findings_total = 0
        # How often the application enriched by itself. Belongs on the system
        # screen: whoever switches that on should see what it sets off.
        self.auto_enriched = 0
        self._quota_reported = False
        self._cert_times: deque[float] = deque()
        self._threads: list[threading.Thread] = []
        self._rules: list = []
        self._rules_at = 0.0
        self._pf = None
        self._pf_key: tuple[str, ...] | None = None
        # Alerting (§8): collects findings and reports them in batches. Without a
        # switch and a target it does nothing, `offer()` checks that itself.
        self.notifier = Notifier(self)
        # Enrichment runs in a thread of its own with its own queue and never slows
        # the scorer. Off by default (the registries' terms of use, §16); and even
        # switched on it only queries on an explicit request per finding
        # (`request_enrichment`). The enricher is always built, even when it is off:
        # that costs nothing. A cache object, a counter, an empty queue, and it
        # lets the switch be flipped at runtime. The decision used to hang off the
        # container start, so whoever wanted enrichment had to restart. Nothing is
        # queried while `enrich_enabled` is off: `request` turns every request down
        # beforehand.
        self.enricher = Enricher(self)
        # The revocation list is filled from the database at startup; with no
        # entries the checker answers "not revoked" to everything.
        from ctwatchtower.revocation import store as _revocation_store

        self.revocation = _revocation_store.load_checker(self.conn)

    # ------------------------------- Rules -------------------------------

    def rulesets(self, force: bool = False) -> list:
        """The RuleStore checks file timestamps. Do not do that per certificate."""
        now = time.monotonic()
        if force or now - self._rules_at > RULES_TTL:
            self._rules = self.store.rulesets
            self._rules_at = now
            with self.db_lock:
                sync_tenants(self.conn, self._rules)
        return self._rules

    def prefilter(self):
        rules = self.rulesets()
        key = tuple(rs.ruleset_hash for rs in rules)
        if key != self._pf_key:
            self._pf_key, self._pf = key, build_from_rulesets(rules)
        return self._pf

    # ----------------------------- Processing ----------------------------

    def process(self, cert: CertContext) -> list[dict[str, Any]]:
        """One certificate through the stations. Returns the events that were sent.

        Can be called synchronously, without a thread. That is exactly how the test
        client calls it.
        """
        self.counters["ingest"] += 1
        self._cert_times.append(time.monotonic())
        rules = self.rulesets()
        pf = self.prefilter()
        events: list[dict[str, Any]] = []

        done: set[str] = set()
        for raw in cert.names:
            cand = normalize(raw)
            # `*.x.com` and `x.com` give the same candidate, once per certificate,
            # otherwise the finding dedupe counts the same certificate twice
            # (cert_count).
            if cand is None or cand.name in done:
                continue
            done.add(cand.name)
            self.counters["normalize"] += 1
            hits = pf.hits(cand)
            if not hits:
                continue
            self.counters["prefilter"] += 1
            related = [n for n in cert.names if n != raw]
            # §4.2: stage 2 only for the tenants whose terms matched.
            wanted = pf.tenants_for(hits)
            for rs in rules:
                if wanted is not None and rs.tenant.id not in wanted:
                    continue
                result = score_candidate(rs, cand, cert)
                self.counters["score"] += 1
                if result.severity is None:
                    continue
                with self.db_lock:
                    fid, action = upsert_finding(
                        self.conn,
                        rs.tenant.id,
                        cand,
                        cert,
                        score=result.score,
                        severity=result.severity,
                        explanation=result.to_dict(),
                        related_names=related,
                        # Requested one at a time, never in bulk: either by a click
                        # on the detail panel or, when `ENRICH_AUTO` is on, for
                        # findings from `thresholds.enrich_from` upwards. The
                        # operators allow "query-based access", not "high volume,
                        # automated processes" (§16, decision 2026-09-19); the daily
                        # caps are the hard brake on that.
                        enrich_state="skipped",
                    )
                if action == "update":
                    continue  # dedupe hit: no new event for the live screen
                self.findings_total += 1
                event = {
                    "id": fid,
                    "action": action,
                    "tenant": rs.tenant.id,
                    "domain": cand.name,
                    "registrable": cand.registrable,
                    "tld": cand.tld,
                    "score": result.score,
                    "severity": result.severity,
                    "matched": result.matched,
                    "first_seen": datetime.now(UTC).isoformat(),
                }
                self.broker.publish(event)
                # Trial mode (§15.2): the tenant scores and writes findings but
                # raises no alert and serves no feed. That way a new ruleset can be
                # judged against the real stream for a few days without waking
                # anybody. `shadow` used to sit in the schema and do nothing, so
                # whoever set it still got alerts.
                if not rs.shadow:
                    self.notifier.offer(event)
                self._maybe_enrich(rs, fid, result.score)
                events.append(event)
        return events

    def _maybe_enrich(self, rs, finding_id: str, score: int) -> None:
        """Enrich a conspicuous finding by itself, if that has been allowed.

        Without it the campaigns stay empty. They group by registrar, nameserver
        and network, and none of that is known before an enrichment.

        Three conditions, and all three have to hold: the main switch `ENRICH_AUTO`,
        the tenant's threshold, and a daily budget with something left in it. The
        worker checks the last one itself; when it runs out it says `quota` and
        stops instead of asking on.
        """
        if not (settings.enrich_auto and settings.enrich_enabled):
            return
        if score < rs.thresholds.enrich_from:
            return
        state = self.request_enrichment(finding_id)
        if state == "quota":
            # Say it once, not for every finding: the cap holds until tomorrow.
            if not self._quota_reported:
                log.info(
                    "daily enrichment cap reached, further findings stay without "
                    "registration data until the budget resets"
                )
                self._quota_reported = True
        elif state == "queued":
            self.auto_enriched += 1

    # ------------------------------ Threads ------------------------------

    def request_enrichment(self, finding_id: str) -> str:
        """Queue one single finding for enrichment, the only way in there.

        Returns: `queued`, `pending` (already waiting), `done` (already enriched),
        `disabled` (enrichment off), `unknown` (no such finding), `quota` (daily cap
        reached) or `busy` (queue full). API and UI build on that.
        """
        if not settings.enrich_enabled:
            # First check whether the finding exists: reporting "off" about a
            # finding that does not exist would be the wrong answer (the API would
            # reply 200 instead of 404).
            with self.db_lock:
                row = self.conn.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone()
            return "disabled" if row else "unknown"
        return self.enricher.request(finding_id)

    def request_scan(self, finding_id: str, service: str) -> dict:
        """Submit one single finding to an external scanner, at the push of a button.

        Unlike the enrichment there is no queue here: it happens rarely, it takes a
        moment, and the user is waiting for the answer. The result is stored on the
        finding so the link survives a restart.

        Returns `{"status": ...}`: `done`, `unknown` (no such finding), `disabled`,
        `quota`, `error` (with `reason`).
        """
        with self.db_lock:
            row = self.conn.execute(
                "SELECT domain, scans FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
        if row is None:
            return {"status": "unknown"}
        if not settings.scan_enabled:
            return {"status": "disabled", "reason": "SCAN_ENABLED is false"}

        quota = self.enricher.quota
        try:
            result = submit(row["domain"], service, quota=quota)
        except Defer as exc:
            return {"status": "quota", "reason": str(exc)}
        except (ScanError, Transient) as exc:
            return {"status": "error", "reason": str(exc)}

        # The scan is still running at the service when we are done here: the result
        # page only exists ten to thirty seconds later. That is recorded on the
        # finding so the UI can show an hourglass instead of a dead link, even if
        # somebody closes the panel in between.
        result = {**result, "state": _initial_scan_state(result["service"]), "polls": 0}
        current = json.loads(row["scans"] or "{}")
        current[result["service"]] = result
        with self.db_lock:
            self.conn.execute(
                "UPDATE findings SET scans=? WHERE id=?", (json.dumps(current), finding_id)
            )
            self.conn.commit()
        return {"status": "done", "scan": result}

    def scan_state(self, finding_id: str, service: str) -> dict:
        """Check whether a triggered scan has finished at the service.

        One query per call; the UI asks again at intervals. Once a state is final
        (`done`, `deleted`, `error`) it stops asking. The stored answer is enough.
        """
        with self.db_lock:
            row = self.conn.execute(
                "SELECT scans FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
        if row is None:
            return {"status": "unknown"}
        current = json.loads(row["scans"] or "{}")
        entry = current.get(service)
        if not entry:
            return {"status": "none"}

        state = entry.get("state", "unknown")
        if state in ("done", "deleted", "error", "unknown"):
            return {"status": "done", "scan": entry}

        polls = int(entry.get("polls") or 0) + 1
        if polls > MAX_POLLS:
            entry["state"] = "unknown"
            entry["note"] = "the service has said nothing for minutes, open the result yourself"
        else:
            response = scan_ready(service, entry.get("scan_id", ""))
            # While throttled the state stays "running": that says something about
            # us, not about the scan. The UI passes the wait time through.
            if response["state"] != "throttled":
                entry["state"] = response["state"]
            if note := response.get("note"):
                entry["note"] = note
            if wait := response.get("retry_after"):
                entry["retry_after"] = wait
        entry["polls"] = polls

        current[service] = entry
        with self.db_lock:
            self.conn.execute(
                "UPDATE findings SET scans=? WHERE id=?", (json.dumps(current), finding_id)
            )
            self.conn.commit()
        return {"status": "done", "scan": entry}

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                cert = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.process(cert)
            except Exception:  # noqa: BLE001 - one broken entry does not stop the pipeline
                log.exception("processing failed")

    def run_retention(self) -> int:
        """Retention (§9.3) on its own connection. Returns the number of deleted findings."""
        with self.db_lock:  # shared connection, so even a read goes under the lock
            path = self.conn.execute("PRAGMA database_list").fetchone()["file"]
        if not path:
            return 0  # in-memory DB (tests): a second connection would not see it
        conn = connect(path)
        try:
            # Under the pipeline lock: VACUUM needs the DB exclusively and locks it
            # for as long as the rewrite takes (seconds on big files). The worker
            # waits that long, the queue buffers, the ingest slows down (§3.3),
            # which is fine for a nightly run. Without the lock the worker would run
            # into "database is locked" and the finding would be lost.
            with self.db_lock:
                deleted = purge_old_findings(conn)
                if deleted:
                    conn.execute("VACUUM")  # otherwise the file never shrinks
        finally:
            conn.close()
        log.info("retention: %d findings deleted", deleted)
        return deleted

    def _retention(self) -> None:
        delay = RETENTION_FIRST
        while not self.stop_event.wait(delay):
            try:
                self.run_retention()
            except Exception:  # noqa: BLE001 - next attempt in 24 h
                log.exception("retention failed")
            delay = RETENTION_INTERVAL

    def run_revocation_sync(self) -> dict:
        """Sync OneCRL. Its own connection, as with the retention.

        The ETag sits in `settings`: if nothing changed, Mozilla answers 304 and no
        payload flows. So the normal case costs one connection and nothing else.
        """
        from ctwatchtower.revocation import store

        with self.db_lock:
            row = self.conn.execute(
                "SELECT value FROM settings WHERE key='_onecrl_etag'").fetchone()
            etag = json.loads(row["value"]) if row else None
            result = store.sync(self.conn, etag if isinstance(etag, str) else None)
            if result.get("etag"):
                self.conn.execute(
                    "INSERT INTO settings (key, value, updated_at)"
                    " VALUES ('_onecrl_etag',?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
                    " updated_at=excluded.updated_at",
                    (json.dumps(result["etag"]), datetime.now(UTC).isoformat()),
                )
            self.conn.commit()
            if self.revocation is not None:
                store.load_checker(self.conn, self.revocation)
        return result

    def _revocation_loop(self) -> None:
        # Wait a minute first: other things matter more at startup, and a fresh
        # container should not reach outwards right away.
        delay = 60.0
        while not self.stop_event.wait(delay):
            if settings.revocation_enabled:
                try:
                    self.run_revocation_sync()
                except Exception:  # noqa: BLE001 - next attempt after the interval
                    log.exception("revocation list sync failed")
            # The setting is read fresh on every pass, so flipping it in the UI
            # takes effect without a restart.
            delay = max(settings.revocation_interval_hours, 1) * 3600.0

    def run_campaigns(self) -> int:
        """Campaign clustering (§17.1) plus cache cleanup (§16.2: nothing past the TTL)."""
        with self.db_lock:
            n = cluster(self.conn)
            cache_purge(self.conn)
        return n

    def _campaigns(self) -> None:
        while not self.stop_event.wait(CAMPAIGN_INTERVAL):
            try:
                self.run_campaigns()
            except Exception:  # noqa: BLE001 - next run in an hour
                log.exception("campaign clustering failed")

    def _sampler(self) -> None:
        while not self.stop_event.wait(SAMPLE_INTERVAL):
            self.queue_history.append(
                {"t": datetime.now(UTC).isoformat(), "depth_pct": self.queue_depth_pct}
            )

    def start(self) -> None:
        if self._threads:
            return
        self.rulesets(force=True)
        self._threads = [self.ingest.start()]
        targets = [
            (self._worker, "scorer"),
            (self._sampler, "metrics-sampler"),
            (self._retention, "retention"),
            (self._campaigns, "campaigns"),
            (self._revocation_loop, "revocation"),
            (lambda: self.notifier.run_forever(self.stop_event), "notifier"),
        ]
        targets.append((lambda: self.enricher.run_forever(self.stop_event), "enricher"))
        for target, name in targets:
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self, timeout: float = 2.0) -> None:
        self.stop_event.set()
        self.ingest.stop.set()
        with self.enricher.cond:  # wakes the waiting enrichment thread at once
            self.enricher.cond.notify_all()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads = []

    # ----------------------------- Metrics -----------------------------

    @property
    def certs_per_sec(self) -> float:
        cutoff = time.monotonic() - RATE_WINDOW
        while self._cert_times and self._cert_times[0] < cutoff:
            self._cert_times.popleft()
        return round(len(self._cert_times) / RATE_WINDOW, 2)

    @property
    def queue_depth_pct(self) -> float:
        return round(100 * self.queue.qsize() / max(self.queue.maxsize, 1), 2)

    def _revocation_summary(self) -> dict[str, Any]:
        """The short version for the system screen. The latest hits, not all of them."""
        from ctwatchtower.revocation import store

        if not settings.revocation_enabled:
            return {"off": True, "new": 0, "revocations": 0, "hits": 0, "latest": []}
        with self.db_lock:
            numbers = store.count_hits(self.conn)
            latest = store.hits(self.conn, limit=5)
        return {
            "off": False,
            "new": numbers["new"],
            "hits": numbers["total"],
            "revocations": len(self.revocation) if self.revocation else 0,
            "latest": latest,
        }

    def metrics(self) -> dict[str, Any]:
        """The 4 metric cards plus the pipeline nodes in one payload (addendum §5)."""
        pf = self._pf
        running = any(t.is_alive() for t in self._threads)
        enricher = self.enricher if settings.enrich_enabled else None
        enriching = any(t.name == "enricher" and t.is_alive() for t in self._threads)
        states = {
            "ingest": "ok" if self.ingest.alive else ("waiting" if running else "off"),
            "normalize": "ok" if running else "off",
            "prefilter": "ok" if running else "off",
            "score": "ok" if running else "off",
            # Switched off is not an error but intent, and it is read from the
            # switch, not remembered at startup, otherwise the display lags behind.
            "enrich": "ok" if (enricher and enriching) else "off",
        }
        return {
            "certs_per_sec": self.certs_per_sec,
            "queue_depth_pct": self.queue_depth_pct,
            "queue_depth": self.queue.qsize(),
            "queue_max": self.queue.maxsize,
            "active_enrichments": enricher.active if enricher else 0,
            "enrich_queue": enricher.queued if enricher else 0,
            "cache_hit_ratio": enricher.cache.hit_ratio if enricher else 0.0,
            # Daily counters and the caps reached (hard limits per source/server)
            "enrich_quota": enricher.quota.status() if enricher else None,
            "notify": self.notifier.status(),
            "prefilter_pass_ratio": round(pf.pass_ratio, 4) if pf else 0.0,
            "findings_total": self.findings_total,
            "auto_enriched": self.auto_enriched,
            "auto_on": settings.enrich_auto and settings.enrich_enabled,
            "sse_subscribers": self.broker.subscribers,
            "revocation": self._revocation_summary(),
            "nodes": [
                {"id": nid, "label": label, "state": states[nid], "count": self.counters[nid]}
                for nid, label in PIPELINE_NODES
            ],
            "ct_logs": [
                {
                    "name": self.ingest.url,
                    "state": "connected" if self.ingest.alive else "disconnected",
                    "certs_seen": self.ingest.certs_seen,
                    "duplicates": self.ingest.certs_duplicate,
                }
            ],
        }
