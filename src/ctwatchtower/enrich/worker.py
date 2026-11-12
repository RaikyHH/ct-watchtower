"""Enrichment thread and phase 2 rescoring (§7.1, §7.9).

**Nothing here runs automatically.** A finding only ever comes in through
`request()`: an explicit request for exactly that finding, triggered by hand in the
UI. Registries allow "query-based access", not "high volume, automated processes"
(§16). A thread of its own works through the queue by due time:

    RDAP/WHOIS (registrable domain) -> DoH -> `score_candidate(..., enrichment, phase=2)`
    -> fields in `findings`, and the result of the second scoring in `score_enriched`
    and `enrich_note`. **`score`, `severity` and `explanation` stay untouched**: a
    score that changes while somebody is looking at the finding confuses more than
    the more accurate number helps.

A throttled server (`Defer`) only pushes *that* job back. A failed attempt
(`Transient`) is retried after 2 h and 24 h, then that is it, and the finding stays
unchanged with its fields empty (§7.1).
"""

from __future__ import annotations

import functools
import heapq
import itertools
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ruamel.yaml import YAML

from ctwatchtower.config import settings
from ctwatchtower.enrich.doh import Resolver
from ctwatchtower.enrich.net import Cache, Defer, Quota, Transient
from ctwatchtower.enrich.rdap import Registration, domain_age_days
from ctwatchtower.normalize.names import CandidateName, CertContext, _extractor, normalize
from ctwatchtower.scoring.engine import score_candidate

if TYPE_CHECKING:
    from ctwatchtower.pipeline import Pipeline

log = logging.getLogger(__name__)

def _enrichment_note(result, score_before: int) -> str | None:
    """One sentence about what the registration data would change in the picture.

    Only the contributions that did not exist without the enrichment; the rest was
    in the finding already. If nothing changes there is nothing to say.
    """
    reasons = [c for c in result.contributions if c.rule.startswith("post:") and c.pts]
    if not reasons and result.score == score_before:
        return None
    parts = ", ".join(f"{c.rule.partition(':')[2]} ({c.pts:+g})" for c in reasons)
    direction = "unchanged" if result.score == score_before else f"score {result.score}"
    return f"{direction}" + (f": {parts}" if parts else "")


MAX_ATTEMPTS = 3
RETRY_DELAYS = (2 * 3600, 22 * 3600)  # attempt 2 after 2 h, attempt 3 after 24 h (§7.1)
MAX_QUEUE = 10_000
FRESH_HOURS = 24  # for that long an enrichment counts as current (RDAP cache TTL, §7.2)


def _fresh(enriched_at: str | None) -> bool:
    """Was it enriched within the last `FRESH_HOURS`?"""
    if not enriched_at:
        return False
    try:
        when = datetime.fromisoformat(enriched_at)
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return (datetime.now(UTC) - when).total_seconds() < FRESH_HOURS * 3600


@dataclass(order=True)
class Job:
    due: float
    seq: int
    finding_id: str = field(compare=False)
    tenant_id: str = field(compare=False)
    cand: CandidateName = field(compare=False)
    cert: CertContext | None = field(compare=False, default=None)
    attempts: int = field(compare=False, default=0)


def cert_from_row(row) -> CertContext:
    """The certificate context from the stored fields. The raw context is not kept.

    Deliberately simple: without `issuer_cn` and `serial`, names from `domain` plus
    `related_names` (21 at most). Enough for the phase 2 certificate rules.
    """
    return CertContext(
        log_id=row["ct_log_id"] or "",
        idx=row["ct_log_index"] or 0,
        seen_at=row["first_seen"],
        not_before=row["cert_not_before"],
        not_after=row["cert_not_after"],
        issuer_cn="",
        issuer_o=row["issuer_o"] or "",
        serial="",
        sha256=row["cert_sha256"] or "",
        is_precert=False,
        names=[row["domain"], *json.loads(row["related_names"] or "[]")],
    )


def enrich_key(cand: CandidateName) -> str:
    """The registrable domain *including* the private PSL section (§7.1: cache key).

    `x.pages.dev` -> `x.pages.dev`, not `pages.dev`: under a private suffix zone
    (hosters, platforms) the subdomain is the unit a stranger controls.
    """
    ext = _extractor()(cand.name, include_psl_private_domains=True)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else cand.registrable


@functools.lru_cache(maxsize=1)
def parking_nameservers() -> tuple[str, ...]:
    try:
        doc = YAML(typ="safe").load(settings.parking_path.read_text(encoding="utf-8")) or {}
    except OSError:
        return ()
    return tuple(str(n).lower().strip(".") for n in doc.get("nameservers") or [])


def enrichment_for(reg: dict[str, Any], dns: dict[str, Any]) -> dict[str, Any]:
    """The flat dict `detect_post_enrichment` reads."""
    ns = reg.get("nameservers") or dns.get("ns") or []
    parked = parking_nameservers()
    out = {
        "registrar": reg.get("registrar"),
        "registrar_iana_id": reg.get("registrar_iana_id"),
        "domain_age_days": domain_age_days(reg),
        "nameservers": ns,
    }
    if dns:
        out["no_resolution"] = bool(dns.get("nxdomain"))
        out["parking_detected"] = any(n == p or n.endswith("." + p) for n in ns for p in parked)
        out["has_mx"] = bool(dns.get("mx"))
    return {k: v for k, v in out.items() if v not in (None, [])}


class Enricher:
    def __init__(self, pipeline: Pipeline, registration=None, resolver=None) -> None:
        self.pipeline = pipeline
        self.cache = Cache(pipeline.conn, pipeline.db_lock)
        self.quota = Quota(pipeline.conn, pipeline.db_lock)
        self.registration = registration or Registration(self.cache)
        self.resolver = resolver or Resolver(self.cache)
        self.heap: list[Job] = []
        self.cond = threading.Condition()
        self.seq = itertools.count()
        self.active = 0
        self.done = 0
        self.dropped = 0

    # ------------------------------- Queue -------------------------------

    def submit(self, finding_id: str, tenant_id: str, cand, cert=None, *, attempts=0, delay=0.0) -> bool:
        """Non-blocking. With a full queue the job is dropped; the finding stays
        `pending` and is picked up on the next start (`recover`)."""
        with self.cond:
            if len(self.heap) >= MAX_QUEUE:
                self.dropped += 1
                return False
            job = Job(time.monotonic() + delay, next(self.seq), finding_id, tenant_id, cand, cert, attempts)
            heapq.heappush(self.heap, job)
            self.cond.notify()
        return True

    def request(self, finding_id: str) -> str:
        """An explicit request for **one** finding. The only way to RDAP/WHOIS/DoH.

        There is no automatic enrichment: the operators allow "query-based access",
        not "high volume, automated processes" (§16).
        """
        with self.pipeline.db_lock:
            row = self.pipeline.conn.execute(
                "SELECT * FROM findings WHERE id=?", (finding_id,)
            ).fetchone()
        if row is None or (cand := normalize(row["domain"])) is None:
            return "unknown"
        if row["enrich_state"] == "pending":
            return "pending"
        # Freshly enriched: do not queue again. Without this, every opening of the
        # detail panel created a job, by the dozen during `j`/`k` triage.
        if row["enrich_state"] == "done" and _fresh(row["enriched_at"]):
            return "done"

        # If the daily cap is reached for every source that is switched on, do not
        # queue at all. Then the UI can say so honestly instead of waiting in
        # silence. Compare cap against counter rather than reading `exhausted`: a
        # cap of 0 has no counter yet and would not be listed there.
        quota = self.quota.status()
        enabled = {
            "rdap": settings.enrich_rdap_enabled,
            "whois": settings.enrich_whois_fallback,
            "doh": settings.enrich_doh_enabled,
        }
        free = [
            src
            for src, on in enabled.items()
            if on and quota["counts"].get(src, 0) < quota["limits"][src]
        ]
        if not free:
            return "quota"

        with self.pipeline.db_lock:
            self.pipeline.conn.execute(
                "UPDATE findings SET enrich_state='pending', enrich_attempts=0,"
                " enrich_requested_at=? WHERE id=?",
                (datetime.now(UTC).isoformat(), finding_id),
            )
            self.pipeline.conn.commit()
        if not self.submit(finding_id, row["tenant_id"], cand, cert_from_row(row)):
            return "busy"
        return "queued"

    def _next(self, stop: threading.Event) -> Job | None:
        with self.cond:
            while not stop.is_set():
                wait = self.heap[0].due - time.monotonic() if self.heap else 1.0
                if self.heap and wait <= 0:
                    return heapq.heappop(self.heap)
                self.cond.wait(timeout=min(wait, 1.0))
        return None

    def run_forever(self, stop: threading.Event) -> None:
        self.recover()
        while (job := self._next(stop)) is not None:
            self.run(job)

    @property
    def queued(self) -> int:
        return len(self.heap)

    # ------------------------------ Sequence -----------------------------

    def gather(self, cand: CandidateName) -> tuple[dict[str, Any], dict[str, Any]]:
        key = enrich_key(cand)
        reg: dict[str, Any] = {}
        # Under a private suffix RDAP describes the platform operator (`pages.dev`
        # belongs to Cloudflare, registered in 2019 through a brand protection
        # registrar), which would clear the attacker on the subdomain. So do not
        # ask at all.
        if settings.enrich_rdap_enabled and key == cand.registrable:
            reg = self.registration.lookup(cand.registrable)
        dns = self.resolver.resolve(key) if settings.enrich_doh_enabled else {}
        return reg, dns

    def run(self, job: Job) -> None:
        self.active += 1
        try:
            reg, dns = self.gather(job.cand)
        except Defer as d:
            self.submit(
                job.finding_id, job.tenant_id, job.cand, job.cert, attempts=job.attempts, delay=d.wait
            )
            return
        except Exception as exc:  # noqa: BLE001 - Transient or a bug: both are a failed attempt
            if not isinstance(exc, Transient):
                log.exception("enrichment %s", job.cand.name)
            self._failed(job, str(exc))
            return
        finally:
            self.active -= 1
        self.apply(job, reg, dns)
        self.done += 1

    def _failed(self, job: Job, why: str) -> None:
        attempts = job.attempts + 1
        final = attempts >= MAX_ATTEMPTS
        with self.pipeline.db_lock:
            self.pipeline.conn.execute(
                "UPDATE findings SET enrich_attempts=?, enrich_state=? WHERE id=?",
                (attempts, "failed" if final else "pending", job.finding_id),
            )
            self.pipeline.conn.commit()
        log.info("enrichment %s, attempt %d/%d: %s", job.cand.name, attempts, MAX_ATTEMPTS, why)
        if not final:
            self.submit(
                job.finding_id,
                job.tenant_id,
                job.cand,
                job.cert,
                attempts=attempts,
                delay=RETRY_DELAYS[attempts - 1],
            )

    def apply(self, job: Job, reg: dict[str, Any], dns: dict[str, Any]) -> dict[str, Any] | None:
        """Store the fields and compute phase 2, with the same function as phase 1."""
        enrichment = enrichment_for(reg, dns)
        ns = enrichment.get("nameservers")
        rs = next((r for r in self.pipeline.rulesets() if r.tenant.id == job.tenant_id), None)
        now = datetime.now(UTC).isoformat()
        conn = self.pipeline.conn
        with self.pipeline.db_lock:
            sql = "SELECT status, severity, score FROM findings WHERE id=?"
            row = conn.execute(sql, (job.finding_id,)).fetchone()
            if row is None:
                return None  # deleted in the meantime (retention, tenant removed)
            cols: dict[str, Any] = {
                "enrich_state": "done",
                "enriched_at": now,
                "enrich_attempts": job.attempts + 1,
                # §16.2: `reg` has already been through the allowlist (`rdap.allow`).
                "registrar": reg.get("registrar"),
                "registrar_id": reg.get("registrar_iana_id"),
                "registrar_abuse_email": reg.get("registrar_abuse_email"),
                "domain_created": reg.get("created"),
                "domain_changed": reg.get("changed"),
                "domain_expires": reg.get("expires"),
                "epp_status": json.dumps(reg["epp_status"]) if reg.get("epp_status") else None,
                "nameservers": json.dumps(ns) if ns else None,
                "a_records": json.dumps(dns.get("a", []) + dns.get("aaaa", [])) if dns else None,
                "has_mx": int(bool(dns.get("mx"))) if dns else None,
            }
            action = "enrich"
            if rs is not None:
                # The score stays put. Changing it afterwards while somebody is
                # looking at the finding is the opposite of helpful: a 90 turns into
                # a 15 and nobody knows whether they misread it. What the scoring
                # with registration data would give sits next to it, as information,
                # not as a silent correction. `score`, `severity` and `explanation`
                # still describe the same thing and still fit together.
                result = score_candidate(rs, job.cand, job.cert, enrichment=enrichment, phase=2)
                cols["score_enriched"] = result.score
                cols["enrich_note"] = _enrichment_note(result, row["score"])
            conn.execute(
                f"UPDATE findings SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?",
                (*cols.values(), job.finding_id),
            )
            conn.commit()
        self.pipeline.counters["enrich"] += 1
        event = {
            "id": job.finding_id,
            "action": action,
            "tenant": job.tenant_id,
            "domain": job.cand.name,
            "registrable": job.cand.registrable,
            "tld": job.cand.tld,
            "score": cols.get("score", row["score"]),
            "severity": cols.get("severity", row["severity"]),
        }
        self.pipeline.broker.publish(event)
        # No alert out of the enrichment: it no longer changes the score, so there is
        # no new severity to report. What it found sits on the finding
        # (`score_enriched`, `enrich_note`) and is read when somebody looks.
        return event

    # ------------------------------ Restart ------------------------------

    def recover(self) -> int:
        """Open jobs from the DB back into the queue. They otherwise live only in memory.

        Deliberately simple: the certificate is rebuilt from the stored fields
        (without `issuer_cn`, 21 names at most). Enough for the certificate rules;
        only storing the context along would be exact.
        """
        with self.pipeline.db_lock:
            rows = self.pipeline.conn.execute(
                # Explicitly requested only: `enrich_state` alone is not enough,
                # rows from the time of automatic enrichment carried it too.
                "SELECT * FROM findings WHERE enrich_state='pending'"
                " AND enrich_requested_at IS NOT NULL AND enrich_attempts<?",
                (MAX_ATTEMPTS,),
            ).fetchall()
        tenants = {r.tenant.id for r in self.pipeline.rulesets()}
        n = 0
        for row in rows:
            # `pending` only comes about through an explicit request, so picking it
            # up after a restart is not automatic enrichment. Picking up a deleted
            # tenant would be a query for nothing.
            cand = normalize(row["domain"])
            if cand is None or row["tenant_id"] not in tenants:
                continue
            n += self.submit(
                row["id"], row["tenant_id"], cand, cert_from_row(row), attempts=row["enrich_attempts"]
            )
        if n:
            log.info("enrichment: %d open jobs taken back up", n)
        return n
