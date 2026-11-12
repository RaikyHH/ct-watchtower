"""Alerting through a generic webhook (§8).

The receiver is an endpoint of the user's own, not somebody else's infrastructure,
so legally uncritical. The risk is a different one: a phishing wave produces
hundreds of findings in minutes, and whoever gets flooded switches the alerts off.
§8.2 names the remedies, and all of them are implemented here for good:

* **Aggregation** over `notify_window` (300 s). One message instead of a hundred.
* **Rate limiting** `notify_max_per_hour` (12).
* **Repeat suppression**: the same registrable domain again at the earliest after
  `notify_renotify_days` (7). Unless the score rises by more than `rescore_delta`.
* **Delivery attempts**: three with growing gaps, after that the channel counts as
  degraded.

Both states live in SQLite, not in memory: otherwise every container start reports
everything again. That exact class of bug set off unwanted queries on 2026-09-19.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from ctwatchtower.config import settings
from ctwatchtower.notify import mail

log = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 1, "warning": 2, "alert": 3}
MAX_IN_PAYLOAD = 20  # §8.2: a summary with examples, not the whole wave
RETRY_DELAYS = (2.0, 10.0)  # two retries, then the attempt is over

SCHEMA = """
CREATE TABLE IF NOT EXISTS notify_state (
    tenant_id   TEXT NOT NULL,
    registrable TEXT NOT NULL,
    sent_at     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, registrable)
);
CREATE TABLE IF NOT EXISTS notify_log (
    sent_at  TEXT NOT NULL,
    ok       INTEGER NOT NULL,
    findings INTEGER NOT NULL
);
"""


def _now() -> datetime:
    return datetime.now(UTC)


def configured() -> tuple[bool, str]:
    """Says whether alerts may go out, and if not, what is missing.

    Two conditions, not one, deliberately: a switch **and** a
    target. That way nothing can go out by accident, and the system screen can say
    which of the two is missing.

    The targets are the webhook and mail. One is enough; both work too.
    """
    if not settings.notify_enabled:
        return False, "off"
    mail_ok, _ = mail.configured()
    if not settings.notify_webhook_url and not mail_ok:
        return False, "no target configured"
    return True, "ready"


class Notifier:
    """Collects findings and sends them to the webhook in batches."""

    def __init__(self, pipeline) -> None:
        self.pipeline = pipeline
        self.buffer: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.sent = 0
        self.failed = 0
        self.suppressed = 0
        # `degraded`: no channel accepted. Next to it one per channel, so the system
        # screen can say which one is stuck.
        self.degraded = False
        self.webhook_degraded = False
        self.mail_degraded = False
        with pipeline.db_lock:
            pipeline.conn.executescript(SCHEMA)
            pipeline.conn.commit()

    # ------------------------------ Intake ------------------------------

    def offer(self, event: dict[str, Any]) -> bool:
        """Note a finding down for the next message. Returns whether it counts."""
        ok, _ = configured()
        if not ok:
            return False
        if SEVERITY_RANK.get(event.get("severity", ""), 0) < SEVERITY_RANK.get(
            settings.notify_min_severity, 2
        ):
            return False
        if not self._may_notify(event):
            self.suppressed += 1
            return False
        with self.lock:
            self.buffer.append(event)
        return True

    def _may_notify(self, event: dict[str, Any]) -> bool:
        """§8.2.3: the same domain only again after `renotify_days`, unless the score jumps."""
        key = (event["tenant"], event.get("registrable") or event["domain"])
        with self.pipeline.db_lock:
            row = self.pipeline.conn.execute(
                "SELECT sent_at, score FROM notify_state WHERE tenant_id=? AND registrable=?", key
            ).fetchone()
        if row is None:
            return True
        try:
            last = datetime.fromisoformat(row["sent_at"])
        except ValueError:
            return True
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if _now() - last >= timedelta(days=settings.notify_renotify_days):
            return True
        return int(event.get("score", 0)) - int(row["score"]) > settings.rescore_delta

    # ------------------------------ Sending -----------------------------

    def _hourly(self) -> int:
        since = (_now() - timedelta(hours=1)).isoformat()
        with self.pipeline.db_lock:
            row = self.pipeline.conn.execute(
                "SELECT COUNT(*) n FROM notify_log WHERE sent_at>=? AND ok=1", (since,)
            ).fetchone()
        return row["n"]

    def payload(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """The message format of §8.3."""
        counts: dict[str, int] = {}
        for e in events:
            counts[e["severity"]] = counts.get(e["severity"], 0) + 1
        base = settings.ui_base_url.rstrip("/")
        tenant = events[0]["tenant"]
        return {
            "version": 1,
            "tenant": tenant,
            "generated_at": _now().isoformat(),
            "window_seconds": settings.notify_window,
            "counts": counts,
            "ui_url": f"{base}/findings?t={tenant}" if base else "",
            "findings": [
                {
                    "id": e["id"],
                    "domain": e["domain"],
                    "registrable": e.get("registrable"),
                    "score": e.get("score"),
                    "severity": e.get("severity"),
                    "first_seen": e.get("first_seen"),
                    "matched": e.get("matched") or [],
                    "links": {
                        "ui": f"{base}/findings?t={tenant}&q={e['domain']}" if base else "",
                        "crtsh": f"https://crt.sh/?q={e['domain']}",
                        "virustotal": f"https://www.virustotal.com/gui/domain/{e['domain']}",
                    },
                }
                for e in sorted(events, key=lambda x: -int(x.get("score") or 0))[:MAX_IN_PAYLOAD]
            ],
            "truncated": max(0, len(events) - MAX_IN_PAYLOAD),
        }

    def _post(self, body: bytes) -> bool:
        headers = {"Content-Type": "application/json", "User-Agent": settings.ct_user_agent}
        if secret := settings.notify_secret:
            headers["X-Watchtower-Signature"] = hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
        for attempt, pause in enumerate((*RETRY_DELAYS, None)):
            try:
                with httpx.Client(timeout=settings.notify_timeout) as client:
                    resp = client.post(settings.notify_webhook_url, content=body, headers=headers)
                if resp.status_code < 400:
                    return True
                log.warning("webhook answered %s (attempt %d)", resp.status_code, attempt + 1)
            except httpx.HTTPError as exc:
                log.warning("webhook unreachable: %s (attempt %d)", exc, attempt + 1)
            if pause is not None and not self.pipeline.stop_event.wait(pause):
                continue
            break
        return False

    def flush(self) -> int:
        """Send the buffered findings as **one** message per tenant. Returns the findings sent."""
        ok, _ = configured()
        with self.lock:
            events, self.buffer = self.buffer, []
        if not ok or not events:
            return 0
        if self._hourly() >= settings.notify_max_per_hour:
            # §8.2.2: do not drop them silently. Say it once and let the findings go,
            # they are in the UI. A backlog would only shift the wave.
            if not self.degraded:
                log.warning(
                    "rate limit: more than %d messages in the last hour, further "
                    "findings stay in the UI only",
                    settings.notify_max_per_hour,
                )
            self.suppressed += len(events)
            return 0

        sent = 0
        by_tenant: dict[str, list[dict]] = {}
        for e in events:
            by_tenant.setdefault(e["tenant"], []).append(e)
        for tenant, group in by_tenant.items():
            data = self.payload(group)
            # Every configured channel gets the same summary. The message counts as
            # delivered as soon as **one** of them accepted it: otherwise a broken
            # webhook would defeat the repeat suppression and the same findings
            # would come by mail over and over.
            results = []
            if settings.notify_webhook_url:
                ok_hook = self._post(json.dumps(data, ensure_ascii=False).encode("utf-8"))
                self.webhook_degraded = not ok_hook
                results.append(ok_hook)
            if mail.configured()[0]:
                results.append(self._mail(data))
            delivered = any(results)
            self.degraded = not delivered
            with self.pipeline.db_lock:
                self.pipeline.conn.execute(
                    "INSERT INTO notify_log (sent_at, ok, findings) VALUES (?,?,?)",
                    (_now().isoformat(), int(delivered), len(group)),
                )
                if delivered:
                    self.pipeline.conn.executemany(
                        "INSERT INTO notify_state (tenant_id, registrable, sent_at, score)"
                        " VALUES (?,?,?,?) ON CONFLICT(tenant_id, registrable) DO UPDATE SET"
                        " sent_at=excluded.sent_at, score=excluded.score",
                        [
                            (tenant, e.get("registrable") or e["domain"], _now().isoformat(),
                             int(e.get("score") or 0))
                            for e in group
                        ],
                    )
                # Clear out old rows: the counter only needs an hour of history.
                self.pipeline.conn.execute(
                    "DELETE FROM notify_log WHERE sent_at < ?",
                    ((_now() - timedelta(days=2)).isoformat(),),
                )
                self.pipeline.conn.commit()
            if delivered:
                self.sent += 1
                sent += len(group)
            else:
                self.failed += 1
                log.error("no route accepted the message, counts as degraded")
        return sent

    def _mail(self, data: dict[str, Any]) -> bool:
        """Send a mail. Without retries: unlike a webhook a mail server either
        accepts or refuses, and a refused mail does not get better by retrying."""
        try:
            mail.send(mail.subject(data), mail.text(data))
            self.mail_degraded = False
            return True
        except Exception as exc:  # noqa: BLE001 - every error is the same state
            self.mail_degraded = True
            log.error("mail not delivered: %s", exc)
            return False

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.wait(settings.notify_window):
            try:
                self.flush()
            except Exception:  # noqa: BLE001 - one broken message does not stop the pipeline
                log.exception("alerting failed")

    def status(self) -> dict[str, Any]:
        ok, reason = configured()
        channels = []
        if settings.notify_webhook_url:
            channels.append({"kind": "webhook", "degraded": self.webhook_degraded,
                            "target": settings.notify_webhook_url.split("//")[-1][:48]})
        mail_state = mail.status()
        if settings.mail_enabled:
            channels.append({
                "kind": "mail", "degraded": self.mail_degraded or not mail_state["ok"],
                "target": mail_state["route"] if mail_state["ok"] else mail_state["state"],
            })
        return {
            "channels": channels,
            "mail_ready": mail_state["ok"],
            "state": reason if not ok else ("degraded" if self.degraded else "ready"),
            "queued": len(self.buffer),
            "sent": self.sent,
            "failed": self.failed,
            "suppressed": self.suppressed,
            "last_hour": self._hourly() if ok else 0,
            "max_per_hour": settings.notify_max_per_hour,
        }
