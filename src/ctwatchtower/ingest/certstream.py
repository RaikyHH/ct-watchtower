"""CertStream ingest (mode A, §3.1) against our own `certstream-server-go`.

Reconnect with exponential backoff and jitter, heartbeat as liveness, the
bandwidth-saving hostname channel. Backpressure instead of data loss (§3.3):
when the queue is full the ingest blocks, it throws nothing away.
"""

import hashlib
import json
import logging
import queue
import random
import threading
import time
from datetime import UTC, datetime

import websocket

from ctwatchtower.config import settings
from ctwatchtower.ingest.dedupe import TTLSet
from ctwatchtower.normalize.names import CertContext

log = logging.getLogger(__name__)

BACKOFF_BASE = 1.0
BACKOFF_CAP = 300.0
HEARTBEAT_TIMEOUT = 120.0


def backoff_delay(attempt: int) -> float:
    """Exponential from 1 s up to 300 s, ±20 % jitter (§3.2)."""
    return min(BACKOFF_CAP, BACKOFF_BASE * 2**attempt) * random.uniform(0.8, 1.2)


def _ts(value) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(value, UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def parse_message(raw: str | bytes) -> CertContext | None:
    """CertStream message -> `CertContext`. `None` for heartbeats and empty ones.

    Understands both channels of `certstream-server-go`: the full
    `certificate_update` and the bandwidth-saving hostname channel
    (`dns_entries`, names only).
    """
    msg = json.loads(raw)
    if not isinstance(msg, dict) or msg.get("message_type") == "heartbeat":
        return None

    data = msg.get("data")
    if isinstance(data, list):  # hostname channel
        names = [n for n in data if n]
        if not names:
            return None
        return CertContext(
            log_id="",
            idx=-1,
            seen_at=datetime.now(UTC),
            not_before=None,
            not_after=None,
            issuer_cn="",
            issuer_o="",
            serial="",
            sha256=_names_digest(names),
            is_precert=False,
            names=names,
        )

    if not isinstance(data, dict):
        return None
    leaf = data.get("leaf_cert") or {}
    names = [n for n in (leaf.get("all_domains") or []) if n]
    if not names:
        return None
    issuer = leaf.get("issuer") or {}
    fingerprint = (leaf.get("fingerprint") or "").replace(":", "").lower()
    return CertContext(
        log_id=(data.get("source") or {}).get("name", ""),
        idx=int(data.get("cert_index", -1) or -1),
        seen_at=_ts(data.get("seen")) or datetime.now(UTC),
        not_before=_ts(leaf.get("not_before")),
        not_after=_ts(leaf.get("not_after")),
        issuer_cn=issuer.get("CN") or "",
        issuer_o=issuer.get("O") or "",
        serial=leaf.get("serial_number") or "",
        sha256=fingerprint or _names_digest(names),
        is_precert=data.get("update_type") == "PrecertLogEntry",
        names=names,
    )


def _names_digest(names: list[str]) -> str:
    """Stand-in key for the hostname channel, which carries no fingerprint."""
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


class CertStreamIngest:
    """Pushes `CertContext` objects into a `queue.Queue`. No Redis, one process."""

    def __init__(
        self,
        out: queue.Queue,
        url: str | None = None,
        user_agent: str | None = None,
        dedupe: TTLSet | None = None,
    ) -> None:
        self.out = out
        self.url = url or settings.certstream_url
        self.user_agent = user_agent or settings.ct_user_agent
        self.dedupe = dedupe if dedupe is not None else TTLSet(settings.dedupe_cert_ttl)
        self.stop = threading.Event()
        self.last_message = 0.0
        self.certs_seen = 0
        self.certs_duplicate = 0

    def handle(self, raw: str | bytes) -> CertContext | None:
        """Handle one message and queue it if needed. Blocks when the queue is full."""
        self.last_message = time.monotonic()
        cert = parse_message(raw)
        if cert is None:
            return None
        self.certs_seen += 1
        if not self.dedupe.add(cert.sha256):
            self.certs_duplicate += 1
            return None
        self.out.put(cert)  # backpressure: blocking, nothing gets dropped
        return cert

    def run(self) -> None:
        attempt = 0
        while not self.stop.is_set():
            try:
                ws = websocket.create_connection(
                    self.url,
                    header=[f"User-Agent: {self.user_agent}"],
                    timeout=HEARTBEAT_TIMEOUT,
                )
            except Exception as exc:  # noqa: BLE001 - any connection error means backoff
                delay = backoff_delay(attempt)
                attempt += 1
                log.warning("CertStream unreachable (%s), retrying in %.1fs", exc, delay)
                self.stop.wait(delay)
                continue

            log.info("CertStream connected: %s", self.url)
            attempt = 0
            self.last_message = time.monotonic()
            try:
                while not self.stop.is_set():
                    self.handle(ws.recv())
            except Exception as exc:  # noqa: BLE001 - a timeout also means: reconnect
                log.warning("CertStream connection lost: %s", exc)
            finally:
                ws.close()

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self.run, name="certstream-ingest", daemon=True)
        thread.start()
        return thread

    @property
    def alive(self) -> bool:
        """Liveness: not too much time since the last heartbeat or certificate."""
        return bool(self.last_message) and time.monotonic() - self.last_message < HEARTBEAT_TIMEOUT
