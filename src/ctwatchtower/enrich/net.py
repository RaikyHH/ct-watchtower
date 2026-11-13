"""Shared parts of the sources: token bucket, per-server blocks, error kinds, HTTP client."""

from __future__ import annotations

import functools
import ipaddress
import logging
import socket
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from datetime import time as dtime

import httpx

from ctwatchtower.config import settings
from ctwatchtower.db import cache_get, cache_put, quota_counts, quota_take

log = logging.getLogger(__name__)

BACKOFF_429 = 600.0  # §7.2: a server that answers 429 rests for 10 min


class Defer(Exception):
    """Not now. Try again later. Does not count as a failed attempt.

    That way a throttled server does not clog the queue: the job goes back with a
    due time of `wait` and other jobs carry on.
    """

    def __init__(self, wait: float, why: str = "") -> None:
        super().__init__(why or f"again in {wait:.1f} s")
        self.wait = wait


class Transient(Exception):
    """A temporary error (network, 5xx, 429). Counts as a failed attempt (§7.1: 3 max)."""


class TokenBucket:
    def __init__(self, rate: float, burst: float = 1.0) -> None:
        self.rate, self.burst = rate, burst
        self.tokens, self.t = burst, time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> float:
        """Takes a token and returns 0, or returns the wait without taking one."""
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            return (1 - self.tokens) / self.rate

    def acquire(self) -> None:
        """Blocking. Only for sources with a short wait (DoH, 10/s)."""
        while wait := self.take():
            time.sleep(wait)


class ServerLimits:
    """One token bucket per server plus the 429 block (§7.2)."""

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self.buckets: dict[str, TokenBucket] = {}
        self.blocked: dict[str, float] = {}
        self.lock = threading.Lock()

    def check(self, server: str) -> None:
        """Raises `Defer` if the server is blocked or its bucket is empty."""
        with self.lock:
            until = self.blocked.get(server, 0.0)
            bucket = self.buckets.setdefault(server, TokenBucket(self.rate))
        if until > time.monotonic():
            raise Defer(until - time.monotonic(), f"{server} is resting after a 429")
        if wait := bucket.take():
            raise Defer(wait)

    def block(self, server: str, seconds: float = BACKOFF_429) -> None:
        with self.lock:
            self.blocked[server] = time.monotonic() + seconds


# Exactly that string, no contact, URL or identity. One source for every outgoing
# request, so two values cannot drift apart by accident.



class BlockedTarget(Exception):
    """The target sits in our own network. Passed outwards as a `Transient`."""


class PublicNetworkTransport(httpx.HTTPTransport):
    """Allows connections to publicly reachable addresses only.

    RDAP servers redirect. A registry sends you on to the registrar for details. The
    client follows those redirects automatically, which means a third party picks
    the target address. If it points at `127.0.0.1`, `169.254.169.254` or into the
    internal network, the enrichment turns into a tool for reaching behind the
    firewall from outside (SSRF).

    Checked when the connection is made, not on the URL: a name resolution that
    only points at an internal address on the second look would otherwise get
    through. A short window stays open between check and connection. Only a
    resolver of our own would help against that, which is out of all proportion.
    """

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if not _is_public(host):
            raise BlockedTarget(f"{host} is not on the public network")
        return super().handle_request(request)


@functools.lru_cache(maxsize=512)
def _is_public(host: str) -> bool:
    """Resolves the name and demands that every address is publicly routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True  # not resolvable: the connection fails on its own anyway
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not address.is_global or address.is_loopback or address.is_private:
            return False
    return True


def proxy_mounts() -> dict[str, httpx.BaseTransport]:
    """Transports per scheme that honour `http_proxy`, `https_proxy` and `no_proxy`.

    httpx reads those variables by itself - but only for the transport it builds. We
    bring our own (the SSRF guard above), and passing `transport=` turns the
    automatic handling off completely: measured with httpx 0.28, a client with a
    custom transport ignores `HTTPS_PROXY` without a word. So the mounts are
    assembled here by hand.

    The parsing is left to `urllib.request`, which reads both spellings of each
    variable and already understands what `no_proxy` entries like `.internal`,
    `localhost` or a bare address mean. Writing that again would only add a second,
    worse implementation.
    """
    proxies = urllib.request.getproxies()
    mounts: dict[str, httpx.BaseTransport] = {}
    for scheme in ("http", "https"):
        url = proxies.get(scheme)
        mounts[f"{scheme}://"] = PublicNetworkTransport(proxy=url) if url else PublicNetworkTransport()
    return mounts


class _ProxyAwareTransport(httpx.BaseTransport):
    """Picks the transport per request, so `no_proxy` can decide per host.

    httpx binds a proxy to a transport, and a transport does not see the request
    before it is chosen. `no_proxy` is a per-host decision, so the choice has to
    happen here.
    """

    def __init__(self) -> None:
        self._mounts = proxy_mounts()
        self._direct = PublicNetworkTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if urllib.request.proxy_bypass(host):
            return self._direct.handle_request(request)
        return self._mounts[f"{request.url.scheme}://"].handle_request(request)

    def close(self) -> None:
        self._direct.close()
        for transport in self._mounts.values():
            transport.close()


def client(accept: str) -> httpx.Client:
    """A client with a connection pool per source, with no route into our network.

    Goes through `http_proxy`/`https_proxy` when they are set, and straight out for
    everything `no_proxy` names - which is what keeps the local certstream and a
    cloud metadata address from being sent to a proxy.
    """
    return httpx.Client(
        timeout=settings.enrich_timeout,
        headers={"User-Agent": settings.ct_user_agent, "Accept": accept},
        follow_redirects=True,
        transport=_ProxyAwareTransport(),
    )


def _seconds_to_midnight() -> float:
    now = datetime.now(UTC)
    return (datetime.combine(now.date() + timedelta(days=1), dtime(), UTC) - now).total_seconds()


class Quota:
    """Hard daily caps per source and per server, counted in SQLite (`enrich_quota`).

    Once a cap is reached, `take()` raises a `Defer` until midnight UTC; the job
    rests, it is not a failed attempt. Every exhausted cap is logged once.
    """

    def __init__(self, conn, lock: threading.Lock) -> None:
        self.conn, self.lock = conn, lock
        self.logged: set[tuple[str, str]] = set()

    @staticmethod
    def today() -> str:
        return datetime.now(UTC).date().isoformat()

    def take(self, limits: dict[str, int]) -> None:
        day = self.today()
        with self.lock:
            full = quota_take(self.conn, day, limits)
        if full is not None:
            if (day, full) not in self.logged:
                self.logged.add((day, full))
                log.warning("daily cap %s (%d) reached, enrichment rests until tomorrow",
                            full, limits[full])
            raise Defer(_seconds_to_midnight(), f"daily cap {full}")

    def status(self) -> dict:
        """Daily counters for the metrics and the system screen."""
        day = self.today()
        with self.lock:
            counts = quota_counts(self.conn, day)
        return {
            "day": day,
            "counts": counts,
            "limits": {src: daily_limits(src)[src] for src in ("rdap", "whois", "doh")},
            "exhausted": sorted(k for k, n in counts.items() if n >= limit_of(k)),
        }


def daily_limits(source: str, server: str | None = None) -> dict[str, int]:
    """Key -> daily cap: the total per source, and for RDAP/WHOIS also per server."""
    total = {"rdap": settings.enrich_rdap_daily, "whois": settings.enrich_whois_daily,
             "doh": settings.enrich_doh_daily,
             # The scan submissions count in the same pot. Their cap applies per
             # service, not across all of them together, which is why the key is
             # always `scan:<service>`; there is no bare `scan` counter.
             "scan": settings.scan_daily}
    per_server = {"rdap": settings.enrich_rdap_daily_per_server,
                  "whois": settings.enrich_whois_daily_per_server,
                  "scan": settings.scan_daily}
    out = {source: total[source]}
    if server and source in per_server:
        out[f"{source}:{server}"] = per_server[source]
    return out


def limit_of(key: str) -> int:
    """The daily cap for a counter key, and `0` when the key is new.

    The fallback is deliberate, not sloppiness: this function runs over *all* stored
    counters on the system screen. A key the code here does not know yet has already
    taken down the whole screen and the enrichment with a KeyError once, set off by a
    single click on "run analysis". A cap nobody knows counts as reached: that is the
    safe side, and it stays visible anyway.
    """
    source, _, server = key.partition(":")
    try:
        return daily_limits(source, server or None)[key]
    except KeyError:
        log.warning("no daily cap on record for the counter %r", key)
        return 0


class Cache:
    """The SQLite cache (`enrich_cache`) behind the pipeline lock, with hit counters.

    The shared connection is `check_same_thread=False`. Every access under `lock`.
    """

    def __init__(self, conn, lock: threading.Lock) -> None:
        self.conn, self.lock = conn, lock
        self.hits = self.misses = 0

    def get(self, source: str, key: str):
        with self.lock:
            data = cache_get(self.conn, source, key)
        if data is None:
            self.misses += 1
        else:
            self.hits += 1
        return data

    def put(self, source: str, key: str, data, ttl: float) -> None:
        with self.lock:
            cache_put(self.conn, source, key, data, ttl)

    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return round(self.hits / total, 4) if total else 0.0
