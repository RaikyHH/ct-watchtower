"""DNS over DoH (§7.4): Google first, Cloudflare on an outage or a rate limit.

The question is asked about the registrable domain (§7.1), never about the full
hostname, and never at the domain itself: the answer comes from the public resolver.
"""

from __future__ import annotations

from typing import Any

import httpx

from ctwatchtower.config import settings
from ctwatchtower.enrich.net import Cache, Quota, TokenBucket, Transient, client, daily_limits

TYPES = {"A": 1, "NS": 2, "MX": 15, "AAAA": 28, "CNAME": 5, "TXT": 16}  # A first: NXDOMAIN saves the rest
TTL_MIN, TTL_MAX = 300, 6 * 3600
NOERROR, NXDOMAIN = 0, 3


def _value(rtype: str, data: str) -> str:
    if rtype == "MX":
        data = data.split()[-1]  # "10 mx.example.com."
    elif rtype == "TXT":
        return data.strip('"')
    return data.lower().rstrip(".")


class Resolver:
    def __init__(self, cache: Cache, http: httpx.Client | None = None) -> None:
        self.cache = cache
        self._http = http
        self.bucket = TokenBucket(settings.enrich_doh_rps, burst=settings.enrich_doh_rps)
        self.servers = [settings.enrich_doh_primary, settings.enrich_doh_fallback]
        self.quota = Quota(cache.conn, cache.lock)

    @property
    def http(self) -> httpx.Client:
        # Only on the first call: an httpx client loads the CA store when created.
        if self._http is None:
            self._http = client("application/dns-json")
        return self._http

    def _query(self, name: str, rtype: str) -> dict[str, Any]:
        last: Exception | None = None
        for server in self.servers:
            self.quota.take(daily_limits("doh"))  # daily cap: Defer until tomorrow
            self.bucket.acquire()  # deliberately simple: blocks briefly (0.1 s at 10/s), no Defer needed
            try:
                resp = self.http.get(server, params={"name": name, "type": rtype})
                if resp.status_code == 200:
                    return resp.json()
                last = Transient(f"{server}: HTTP {resp.status_code}")
            except (httpx.HTTPError, ValueError) as exc:
                last = exc
        raise Transient(f"DoH {name}/{rtype}: {last}") from last

    def resolve(self, registrable: str) -> dict[str, Any]:
        """`{"a": [...], "aaaa": [...], "ns", "mx", "cname", "txt", "nxdomain": bool}`."""
        cached = self.cache.get("doh", registrable)
        if cached is not None:
            return cached
        out: dict[str, Any] = {t.lower(): [] for t in TYPES}
        out["nxdomain"] = False
        ttls: list[int] = []
        for rtype, code in TYPES.items():
            answer = self._query(registrable, rtype)
            if answer.get("Status") == NXDOMAIN:
                out["nxdomain"] = True
                ttls += [r.get("TTL", TTL_MIN) for r in answer.get("Authority") or []]
                break
            for rec in answer.get("Answer") or []:
                if rec.get("type") == code and rec.get("data"):
                    out[rtype.lower()].append(_value(rtype, rec["data"]))
                    ttls.append(rec.get("TTL", TTL_MIN))
        for key in TYPES:
            out[key.lower()] = sorted(set(out[key.lower()]))
        ttl = min(max(min(ttls, default=TTL_MIN), TTL_MIN), TTL_MAX)
        self.cache.put("doh", registrable, out, ttl)
        return out
