"""DoH against recorded Google answers (2026-09-18), never against real resolvers."""

from __future__ import annotations

import threading
from pathlib import Path

import httpx
import pytest

from ctwatchtower import db
from ctwatchtower.enrich.doh import Resolver
from ctwatchtower.enrich.net import Cache, TokenBucket, Transient

FIX = Path(__file__).parent / "fixtures" / "enrich"
GOOGLE, CLOUDFLARE = "dns.google", "cloudflare-dns.com"


def recorded(request: httpx.Request) -> httpx.Response:
    name, rtype = request.url.params["name"], request.url.params["type"]
    path = FIX / f"doh_{name.replace('.', '_')}_{rtype}.json"
    if name.startswith("not-registered"):
        path = FIX / "doh_nxdomain_A.json"
    if path.is_file():
        return httpx.Response(200, text=path.read_text(encoding="utf-8"))
    return httpx.Response(200, json={"Status": 0})


def resolver(handler) -> tuple[Resolver, list[str]]:
    seen: list[str] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.host} {request.url.params['type']}")
        return handler(request)

    conn = db.connect(":memory:")
    r = Resolver(Cache(conn, threading.Lock()), http=httpx.Client(transport=httpx.MockTransport(wrapped)))
    return r, seen


def test_resolves_all_types_and_caches_with_dns_ttl() -> None:
    r, seen = resolver(recorded)
    got = r.resolve("lledgerr.com")
    assert got == {
        "a": ["216.198.79.1"],
        "ns": ["dns1.harmonweb.net", "dns2.harmonweb.net"],
        "mx": ["lledgerr.com"],
        "aaaa": [],
        "cname": [],
        "txt": [
            "brevo-code:d0d5fe4f4561e731e1929ce6c02cb3f6",
            "v=spf1 +a +mx +ip4:157.90.178.254 include:relay.mailbaby.net ~all",
        ],
        "nxdomain": False,
    }
    assert len(seen) == 6 and all(s.startswith(GOOGLE) for s in seen)
    assert r.resolve("lledgerr.com") == got and len(seen) == 6  # Cache
    exp = r.cache.conn.execute("SELECT expires_at FROM enrich_cache WHERE key='lledgerr.com'").fetchone()
    from datetime import UTC, datetime

    left = (datetime.fromisoformat(exp[0]) - datetime.now(UTC)).total_seconds()
    assert 14_000 < left <= 14_400  # the smallest TTL of the answers


def test_nxdomain_stops_after_the_first_query() -> None:
    r, seen = resolver(recorded)
    got = r.resolve("not-registered-ctw-4711.com")
    assert got["nxdomain"] is True and got["a"] == [] and len(seen) == 1
    ttl_row = r.cache.conn.execute("SELECT expires_at FROM enrich_cache").fetchone()
    assert ttl_row is not None  # 900 s out of the SOA, inside 5 min ... 6 h


def test_cloudflare_takes_over_when_google_fails() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == GOOGLE:
            return httpx.Response(429) if request.url.params["type"] == "A" else httpx.Response(503)
        return recorded(request)

    r, seen = resolver(handler)
    assert r.resolve("lledgerr.com")["a"] == ["216.198.79.1"]
    assert seen[:2] == [f"{GOOGLE} A", f"{CLOUDFLARE} A"]


def test_both_resolvers_down_is_transient() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == GOOGLE:
            raise httpx.ConnectTimeout("weg")
        return httpx.Response(200, text="not json")

    r, _ = resolver(handler)
    with pytest.raises(Transient):
        r.resolve("lledgerr.com")
    assert r.cache.conn.execute("SELECT COUNT(*) FROM enrich_cache").fetchone()[0] == 0


def test_token_bucket_paces_requests() -> None:
    bucket = TokenBucket(rate=50, burst=1)
    assert bucket.take() == 0.0
    assert 0 < bucket.take() <= 0.02
    import time

    t = time.monotonic()
    bucket.acquire()
    bucket.acquire()
    assert time.monotonic() - t >= 0.02
