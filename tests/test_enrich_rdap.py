"""RDAP and WHOIS against recorded answers (tests/fixtures/enrich/), never against real servers.

Recorded on 2026-09-18: `vendora.dev` (Google Registry), `lledgerr.com` (Verisign),
WHOIS `vendoraaws.eu` (EURid) and `vendoraaws.com.cn` (CNNIC, with a registrant and an email).
Cut down for data frugality: the registrant's email is replaced by `hostmaster@example.cn`,
and the IANA answer for `.cn` is reduced to the lines without contact persons.
"""

from __future__ import annotations

import copy
import json
import threading
from pathlib import Path

import httpx
import pytest

from ctwatchtower import db
from ctwatchtower.enrich.net import Cache, Defer, Transient
from ctwatchtower.enrich.rdap import (
    REGISTRATION_FIELDS,
    Registration,
    domain_age_days,
    parse_rdap,
    parse_whois,
)

FIX = Path(__file__).parent / "fixtures" / "enrich"

# Synthetic personal data. This is what an unredacted answer would look like.
PII = [
    "John Doe",
    "Doe Phishing Ltd",
    "1 Example Street",
    "10115",
    "max@example.org",
    "+49.301234567",
    "Privacy notice",
    "REDACTED FOR PRIVACY",
]
REGISTRANT = {
    "objectClassName": "entity",
    "roles": ["registrant", "administrative"],
    "handle": "C123-LLEDGERR",
    "vcardArray": [
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "John Doe"],
            ["org", {}, "text", "Doe Phishing Ltd"],
            ["adr", {}, "text", ["", "", "1 Example Street", "Berlin", "", "10115", "DE"]],
            ["email", {}, "text", "max@example.org"],
            ["tel", {"type": "voice"}, "uri", "tel:+49.301234567"],
        ],
    ],
    "remarks": [{"title": "Privacy notice", "description": ["REDACTED FOR PRIVACY"]}],
}


def fixture(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def rdap_with_registrant() -> dict:
    doc = json.loads(fixture("rdap_lledgerr_com.json"))
    doc["entities"].append(copy.deepcopy(REGISTRANT))
    # A registrar with a nested abuse contact (email, phone); that stays out as well.
    doc["entities"][0].setdefault("entities", []).append(
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@namesilo.com"]]]}
    )
    return doc


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


def registration(conn, routes: dict[str, httpx.Response | Exception], whois=None) -> Registration:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        answer = routes.get(str(request.url))
        if isinstance(answer, Exception):
            raise answer
        return answer if answer is not None else httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    reg = Registration(Cache(conn, threading.Lock()), http=http, whois=whois)
    reg.calls = calls
    return reg


BOOT = "https://data.iana.org/rdap/dns.json"
VRSN = "https://rdap.verisign.com/com/v1/domain/"


def boot() -> httpx.Response:
    return httpx.Response(200, text=fixture("rdap_bootstrap_dns.json"))


# ──────────────────────────── The §16.2 allowlist ────────────────────────


def test_registrant_vcard_leaves_nothing_in_result_cache_or_database(conn) -> None:
    """The evidence for §16.2: the registrant's name, organisation, address, email
    and phone stand in the answer and nowhere after it."""
    answer = httpx.Response(200, json=rdap_with_registrant())
    reg = registration(conn, {BOOT: boot(), VRSN + "lledgerr.com": answer})
    data = reg.lookup("lledgerr.com")

    assert set(data) <= REGISTRATION_FIELDS
    assert data["registrar"] == "NameSilo, LLC" and data["registrar_iana_id"] == 1479
    assert data["created"].startswith("2026-09-13")
    # The one deliberate exception (§17.2): the abuse contact **of the registrar**, an
    # organisational address. It comes out of the `abuse` role below the registrar -
    # never out of the registrant entry that stands beside it in this answer.
    assert data["registrar_abuse_email"] == "abuse@namesilo.com"
    dump = "\n".join(conn.iterdump())
    assert "lledgerr.com" in dump  # the cache entry exists ...
    for needle in PII + ["C123-LLEDGERR"]:
        assert needle not in dump and needle not in json.dumps(data, ensure_ascii=False)
    assert reg.lookup("lledgerr.com") == data and reg.calls.count(VRSN + "lledgerr.com") == 1  # Cache


def test_whois_registrant_and_contact_email_are_dropped() -> None:
    cn = parse_whois(fixture("whois_amazonaws_com_cn.txt"))
    assert set(cn) <= REGISTRATION_FIELDS
    assert cn["registrar"] == "厦门易名科技股份有限公司" and cn["created"].startswith("2006-01-13")
    assert cn["expires"].startswith("2027-01-13") and "clientTransferProhibited" in cn["epp_status"]
    assert "ns-3287.awsdns-cn-13.cn" in cn["nameservers"]
    text = json.dumps(cn, ensure_ascii=False)
    assert "宁夏西云" not in text and "example.cn" not in text


def test_whois_sections_only_yield_registrar_name_and_nameservers() -> None:
    eu = parse_whois(fixture("whois_amazonaws_eu.txt"))
    assert eu == {
        "registrar": "Com Laude (Nom IQ Ltd, trading as)",
        "nameservers": [
            "ns-1166.awsdns-eusc-17.nl",
            "ns-184.awsdns-eusc-23.fr",
            "ns-2023.awsdns-eusc-60.eu",
            "ns-658.awsdns-eusc-18.de",
        ],
    }
    # A `Name:` under `Registrant:` never becomes the registrar.
    text = "Registrant:\n        Name: John Doe\n        Email: max@example.org\n\n"
    text += "Registrar IANA ID: 292\n"
    assert parse_whois(text) == {"registrar_iana_id": 292}


def test_whois_generic_keys_and_unreadable_dates() -> None:
    text = (
        "% Kommentar\n>>> Last update <<<\nRegistrar: Example Registrar\nRegistrar IANA ID: n/a\n"
        "Creation Date: gestern\nCreated On: 12-Nov-2002\nUpdated Date: 01.02.2020\n"
        "Domain Status: ok https://icann.org/epp#ok\nnserver: NS1.Example.NET.\nfree text without a colon\n"
    )
    assert parse_whois(text) == {
        "registrar": "Example Registrar",
        "created": "2002-11-12T00:00:00+00:00",
        "changed": "2020-02-01T00:00:00+00:00",
        "epp_status": ["ok"],
        "nameservers": ["ns1.example.net"],
    }


def test_parse_rdap_real_response_and_brand_registrar() -> None:
    data = parse_rdap(json.loads(fixture("rdap_amazon_dev.json")))
    assert data["registrar"] == "Nom-IQ Limited dba Com Laude" and data["registrar_iana_id"] == 470
    assert data["epp_status"][0] == "clientDeleteProhibited"
    assert data["nameservers"][0] == "ns-101.awsdns-12.com"
    assert parse_rdap({"entities": [{"roles": ["registrar"]}], "status": [" "]}) == {}


def test_domain_age() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 9, 18, tzinfo=UTC)
    assert domain_age_days({"created": "2026-09-13T19:01:02+00:00"}, now) == 4
    assert domain_age_days({"created": "2027-01-01T00:00:00+00:00"}, now) == 0
    assert domain_age_days({}) is None


# ───────────────────────────── Betrieb ──────────────────────────────


def test_cache_ttl_depends_on_domain_age(conn) -> None:
    reg = registration(
        conn,
        {
            BOOT: boot(),
            VRSN + "lledgerr.com": httpx.Response(200, text=fixture("rdap_lledgerr_com.json")),
            "https://pubapi.registry.google/rdap/domain/vendora.dev": httpx.Response(
                200, text=fixture("rdap_amazon_dev.json")
            ),
        },
    )
    reg.lookup("lledgerr.com")
    reg.limits.buckets.clear()  # a different server, but better safe than sorry
    reg.lookup("vendora.dev")
    sql = "SELECT key, expires_at FROM enrich_cache WHERE source='rdap'"
    rows = {r["key"]: r["expires_at"] for r in conn.execute(sql)}
    from datetime import datetime

    young, old = (datetime.fromisoformat(rows[k]) for k in ("lledgerr.com", "vendora.dev"))
    assert round((old - young).total_seconds() / 86400) == 6  # 7 d gegen 24 h


def test_404_and_garbage_are_results_not_failures(conn) -> None:
    reg = registration(conn, {BOOT: boot(), VRSN + "broken.com": httpx.Response(200, text="<html>")})
    assert reg.lookup("unbekannt.com") == {}
    reg.limits.buckets.clear()
    assert reg.lookup("broken.com") == {}


def test_429_parks_the_server_and_defers_other_domains(conn) -> None:
    reg = registration(conn, {BOOT: boot(), VRSN + "a.com": httpx.Response(429)})
    with pytest.raises(Transient):
        reg.lookup("a.com")
    reg.limits.buckets.clear()
    with pytest.raises(Defer) as exc:
        reg.lookup("b.com")
    assert 590 < exc.value.wait <= 600


def test_rate_limit_defers_instead_of_blocking(conn) -> None:
    reg = registration(conn, {BOOT: boot()})
    reg.lookup("a.com")
    with pytest.raises(Defer) as exc:
        reg.lookup("b.com")  # the same server inside one second
    assert 0 < exc.value.wait <= 1.0


def test_server_errors_and_network_errors_are_transient(conn) -> None:
    reg = registration(
        conn, {BOOT: boot(), VRSN + "a.com": httpx.Response(503), VRSN + "b.com": httpx.ConnectError("weg")}
    )
    with pytest.raises(Transient):
        reg.lookup("a.com")
    reg.limits.buckets.clear()
    with pytest.raises(Transient):
        reg.lookup("b.com")
    broken = registration(db.connect(":memory:"), {BOOT: httpx.Response(500)})
    with pytest.raises(Transient):
        broken.lookup("a.com")


def test_whois_fallback_finds_server_via_iana(conn, monkeypatch) -> None:
    from ctwatchtower.config import settings

    monkeypatch.setattr(settings, "enrich_whois_fallback", True)  # the default is off
    asked: list[tuple[str, str]] = []

    def whois(server: str, query: str) -> str:
        asked.append((server, query))
        name = "whois_iana_cn.txt" if server == "whois.iana.org" else "whois_amazonaws_com_cn.txt"
        return fixture(name)

    reg = registration(conn, {BOOT: boot()}, whois=whois)
    assert reg.lookup("vendoraaws.com.cn")["registrar"] == "厦门易名科技股份有限公司"
    reg.limits.buckets.clear()
    reg.lookup("vendoraservices.com.cn")
    assert asked == [
        ("whois.iana.org", "cn"),
        ("whois.cnnic.cn", "vendoraaws.com.cn"),
        ("whois.cnnic.cn", "vendoraservices.com.cn"),
    ]  # IANA only once

    # An IANA answer without a WHOIS server (as with `.lk`): an empty `whois:`, then `status:`.
    iana_lk = "domain:       LK\n\nwhois:        \n\nstatus:       ACTIVE\n"
    none = registration(db.connect(":memory:"), {BOOT: boot()}, whois=lambda s, q: iana_lk)
    assert none.lookup("cardex.com.lk") == {}
    assert none.cache.get("whois-server", "lk") == ""
    monkeypatch.setattr(settings, "enrich_whois_fallback", False)
    off = registration(db.connect(":memory:"), {BOOT: boot()}, whois=lambda s, q: pytest.fail("no WHOIS"))
    assert off.lookup("vendoraaws.com.cn") == {}


def test_abuse_address_is_only_taken_from_the_registrar_branch() -> None:
    """An abuse role on the registrant must never become the recipient address."""
    doc = rdap_with_registrant()
    for entity in doc["entities"]:
        if "registrant" in (entity.get("roles") or []):
            entity["entities"] = [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["email", {}, "text", "max.privat@example.org"]]],
                }
            ]
    data = parse_rdap(doc)
    assert data["registrar_abuse_email"] == "abuse@namesilo.com"
    assert "max.privat@example.org" not in json.dumps(data)
