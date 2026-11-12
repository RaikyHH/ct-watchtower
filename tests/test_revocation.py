"""Revoked CA certificates: reading DER, reading OneCRL in, checking, maintaining.

No test here goes onto the network. `conftest` blocks sockets, and the fetch gets
a fake of its own. Mozilla's Remote Settings is public infrastructure, but a test
suite that runs against it on every pass would still be bad manners.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from ctwatchtower.db import connect
from ctwatchtower.revocation import onecrl, store
from ctwatchtower.revocation.checker import Checker
from ctwatchtower.revocation.der import DerError, fields, readable, spki_hash


def tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def certificate(serial: bytes = b"\x12\x34", issuer: bytes = b"ISSUER",
               subject: bytes = b"SUBJECT", key: bytes = b"PUBKEY") -> bytes:
    """A minimal certificate with exactly the fields revocation lists address."""
    tbs = tlv(0x30,
              tlv(0xA0, tlv(0x02, b"\x02"))
              + tlv(0x02, serial)
              + tlv(0x30, b"ALG")
              + tlv(0x30, issuer)
              + tlv(0x30, b"VALID")
              + tlv(0x30, subject)
              + tlv(0x30, key))
    return tlv(0x30, tbs + tlv(0x30, b"ALG") + tlv(0x03, b"\x00SIG"))


# ───────────────────────────── Reading DER ───────────────────────────


def test_der_self_check():
    from ctwatchtower.revocation.der import demo

    demo()


def test_the_four_fields_come_out_right():
    der = certificate()
    f = fields(der)
    assert f["serial"] == b"\x12\x34", "the serial without its header - that is how OneCRL counts"
    assert f["issuer"] == tlv(0x30, b"ISSUER"), "the issuer with its header"
    assert f["subject"] == tlv(0x30, b"SUBJECT")
    assert spki_hash(der) == hashlib.sha256(tlv(0x30, b"PUBKEY")).digest()


def test_broken_bytes_raise_instead_of_guessing():
    for junk in (b"", b"\x30", b"\x30\x7fzuwenig", b"\x02\x01\x00"):
        with pytest.raises(DerError):
            fields(junk)


def test_names_become_readable():
    """Without plain text the interface shows base64, which is of no use."""
    real = base64.b64decode(
        "MD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJWMRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0I=")
    assert readable(real) == "NL, eMudhra BV, EM DV TLS CA - G3B"
    assert readable(b"\x00broken") == "", "unreadable means empty, not a crash"


# ───────────────────────── Reading OneCRL in ─────────────────────────


def fake(response: httpx.Response, seen: list | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return response

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_the_fetch_sends_the_etag_and_understands_a_304():
    seen: list[httpx.Request] = []
    rulesets, etag = onecrl.fetch("\"abc\"", http=fake(httpx.Response(304), seen))
    assert seen[0].headers["If-None-Match"] == "\"abc\""
    assert seen[0].headers["User-Agent"] == "CT-Watchtower", "no contact details"
    # A 304 means "unchanged", not "no revocations".
    assert (rulesets, etag) == ([], "\"abc\"")


def test_an_empty_list_is_not_taken_over():
    """Otherwise a broken server deletes the whole revocation list."""
    with pytest.raises(onecrl.Unreachable):
        onecrl.fetch(http=fake(httpx.Response(200, json={"data": []})))


def test_switched_off_revocations_do_not_count():
    rulesets = [
        {"enabled": True, "issuerName": "QQ==", "serialNumber": "Ag==", "details": {}},
        {"enabled": False, "issuerName": "Qg==", "serialNumber": "Aw==", "details": {}},
    ]
    e = onecrl.entries(rulesets)
    assert len(e) == 1, "a withdrawn revocation is none"
    assert e[0]["kind"] == "issuer_serial"


def test_both_ways_of_addressing_are_taken_over():
    rulesets = [
        {"enabled": True, "subject": "QQ==", "pubKeyHash": "Qg==", "details": {}},
        {"enabled": True, "issuerName": "Qw==", "serialNumber": "RA==", "details": {}},
    ]
    assert {e["kind"] for e in onecrl.entries(rulesets)} == {"spki", "issuer_serial"}


# ───────────────────────────── Checking ──────────────────────────────


def test_checks_over_the_key_hash_as_mozilla_did_with_emudhra():
    der = certificate(subject=b"EMUDHRA", key=b"WEAKKEY")
    f = fields(der)
    entry = {
        "kind": "spki", "name": "Sample",
        "value": f"{base64.b64encode(f['subject']).decode()}|"
                f"{base64.b64encode(hashlib.sha256(f['spki']).digest()).decode()}",
    }
    p = Checker()
    p.load([entry])
    assert p.check(der) is entry
    assert p.check(certificate(subject=b"OTHER", key=b"WEAKKEY")) is None


def test_checks_over_the_issuer_and_the_serial():
    der = certificate(serial=b"\xde\xad", issuer=b"ROOT")
    f = fields(der)
    entry = {
        "kind": "issuer_serial", "name": "Sample",
        "value": f"{base64.b64encode(f['issuer']).decode()}|"
                f"{base64.b64encode(f['serial']).decode()}",
    }
    p = Checker()
    p.load([entry])
    assert p.check(der) is entry
    # The same serial under a different issuer is a different certificate.
    assert p.check(certificate(serial=b"\xde\xad", issuer=b"OTHER")) is None


def test_sha256_matches_exactly_one_certificate():
    der = certificate()
    entry = {"kind": "sha256", "value": hashlib.sha256(der).hexdigest(), "name": "Sample"}
    p = Checker()
    p.load([entry])
    assert p.check(der) is entry
    assert p.check(certificate(serial=b"\x99")) is None


def test_an_empty_list_revokes_nothing():
    p = Checker()
    assert p.check(certificate()) is None
    assert len(p) == 0


def test_the_chain_is_checked_from_the_back():
    """A revoked intermediate certificate weighs more than a revoked leaf."""
    intermediate = certificate(subject=b"INTERMEDIATE", key=b"IK")
    leaf = certificate(subject=b"LEAF", key=b"LK")
    f = fields(intermediate)
    entry = {
        "kind": "spki", "name": "Intermediate certificate",
        "value": f"{base64.b64encode(f['subject']).decode()}|"
                f"{base64.b64encode(hashlib.sha256(f['spki']).digest()).decode()}",
    }
    p = Checker()
    p.load([entry])
    chain = [
        {"as_der": base64.b64encode(leaf).decode(), "sha256": hashlib.sha256(leaf).hexdigest()},
        {"as_der": base64.b64encode(intermediate).decode(),
         "sha256": hashlib.sha256(intermediate).hexdigest()},
    ]
    hits = p.check_chain(chain)
    assert hits is not None
    assert hits[0] is entry


def test_the_verdict_is_remembered():
    """Otherwise the check could not be afforded in the CT stream."""
    der = certificate()
    p = Checker()
    p.load([{"kind": "sha256", "value": hashlib.sha256(der).hexdigest(), "name": "x"}])
    key = hashlib.sha256(der).hexdigest()
    p.check(der, key)
    assert key in p._verdict
    # A new state of the list discards the old verdicts.
    p.load([])
    assert p._verdict == {}


# ──────────────────────────── Maintaining ────────────────────────────


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "t.sqlite3")
    yield c
    c.close()


def test_an_own_entry_is_normalised(conn):
    """A fingerprint gets copied with colons in it. That must not be an error."""
    with_colons = ("0F:C0:90:1C:CA:2B:AE:9E:9F:DB:B0:2D:50:D0"
                   ":2F:10:94:F7:B3:66:72:08:69:91:B9:E8:97:62:6D:C4:85:F0")
    store.add_entry(conn, "sha256", with_colons, name="Sample")
    stored = store.all_entries(conn)[0]
    assert stored["value"] == with_colons.replace(":", "").lower()
    assert stored["source"] == "manual"


def test_nonsense_is_refused(conn):
    for kind, value in (("sha256", "too-short"), ("made-up", "x"),
                      ("spki", "no-separator"), ("sha256", "")):
        with pytest.raises(ValueError):
            store.add_entry(conn, kind, value)


def test_fetched_entries_can_only_be_switched_off(conn):
    """Deleting them would be in vain. The next sync brings them back."""
    conn.execute("INSERT INTO ca_revocations (source, kind, value, created_at)"
                 " VALUES ('onecrl','sha256','a'||hex(randomblob(31)),'2026-01-01')")
    conn.commit()
    entry_id = store.all_entries(conn)[0]["id"]
    with pytest.raises(ValueError):
        store.remove_entry(conn, entry_id)
    assert store.toggle_entry(conn, entry_id, False) is True
    assert store.all_entries(conn, only_active=True) == []


def test_a_sync_replaces_only_the_fetched_ones(conn, monkeypatch):
    """A sync must not clear away entries of our own."""
    store.add_entry(conn, "sha256", "ab" * 32, name="mine")
    monkeypatch.setattr(onecrl, "fetch", lambda etag=None, **kw: (
        [{"enabled": True, "issuerName": "QQ==", "serialNumber": "Ag==", "details": {}}], "\"new\""))
    result = store.sync(conn)
    assert result["status"] == "updated"
    sources = {e["source"] for e in store.all_entries(conn)}
    assert sources == {"manual", "onecrl"}
    assert any(e["name"] == "mine" for e in store.all_entries(conn))


def test_unchanged_leaves_what_is_there_standing(conn, monkeypatch):
    conn.execute("INSERT INTO ca_revocations (source, kind, value, created_at)"
                 " VALUES ('onecrl','sha256','cd','2026-01-01')")
    conn.commit()
    monkeypatch.setattr(onecrl, "fetch", lambda etag=None, **kw: ([], etag))
    result = store.sync(conn, "\"old\"")
    assert result["status"] == "unchanged"
    assert len(store.all_entries(conn)) == 1, "a 304 deletes nothing"


# ───────────────────────────── The hits ──────────────────────────────


def test_the_same_hit_stands_there_once_and_is_counted(conn):
    """A certificate arrives several times in the CT stream; as a hit it is one."""
    record = {"leaf_sha256": "AB" * 32, "revoked_issuer": "Test-CA",
            "names": ["evil.example"], "names_total": 1, "chain": ["A", "B"]}
    assert store.report_hit(conn, record) is True, "new the first time"
    assert store.report_hit(conn, record) is False, "not any more after that"
    hits = store.hits(conn)
    assert len(hits) == 1
    assert hits[0]["hit_count"] == 2
    assert hits[0]["names"] == ["evil.example"], "lists come back as lists"


def test_hits_that_were_ticked_off_do_not_come_back(conn):
    """The watch sees the same certificate again, and the status has to stay."""
    record = {"leaf_sha256": "CD" * 32, "revoked_issuer": "Test-CA", "names": [], "chain": []}
    store.report_hit(conn, record)
    assert store.set_hit_status(conn, "CD" * 32, "checked") is True
    store.report_hit(conn, record)
    assert store.hits(conn)[0]["status"] == "checked"
    assert store.count_hits(conn) == {"total": 1, "new": 0}


def test_an_unknown_status_is_refused(conn):
    store.report_hit(conn, {"leaf_sha256": "EF" * 32, "names": [], "chain": []})
    with pytest.raises(ValueError):
        store.set_hit_status(conn, "EF" * 32, "made-up")
    assert store.set_hit_status(conn, "99" * 32, "checked") is False


def test_the_api_serves_hits_and_accepts_the_status(tmp_path, monkeypatch):
    from conftest import copy_rule_base

    from ctwatchtower.app import create_app
    from ctwatchtower.config import settings as s

    monkeypatch.setattr(s, "api_token", None)
    rules = copy_rule_base(tmp_path / "rules")
    app = create_app(db_path=tmp_path / "t.sqlite3", rules_dir=rules, start_pipeline=False)
    try:
        store.report_hit(app.config["DB"], {
            "leaf_sha256": "11" * 32, "revoked_issuer": "Test-CA",
            "names": ["x.example"], "names_total": 1, "chain": ["A"]})
        c = app.test_client()
        d = c.get("/api/v1/revocations/findings").get_json()
        assert d["numbers"] == {"total": 1, "new": 1}
        assert d["items"][0]["names"] == ["x.example"]

        assert c.patch(f"/api/v1/revocations/findings/{'11' * 32}",
                       json={"status": "benign"}).status_code == 200
        assert c.get("/api/v1/revocations/findings?status=new").get_json()["items"] == []
        assert c.patch(f"/api/v1/revocations/findings/{'11' * 32}",
                       json={"status": "nonsense"}).status_code == 422
        assert c.patch(f"/api/v1/revocations/findings/{'22' * 32}",
                       json={"status": "new"}).status_code == 404
    finally:
        app.config["DB"].close()


def test_several_processes_may_write(tmp_path):
    """The watch runs as a service of its own against the same file as the application.

    Without `busy_timeout` the second writer would get "database is locked" at once.
    """
    path = tmp_path / "shared.sqlite3"
    a, b = connect(path), connect(path)
    try:
        assert a.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
        store.report_hit(a, {"leaf_sha256": "aa" * 32, "names": [], "chain": []})
        store.report_hit(b, {"leaf_sha256": "bb" * 32, "names": [], "chain": []})
        assert len(store.hits(a)) == 2, "both connections write into the same file"
    finally:
        a.close()
        b.close()
