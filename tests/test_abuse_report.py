"""Abuse report (§17.2): a draft for the mail program, never a send."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from ctwatchtower.enrich.abuse import MAILTO_MAX, fields, report, template

FINDING = {
    "domain": "payli0-secure-login.top",
    "registrable": "payli0-secure-login.top",
    "tenant_id": "banking",
    "score": 97,
    "severity": "alert",
    "first_seen": "2026-09-19T10:22:31+00:00",
    "issuer_o": "Let's Encrypt",
    "cert_not_before": "2026-09-19T10:20:00+00:00",
    "cert_sha256": "9f2c",
    "ct_log_id": "oak2026h1",
    "ct_log_index": 918273645,
    "registrar": "NameSilo, LLC",
    "registrar_abuse_email": "abuse@namesilo.com",
    "domain_created": "2026-09-17",
    "nameservers": '["ns1.example.net", "ns2.example.net"]',
    "a_records": '["203.0.113.44"]',
    "epp_status": '["clientTransferProhibited"]',
    "explanation": {"matched": ["anchor:paylio(homoglyph)", "lure:login"]},
}


def test_the_report_carries_the_evidence_from_the_ct_log() -> None:
    r = report(FINDING)
    assert r["to"] == "abuse@namesilo.com"
    assert r["subject"] == "Abuse report: payli0-secure-login.top"
    # Without the CT log index and the certificate it would be a claim, not a report (§17.2)
    for required in ("oak2026h1", "918273645", "Let's Encrypt", "9f2c",
                     "https://crt.sh/?q=payli0-secure-login.top"):
        assert required in r["body"], required
    assert "NameSilo, LLC" in r["body"] and "2026-09-17" in r["body"]
    assert "ns1.example.net, ns2.example.net" in r["body"], "lists readable, not as JSON"
    assert "anchor:paylio(homoglyph), lure:login" in r["body"]


def test_the_mailto_holds_subject_and_text() -> None:
    r = report(FINDING)
    parts = urlsplit(r["mailto"])
    assert parts.scheme == "mailto" and unquote(parts.path) == "abuse@namesilo.com"
    query = parse_qs(parts.query)
    assert query["subject"][0] == r["subject"]
    assert query["body"][0] == r["body"]
    assert r["mailto_ok"] is True and len(r["mailto"]) <= MAILTO_MAX


def test_without_enrichment_there_is_no_recipient_but_a_reason() -> None:
    """The abuse address is only known after a click, and the panel says so."""
    r = report({"domain": "velton-login.top"})
    assert r["to"] == "" and "enrich" in r["reason"]
    assert r["body"], "the report itself is ready to copy anyway"


def test_unknown_values_are_not_invented() -> None:
    values = fields({"domain": "x.top"})
    assert values["registrar"] == "-" and values["nameservers"] == "-"
    assert "-" in report({"domain": "x.top"})["body"]


def test_a_report_that_is_too_long_drops_the_mailto(monkeypatch) -> None:
    """Windows only opens `mailto:` up to around 2000 characters, so copy instead."""
    long = dict(FINDING,
                nameservers='["' + '", "'.join(f"ns{i}.example.net" for i in range(200)) + '"]')
    r = report(long)
    assert len(r["mailto"]) > MAILTO_MAX and r["mailto_ok"] is False
    assert r["to"] == "abuse@namesilo.com" and r["body"]


@pytest.mark.parametrize("language", ["de", "en"])
def test_both_templates_are_usable(language: str) -> None:
    subject, body = template(language)
    assert "{domain}" in subject and "{ct_index}" in body
    assert not body.lstrip().startswith("#"), "comment lines do not belong in the mail"


def test_an_unknown_language_falls_back_to_english() -> None:
    assert template("klingon") == template("en")
