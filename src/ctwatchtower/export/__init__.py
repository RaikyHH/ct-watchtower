"""The feed formats (§11): CSV, JSON, JSON Lines, a plain list of domains.

What gets included is whatever reaches `thresholds.feed_from` and is neither
`false_positive` nor `suppressed` (§11). Every record carries the score **and** the
rule reasoning - a feed is a list of domains with the label "suspicious", and the
consumer should be able to judge for themselves instead of trusting a bare name
(§16.3, §16.5).
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

SCHEMA_VERSION = 1
PRODUCER = "CT-Watchtower"

CSV_COLUMNS = (
    "first_seen", "last_seen", "domain", "registrable", "tld", "tenant", "score",
    "severity", "status", "matched_rules", "issuer", "cert_not_before", "cert_sha256",
    "ct_log", "ct_index", "registrar", "domain_created", "epp_status", "nameservers",
    "a_records", "mx_present", "asn", "as_org", "country", "vt_detections",
    "campaign_id", "ui_url",
)


def _matched(row: dict) -> list[str]:
    explanation = row.get("explanation") or {}
    return list(explanation.get("matched") or []) if isinstance(explanation, dict) else []


def _joined(value: Any) -> str:
    """List-valued fields with `|`. A comma collides with the CSV separator (§11.1)."""
    if isinstance(value, list):
        return "|".join(str(v) for v in value)
    return "" if value is None else str(value)


def _ui_url(base: str, row: dict) -> str:
    return f"{base.rstrip('/')}/findings?t={row['tenant_id']}&q={row['domain']}" if base else ""


def to_csv(rows: list[dict], *, ui_base: str = "") -> bytes:
    """UTF-8 **with a BOM**. Otherwise Excel shows accented characters wrongly (§11.1)."""
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")  # RFC 4180
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow(
            [
                row.get("first_seen", ""), row.get("last_seen", ""), row["domain"],
                row.get("registrable", ""), row.get("tld", ""), row["tenant_id"],
                row.get("score", ""), row.get("severity", ""), row.get("status", ""),
                _joined(_matched(row)), row.get("issuer_o", ""),
                row.get("cert_not_before", ""), row.get("cert_sha256", ""),
                row.get("ct_log_id", ""), row.get("ct_log_index", ""),
                row.get("registrar", ""), row.get("domain_created", ""),
                _joined(row.get("epp_status")), _joined(row.get("nameservers")),
                _joined(row.get("a_records")), _joined(row.get("has_mx")),
                row.get("asn", ""), row.get("as_org", ""), row.get("country", ""),
                row.get("vt_detections", ""), row.get("campaign_id", ""),
                _ui_url(ui_base, row),
            ]
        )
    return b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")


def indicator(row: dict, *, ttl_days: int, ui_base: str = "") -> dict:
    """A finding as an indicator (§11.2). `confidence` is the score, not a verdict (§16.3)."""
    valid_until = None
    if first := row.get("first_seen"):
        try:
            valid_until = (datetime.fromisoformat(first) + timedelta(days=ttl_days)).isoformat()
        except ValueError:
            valid_until = None
    domain = row["domain"]
    return {
        "id": row["id"],
        "type": "domain",
        "value": domain,
        "registrable": row.get("registrable"),
        "score": row.get("score"),
        "severity": row.get("severity"),
        "confidence": row.get("score"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "valid_until": valid_until,
        "matched_rules": _matched(row),
        "certificate": {
            "sha256": row.get("cert_sha256"),
            "issuer": row.get("issuer_o"),
            "not_before": row.get("cert_not_before"),
            "not_after": row.get("cert_not_after"),
            "ct_log": row.get("ct_log_id"),
            "ct_index": row.get("ct_log_index"),
        },
        "enrichment": {
            "registrar": row.get("registrar"),
            "domain_created": row.get("domain_created"),
            "epp_status": row.get("epp_status"),
            "nameservers": row.get("nameservers"),
            "a_records": row.get("a_records"),
            "mx_present": row.get("has_mx"),
            "asn": row.get("asn"),
            "as_org": row.get("as_org"),
            "country": row.get("country"),
        },
        "references": {
            "crtsh": f"https://crt.sh/?q={domain}",
            "virustotal": f"https://www.virustotal.com/gui/domain/{domain}",
            "ui": _ui_url(ui_base, row),
        },
    }


def to_json(rows: list[dict], *, tenant: str, tlp: str, since: str | None,
            ttl_days: int, ui_base: str = "") -> bytes:
    doc = {
        "feed": {
            "name": f"ct-watchtower/{tenant}",
            "generated_at": datetime.now(UTC).isoformat(),
            "since": since,
            "count": len(rows),
            "tlp": tlp,
            "producer": PRODUCER,
            "schema_version": SCHEMA_VERSION,
        },
        "indicators": [indicator(r, ttl_days=ttl_days, ui_base=ui_base) for r in rows],
    }
    return json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")


def to_jsonl(rows: list[dict], *, ttl_days: int, ui_base: str = "") -> bytes:
    lines = (json.dumps(indicator(r, ttl_days=ttl_days, ui_base=ui_base), ensure_ascii=False)
             for r in rows)
    return ("\n".join(lines) + "\n" if rows else b"".decode()).encode("utf-8")


def to_domains(rows: list[dict]) -> bytes:
    """The watched names, unique and sorted, for sinkholes and pihole.

    What gets written out is what stood in the certificate, not the registrable
    domain derived from it. The difference is the one between a blocklist and an
    outage: if the suspicion sits in the subdomain, the registrable domain belongs
    to the provider, not to the attacker. That way
    `dbserver-hz-dataset.postgres.database.azure.com` became `azure.com` and
    `z4n-paylio-smoke-test-pod28.zendesk.com` became `zendesk.com`; measured, that
    affected 1447 out of 1945 entries of one tenant. Anyone who tips this file into
    a resolver blocks out half their own house.

    Wildcard certificates lose nothing by this: `*.phish.top` becomes `phish.top`
    while being normalised, so the apex stands in the list in any case.
    """
    names = sorted({r["domain"] for r in rows})
    return ("\n".join(names) + "\n" if names else "").encode("utf-8")
